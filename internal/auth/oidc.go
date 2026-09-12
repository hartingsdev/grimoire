package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hartingsdev/solid-bassoon/internal/config"
)

// Identity is what the app knows about a person after a login or a
// revalidation. The role comes from the claims and nowhere else.
type Identity struct {
	Subject     string
	Email       string
	DisplayName string
	Role        Role
}

// ErrProviderUnavailable means the IdP did not answer. This is explicitly NOT
// an authoritative "no access" — the caller must not revoke anything over it.
var ErrProviderUnavailable = errors.New("OIDC provider unreachable")

// ErrSessionEndedAtProvider means the provider ended the session or rejected
// the refresh token. This is authoritative.
var ErrSessionEndedAtProvider = errors.New("session ended at the provider")

type OIDCClient struct {
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth         oauth2.Config
	mapper        *RoleMapper
	claimsSource  config.ClaimsSource
	endSessionURL string
	postLogout    string
}

// Provider holds the OIDC client and retries discovery in the background. If
// the IdP is down at startup the process still comes up and reports "not
// ready": a container that crash-loops because the IdP is restarting helps
// nobody.
type Provider struct {
	cfg    config.OIDC
	log    *slog.Logger
	mapper *RoleMapper

	mu     sync.RWMutex
	client *OIDCClient
	err    error
}

func NewProvider(cfg config.OIDC, log *slog.Logger) (*Provider, error) {
	mapper, err := NewRoleMapper(cfg.RoleClaim, cfg.RoleMap)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, log: log, mapper: mapper,
		err: fmt.Errorf("%w: discovery still running", ErrProviderUnavailable)}, nil
}

// Discover loads the provider configuration, retrying until it succeeds or
// the context ends.
func (p *Provider) Discover(ctx context.Context) {
	delay := time.Second
	for {
		client, err := p.connect(ctx)
		p.mu.Lock()
		p.client, p.err = client, err
		p.mu.Unlock()
		if err == nil {
			p.log.Info("OIDC provider reached", "issuer", p.cfg.Issuer)
			return
		}
		p.log.Warn("OIDC discovery failed, retrying",
			"issuer", p.cfg.Issuer, "error", err, "retry_in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < time.Minute {
			delay *= 2
		}
	}
}

func (p *Provider) connect(ctx context.Context) (*OIDCClient, error) {
	provider, err := oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	var extra struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&extra)

	return &OIDCClient{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: p.cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     p.cfg.ClientID,
			ClientSecret: p.cfg.ClientSecret,
			RedirectURL:  p.cfg.RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       p.cfg.Scopes,
		},
		mapper:        p.mapper,
		claimsSource:  p.cfg.ClaimsSource,
		endSessionURL: extra.EndSessionEndpoint,
		postLogout:    p.cfg.PostLogoutRedirect,
	}, nil
}

func (p *Provider) Client() (*OIDCClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.client, p.err
}

func (p *Provider) Ready() bool {
	_, err := p.Client()
	return err == nil
}

// AuthCodeURL builds the redirect to the provider: authorization code flow
// with PKCE, state and nonce.
func (c *OIDCClient) AuthCodeURL(state, nonce, verifier string) string {
	return c.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.AccessTypeOffline)
}

func NewVerifier() string { return oauth2.GenerateVerifier() }

// Exchange redeems the authorization code and verifies the ID token against
// the provider's signature and the nonce.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, *oauth2.Token, error) {
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("code exchange failed: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, nil, errors.New("the provider returned no id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("ID token is not valid: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, nil, errors.New("ID token nonce does not match this login")
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, nil, err
	}
	identity, err := c.identityFrom(ctx, claims, token)
	if err != nil {
		return Identity{}, nil, err
	}
	if identity.Subject == "" {
		identity.Subject = idToken.Subject
	}
	return identity, token, nil
}

// Revalidate asks the provider whether the role still holds. The returned
// token may have been refreshed and should then be persisted.
//
// The error cases are deliberately distinct: ErrProviderUnavailable means "no
// answer" and must take nothing away; ErrSessionEndedAtProvider and an identity
// with RoleNone are authoritative.
func (c *OIDCClient) Revalidate(ctx context.Context, tok *oauth2.Token) (Identity, *oauth2.Token, error) {
	source := c.oauth.TokenSource(ctx, tok)
	fresh, err := source.Token()
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil &&
			retrieveErr.Response.StatusCode >= 400 && retrieveErr.Response.StatusCode < 500 {
			return Identity{}, nil, fmt.Errorf("%w: %v", ErrSessionEndedAtProvider, err)
		}
		return Identity{}, nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	info, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(fresh))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("%w: userinfo: %v", ErrProviderUnavailable, err)
	}
	claims := map[string]any{}
	if err := info.Claims(&claims); err != nil {
		return Identity{}, nil, fmt.Errorf("%w: userinfo unreadable: %v", ErrProviderUnavailable, err)
	}
	identity := c.identityFromClaims(claims)
	if identity.Subject == "" {
		identity.Subject = info.Subject
	}
	return identity, fresh, nil
}

// identityFrom merges claims from the ID token and userinfo. Many providers
// only expose groups at the userinfo endpoint, which is why "both" is the
// default and spares the classic "why is my groups claim empty".
func (c *OIDCClient) identityFrom(ctx context.Context, idClaims map[string]any, token *oauth2.Token) (Identity, error) {
	merged := map[string]any{}
	if c.claimsSource == config.ClaimsIDToken || c.claimsSource == config.ClaimsBoth {
		for k, v := range idClaims {
			merged[k] = v
		}
	}
	if c.claimsSource == config.ClaimsUserinfo || c.claimsSource == config.ClaimsBoth {
		info, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			if c.claimsSource == config.ClaimsUserinfo {
				return Identity{}, fmt.Errorf("userinfo not retrievable: %w", err)
			}
			// Under "both", userinfo is a supplement, not a requirement.
		} else {
			infoClaims := map[string]any{}
			if err := info.Claims(&infoClaims); err == nil {
				for k, v := range infoClaims {
					merged[k] = v
				}
			}
		}
	}
	return c.identityFromClaims(merged), nil
}

func (c *OIDCClient) identityFromClaims(claims map[string]any) Identity {
	return Identity{
		Subject: claimString(claims, "sub"),
		Email:   claimString(claims, "email"),
		DisplayName: firstNonEmpty(claimString(claims, "name"),
			claimString(claims, "preferred_username"), claimString(claims, "email")),
		Role: c.mapper.Resolve(claims),
	}
}

func (c *OIDCClient) EndSessionURL() (string, string) {
	return c.endSessionURL, c.postLogout
}

func claimString(claims map[string]any, key string) string {
	switch v := claims[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
