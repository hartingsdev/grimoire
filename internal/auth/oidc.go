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

// Identity ist das, was die App nach einem Login oder einer Revalidierung über
// einen Menschen weiß. Die Rolle stammt ausschließlich aus den Claims.
type Identity struct {
	Subject     string
	Email       string
	DisplayName string
	Role        Role
}

// ErrProviderUnavailable bedeutet: der IdP hat nicht geantwortet. Das ist
// ausdrücklich KEINE autoritative Auskunft "kein Zugriff" — der Aufrufer darf
// daraufhin niemandem Rechte entziehen.
var ErrProviderUnavailable = errors.New("OIDC-Provider nicht erreichbar")

// ErrSessionEndedAtProvider bedeutet: der Provider hat die Sitzung beendet oder
// den Refresh-Token verworfen. Das ist autoritativ.
var ErrSessionEndedAtProvider = errors.New("Sitzung beim Provider beendet")

type OIDCClient struct {
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth         oauth2.Config
	mapper        *RoleMapper
	claimsSource  config.ClaimsSource
	endSessionURL string
	postLogout    string
}

// Provider hält den OIDC-Client und holt die Discovery notfalls im Hintergrund
// nach. Ist der IdP beim Start nicht erreichbar, läuft der Prozess trotzdem an
// und meldet sich nur als "nicht bereit" — ein Container, der beim Neustart in
// eine Crash-Schleife läuft, weil der IdP gerade neu startet, hilft niemandem.
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
		err: fmt.Errorf("%w: Discovery läuft noch", ErrProviderUnavailable)}, nil
}

// Discover versucht die Provider-Konfiguration zu laden und wiederholt das im
// Hintergrund, bis es klappt oder der Kontext endet.
func (p *Provider) Discover(ctx context.Context) {
	delay := time.Second
	for {
		client, err := p.connect(ctx)
		p.mu.Lock()
		p.client, p.err = client, err
		p.mu.Unlock()
		if err == nil {
			p.log.Info("OIDC-Provider erreicht", "issuer", p.cfg.Issuer)
			return
		}
		p.log.Warn("OIDC-Discovery fehlgeschlagen, neuer Versuch",
			"issuer", p.cfg.Issuer, "fehler", err, "in", delay)
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

// Client liefert den einsatzbereiten Client oder den Grund, warum es noch keinen gibt.
func (p *Provider) Client() (*OIDCClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.client, p.err
}

func (p *Provider) Ready() bool {
	_, err := p.Client()
	return err == nil
}

// AuthCodeURL baut die Weiterleitung zum Provider — Authorization Code Flow mit
// PKCE, State und Nonce.
func (c *OIDCClient) AuthCodeURL(state, nonce, verifier string) string {
	return c.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.AccessTypeOffline)
}

// NewVerifier erzeugt einen PKCE-Verifier.
func NewVerifier() string { return oauth2.GenerateVerifier() }

// Exchange löst den Autorisierungscode ein und prüft das ID-Token gegen Nonce
// und Signatur des Providers.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, *oauth2.Token, error) {
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("Code-Einlösung fehlgeschlagen: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, nil, errors.New("der Provider hat kein id_token geliefert")
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("ID-Token nicht gültig: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, nil, errors.New("Nonce des ID-Tokens passt nicht zum Login-Vorgang")
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

// Revalidate fragt den Provider, ob die Rolle noch gilt. Der zurückgegebene
// Token kann erneuert sein und gehört dann gespeichert.
//
// Fehlerfälle sind sorgfältig getrennt: ErrProviderUnavailable heißt "keine
// Auskunft" und darf niemandem etwas wegnehmen; ErrSessionEndedAtProvider und
// eine Identität mit RoleNone sind autoritativ.
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
		return Identity{}, nil, fmt.Errorf("%w: userinfo unlesbar: %v", ErrProviderUnavailable, err)
	}
	identity := c.identityFromClaims(claims)
	if identity.Subject == "" {
		identity.Subject = info.Subject
	}
	return identity, fresh, nil
}

// identityFrom führt die Claims aus ID-Token und userinfo zusammen. Viele
// Provider liefern Gruppen nur am userinfo-Endpunkt — deshalb ist "both" der
// Standard und erspart das klassische "warum ist mein groups-Claim leer".
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
				return Identity{}, fmt.Errorf("userinfo nicht abrufbar: %w", err)
			}
			// Bei "both" ist userinfo eine Ergänzung, kein Muss.
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

// EndSessionURL liefert die Abmelde-Adresse des Providers, sofern er eine anbietet.
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
