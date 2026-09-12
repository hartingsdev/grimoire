package httpapi

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hartingsdev/grimoire/internal/auth"
	"github.com/hartingsdev/grimoire/internal/store"
)

const oauthStateTTL = 10 * time.Minute

// handleLogin starts the authorization code flow with PKCE. State, nonce and
// verifier stay server-side; none of it reaches the browser.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if p := auth.FromContext(r.Context()); p != nil && p.Kind == auth.KindSession {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	client, err := s.provider.Client()
	if err != nil {
		s.log.Warn("login unavailable, provider unreachable", "error", err)
		s.htmlMessage(w, http.StatusServiceUnavailable, "Sign-in currently unavailable",
			"The identity provider is not reachable. Please try again in a moment.")
		return
	}

	state, nonce, verifier := store.NewToken(), store.NewToken(), auth.NewVerifier()
	now := time.Now()
	if err := s.store.SaveOAuthState(r.Context(), state, nonce, verifier,
		safeRedirect(r.URL.Query().Get("next")), now, now.Add(oauthStateTTL)); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	http.Redirect(w, r, client.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		s.log.Warn("provider rejected the login",
			"error", providerError, "description", query.Get("error_description"))
		s.htmlMessage(w, http.StatusForbidden, "Sign-in cancelled",
			"The identity provider rejected the sign-in: "+providerError)
		return
	}
	client, err := s.provider.Client()
	if err != nil {
		s.htmlMessage(w, http.StatusServiceUnavailable, "Sign-in currently unavailable",
			"The identity provider is not reachable.")
		return
	}

	now := time.Now()
	nonce, verifier, redirectTo, err := s.store.TakeOAuthState(r.Context(), query.Get("state"), now)
	if err != nil {
		// Clicking the same link twice lands here too: a state is single-use.
		s.htmlMessage(w, http.StatusBadRequest, "Sign-in expired",
			"This sign-in is no longer valid. Please sign in again.")
		return
	}

	identity, token, err := client.Exchange(r.Context(), query.Get("code"), verifier, nonce)
	if err != nil {
		s.log.Warn("code exchange failed", "error", err)
		s.htmlMessage(w, http.StatusForbidden, "Sign-in failed",
			"The sign-in could not be completed.")
		return
	}
	if identity.Subject == "" {
		s.htmlMessage(w, http.StatusForbidden, "Sign-in failed",
			"The identity provider returned no subject (sub).")
		return
	}

	// The claim decides access, not any record in the app. Without a role it
	// ends here, and no account is created.
	if !identity.Role.Valid() {
		s.log.Info("sign-in refused, no matching role",
			"sub", identity.Subject, "claim", s.cfg.OIDC.RoleClaim)
		s.htmlMessage(w, http.StatusForbidden, "No access",
			fmt.Sprintf("Your account has no role for this instance. It needs a "+
				"matching value in the %q claim from your identity provider. "+
				"Please contact an administrator.", s.cfg.OIDC.RoleClaim))
		return
	}

	user, err := s.store.UpsertUserOnLogin(r.Context(), identity.Subject,
		identity.Email, identity.DisplayName, identity.Role, now)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	sess, err := s.store.CreateSession(r.Context(), user.ID, identity.Role,
		token.AccessToken, token.RefreshToken, token.Expiry,
		now, now.Add(s.cfg.SessionMaxAge), now.Add(s.cfg.RevalidateInterval))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.setSessionCookie(w, sess.ID, s.cfg.SessionMaxAge)
	s.log.Info("sign-in succeeded", "user", user.ID, "role", string(identity.Role))
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// handleLogout ends the local session and, if the provider offers one, returns
// its logout URL.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if p != nil && p.SessionID != "" {
		if err := s.store.DeleteSession(r.Context(), p.SessionID); err != nil {
			s.log.Warn("could not delete session", "error", err)
		}
	}
	s.clearSessionCookie(w)

	providerLogout := ""
	if client, err := s.provider.Client(); err == nil {
		endpoint, postLogout := client.EndSessionURL()
		if endpoint != "" {
			u, err := url.Parse(endpoint)
			if err == nil {
				q := u.Query()
				q.Set("client_id", s.cfg.OIDC.ClientID)
				if postLogout != "" {
					q.Set("post_logout_redirect_uri", postLogout)
				}
				u.RawQuery = q.Encode()
				providerLogout = u.String()
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"providerLogoutUrl": providerLogout})
}

// safeRedirect keeps ?next= from becoming an open redirect.
func safeRedirect(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// htmlMessage renders the few pages needed before the UI loads — no script,
// no dependencies.
func (s *Server) htmlMessage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s – %s</title>
<style>
 :root{color-scheme:light dark}
 body{font:16px/1.6 system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1.5rem}
 h1{font-size:1.4rem;margin:0 0 .5rem}
 p{margin:0 0 1.5rem;opacity:.85}
 a{color:inherit}
</style></head><body>
<h1>%s</h1><p>%s</p><p><a href="/">Back to the library</a></p>
</body></html>`,
		html.EscapeString(title), html.EscapeString(s.cfg.AppTitle),
		html.EscapeString(title), html.EscapeString(message))
}
