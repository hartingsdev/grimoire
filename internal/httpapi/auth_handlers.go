package httpapi

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

// oauthStateTTL begrenzt, wie lange ein begonnener Login eingelöst werden kann.
const oauthStateTTL = 10 * time.Minute

// handleLogin startet den Authorization Code Flow mit PKCE. State, Nonce und
// der PKCE-Verifier liegen serverseitig — im Browser landet nichts davon.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if p := auth.FromContext(r.Context()); p != nil && p.Kind == auth.KindSession {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	client, err := s.provider.Client()
	if err != nil {
		s.log.Warn("Login nicht möglich, Provider nicht erreichbar", "fehler", err)
		s.htmlMessage(w, http.StatusServiceUnavailable, "Anmeldung derzeit nicht möglich",
			"Der Anmeldedienst ist nicht erreichbar. Bitte in einem Moment erneut versuchen.")
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

// handleCallback nimmt den Provider entgegen, prüft ID-Token, Nonce und State
// und legt erst danach eine Sitzung an.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		s.log.Warn("Provider hat den Login abgelehnt",
			"fehler", providerError, "beschreibung", query.Get("error_description"))
		s.htmlMessage(w, http.StatusForbidden, "Anmeldung abgebrochen",
			"Der Anmeldedienst hat die Anmeldung abgelehnt: "+providerError)
		return
	}
	client, err := s.provider.Client()
	if err != nil {
		s.htmlMessage(w, http.StatusServiceUnavailable, "Anmeldung derzeit nicht möglich",
			"Der Anmeldedienst ist nicht erreichbar.")
		return
	}

	now := time.Now()
	nonce, verifier, redirectTo, err := s.store.TakeOAuthState(r.Context(), query.Get("state"), now)
	if err != nil {
		// Auch der Fall "zweimal auf denselben Link geklickt" landet hier: ein
		// State ist genau einmal einlösbar.
		s.htmlMessage(w, http.StatusBadRequest, "Anmeldung abgelaufen",
			"Dieser Anmeldevorgang ist nicht mehr gültig. Bitte erneut anmelden.")
		return
	}

	identity, token, err := client.Exchange(r.Context(), query.Get("code"), verifier, nonce)
	if err != nil {
		s.log.Warn("Code-Einlösung fehlgeschlagen", "fehler", err)
		s.htmlMessage(w, http.StatusForbidden, "Anmeldung fehlgeschlagen",
			"Die Anmeldung konnte nicht abgeschlossen werden.")
		return
	}
	if identity.Subject == "" {
		s.htmlMessage(w, http.StatusForbidden, "Anmeldung fehlgeschlagen",
			"Der Anmeldedienst hat keine Kennung (sub) geliefert.")
		return
	}

	// Kein Eintrag in der App entscheidet über den Zugang, sondern der Claim.
	// Fehlt die Rolle, endet es hier — ohne dass ein Konto angelegt wird.
	if !identity.Role.Valid() {
		s.log.Info("Anmeldung ohne passende Rolle abgelehnt",
			"sub", identity.Subject, "claim", s.cfg.OIDC.RoleClaim)
		s.htmlMessage(w, http.StatusForbidden, "Kein Zugriff",
			fmt.Sprintf("Dein Konto hat für diese Instanz keine Rolle. "+
				"Nötig ist ein passender Wert im Claim %q deines Anmeldedienstes. "+
				"Wende dich an die Administration.", s.cfg.OIDC.RoleClaim))
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
	s.log.Info("Anmeldung erfolgreich", "nutzer", user.ID, "rolle", string(identity.Role))
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// handleLogout beendet die Sitzung lokal und nennt, sofern der Provider eine
// Abmeldeadresse anbietet, den Ort für die Abmeldung dort.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if p != nil && p.SessionID != "" {
		if err := s.store.DeleteSession(r.Context(), p.SessionID); err != nil {
			s.log.Warn("Sitzung konnte nicht gelöscht werden", "fehler", err)
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

// safeRedirect lässt nur Ziele innerhalb dieser Anwendung zu. Ohne diese Prüfung
// wäre ?next= eine offene Weiterleitung.
func safeRedirect(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// htmlMessage rendert die wenigen Seiten, die vor dem Laden der Oberfläche
// nötig sind — bewusst ohne Skript und ohne Abhängigkeiten.
func (s *Server) htmlMessage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s – %s</title>
<style>
 :root{color-scheme:light dark}
 body{font:16px/1.6 system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1.5rem}
 h1{font-size:1.4rem;margin:0 0 .5rem}
 p{margin:0 0 1.5rem;opacity:.85}
 a{color:inherit}
</style></head><body>
<h1>%s</h1><p>%s</p><p><a href="/">Zurück zur Übersicht</a></p>
</body></html>`,
		html.EscapeString(title), html.EscapeString(s.cfg.AppTitle),
		html.EscapeString(title), html.EscapeString(message))
}
