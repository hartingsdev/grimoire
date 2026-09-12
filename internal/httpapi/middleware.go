package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/ratelimit"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

const (
	sessionCookie = "pl_session"
	csrfHeader    = "X-CSRF-Token"
	// Wie lange "zuletzt genutzt" eines Keys stehen bleiben darf, bevor es neu
	// geschrieben wird. Bei jedem Request zu schreiben wäre der teuerste Teil
	// eines ansonsten sehr billigen Requests.
	keyTouchInterval = 5 * time.Minute
)

// guard setzt den deklarierten Schutz einer Route durch.
func (s *Server) guard(route Route, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.authenticate(w, r)
		if !ok {
			return // authenticate hat bereits geantwortet
		}
		if principal != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
		}

		if route.Access == AccessPublic {
			h(w, r)
			return
		}
		if principal == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"Anmeldung erforderlich. Im Browser über /auth/login, für Skripte per Authorization: Bearer <key>.")
			return
		}
		if route.Access == AccessCapability && !principal.Can(route.Cap) {
			s.denied(w, principal, route)
			return
		}
		// Cookie-Sitzungen brauchen bei schreibenden Zugriffen zusätzlich einen
		// CSRF-Token; Bearer-Aufrufe nicht, da sie keine Cookies mitschicken.
		if principal.Kind == auth.KindSession && !safeMethod(r.Method) {
			if r.Header.Get(csrfHeader) != principal.CSRFToken {
				writeError(w, http.StatusForbidden, "csrf",
					"CSRF-Token fehlt oder passt nicht. Die Seite neu laden.")
				return
			}
		}
		h(w, r)
	})
}

// denied formuliert die Ablehnung so, dass der Aufrufer den Grund erkennt.
func (s *Server) denied(w http.ResponseWriter, p *auth.Principal, route Route) {
	if p.Kind == auth.KindAPIKey {
		for _, managed := range auth.ManagementCapabilities {
			if route.Cap == managed {
				writeError(w, http.StatusForbidden, "forbidden_for_api_key",
					"Dieser Endpunkt ist nur nach Anmeldung im Browser erreichbar. "+
						"API-Keys können weder Keys noch Nutzer verwalten.")
				return
			}
		}
		writeError(w, http.StatusForbidden, "forbidden",
			"Dieser Key darf nur lesen. Für Schreibzugriffe wird ein Key mit der Rolle 'editor' benötigt.")
		return
	}
	writeError(w, http.StatusForbidden, "forbidden",
		"Dafür fehlt dir die Berechtigung. Deine Rolle: "+p.Role.Label()+".")
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// authenticate ermittelt den Principal. Ein fehlender Nachweis ist kein Fehler —
// darüber entscheidet guard anhand der Route. Liefert ok=false, wurde bereits
// geantwortet (etwa beim Rate-Limit).
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		return s.authenticateAPIKey(w, r, header)
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		return s.authenticateSession(w, r, cookie.Value), true
	}
	return nil, true
}

// authenticateAPIKey arbeitet die acht Prüfschritte ab. Jeder bricht ab, und
// keiner verrät dem Aufrufer mehr als nötig.
func (s *Server) authenticateAPIKey(w http.ResponseWriter, r *http.Request, header string) (*auth.Principal, bool) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"Erwartet wird: Authorization: Bearer <key>")
		return nil, false
	}
	// 1+2: Präfix und Instanz prüfen, noch ohne Datenbankzugriff.
	id, secret, err := auth.ParseKey(s.cfg.AppInstance, strings.TrimSpace(raw))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_key",
			"Der Key ist ungültig oder gehört zu einer anderen Instanz.")
		return nil, false
	}
	// 3: Nachschlagen über den Index.
	key, hash, owner, err := s.store.LookupAPIKey(r.Context(), id)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("Key konnte nicht nachgeschlagen werden", "key", auth.MaskKeyID(id), "fehler", err)
		}
		writeError(w, http.StatusUnauthorized, "invalid_key", "Der Key ist ungültig.")
		return nil, false
	}
	// 4: Geheimnis in konstanter Zeit vergleichen.
	if !auth.SecretMatches(secret, hash) {
		writeError(w, http.StatusUnauthorized, "invalid_key", "Der Key ist ungültig.")
		return nil, false
	}
	now := time.Now()
	// 5: Widerruf und Ablauf.
	if key.Revoked() {
		writeError(w, http.StatusUnauthorized, "key_revoked", "Dieser Key wurde widerrufen.")
		return nil, false
	}
	if key.Expired(now) {
		writeError(w, http.StatusUnauthorized, "key_expired", "Dieser Key ist abgelaufen.")
		return nil, false
	}
	// 6: Rate-Limit pro Key.
	res := s.limiter.Allow(key.ID, now)
	setRateLimitHeaders(w, res)
	if !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds()+1)))
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"Zu viele Anfragen. Die RateLimit-Header nennen das erlaubte Tempo.")
		return nil, false
	}
	// 7: min(Rolle des Keys, aktuelle Rolle des Besitzers), inklusive Veralterung.
	effective := store.EffectiveKeyRole(key, owner.CachedRole, owner.CachedRoleAt,
		s.cfg.OwnerStaleAfter, now)
	if !effective.Valid() || owner.Deleted() {
		writeError(w, http.StatusUnauthorized, "owner_inactive",
			"Der Besitzer dieses Keys hat derzeit keinen Zugang. Der Key ist dadurch inaktiv.")
		return nil, false
	}
	if err := s.store.TouchAPIKey(r.Context(), key.ID, now, keyTouchInterval); err != nil {
		s.log.Warn("zuletzt-genutzt konnte nicht geschrieben werden", "key", auth.MaskKeyID(key.ID), "fehler", err)
	}
	// 8: Principal — ab hier kennt kein Handler mehr den Unterschied zur Sitzung.
	return &auth.Principal{
		Kind: auth.KindAPIKey, UserID: owner.ID, Subject: owner.Sub,
		Email: owner.Email, DisplayName: owner.Name(),
		Role: effective, KeyID: key.ID, KeyRole: key.Role,
	}, true
}

// authenticateSession löst eine Browser-Sitzung auf und fragt dabei fällig
// gewordene Rollen beim Provider neu ab.
func (s *Server) authenticateSession(w http.ResponseWriter, r *http.Request, id string) *auth.Principal {
	ctx := r.Context()
	now := time.Now()
	sess, user, err := s.store.GetSession(ctx, id, now)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("Sitzung konnte nicht gelesen werden", "fehler", err)
		}
		s.clearSessionCookie(w)
		return nil
	}
	if now.After(sess.RevalidateAfter) {
		role, ok := s.revalidate(ctx, sess, user, now)
		if !ok {
			s.clearSessionCookie(w)
			return nil
		}
		sess.Role = role
	}
	if err := s.store.TouchSession(ctx, sess.ID, now); err != nil {
		s.log.Warn("Sitzungszeitstempel nicht geschrieben", "fehler", err)
	}
	if !sess.Role.Valid() {
		s.clearSessionCookie(w)
		return nil
	}
	return &auth.Principal{
		Kind: auth.KindSession, UserID: user.ID, Subject: user.Sub,
		Email: user.Email, DisplayName: user.Name(), Role: sess.Role,
		SessionID: sess.ID, CSRFToken: sess.CSRFToken,
	}
}

// revalidate fragt den Provider, ob die Rolle noch gilt.
//
// Entscheidend ist die Unterscheidung der Fehlerfälle: ein nicht erreichbarer
// Provider ist keine Auskunft und darf niemandem etwas wegnehmen, sonst würde
// ein kurzer Ausfall des IdP alle Sitzungen beenden. Nur eine echte Antwort
// ohne passende Rolle beendet die Sitzung.
func (s *Server) revalidate(ctx context.Context, sess store.Session, user store.User, now time.Time) (auth.Role, bool) {
	client, err := s.provider.Client()
	if err != nil {
		s.log.Warn("Revalidierung übersprungen, Provider nicht erreichbar", "fehler", err)
		s.deferRevalidation(ctx, sess, now)
		return sess.Role, true
	}
	identity, fresh, err := client.Revalidate(ctx, &oauth2.Token{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		Expiry:       sess.TokenExpiry,
	})
	switch {
	case errors.Is(err, auth.ErrSessionEndedAtProvider):
		s.log.Info("Sitzung beim Provider beendet", "nutzer", user.ID)
		s.store.DeleteSession(ctx, sess.ID)
		return auth.RoleNone, false
	case errors.Is(err, auth.ErrProviderUnavailable):
		s.log.Warn("Revalidierung fehlgeschlagen, Sitzung bleibt bestehen", "fehler", err)
		s.deferRevalidation(ctx, sess, now)
		return sess.Role, true
	case err != nil:
		s.log.Error("Revalidierung mit unerwartetem Fehler", "fehler", err)
		s.deferRevalidation(ctx, sess, now)
		return sess.Role, true
	}

	// Ab hier ist die Auskunft autoritativ.
	if err := s.store.SetCachedRole(ctx, user.ID, identity.Role, now); err != nil {
		s.log.Error("Rollen-Cache nicht geschrieben", "fehler", err)
	}
	if !identity.Role.Valid() {
		s.log.Info("Zugang entzogen, alle Sitzungen beendet", "nutzer", user.ID)
		s.store.DeleteSessionsForUser(ctx, user.ID)
		return auth.RoleNone, false
	}
	if err := s.store.UpdateSessionAfterRevalidation(ctx, sess.ID, identity.Role,
		fresh.AccessToken, fresh.RefreshToken, fresh.Expiry,
		now.Add(s.cfg.RevalidateInterval)); err != nil {
		s.log.Error("Sitzung nach Revalidierung nicht aktualisiert", "fehler", err)
	}
	return identity.Role, true
}

// deferRevalidation verschiebt den nächsten Versuch um eine Minute, damit ein
// ausgefallener Provider nicht bei jedem Request neu angefragt wird.
func (s *Server) deferRevalidation(ctx context.Context, sess store.Session, now time.Time) {
	_ = s.store.UpdateSessionAfterRevalidation(ctx, sess.ID, sess.Role,
		sess.AccessToken, sess.RefreshToken, sess.TokenExpiry, now.Add(time.Minute))
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// setRateLimitHeaders gibt aufrufenden Skripten die Werte, mit denen sie sich
// selbst bremsen können, statt in 429er zu laufen.
func setRateLimitHeaders(w http.ResponseWriter, res ratelimit.Result) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(res.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(int(time.Until(res.Reset).Seconds()+0.5)))
}

// withSecurityHeaders setzt Kopfzeilen, die für eine Anwendung ohne externe
// Einbindungen gefahrlos streng sein können.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// withLogging protokolliert jeden Request. Der Authorization-Header wird
// grundsätzlich nicht ausgegeben — ein Key darf nie in einem Log landen.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		attrs := []any{
			"methode", r.Method, "pfad", r.URL.Path, "status", sw.status,
			"dauer_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r),
		}
		if p := auth.FromContext(r.Context()); p != nil {
			attrs = append(attrs, "principal", string(p.Kind), "rolle", string(p.Role))
			if p.KeyID != "" {
				attrs = append(attrs, "key", auth.MaskKeyID(p.KeyID))
			}
		}
		s.log.Info("request", attrs...)
	})
}

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("Panik im Handler", "pfad", r.URL.Path,
					"fehler", rec, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal", "Unerwarteter Fehler.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP wertet X-Forwarded-For nur aus, wenn der unmittelbare Absender ein
// als vertrauenswürdig konfigurierter Proxy ist. Sonst könnte jeder Aufrufer
// seine Herkunft frei behaupten.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !s.fromTrustedProxy(addr) {
		return addr.String()
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return addr.String()
	}
	first, _, _ := strings.Cut(forwarded, ",")
	return strings.TrimSpace(first)
}

func (s *Server) fromTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
