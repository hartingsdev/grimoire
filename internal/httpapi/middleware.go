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
	// How stale a key's "last used" may get before it is rewritten. Writing it
	// on every request would be the most expensive part of a cheap request.
	keyTouchInterval = 5 * time.Minute
)

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
				"Authentication required. In a browser via /auth/login, for scripts via Authorization: Bearer <key>.")
			return
		}
		if route.Access == AccessCapability && !principal.Can(route.Cap) {
			s.denied(w, principal, route)
			return
		}
		// Cookie sessions need a CSRF token for writes; bearer calls do not,
		// since they carry no cookies.
		if principal.Kind == auth.KindSession && !safeMethod(r.Method) {
			if r.Header.Get(csrfHeader) != principal.CSRFToken {
				writeError(w, http.StatusForbidden, "csrf",
					"CSRF token missing or mismatched. Reload the page.")
				return
			}
		}
		h(w, r)
	})
}

func (s *Server) denied(w http.ResponseWriter, p *auth.Principal, route Route) {
	if p.Kind == auth.KindAPIKey {
		for _, managed := range auth.ManagementCapabilities {
			if route.Cap == managed {
				writeError(w, http.StatusForbidden, "forbidden_for_api_key",
					"This endpoint is reachable only after signing in with a browser. "+
						"API keys can manage neither keys nor users.")
				return
			}
		}
		writeError(w, http.StatusForbidden, "forbidden",
			"This key may only read. Writing needs a key with the 'editor' role.")
		return
	}
	writeError(w, http.StatusForbidden, "forbidden",
		"You do not have permission for that. Your role: "+p.Role.Label()+".")
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// authenticate resolves the principal. A missing credential is not an error —
// guard decides that per route. ok=false means a response was already written.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		return s.authenticateAPIKey(w, r, header)
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		return s.authenticateSession(w, r, cookie.Value), true
	}
	return nil, true
}

// authenticateAPIKey walks the eight checks. Each one bails out, and none
// tells the caller more than it must.
func (s *Server) authenticateAPIKey(w http.ResponseWriter, r *http.Request, header string) (*auth.Principal, bool) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"Expected: Authorization: Bearer <key>")
		return nil, false
	}
	// 1+2: prefix and instance, still without touching the database.
	id, secret, err := auth.ParseKey(s.cfg.AppInstance, strings.TrimSpace(raw))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_key",
			"The key is invalid or belongs to a different instance.")
		return nil, false
	}
	// 3: index lookup.
	key, hash, owner, err := s.store.LookupAPIKey(r.Context(), id)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("key lookup failed", "key", auth.MaskKeyID(id), "error", err)
		}
		writeError(w, http.StatusUnauthorized, "invalid_key", "The key is invalid.")
		return nil, false
	}
	// 4: compare the secret in constant time.
	if !auth.SecretMatches(secret, hash) {
		writeError(w, http.StatusUnauthorized, "invalid_key", "The key is invalid.")
		return nil, false
	}
	now := time.Now()
	// 5: revocation and expiry.
	if key.Revoked() {
		writeError(w, http.StatusUnauthorized, "key_revoked", "This key has been revoked.")
		return nil, false
	}
	if key.Expired(now) {
		writeError(w, http.StatusUnauthorized, "key_expired", "This key has expired.")
		return nil, false
	}
	// 6: per-key rate limit.
	res := s.limiter.Allow(key.ID, now)
	setRateLimitHeaders(w, res)
	if !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds()+1)))
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"Too many requests. The RateLimit headers state the allowed pace.")
		return nil, false
	}
	// 7: min(key role, owner's current role), staleness included.
	effective := store.EffectiveKeyRole(key, owner.CachedRole, owner.CachedRoleAt,
		s.cfg.OwnerStaleAfter, now)
	if !effective.Valid() || owner.Deleted() {
		writeError(w, http.StatusUnauthorized, "owner_inactive",
			"The owner of this key currently has no access, so the key is inactive.")
		return nil, false
	}
	if err := s.store.TouchAPIKey(r.Context(), key.ID, now, keyTouchInterval); err != nil {
		s.log.Warn("could not record last-used", "key", auth.MaskKeyID(key.ID), "error", err)
	}
	// 8: principal — past here no handler tells a key from a session.
	return &auth.Principal{
		Kind: auth.KindAPIKey, UserID: owner.ID, Subject: owner.Sub,
		Email: owner.Email, DisplayName: owner.Name(),
		Role: effective, KeyID: key.ID, KeyRole: key.Role,
	}, true
}

// authenticateSession resolves a browser session, re-checking the role with
// the provider when revalidation falls due.
func (s *Server) authenticateSession(w http.ResponseWriter, r *http.Request, id string) *auth.Principal {
	ctx := r.Context()
	now := time.Now()
	sess, user, err := s.store.GetSession(ctx, id, now)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("could not read session", "error", err)
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
		s.log.Warn("could not update session timestamp", "error", err)
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

// revalidate asks the provider whether the role still holds.
//
// Telling the failure modes apart is the whole point: an unreachable provider
// is not an answer and must take nothing away, or a brief IdP outage would end
// every session. Only a real response without a matching role ends one.
func (s *Server) revalidate(ctx context.Context, sess store.Session, user store.User, now time.Time) (auth.Role, bool) {
	client, err := s.provider.Client()
	if err != nil {
		s.log.Warn("revalidation skipped, provider unreachable", "error", err)
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
		s.log.Info("session ended at the provider", "user", user.ID)
		s.store.DeleteSession(ctx, sess.ID)
		return auth.RoleNone, false
	case errors.Is(err, auth.ErrProviderUnavailable):
		s.log.Warn("revalidation failed, session kept", "error", err)
		s.deferRevalidation(ctx, sess, now)
		return sess.Role, true
	case err != nil:
		s.log.Error("revalidation failed unexpectedly", "error", err)
		s.deferRevalidation(ctx, sess, now)
		return sess.Role, true
	}

	// From here the answer is authoritative.
	if err := s.store.SetCachedRole(ctx, user.ID, identity.Role, now); err != nil {
		s.log.Error("could not update cached role", "error", err)
	}
	if !identity.Role.Valid() {
		s.log.Info("access withdrawn, all sessions ended", "user", user.ID)
		s.store.DeleteSessionsForUser(ctx, user.ID)
		return auth.RoleNone, false
	}
	if err := s.store.UpdateSessionAfterRevalidation(ctx, sess.ID, identity.Role,
		fresh.AccessToken, fresh.RefreshToken, fresh.Expiry,
		now.Add(s.cfg.RevalidateInterval)); err != nil {
		s.log.Error("could not update session after revalidation", "error", err)
	}
	return identity.Role, true
}

// deferRevalidation pushes the next attempt out a minute, so a provider that
// is down is not re-asked on every request.
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

func setRateLimitHeaders(w http.ResponseWriter, res ratelimit.Result) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(res.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(int(time.Until(res.Reset).Seconds()+0.5)))
}

// withSecurityHeaders can afford to be strict: the app embeds nothing external.
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

// withLogging logs every request. The Authorization header is never emitted:
// a key must not end up in a log.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		attrs := []any{
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r),
		}
		if p := auth.FromContext(r.Context()); p != nil {
			attrs = append(attrs, "principal", string(p.Kind), "role", string(p.Role))
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
				s.log.Error("panic in handler", "path", r.URL.Path,
					"error", rec, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal", "Unexpected error.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP honours X-Forwarded-For only from a configured trusted proxy;
// otherwise any caller could claim any origin.
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
