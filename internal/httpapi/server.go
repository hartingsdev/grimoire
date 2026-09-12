// Package httpapi verbindet Oberfläche und REST-API. Beide laufen über dieselben
// Endpunkte und dieselbe Rechteprüfung; der einzige Unterschied ist, wie sich
// der Aufrufer ausweist.
package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/config"
	"github.com/hartingsdev/solid-bassoon/internal/ratelimit"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

// Access beschreibt, wie eine Route abgesichert ist. Es gibt keinen vierten
// Wert und keine Route ohne Angabe — siehe register().
type Access int

const (
	AccessPublic Access = iota
	AccessAuthenticated
	AccessCapability
)

// Route ist der deklarierte Schutz eines Endpunkts. Die Liste ist der
// Prüfgegenstand von routes_test.go.
type Route struct {
	Method  string
	Pattern string
	Access  Access
	Cap     auth.Capability
}

type Server struct {
	cfg      *config.Config
	store    *store.Store
	provider *auth.Provider
	limiter  *ratelimit.Limiter
	log      *slog.Logger
	static   fs.FS

	mux    *http.ServeMux
	routes []Route
}

func New(cfg *config.Config, st *store.Store, provider *auth.Provider,
	log *slog.Logger, static fs.FS) (*Server, error) {

	s := &Server{
		cfg: cfg, store: st, provider: provider, log: log, static: static,
		limiter: ratelimit.New(cfg.RateLimitPerMin),
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	if err := s.verifyRoutes(); err != nil {
		return nil, err
	}
	return s, nil
}

// Routes gibt die Routentabelle für Tests frei.
func (s *Server) Routes() []Route { return s.routes }

func (s *Server) registerRoutes() {
	// Betrieb
	s.public("GET", "/healthz", s.handleHealthz)
	s.public("GET", "/readyz", s.handleReadyz)

	// Anmeldung
	s.public("GET", "/auth/login", s.handleLogin)
	s.public("GET", "/auth/callback", s.handleCallback)
	s.authenticated("POST", "/auth/logout", s.handleLogout)

	// Wer bin ich — jeder Angemeldete, auch ein API-Key.
	s.authenticated("GET", "/api/v1/me", s.handleMe)

	// Prompts: identisch für Oberfläche und API.
	s.capability("GET", "/api/v1/prompts", auth.CapPromptsRead, s.handleListPrompts)
	s.capability("POST", "/api/v1/prompts", auth.CapPromptsWrite, s.handleCreatePrompt)
	s.capability("GET", "/api/v1/prompts/{id}", auth.CapPromptsRead, s.handleGetPrompt)
	s.capability("PATCH", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleUpdatePrompt)
	s.capability("PUT", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleUpdatePrompt)
	s.capability("DELETE", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleDeletePrompt)
	s.capability("GET", "/api/v1/prompts/{id}/revisions", auth.CapPromptsRead, s.handleListRevisions)
	s.capability("POST", "/api/v1/prompts/{id}/restore", auth.CapPromptsWrite, s.handleRestorePrompt)
	s.capability("GET", "/api/v1/tags", auth.CapPromptsRead, s.handleListTags)

	// Verwaltung. Diese Rechte erreicht ein API-Key nie — siehe auth.Capabilities.
	s.capability("GET", "/api/v1/api-keys", auth.CapKeysManage, s.handleListKeys)
	s.capability("POST", "/api/v1/api-keys", auth.CapKeysManage, s.handleCreateKey)
	s.capability("DELETE", "/api/v1/api-keys/{id}", auth.CapKeysManage, s.handleRevokeKey)
	s.capability("GET", "/api/v1/admin/users", auth.CapAdminRead, s.handleListUsers)
	s.capability("GET", "/api/v1/admin/users/{id}/footprint", auth.CapAdminUsers, s.handleUserFootprint)
	s.capability("DELETE", "/api/v1/admin/users/{id}", auth.CapAdminUsers, s.handleDeleteUser)
	s.capability("GET", "/api/v1/admin/audit", auth.CapAuditRead, s.handleListAudit)

	// Oberfläche
	s.public("GET", "/", s.handleStatic)
}

// register ist der einzige Weg, eine Route einzutragen — und verlangt dabei
// immer eine Aussage über ihren Schutz. Eine vergessene Absicherung ist damit
// kein stiller Mangel, sondern ein Übersetzungsfehler.
func (s *Server) register(method, pattern string, access Access, cap auth.Capability, h http.HandlerFunc) {
	s.routes = append(s.routes, Route{Method: method, Pattern: pattern, Access: access, Cap: cap})
	s.mux.Handle(method+" "+pattern, s.guard(Route{
		Method: method, Pattern: pattern, Access: access, Cap: cap}, h))
}

func (s *Server) public(method, pattern string, h http.HandlerFunc) {
	s.register(method, pattern, AccessPublic, "", h)
}

func (s *Server) authenticated(method, pattern string, h http.HandlerFunc) {
	s.register(method, pattern, AccessAuthenticated, "", h)
}

func (s *Server) capability(method, pattern string, cap auth.Capability, h http.HandlerFunc) {
	s.register(method, pattern, AccessCapability, cap, h)
}

// verifyRoutes läuft beim Start. Eine Route, die eine Fähigkeit verlangt, aber
// keine nennt, lässt den Prozess gar nicht erst hochkommen.
func (s *Server) verifyRoutes() error {
	seen := map[string]bool{}
	for _, r := range s.routes {
		key := r.Method + " " + r.Pattern
		if seen[key] {
			return fmt.Errorf("Route %s ist doppelt registriert", key)
		}
		seen[key] = true
		if r.Access == AccessCapability && r.Cap == "" {
			return fmt.Errorf("Route %s verlangt eine Fähigkeit, nennt aber keine", key)
		}
		if r.Access != AccessCapability && r.Cap != "" {
			return fmt.Errorf("Route %s nennt die Fähigkeit %q, prüft sie aber nicht", key, r.Cap)
		}
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.withRecovery(s.withLogging(s.withSecurityHeaders(s.mux))).ServeHTTP(w, r)
}

// Background erledigt das periodische Aufräumen: abgelaufene Sitzungen und
// Login-Vorgänge aus der Datenbank, unbenutzte Rate-Limit-Eimer aus dem Speicher.
func (s *Server) Background(ctx context.Context, now time.Time) {
	if err := s.store.Cleanup(ctx); err != nil {
		s.log.Warn("Aufräumen fehlgeschlagen", "fehler", err)
	}
	s.limiter.Cleanup(now, time.Hour)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz meldet erst "bereit", wenn der OIDC-Provider erreichbar war —
// ohne ihn kann sich niemand anmelden.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !s.provider.Ready() {
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable",
			"OIDC-Provider noch nicht erreichbar.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
