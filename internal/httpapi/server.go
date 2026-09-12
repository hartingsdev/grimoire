// Package httpapi serves the UI and the REST API over the same endpoints and
// the same permission check. The only difference is how a caller identifies.
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

// Access says how a route is protected. There is no fourth value and no route
// without one — see register().
type Access int

const (
	AccessPublic Access = iota
	AccessAuthenticated
	AccessCapability
)

// Route is an endpoint's declared protection. routes_test.go checks this table.
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

func (s *Server) Routes() []Route { return s.routes }

func (s *Server) registerRoutes() {
	s.public("GET", "/healthz", s.handleHealthz)
	s.public("GET", "/readyz", s.handleReadyz)

	s.public("GET", "/auth/login", s.handleLogin)
	s.public("GET", "/auth/callback", s.handleCallback)
	s.authenticated("POST", "/auth/logout", s.handleLogout)

	// Identity, for anyone authenticated including an API key.
	s.authenticated("GET", "/api/v1/me", s.handleMe)

	// Prompts: identical for the UI and the API.
	s.capability("GET", "/api/v1/prompts", auth.CapPromptsRead, s.handleListPrompts)
	s.capability("POST", "/api/v1/prompts", auth.CapPromptsWrite, s.handleCreatePrompt)
	s.capability("GET", "/api/v1/prompts/{id}", auth.CapPromptsRead, s.handleGetPrompt)
	s.capability("PATCH", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleUpdatePrompt)
	s.capability("PUT", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleUpdatePrompt)
	s.capability("DELETE", "/api/v1/prompts/{id}", auth.CapPromptsWrite, s.handleDeletePrompt)
	s.capability("GET", "/api/v1/prompts/{id}/revisions", auth.CapPromptsRead, s.handleListRevisions)
	s.capability("POST", "/api/v1/prompts/{id}/restore", auth.CapPromptsWrite, s.handleRestorePrompt)
	s.capability("GET", "/api/v1/tags", auth.CapPromptsRead, s.handleListTags)

	// Management. An API key never reaches these — see auth.Capabilities.
	s.capability("GET", "/api/v1/api-keys", auth.CapKeysManage, s.handleListKeys)
	s.capability("POST", "/api/v1/api-keys", auth.CapKeysManage, s.handleCreateKey)
	s.capability("DELETE", "/api/v1/api-keys/{id}", auth.CapKeysManage, s.handleRevokeKey)
	s.capability("GET", "/api/v1/admin/users", auth.CapAdminRead, s.handleListUsers)
	s.capability("GET", "/api/v1/admin/users/{id}/footprint", auth.CapAdminUsers, s.handleUserFootprint)
	s.capability("DELETE", "/api/v1/admin/users/{id}", auth.CapAdminUsers, s.handleDeleteUser)
	s.capability("GET", "/api/v1/admin/audit", auth.CapAuditRead, s.handleListAudit)
	s.capability("POST", "/api/v1/admin/prompts/{id}/reveal", auth.CapAdminRead, s.handleRevealPrivate)

	// Everyone can see their own audit trail, above all a revealed private prompt.
	s.authenticated("GET", "/api/v1/me/audit", s.handleMyAudit)

	s.public("GET", "/", s.handleStatic)
}

// register is the only way to add a route, and it always demands a statement
// about protection. A forgotten guard is therefore a compile error, not a
// silent hole.
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

// verifyRoutes runs at startup: a route that requires a capability but names
// none keeps the process from coming up at all.
func (s *Server) verifyRoutes() error {
	seen := map[string]bool{}
	for _, r := range s.routes {
		key := r.Method + " " + r.Pattern
		if seen[key] {
			return fmt.Errorf("route %s is registered twice", key)
		}
		seen[key] = true
		if r.Access == AccessCapability && r.Cap == "" {
			return fmt.Errorf("route %s requires a capability but names none", key)
		}
		if r.Access != AccessCapability && r.Cap != "" {
			return fmt.Errorf("route %s names capability %q but never checks it", key, r.Cap)
		}
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.withRecovery(s.withLogging(s.withSecurityHeaders(s.mux))).ServeHTTP(w, r)
}

// Background does the periodic housekeeping: expired sessions and login states
// out of the database, idle rate-limit buckets out of memory.
func (s *Server) Background(ctx context.Context, now time.Time) {
	if err := s.store.Cleanup(ctx); err != nil {
		s.log.Warn("cleanup failed", "error", err)
	}
	s.limiter.Cleanup(now, time.Hour)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports ready only once the OIDC provider has been reached —
// without it nobody can sign in.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !s.provider.Ready() {
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable",
			"OIDC provider not reachable yet.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
