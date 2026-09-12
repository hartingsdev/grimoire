package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/config"
	"github.com/hartingsdev/solid-bassoon/internal/ratelimit"
	"github.com/hartingsdev/solid-bassoon/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store, *config.Config) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := &config.Config{
		AppTitle: "Test", AppInstance: "personal", BaseURL: "http://localhost",
		SessionMaxAge: time.Hour, RevalidateInterval: time.Hour,
		OwnerStaleAfter: 720 * time.Hour, APIKeyMaxLifetime: 8760 * time.Hour,
		RateLimitPerMin: 120, PrivatePrompts: true,
		AdminPrivateAccess: config.AdminPrivateBreakGlass,
		OIDC: config.OIDC{Issuer: "http://idp.invalid", ClientID: "x",
			ClientSecret: "y", RedirectURI: "http://localhost/auth/callback",
			RoleClaim: "groups", ClaimsSource: config.ClaimsBoth},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provider, err := auth.NewProvider(cfg.OIDC, log)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, provider, log, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<p>ok</p>")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, cfg
}

func mustKey(t *testing.T, st *store.Store, sub string, userRole, keyRole auth.Role) string {
	t.Helper()
	now := time.Now()
	u, err := st.UpsertUserOnLogin(t.Context(), sub, sub+"@example.org", sub, userRole, now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _, err := st.CreateAPIKey(t.Context(), "personal", "Test", keyRole,
		u.ID, now.Add(24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func do(t *testing.T, srv *Server, method, path, key string, bodies ...string) *httptest.ResponseRecorder {
	t.Helper()
	body := ""
	if len(bodies) > 0 {
		body = bodies[0]
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// Every route must declare its protection. The same check runs at startup, so
// a forgotten guard is never a silent hole.
func TestEveryRouteDeclaresItsProtection(t *testing.T) {
	srv, _, _ := testServer(t)
	if err := srv.verifyRoutes(); err != nil {
		t.Fatal(err)
	}
	if len(srv.Routes()) == 0 {
		t.Fatal("no routes registered")
	}
	for _, r := range srv.Routes() {
		if r.Access == AccessCapability && r.Cap == "" {
			t.Errorf("route %s %s requires a capability but names none", r.Method, r.Pattern)
		}
	}
}

// The load-bearing invariant, checked against the route table: no route hands
// an API key a management capability. Add an admin route that bypasses the
// derivation and this test goes red.
func TestNoRouteGrantsManagementCapabilityToAPIKey(t *testing.T) {
	srv, _, _ := testServer(t)
	for _, route := range srv.Routes() {
		if route.Access != AccessCapability {
			continue
		}
		for _, role := range []auth.Role{auth.RoleViewer, auth.RoleEditor, auth.RoleAdmin} {
			p := &auth.Principal{Kind: auth.KindAPIKey, Role: role}
			if !p.Can(route.Cap) {
				continue
			}
			for _, managed := range auth.ManagementCapabilities {
				if route.Cap == managed {
					t.Errorf("route %s %s grants an API key (role %s) the capability %s",
						route.Method, route.Pattern, role, route.Cap)
				}
			}
		}
	}
}

// The same invariant over real HTTP: a key with the highest role a key can
// hold is refused on every management route.
func TestManagementRoutesRejectAPIKeysOverHTTP(t *testing.T) {
	srv, st, _ := testServer(t)
	key := mustKey(t, st, "admin", auth.RoleAdmin, auth.RoleEditor)

	var checked int
	for _, route := range srv.Routes() {
		if route.Access != AccessCapability {
			continue
		}
		managed := false
		for _, m := range auth.ManagementCapabilities {
			if route.Cap == m {
				managed = true
			}
		}
		if !managed {
			continue
		}
		checked++
		path := strings.ReplaceAll(route.Pattern, "{id}", "beliebig")
		body := ""
		if route.Method == http.MethodPost {
			body = `{}`
		}
		w := do(t, srv, route.Method, path, key, body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s with an API key: status %d, want 403",
				route.Method, path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "forbidden_for_api_key") {
			t.Errorf("%s %s: error code does not state the reason: %s",
				route.Method, path, w.Body.String())
		}
	}
	if checked == 0 {
		t.Fatal("no management route was checked — this test is vacuous")
	}
}

// A read-only key can write through the API no more than a viewer can in the UI.
func TestViewerKeyCannotWrite(t *testing.T) {
	srv, st, _ := testServer(t)
	viewer := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)
	editor := mustKey(t, st, "bernd", auth.RoleEditor, auth.RoleEditor)

	body := `{"title":"Test","body":"Inhalt"}`
	if w := do(t, srv, "POST", "/api/v1/prompts", viewer, body); w.Code != http.StatusForbidden {
		t.Errorf("read key was allowed to write: status %d", w.Code)
	}
	if w := do(t, srv, "GET", "/api/v1/prompts", viewer); w.Code != http.StatusOK {
		t.Errorf("read key was not allowed to read: status %d", w.Code)
	}
	if w := do(t, srv, "POST", "/api/v1/prompts", editor, body); w.Code != http.StatusCreated {
		t.Errorf("write key could not create: status %d, %s", w.Code, w.Body.String())
	}
}

// A key never outranks its owner: demote them and the write key loses write
// access by itself.
func TestKeyFollowsOwnerDowngrade(t *testing.T) {
	srv, st, _ := testServer(t)
	key := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleEditor)
	body := `{"title":"Test","body":"Inhalt"}`
	if w := do(t, srv, "POST", "/api/v1/prompts", key, body); w.Code != http.StatusCreated {
		t.Fatalf("precondition: status %d", w.Code)
	}

	users, _ := st.ListUsers(t.Context())
	if err := st.SetCachedRole(t.Context(), users[0].ID, auth.RoleViewer, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := do(t, srv, "POST", "/api/v1/prompts", key, body); w.Code != http.StatusForbidden {
		t.Errorf("write key of a demoted owner could still write: %d", w.Code)
	}
	if w := do(t, srv, "GET", "/api/v1/prompts", key); w.Code != http.StatusOK {
		t.Errorf("reading should still work: %d", w.Code)
	}

	// Access withdrawn entirely: the key goes inactive, not revoked.
	if err := st.SetCachedRole(t.Context(), users[0].ID, auth.RoleNone, time.Now()); err != nil {
		t.Fatal(err)
	}
	w := do(t, srv, "GET", "/api/v1/prompts", key)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("key without an entitled owner: status %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "owner_inactive") {
		t.Errorf("reason not stated: %s", w.Body.String())
	}
}

func TestKeyRejections(t *testing.T) {
	srv, st, _ := testServer(t)
	good := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)

	tests := []struct {
		name, key, wantCode string
	}{
		{"no key", "", "unauthorized"},
		{"nonsense", "utter-nonsense", "invalid_key"},
		{"wrong instance", strings.Replace(good, "_personal_", "_work_", 1), "invalid_key"},
		{"unknown id", good[:len(good)-8] + "AAAAAAAA", "invalid_key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, srv, "GET", "/api/v1/prompts", tc.key)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.wantCode) {
				t.Errorf("want error code %q, got: %s", tc.wantCode, w.Body.String())
			}
		})
	}
}

// A key must never be accepted as a query parameter: it would land in access
// logs and proxy caches.
func TestKeyInQueryParameterIsIgnored(t *testing.T) {
	srv, st, _ := testServer(t)
	key := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)
	w := do(t, srv, "GET", "/api/v1/prompts?api_key="+key, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("key in a query parameter was accepted: status %d", w.Code)
	}
}

func TestRateLimitHeadersAndBlocking(t *testing.T) {
	srv, st, cfg := testServer(t)
	cfg.RateLimitPerMin = 3
	srv.limiter = ratelimit.New(3)
	key := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)

	var last *httptest.ResponseRecorder
	for i := 0; i < 4; i++ {
		last = do(t, srv, "GET", "/api/v1/prompts", key)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("fourth request: status %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is missing")
	}
	if last.Header().Get("RateLimit-Limit") != "3" {
		t.Errorf("RateLimit-Limit = %q", last.Header().Get("RateLimit-Limit"))
	}
}

func TestHealthAndReadiness(t *testing.T) {
	srv, _, _ := testServer(t)
	if w := do(t, srv, "GET", "/healthz", ""); w.Code != http.StatusOK {
		t.Errorf("/healthz: status %d", w.Code)
	}
	// Without a reachable provider the instance is not ready.
	if w := do(t, srv, "GET", "/readyz", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz without a provider: status %d, want 503", w.Code)
	}
}

// Break-glass: an admin can reach someone else's private prompt, but one at a
// time, only with a reason — and the owner sees it afterwards.
func TestBreakGlassIsAuditedAndVisibleToOwner(t *testing.T) {
	srv, st, _ := testServer(t)
	now := time.Now()
	anna, err := st.UpsertUserOnLogin(t.Context(), "anna", "anna@example.org", "Anna", auth.RoleEditor, now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := st.UpsertUserOnLogin(t.Context(), "chef", "chef@example.org", "Chef", auth.RoleAdmin, now)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := st.CreatePrompt(t.Context(), store.Prompt{
		Title: "Secret", Body: "for anna only", Visibility: store.VisibilityPrivate,
	}, anna.ID, now)
	if err != nil {
		t.Fatal(err)
	}

	// No reason, no reveal.
	w := call(t, srv, "POST", "/api/v1/admin/prompts/"+priv.ID+"/reveal", admin, `{"reason":""}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "reason_required") {
		t.Errorf("reveal without a reason: status %d, %s", w.Code, w.Body.String())
	}

	w = call(t, srv, "POST", "/api/v1/admin/prompts/"+priv.ID+"/reveal", admin,
		`{"reason":"suspected leak of customer data"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reveal with a reason: status %d, %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "for anna only") {
		t.Error("the body was not returned")
	}

	// The owner sees it in their own audit trail.
	w = call(t, srv, "GET", "/api/v1/me/audit", anna, "")
	if w.Code != http.StatusOK {
		t.Fatalf("own audit trail: status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), store.ActionPrivateRevealed) ||
		!strings.Contains(w.Body.String(), "customer data") {
		t.Errorf("the owner cannot see the reveal: %s", w.Body.String())
	}
}

func call(t *testing.T, srv *Server, method, path string, user store.User, body string) *httptest.ResponseRecorder {
	t.Helper()
	now := time.Now()
	sess, err := srv.store.CreateSession(t.Context(), user.ID, user.CachedRole,
		"", "", time.Time{}, now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.ID})
	r.Header.Set("X-CSRF-Token", sess.CSRFToken)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// A browser write without a CSRF token is refused even with a valid session.
func TestSessionWriteRequiresCSRFToken(t *testing.T) {
	srv, st, _ := testServer(t)
	now := time.Now()
	anna, err := st.UpsertUserOnLogin(t.Context(), "anna", "a@example.org", "Anna", auth.RoleEditor, now)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateSession(t.Context(), anna.ID, auth.RoleEditor, "", "",
		time.Time{}, now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/prompts",
		strings.NewReader(`{"title":"x","body":"y"}`))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.ID})
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "csrf") {
		t.Errorf("write without a CSRF token: status %d, %s", w.Code, w.Body.String())
	}
}
