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
		AppTitle: "Test", AppInstance: "privat", BaseURL: "http://localhost",
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

// mustKey legt einen Nutzer samt API-Key an und liefert den Klartext-Key.
func mustKey(t *testing.T, st *store.Store, sub string, userRole, keyRole auth.Role) string {
	t.Helper()
	now := time.Now()
	u, err := st.UpsertUserOnLogin(t.Context(), sub, sub+"@example.org", sub, userRole, now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _, err := st.CreateAPIKey(t.Context(), "privat", "Test", keyRole,
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

// Jede Route muss ihren Schutz deklarieren. Diese Prüfung läuft auch beim Start
// des Prozesses — eine vergessene Absicherung ist damit kein stiller Mangel.
func TestEveryRouteDeclaresItsProtection(t *testing.T) {
	srv, _, _ := testServer(t)
	if err := srv.verifyRoutes(); err != nil {
		t.Fatal(err)
	}
	if len(srv.Routes()) == 0 {
		t.Fatal("keine Routen registriert")
	}
	for _, r := range srv.Routes() {
		if r.Access == AccessCapability && r.Cap == "" {
			t.Errorf("Route %s %s verlangt eine Fähigkeit, nennt aber keine", r.Method, r.Pattern)
		}
	}
}

// Die tragende Invariante, an der Routentabelle geprüft: keine Route gibt einem
// API-Key ein Verwaltungsrecht. Wird später eine Admin-Route ergänzt und die
// Ableitung dabei umgangen, wird dieser Test rot.
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
					t.Errorf("Route %s %s gibt einem API-Key (Rolle %s) das Recht %s",
						route.Method, route.Pattern, role, route.Cap)
				}
			}
		}
	}
}

// Dieselbe Invariante noch einmal über echte HTTP-Aufrufe: ein Key mit der
// höchsten für Keys erreichbaren Rolle wird auf jeder Verwaltungsroute abgewiesen.
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
			t.Errorf("%s %s mit API-Key: Status %d, erwartet 403",
				route.Method, path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "forbidden_for_api_key") {
			t.Errorf("%s %s: Fehlercode nennt den Grund nicht: %s",
				route.Method, path, w.Body.String())
		}
	}
	if checked == 0 {
		t.Fatal("keine Verwaltungsroute geprüft — der Test läuft ins Leere")
	}
}

// Ein Nur-Lesen-Key darf über die API genauso wenig schreiben wie ein
// Betrachter in der Oberfläche.
func TestViewerKeyCannotWrite(t *testing.T) {
	srv, st, _ := testServer(t)
	viewer := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)
	editor := mustKey(t, st, "bernd", auth.RoleEditor, auth.RoleEditor)

	body := `{"title":"Test","body":"Inhalt"}`
	if w := do(t, srv, "POST", "/api/v1/prompts", viewer, body); w.Code != http.StatusForbidden {
		t.Errorf("Lese-Key durfte schreiben: Status %d", w.Code)
	}
	if w := do(t, srv, "GET", "/api/v1/prompts", viewer); w.Code != http.StatusOK {
		t.Errorf("Lese-Key durfte nicht lesen: Status %d", w.Code)
	}
	if w := do(t, srv, "POST", "/api/v1/prompts", editor, body); w.Code != http.StatusCreated {
		t.Errorf("Schreib-Key konnte nicht anlegen: Status %d, %s", w.Code, w.Body.String())
	}
}

// Ein Key kann nie mehr als sein Besitzer: wird dieser herabgestuft, verliert
// auch sein Schreib-Key das Schreibrecht — ohne Zutun.
func TestKeyFollowsOwnerDowngrade(t *testing.T) {
	srv, st, _ := testServer(t)
	key := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleEditor)
	body := `{"title":"Test","body":"Inhalt"}`
	if w := do(t, srv, "POST", "/api/v1/prompts", key, body); w.Code != http.StatusCreated {
		t.Fatalf("Vorbedingung: Status %d", w.Code)
	}

	users, _ := st.ListUsers(t.Context())
	if err := st.SetCachedRole(t.Context(), users[0].ID, auth.RoleViewer, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := do(t, srv, "POST", "/api/v1/prompts", key, body); w.Code != http.StatusForbidden {
		t.Errorf("Schreib-Key eines herabgestuften Besitzers durfte noch schreiben: %d", w.Code)
	}
	if w := do(t, srv, "GET", "/api/v1/prompts", key); w.Code != http.StatusOK {
		t.Errorf("Lesen sollte weiterhin möglich sein: %d", w.Code)
	}

	// Zugang ganz entzogen: der Key ist inaktiv, aber nicht widerrufen.
	if err := st.SetCachedRole(t.Context(), users[0].ID, auth.RoleNone, time.Now()); err != nil {
		t.Fatal(err)
	}
	w := do(t, srv, "GET", "/api/v1/prompts", key)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Key ohne berechtigten Besitzer: Status %d, erwartet 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "owner_inactive") {
		t.Errorf("Grund nicht genannt: %s", w.Body.String())
	}
}

func TestKeyRejections(t *testing.T) {
	srv, st, _ := testServer(t)
	good := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)

	tests := []struct {
		name, key, wantCode string
	}{
		{"ohne Key", "", "unauthorized"},
		{"Unsinn", "voellig-falsch", "invalid_key"},
		{"falsche Instanz", strings.Replace(good, "_privat_", "_arbeit_", 1), "invalid_key"},
		{"unbekannte ID", good[:len(good)-8] + "AAAAAAAA", "invalid_key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, srv, "GET", "/api/v1/prompts", tc.key)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("Status %d, erwartet 401", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.wantCode) {
				t.Errorf("Fehlercode %q erwartet, bekam: %s", tc.wantCode, w.Body.String())
			}
		})
	}
}

// Der Klartext eines Keys darf nie als Query-Parameter akzeptiert werden — dort
// landete er in Zugriffsprotokollen und Proxy-Zwischenspeichern.
func TestKeyInQueryParameterIsIgnored(t *testing.T) {
	srv, st, _ := testServer(t)
	key := mustKey(t, st, "anna", auth.RoleEditor, auth.RoleViewer)
	w := do(t, srv, "GET", "/api/v1/prompts?api_key="+key, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Key im Query-Parameter wurde akzeptiert: Status %d", w.Code)
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
		t.Errorf("vierte Anfrage: Status %d, erwartet 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("Retry-After fehlt")
	}
	if last.Header().Get("RateLimit-Limit") != "3" {
		t.Errorf("RateLimit-Limit = %q", last.Header().Get("RateLimit-Limit"))
	}
}

func TestHealthAndReadiness(t *testing.T) {
	srv, _, _ := testServer(t)
	if w := do(t, srv, "GET", "/healthz", ""); w.Code != http.StatusOK {
		t.Errorf("/healthz: Status %d", w.Code)
	}
	// Ohne erreichbaren Provider ist die Instanz nicht bereit.
	if w := do(t, srv, "GET", "/readyz", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz ohne Provider: Status %d, erwartet 503", w.Code)
	}
}
