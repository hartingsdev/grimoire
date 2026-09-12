package auth

import (
	"encoding/json"
	"testing"
	"time"
)

// The load-bearing invariant: an API key never receives a management
// capability, not even with role='admin' in its row (which creation rejects).
func TestAPIKeyNeverGetsManagementCapabilities(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleEditor, RoleAdmin} {
		p := Principal{Kind: KindAPIKey, Role: role}
		for _, cap := range ManagementCapabilities {
			if p.Can(cap) {
				t.Errorf("API key with role %s was granted %s — that must never happen", role, cap)
			}
		}
	}
}

func TestSessionCapabilities(t *testing.T) {
	tests := []struct {
		role Role
		want []Capability
	}{
		{RoleNone, nil},
		{RoleViewer, []Capability{CapPromptsRead}},
		{RoleEditor, []Capability{CapPromptsRead, CapPromptsWrite, CapKeysManage}},
		{RoleAdmin, []Capability{
			CapPromptsRead, CapPromptsWrite, CapKeysManage,
			CapAdminRead, CapAdminUsers, CapAuditRead,
		}},
	}
	for _, tc := range tests {
		p := Principal{Kind: KindSession, Role: tc.role}
		got := p.CapabilityList()
		if len(got) != len(tc.want) {
			t.Fatalf("role %s: %v, want %v", tc.role, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("role %s: %v, want %v", tc.role, got, tc.want)
			}
		}
	}
}

func TestMinRole(t *testing.T) {
	tests := []struct{ key, owner, want Role }{
		{RoleEditor, RoleEditor, RoleEditor},
		{RoleEditor, RoleViewer, RoleViewer}, // Besitzer herabgestuft: Schreib-Key liest nur noch
		{RoleViewer, RoleAdmin, RoleViewer},  // Key bleibt bei seiner eigenen Rolle
		{RoleEditor, RoleNone, RoleNone},     // Besitzer hat keinen Zugang mehr
	}
	for _, tc := range tests {
		if got := MinRole(tc.key, tc.owner); got != tc.want {
			t.Errorf("MinRole(%s, %s) = %s, want %s", tc.key, tc.owner, got, tc.want)
		}
	}
}

func TestKeyRoundTrip(t *testing.T) {
	plaintext, id, hash, err := NewKey("personal")
	if err != nil {
		t.Fatal(err)
	}
	gotID, secret, err := ParseKey("personal", plaintext)
	if err != nil {
		t.Fatalf("our own key could not be parsed: %v", err)
	}
	if gotID != id {
		t.Errorf("key id %q, want %q", gotID, id)
	}
	if !SecretMatches(secret, hash) {
		t.Error("secret does not match the stored hash")
	}
	if SecretMatches(secret+"x", hash) {
		t.Error("a tampered secret was accepted")
	}
}

// The base64url alphabet contains underscores. A parser that splits on every
// underscore throws away roughly every other key it mints.
func TestKeyWithUnderscoreInSecret(t *testing.T) {
	for i := 0; i < 200; i++ {
		plaintext, id, hash, err := NewKey("personal")
		if err != nil {
			t.Fatal(err)
		}
		gotID, secret, err := ParseKey("personal", plaintext)
		if err != nil {
			t.Fatalf("key %q could not be parsed: %v", plaintext, err)
		}
		if gotID != id || !SecretMatches(secret, hash) {
			t.Fatalf("key %q was split incorrectly", plaintext)
		}
	}
}

// A key from another instance is rejected before any database access.
func TestKeyRejectsForeignInstance(t *testing.T) {
	plaintext, _, _, err := NewKey("work")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseKey("personal", plaintext); err == nil {
		t.Error("a key for instance 'work' was accepted by 'personal'")
	}
}

func TestKeyRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"", "plk", "plk_privat", "plk_personal_kurz_abc",
		"xyz_personal_9f3k2md7qa4x_secret",
		"plk_personal_9f3k2md7qa4x_", // leeres Geheimnis
		"Bearer plk_personal_9f3k2md7qa4x_secret",
	} {
		if _, _, err := ParseKey("personal", raw); err == nil {
			t.Errorf("%q was accepted as a valid key", raw)
		}
	}
}

func TestRoleMapper(t *testing.T) {
	claimsOf := func(js string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(js), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	tests := []struct {
		name, claim, mapping, claims string
		want                         Role
	}{
		{"groups array, highest wins", "groups", "pl-viewer:viewer,pl-admin:admin",
			`{"groups":["pl-viewer","pl-admin","unbeteiligt"]}`, RoleAdmin},
		{"custom claim without a mapping", "grimoire_role", "",
			`{"grimoire_role":"editor"}`, RoleEditor},
		{"Keycloak, nested", "resource_access.prompt-lib.roles", "",
			`{"resource_access":{"prompt-lib":{"roles":["viewer"]}}}`, RoleViewer},
		{"no match", "groups", "pl-editor:editor",
			`{"groups":["irgendwas"]}`, RoleNone},
		{"claim missing", "groups", "pl-editor:editor", `{"sub":"abc"}`, RoleNone},
		{"claim is not an object along the path", "a.b.c", "", `{"a":"text"}`, RoleNone},
		{"unknown role name without a mapping", "role", "", `{"role":"superuser"}`, RoleNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewRoleMapper(tc.claim, tc.mapping)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Resolve(claimsOf(tc.claims)); got != tc.want {
				t.Errorf("Resolve = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRoleMapperRejectsBadConfig(t *testing.T) {
	for _, mapping := range []string{"ohne-doppelpunkt", "gruppe:superuser", "   ,  "} {
		if _, err := NewRoleMapper("groups", mapping); err == nil {
			t.Errorf("OIDC_ROLE_MAP=%q was accepted", mapping)
		}
	}
	if _, err := NewRoleMapper("", ""); err == nil {
		t.Error("an empty OIDC_ROLE_CLAIM was accepted")
	}
}

func TestOwnerStale(t *testing.T) {
	now := time.Now()
	if !OwnerStale(time.Time{}, time.Hour, now) {
		t.Error("an owner never verified must count as stale")
	}
	if !OwnerStale(now.Add(-2*time.Hour), time.Hour, now) {
		t.Error("a cache that is too old must count as stale")
	}
	if OwnerStale(now.Add(-time.Minute), time.Hour, now) {
		t.Error("a fresh cache must not count as stale")
	}
	if OwnerStale(time.Time{}, 0, now) {
		t.Error("a disabled check (0) must never fire")
	}
}
