package auth

import (
	"encoding/json"
	"testing"
	"time"
)

// Die tragende Invariante des Rechtemodells: ein API-Key erhält niemals ein
// Verwaltungsrecht — auch dann nicht, wenn in seiner Datenbankzeile 'admin'
// stünde, was die Erstellung gar nicht zulässt.
func TestAPIKeyNeverGetsManagementCapabilities(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleEditor, RoleAdmin} {
		p := Principal{Kind: KindAPIKey, Role: role}
		for _, cap := range ManagementCapabilities {
			if p.Can(cap) {
				t.Errorf("API-Key mit Rolle %s hat %s erhalten — das darf nicht passieren", role, cap)
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
			t.Fatalf("Rolle %s: %v, erwartet %v", tc.role, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("Rolle %s: %v, erwartet %v", tc.role, got, tc.want)
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
			t.Errorf("MinRole(%s, %s) = %s, erwartet %s", tc.key, tc.owner, got, tc.want)
		}
	}
}

func TestKeyRoundTrip(t *testing.T) {
	plaintext, id, hash, err := NewKey("privat")
	if err != nil {
		t.Fatal(err)
	}
	gotID, secret, err := ParseKey("privat", plaintext)
	if err != nil {
		t.Fatalf("eigener Key nicht parsebar: %v", err)
	}
	if gotID != id {
		t.Errorf("Key-ID %q, erwartet %q", gotID, id)
	}
	if !SecretMatches(secret, hash) {
		t.Error("Geheimnis passt nicht zum gespeicherten Hash")
	}
	if SecretMatches(secret+"x", hash) {
		t.Error("verändertes Geheimnis wurde akzeptiert")
	}
}

// Das base64url-Alphabet enthält Unterstriche. Ein Parser, der am Unterstrich
// zerlegt, verwirft dadurch jeden zweiten erzeugten Key.
func TestKeyWithUnderscoreInSecret(t *testing.T) {
	for i := 0; i < 200; i++ {
		plaintext, id, hash, err := NewKey("privat")
		if err != nil {
			t.Fatal(err)
		}
		gotID, secret, err := ParseKey("privat", plaintext)
		if err != nil {
			t.Fatalf("Key %q nicht parsebar: %v", plaintext, err)
		}
		if gotID != id || !SecretMatches(secret, hash) {
			t.Fatalf("Key %q falsch zerlegt", plaintext)
		}
	}
}

// Ein Key der anderen Instanz wird abgewiesen, bevor die Datenbank angefasst wird.
func TestKeyRejectsForeignInstance(t *testing.T) {
	plaintext, _, _, err := NewKey("arbeit")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseKey("privat", plaintext); err == nil {
		t.Error("Key der Instanz 'arbeit' wurde in 'privat' akzeptiert")
	}
}

func TestKeyRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"", "plk", "plk_privat", "plk_privat_kurz_abc",
		"xyz_privat_9f3k2md7qa4x_secret",
		"plk_privat_9f3k2md7qa4x_", // leeres Geheimnis
		"Bearer plk_privat_9f3k2md7qa4x_secret",
	} {
		if _, _, err := ParseKey("privat", raw); err == nil {
			t.Errorf("%q wurde als gültiger Key akzeptiert", raw)
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
		{"Gruppen-Array, höchste gewinnt", "groups", "pl-viewer:viewer,pl-admin:admin",
			`{"groups":["pl-viewer","pl-admin","unbeteiligt"]}`, RoleAdmin},
		{"eigener Claim ohne Mapping", "prompt_library_role", "",
			`{"prompt_library_role":"editor"}`, RoleEditor},
		{"Keycloak, verschachtelt", "resource_access.prompt-lib.roles", "",
			`{"resource_access":{"prompt-lib":{"roles":["viewer"]}}}`, RoleViewer},
		{"kein Treffer", "groups", "pl-editor:editor",
			`{"groups":["irgendwas"]}`, RoleNone},
		{"Claim fehlt", "groups", "pl-editor:editor", `{"sub":"abc"}`, RoleNone},
		{"Claim ist kein Objekt auf dem Pfad", "a.b.c", "", `{"a":"text"}`, RoleNone},
		{"unbekannter Rollenname ohne Mapping", "role", "", `{"role":"superuser"}`, RoleNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewRoleMapper(tc.claim, tc.mapping)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Resolve(claimsOf(tc.claims)); got != tc.want {
				t.Errorf("Resolve = %q, erwartet %q", got, tc.want)
			}
		})
	}
}

func TestRoleMapperRejectsBadConfig(t *testing.T) {
	for _, mapping := range []string{"ohne-doppelpunkt", "gruppe:superuser", "   ,  "} {
		if _, err := NewRoleMapper("groups", mapping); err == nil {
			t.Errorf("OIDC_ROLE_MAP=%q wurde akzeptiert", mapping)
		}
	}
	if _, err := NewRoleMapper("", ""); err == nil {
		t.Error("leerer OIDC_ROLE_CLAIM wurde akzeptiert")
	}
}

func TestOwnerStale(t *testing.T) {
	now := time.Now()
	if !OwnerStale(time.Time{}, time.Hour, now) {
		t.Error("nie verifizierter Besitzer muss als veraltet gelten")
	}
	if !OwnerStale(now.Add(-2*time.Hour), time.Hour, now) {
		t.Error("zu alter Cache muss als veraltet gelten")
	}
	if OwnerStale(now.Add(-time.Minute), time.Hour, now) {
		t.Error("frischer Cache darf nicht als veraltet gelten")
	}
	if OwnerStale(time.Time{}, 0, now) {
		t.Error("abgeschaltete Prüfung (0) darf nie greifen")
	}
}
