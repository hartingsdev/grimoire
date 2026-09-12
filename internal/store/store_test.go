package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

func testStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, context.Background()
}

func mustUser(t *testing.T, s *Store, ctx context.Context, sub string, role auth.Role) User {
	t.Helper()
	u, err := s.UpsertUserOnLogin(ctx, sub, sub+"@example.org", sub, role, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSchemaAndPromptLifecycle(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleEditor)
	scope := Scope{ViewerID: anna.ID}

	p, err := s.CreatePrompt(ctx, Prompt{
		Title: "Zusammenfassung", Body: "Fasse den Text präzise zusammen",
		Visibility: VisibilityShared, Tags: []string{"Text", "text", " Analyse "},
	}, anna.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tags) != 2 {
		t.Errorf("Tags nicht normalisiert: %v", p.Tags)
	}
	if p.Revision != 1 {
		t.Errorf("erste Revision = %d, erwartet 1", p.Revision)
	}

	// FTS5 findet Wortanfänge und normalisiert Diakritika.
	for _, q := range []string{"zusammenfass", "Übersetz", "praez", "fasse"} {
		got, err := s.ListPrompts(ctx, scope, ListOptions{Query: q})
		if err != nil {
			t.Fatalf("Suche %q: %v", q, err)
		}
		want := q != "Übersetz" && q != "praez"
		if (len(got) > 0) != want {
			t.Errorf("Suche %q: %d Treffer, erwartet Treffer=%v", q, len(got), want)
		}
	}
	// LIKE fängt die Teilwortsuche mitten im Wort ab, die FTS5 nicht kann.
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{Query: "fassung"}); len(got) != 1 {
		t.Errorf("Teilwortsuche 'fassung': %d Treffer, erwartet 1", len(got))
	}

	updated, err := s.UpdatePrompt(ctx, scope, p.ID,
		Prompt{Title: "Zusammenfassung kurz", Tags: []string{"Analyse"}}, anna.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Body == "" {
		t.Errorf("Update: Revision %d, Body %q", updated.Revision, updated.Body)
	}

	if err := s.DeletePrompt(ctx, scope, p.ID, anna.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{}); len(got) != 0 {
		t.Error("weich gelöschter Eintrag taucht noch in der Liste auf")
	}
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{Query: "zusammenfass"}); len(got) != 0 {
		t.Error("weich gelöschter Eintrag steht noch im Suchindex")
	}

	restored, err := s.RestorePrompt(ctx, scope, p.ID, 1, anna.ID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Title != "Zusammenfassung" {
		t.Errorf("Wiederherstellung auf Revision 1: Titel %q", restored.Title)
	}
	revs, err := s.ListRevisions(ctx, scope, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 4 {
		t.Errorf("%d Revisionen, erwartet 4 (create, update, delete, restore)", len(revs))
	}
}

// Private Prompts sind für andere unsichtbar — und ein API-Key sieht genau das,
// was sein Besitzer sieht, weil er dessen ViewerID trägt.
func TestPrivateVisibility(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleEditor)
	bernd := mustUser(t, s, ctx, "bernd", auth.RoleEditor)

	priv, err := s.CreatePrompt(ctx, Prompt{Title: "Geheim", Body: "nur für anna",
		Visibility: VisibilityPrivate}, anna.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrompt(ctx, Prompt{Title: "Offen", Body: "für alle",
		Visibility: VisibilityShared}, anna.ID, now); err != nil {
		t.Fatal(err)
	}

	annasSicht, _ := s.ListPrompts(ctx, Scope{ViewerID: anna.ID}, ListOptions{})
	berndsSicht, _ := s.ListPrompts(ctx, Scope{ViewerID: bernd.ID}, ListOptions{})
	if len(annasSicht) != 2 {
		t.Errorf("Besitzerin sieht %d Einträge, erwartet 2", len(annasSicht))
	}
	if len(berndsSicht) != 1 {
		t.Errorf("Fremder sieht %d Einträge, erwartet 1", len(berndsSicht))
	}
	if _, err := s.GetPrompt(ctx, Scope{ViewerID: bernd.ID}, priv.ID); err != ErrNotFound {
		t.Error("Fremder konnte einen privaten Eintrag direkt abrufen")
	}
	if _, err := s.GetPrompt(ctx, Scope{ViewerID: bernd.ID, SeeAllPrivate: true}, priv.ID); err != nil {
		t.Errorf("Admin mit ADMIN_PRIVATE_ACCESS=full kam nicht an den Eintrag: %v", err)
	}
	// Auch die Tag-Liste darf nichts über fremde private Einträge verraten.
	if _, err := s.ListTags(ctx, Scope{ViewerID: bernd.ID}); err != nil {
		t.Fatal(err)
	}
}

// Beim Löschen eines Nutzers bleiben geteilte Prompts und die Historie erhalten;
// die Nutzerzeile wird zum Grabstein.
func TestDeleteUserKeepsSharedContentAndHistory(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleEditor)
	admin := mustUser(t, s, ctx, "admin", auth.RoleAdmin)

	shared, _ := s.CreatePrompt(ctx, Prompt{Title: "Teamwissen", Body: "bleibt",
		Visibility: VisibilityShared}, anna.ID, now)
	if _, err := s.CreatePrompt(ctx, Prompt{Title: "Privat", Body: "geht",
		Visibility: VisibilityPrivate}, anna.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateAPIKey(ctx, "privat", "Skript", auth.RoleViewer,
		anna.ID, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}

	fp, err := s.UserFootprint(ctx, anna.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fp.SharedPrompts != 1 || fp.PrivatePrompts != 1 || fp.ActiveKeys != 1 {
		t.Errorf("Fußabdruck falsch: %+v", fp)
	}

	if err := s.DeleteUser(ctx, anna.ID, DeleteUserOptions{}, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPrompt(ctx, Scope{ViewerID: admin.ID}, shared.ID)
	if err != nil {
		t.Fatalf("geteilter Prompt wurde mitgelöscht: %v", err)
	}
	if got.OwnerName != TombstoneName {
		t.Errorf("Autor = %q, erwartet %q", got.OwnerName, TombstoneName)
	}
	if revs, err := s.ListRevisions(ctx, Scope{ViewerID: admin.ID}, shared.ID); err != nil || len(revs) == 0 {
		t.Errorf("Historie verloren: %d Revisionen, err=%v", len(revs), err)
	}
	keys, _ := s.ListAPIKeys(ctx, "", time.Hour, now)
	if len(keys) != 0 {
		t.Errorf("%d Keys überlebten die Löschung des Besitzers", len(keys))
	}
	// Derselbe Mensch kann sich neu anmelden und bekommt ein frisches Konto.
	wieder := mustUser(t, s, ctx, "anna", auth.RoleViewer)
	if wieder.ID == anna.ID {
		t.Error("Login nach Löschung landete wieder auf der Grabstein-Zeile")
	}
}

func TestSessionTokensAreEncryptedAtRest(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleViewer)

	sess, err := s.CreateSession(ctx, anna.ID, auth.RoleViewer, "geheimes-access-token",
		"geheimes-refresh-token", now, now.Add(time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := s.DB().QueryRow(`SELECT access_token_enc FROM sessions WHERE id = ?`,
		sess.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == "geheimes-access-token" {
		t.Error("Access-Token liegt im Klartext in der Datenbank")
	}
	back, _, err := s.GetSession(ctx, sess.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if back.AccessToken != "geheimes-access-token" {
		t.Errorf("Access-Token nach dem Lesen = %q", back.AccessToken)
	}
	if _, _, err := s.GetSession(ctx, sess.ID, now.Add(2*time.Hour)); err != ErrNotFound {
		t.Error("abgelaufene Session wurde noch geliefert")
	}
}

func TestEffectiveKeyRole(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Minute)
	base := APIKey{Role: auth.RoleEditor, OwnerID: "u1", ExpiresAt: now.Add(time.Hour)}

	cases := []struct {
		name      string
		key       APIKey
		ownerRole auth.Role
		ownerAt   time.Time
		want      auth.Role
	}{
		{"normal", base, auth.RoleEditor, fresh, auth.RoleEditor},
		{"Besitzer herabgestuft", base, auth.RoleViewer, fresh, auth.RoleViewer},
		{"Besitzer ohne Zugang", base, auth.RoleNone, fresh, auth.RoleNone},
		{"Besitzer zu lange nicht gesehen", base, auth.RoleEditor, now.Add(-48 * time.Hour), auth.RoleNone},
		{"widerrufen", APIKey{Role: auth.RoleEditor, OwnerID: "u1",
			ExpiresAt: now.Add(time.Hour), RevokedAt: now}, auth.RoleEditor, fresh, auth.RoleNone},
		{"abgelaufen", APIKey{Role: auth.RoleEditor, OwnerID: "u1",
			ExpiresAt: now.Add(-time.Hour)}, auth.RoleEditor, fresh, auth.RoleNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveKeyRole(tc.key, tc.ownerRole, tc.ownerAt, 24*time.Hour, now)
			if got != tc.want {
				t.Errorf("= %q, erwartet %q", got, tc.want)
			}
		})
	}
}
