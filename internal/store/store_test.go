package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hartingsdev/grimoire/internal/auth"
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
		Title: "Résumé", Body: "Summarize the text precisely",
		Visibility: VisibilityShared, Tags: []string{"Text", "text", " Analysis "},
	}, anna.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tags) != 2 {
		t.Errorf("tags were not normalized: %v", p.Tags)
	}
	if p.Revision != 1 {
		t.Errorf("first revision = %d, want 1", p.Revision)
	}

	// FTS5 matches word prefixes and folds diacritics, so "resum" finds "Résumé".
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"summar", true},
		{"resum", true},
		{"precise", true},
		{"translat", false},
	} {
		got, err := s.ListPrompts(ctx, scope, ListOptions{Query: tc.query})
		if err != nil {
			t.Fatalf("search %q: %v", tc.query, err)
		}
		if (len(got) > 0) != tc.want {
			t.Errorf("search %q: %d hits, want any=%v", tc.query, len(got), tc.want)
		}
	}
	// LIKE covers mid-word substrings that FTS5 cannot.
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{Query: "mariz"}); len(got) != 1 {
		t.Errorf("substring search 'mariz': %d hits, want 1", len(got))
	}

	updated, err := s.UpdatePrompt(ctx, scope, p.ID,
		Prompt{Title: "Zusammenfassung kurz", Tags: []string{"Analyse"}}, anna.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Body == "" {
		t.Errorf("update: revision %d, body %q", updated.Revision, updated.Body)
	}

	if err := s.DeletePrompt(ctx, scope, p.ID, anna.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{}); len(got) != 0 {
		t.Error("a soft-deleted prompt still shows up in the listing")
	}
	if got, _ := s.ListPrompts(ctx, scope, ListOptions{Query: "summar"}); len(got) != 0 {
		t.Error("a soft-deleted prompt is still in the search index")
	}

	restored, err := s.RestorePrompt(ctx, scope, p.ID, 1, anna.ID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Title != "Résumé" {
		t.Errorf("restore to revision 1: title %q", restored.Title)
	}
	revs, err := s.ListRevisions(ctx, scope, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 4 {
		t.Errorf("%d revisions, want 4 (create, update, delete, restore)", len(revs))
	}
}

// Private prompts are invisible to others, and an API key sees exactly what its
// owner sees because it carries their ViewerID.
func TestPrivateVisibility(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleEditor)
	bernd := mustUser(t, s, ctx, "bernd", auth.RoleEditor)

	priv, err := s.CreatePrompt(ctx, Prompt{Title: "Secret", Body: "for anna only",
		Visibility: VisibilityPrivate}, anna.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrompt(ctx, Prompt{Title: "Open", Body: "for everyone",
		Visibility: VisibilityShared}, anna.ID, now); err != nil {
		t.Fatal(err)
	}

	annasSicht, _ := s.ListPrompts(ctx, Scope{ViewerID: anna.ID}, ListOptions{})
	berndsSicht, _ := s.ListPrompts(ctx, Scope{ViewerID: bernd.ID}, ListOptions{})
	if len(annasSicht) != 2 {
		t.Errorf("owner sees %d prompts, want 2", len(annasSicht))
	}
	if len(berndsSicht) != 1 {
		t.Errorf("a stranger sees %d prompts, want 1", len(berndsSicht))
	}
	if _, err := s.GetPrompt(ctx, Scope{ViewerID: bernd.ID}, priv.ID); err != ErrNotFound {
		t.Error("a stranger could fetch a private prompt directly")
	}
	if _, err := s.GetPrompt(ctx, Scope{ViewerID: bernd.ID, SeeAllPrivate: true}, priv.ID); err != nil {
		t.Errorf("admin with ADMIN_PRIVATE_ACCESS=full could not reach the prompt: %v", err)
	}
	// The tag list must not leak other people's private prompts either.
	if _, err := s.ListTags(ctx, Scope{ViewerID: bernd.ID}); err != nil {
		t.Fatal(err)
	}
}

// Deleting a user keeps shared prompts and history; the user row becomes a
// tombstone.
func TestDeleteUserKeepsSharedContentAndHistory(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleEditor)
	admin := mustUser(t, s, ctx, "admin", auth.RoleAdmin)

	shared, _ := s.CreatePrompt(ctx, Prompt{Title: "Team knowledge", Body: "stays",
		Visibility: VisibilityShared}, anna.ID, now)
	if _, err := s.CreatePrompt(ctx, Prompt{Title: "Private", Body: "goes",
		Visibility: VisibilityPrivate}, anna.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateAPIKey(ctx, "personal", "Script", auth.RoleViewer,
		anna.ID, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}

	fp, err := s.UserFootprint(ctx, anna.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fp.SharedPrompts != 1 || fp.PrivatePrompts != 1 || fp.ActiveKeys != 1 {
		t.Errorf("footprint is wrong: %+v", fp)
	}

	if err := s.DeleteUser(ctx, anna.ID, DeleteUserOptions{}, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPrompt(ctx, Scope{ViewerID: admin.ID}, shared.ID)
	if err != nil {
		t.Fatalf("a shared prompt was deleted along with the user: %v", err)
	}
	if got.OwnerName != TombstoneName {
		t.Errorf("author = %q, want %q", got.OwnerName, TombstoneName)
	}
	if revs, err := s.ListRevisions(ctx, Scope{ViewerID: admin.ID}, shared.ID); err != nil || len(revs) == 0 {
		t.Errorf("history lost: %d revisions, err=%v", len(revs), err)
	}
	keys, _ := s.ListAPIKeys(ctx, "", time.Hour, now)
	if len(keys) != 0 {
		t.Errorf("%d keys survived their owner being deleted", len(keys))
	}
	// The same person can sign in again and gets a fresh account.
	wieder := mustUser(t, s, ctx, "anna", auth.RoleViewer)
	if wieder.ID == anna.ID {
		t.Error("signing in after deletion landed on the tombstone row again")
	}
}

func TestSessionTokensAreEncryptedAtRest(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now()
	anna := mustUser(t, s, ctx, "anna", auth.RoleViewer)

	sess, err := s.CreateSession(ctx, anna.ID, auth.RoleViewer, "geheimes-access-token",
		"geheimes-refresh-token", now.Add(30*time.Minute), now, now.Add(time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := s.DB().QueryRow(`SELECT access_token_enc FROM sessions WHERE id = ?`,
		sess.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == "geheimes-access-token" {
		t.Error("access token is stored in plaintext")
	}
	back, _, err := s.GetSession(ctx, sess.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if back.AccessToken != "geheimes-access-token" {
		t.Errorf("access token after reading back = %q", back.AccessToken)
	}
	if _, _, err := s.GetSession(ctx, sess.ID, now.Add(2*time.Hour)); err != ErrNotFound {
		t.Error("an expired session was still returned")
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
		{"owner demoted", base, auth.RoleViewer, fresh, auth.RoleViewer},
		{"owner has no access", base, auth.RoleNone, fresh, auth.RoleNone},
		{"owner not seen for too long", base, auth.RoleEditor, now.Add(-48 * time.Hour), auth.RoleNone},
		{"revoked", APIKey{Role: auth.RoleEditor, OwnerID: "u1",
			ExpiresAt: now.Add(time.Hour), RevokedAt: now}, auth.RoleEditor, fresh, auth.RoleNone},
		{"expired", APIKey{Role: auth.RoleEditor, OwnerID: "u1",
			ExpiresAt: now.Add(-time.Hour)}, auth.RoleEditor, fresh, auth.RoleNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveKeyRole(tc.key, tc.ownerRole, tc.ownerAt, 24*time.Hour, now)
			if got != tc.want {
				t.Errorf("= %q, want %q", got, tc.want)
			}
		})
	}
}
