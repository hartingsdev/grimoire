package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

// CreateSession legt eine Browser-Sitzung an. Die Provider-Tokens werden
// verschlüsselt abgelegt, damit die Sitzung später beim IdP nachfragen kann,
// ob die Rolle noch gilt.
func (s *Store) CreateSession(ctx context.Context, userID string, role auth.Role,
	accessToken, refreshToken string, now, expiresAt, revalidateAfter time.Time) (Session, error) {

	access, err := s.seal(accessToken)
	if err != nil {
		return Session{}, err
	}
	refresh, err := s.seal(refreshToken)
	if err != nil {
		return Session{}, err
	}
	sess := Session{
		ID: NewToken(), UserID: userID, Role: role, CSRFToken: NewToken(),
		CreatedAt: now, ExpiresAt: expiresAt, LastSeenAt: now, RevalidateAfter: revalidateAfter,
		AccessToken: accessToken, RefreshToken: refreshToken,
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, role, csrf_token, created_at, expires_at, last_seen_at,
		 revalidate_after, access_token_enc, refresh_token_enc)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, userID, string(role), sess.CSRFToken, now.Unix(), expiresAt.Unix(),
		now.Unix(), revalidateAfter.Unix(), access, refresh)
	return sess, err
}

// GetSession liefert Sitzung und Nutzer. Abgelaufene Sitzungen gelten als nicht
// vorhanden.
func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (Session, User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT s.id, s.user_id, s.role, s.csrf_token,
		s.created_at, s.expires_at, s.last_seen_at, s.revalidate_after,
		s.access_token_enc, s.refresh_token_enc, `+userColumnsU+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ? AND u.deleted_at IS NULL`, id, now.Unix())

	var sess Session
	var role string
	var created, expires, lastSeen, reval int64
	var access, refresh []byte
	var u User
	var sub, email, name sql.NullString
	var uRoleAt, uCreated, uLogin int64
	var uDeleted sql.NullInt64
	var uRole string

	err := row.Scan(&sess.ID, &sess.UserID, &role, &sess.CSRFToken,
		&created, &expires, &lastSeen, &reval, &access, &refresh,
		&u.ID, &sub, &email, &name, &uRole, &uRoleAt, &uCreated, &uLogin, &uDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, err
	}

	sess.Role = auth.ParseRole(role)
	sess.CreatedAt, sess.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	sess.LastSeenAt, sess.RevalidateAfter = time.Unix(lastSeen, 0), time.Unix(reval, 0)
	// Lassen sich die Tokens nicht entschlüsseln (gewechselter Schlüssel), gilt
	// die Sitzung als nicht revalidierbar — sie wird beim nächsten Fälligwerden
	// verworfen statt stillschweigend weiterzulaufen.
	sess.AccessToken, _ = s.open(access)
	sess.RefreshToken, _ = s.open(refresh)

	u.Sub, u.Email, u.DisplayName = sub.String, email.String, name.String
	u.CachedRole = auth.ParseRole(uRole)
	u.CachedRoleAt = time.Unix(uRoleAt, 0)
	u.CreatedAt, u.LastLoginAt = time.Unix(uCreated, 0), time.Unix(uLogin, 0)
	u.DeletedAt = unix(uDeleted)
	return sess, u, nil
}

func (s *Store) TouchSession(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?`,
		now.Unix(), id, now.Add(-time.Minute).Unix())
	return err
}

// UpdateSessionAfterRevalidation schreibt die beim IdP frisch bestätigte Rolle
// und die neuen Tokens fort.
func (s *Store) UpdateSessionAfterRevalidation(ctx context.Context, id string, role auth.Role,
	accessToken, refreshToken string, revalidateAfter time.Time) error {

	access, err := s.seal(accessToken)
	if err != nil {
		return err
	}
	refresh, err := s.seal(refreshToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE sessions SET role = ?, revalidate_after = ?,
		access_token_enc = ?, refresh_token_enc = ? WHERE id = ?`,
		string(role), revalidateAfter.Unix(), access, refresh, id)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsForUser beendet alle Sitzungen eines Nutzers — nach einem
// Rollenentzug im IdP oder beim Löschen des Nutzers.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// SaveOAuthState hinterlegt State, Nonce und PKCE-Verifier für einen laufenden
// Login. Serverseitig, damit nichts davon im Browser landet.
func (s *Store) SaveOAuthState(ctx context.Context, state, nonce, verifier, redirectTo string, now, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_states
		(state, nonce, pkce_verifier, redirect_to, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		state, nonce, verifier, redirectTo, now.Unix(), expiresAt.Unix())
	return err
}

// TakeOAuthState holt einen State ab und löscht ihn dabei: jeder Login-Vorgang
// ist genau einmal einlösbar.
func (s *Store) TakeOAuthState(ctx context.Context, state string, now time.Time) (nonce, verifier, redirectTo string, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT nonce, pkce_verifier, redirect_to FROM oauth_states
			  WHERE state = ? AND expires_at > ?`, state, now.Unix())
		if err := row.Scan(&nonce, &verifier, &redirectTo); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM oauth_states WHERE state = ?`, state)
		return err
	})
	return nonce, verifier, redirectTo, err
}
