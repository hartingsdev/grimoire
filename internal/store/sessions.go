package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

// CreateSession opens a browser session. Provider tokens are stored encrypted
// so the session can later re-check the role with the IdP.
func (s *Store) CreateSession(ctx context.Context, userID string, role auth.Role,
	accessToken, refreshToken string, tokenExpiry time.Time,
	now, expiresAt, revalidateAfter time.Time) (Session, error) {

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
		AccessToken: accessToken, RefreshToken: refreshToken, TokenExpiry: tokenExpiry,
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, role, csrf_token, created_at, expires_at, last_seen_at,
		 revalidate_after, access_token_enc, refresh_token_enc, token_expiry)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, userID, string(role), sess.CSRFToken, now.Unix(), expiresAt.Unix(),
		now.Unix(), revalidateAfter.Unix(), access, refresh, nullTimeZero(tokenExpiry))
	return sess, err
}

func (s *Store) GetSession(ctx context.Context, id string, now time.Time) (Session, User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT s.id, s.user_id, s.role, s.csrf_token,
		s.created_at, s.expires_at, s.last_seen_at, s.revalidate_after,
		s.access_token_enc, s.refresh_token_enc, s.token_expiry, `+userColumnsU+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ? AND u.deleted_at IS NULL`, id, now.Unix())

	var sess Session
	var role string
	var created, expires, lastSeen, reval int64
	var access, refresh []byte
	var tokenExpiry int64
	var u User
	var sub, email, name sql.NullString
	var uRoleAt, uCreated, uLogin int64
	var uDeleted sql.NullInt64
	var uRole string

	err := row.Scan(&sess.ID, &sess.UserID, &role, &sess.CSRFToken,
		&created, &expires, &lastSeen, &reval, &access, &refresh, &tokenExpiry,
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
	// If the tokens will not decrypt (rotated key), the session cannot be
	// revalidated and is dropped when revalidation next falls due.
	sess.AccessToken, _ = s.open(access)
	sess.RefreshToken, _ = s.open(refresh)
	if tokenExpiry > 0 {
		sess.TokenExpiry = time.Unix(tokenExpiry, 0)
	}

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

func (s *Store) UpdateSessionAfterRevalidation(ctx context.Context, id string, role auth.Role,
	accessToken, refreshToken string, tokenExpiry, revalidateAfter time.Time) error {

	access, err := s.seal(accessToken)
	if err != nil {
		return err
	}
	refresh, err := s.seal(refreshToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE sessions SET role = ?, revalidate_after = ?,
		access_token_enc = ?, refresh_token_enc = ?, token_expiry = ? WHERE id = ?`,
		string(role), revalidateAfter.Unix(), access, refresh, nullTimeZero(tokenExpiry), id)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsForUser ends every session of one user, after a role was
// withdrawn at the IdP or the user was deleted.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// SaveOAuthState parks state, nonce and PKCE verifier for a login in flight —
// server-side, so none of it reaches the browser.
func (s *Store) SaveOAuthState(ctx context.Context, state, nonce, verifier, redirectTo string, now, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_states
		(state, nonce, pkce_verifier, redirect_to, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		state, nonce, verifier, redirectTo, now.Unix(), expiresAt.Unix())
	return err
}

// TakeOAuthState consumes a state: every login is redeemable exactly once.
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
