package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

// CreateAPIKey mints a key and stores only its hash. The plaintext is returned
// once, shown once, and never again.
func (s *Store) CreateAPIKey(ctx context.Context, instance, name string, role auth.Role,
	ownerID string, expiresAt, now time.Time) (plaintext string, key APIKey, err error) {

	plaintext, id, hash, err := auth.NewKey(instance)
	if err != nil {
		return "", APIKey{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO api_keys
		(id, key_hash, name, role, owner_id, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?)`,
		id, hash, name, string(role), nullString(ownerID), now.Unix(), expiresAt.Unix())
	if err != nil {
		return "", APIKey{}, err
	}
	return plaintext, APIKey{
		ID: id, Name: name, Role: role, OwnerID: ownerID,
		CreatedAt: now, ExpiresAt: expiresAt, EffectiveRole: role,
	}, nil
}

func (s *Store) LookupAPIKey(ctx context.Context, id string) (APIKey, []byte, User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT k.id, k.key_hash, k.name, k.role, k.owner_id,
		k.created_at, k.expires_at, k.last_used_at, k.revoked_at, k.revoked_reason,
		u.id, u.sub, u.email, u.display_name, u.cached_role, u.cached_role_at,
		u.created_at, u.last_login_at, u.deleted_at
		FROM api_keys k LEFT JOIN users u ON u.id = k.owner_id WHERE k.id = ?`, id)

	var k APIKey
	var hash []byte
	var ownerID, revokedReason sql.NullString
	var created, expires, lastUsed int64
	var revoked sql.NullInt64
	var role string
	var uID, uSub, uEmail, uName, uRole sql.NullString
	var uRoleAt, uCreated, uLogin sql.NullInt64
	var uDeleted sql.NullInt64

	err := row.Scan(&k.ID, &hash, &k.Name, &role, &ownerID,
		&created, &expires, &lastUsed, &revoked, &revokedReason,
		&uID, &uSub, &uEmail, &uName, &uRole, &uRoleAt, &uCreated, &uLogin, &uDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, nil, User{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, nil, User{}, err
	}

	k.Role = auth.ParseRole(role)
	k.OwnerID = ownerID.String
	k.CreatedAt = time.Unix(created, 0)
	k.ExpiresAt = time.Unix(expires, 0)
	k.LastUsedAt = unix(sql.NullInt64{Int64: lastUsed, Valid: true})
	k.RevokedAt = unix(revoked)
	k.RevokedReason = revokedReason.String

	owner := User{
		ID: uID.String, Sub: uSub.String, Email: uEmail.String, DisplayName: uName.String,
		CachedRole:   auth.ParseRole(uRole.String),
		CachedRoleAt: unix(uRoleAt),
		CreatedAt:    unix(uCreated), LastLoginAt: unix(uLogin), DeletedAt: unix(uDeleted),
	}
	return k, hash, owner, nil
}

// TouchAPIKey advances "last used", but only once the value is older than
// minInterval. Writing it on every request would be the most expensive part of
// an otherwise very cheap request.
func (s *Store) TouchAPIKey(ctx context.Context, id string, now time.Time, minInterval time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = ? WHERE id = ? AND last_used_at < ?`,
		now.Unix(), id, now.Add(-minInterval).Unix())
	return err
}

// ListAPIKeys returns metadata, never the key itself. An empty ownerID means
// "every key" and is reserved for admins.
func (s *Store) ListAPIKeys(ctx context.Context, ownerID string, staleAfter time.Duration, now time.Time) ([]APIKey, error) {
	q := `SELECT k.id, k.name, k.role, k.owner_id, k.created_at, k.expires_at,
		k.last_used_at, k.revoked_at, k.revoked_reason,
		u.display_name, u.email, u.deleted_at, u.cached_role, u.cached_role_at
		FROM api_keys k LEFT JOIN users u ON u.id = k.owner_id`
	var args []any
	if ownerID != "" {
		q += ` WHERE k.owner_id = ?`
		args = append(args, ownerID)
	}
	q += ` ORDER BY k.revoked_at IS NOT NULL, k.created_at DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var role string
		var ownerCol, revokedReason, name, email, ownerRole sql.NullString
		var created, expires, lastUsed int64
		var revoked, ownerDeleted, ownerRoleAt sql.NullInt64
		if err := rows.Scan(&k.ID, &k.Name, &role, &ownerCol, &created, &expires,
			&lastUsed, &revoked, &revokedReason,
			&name, &email, &ownerDeleted, &ownerRole, &ownerRoleAt); err != nil {
			return nil, err
		}
		k.Role = auth.ParseRole(role)
		k.OwnerID = ownerCol.String
		k.OwnerName = displayName(name, email, ownerDeleted)
		k.CreatedAt = time.Unix(created, 0)
		k.ExpiresAt = time.Unix(expires, 0)
		k.LastUsedAt = unix(sql.NullInt64{Int64: lastUsed, Valid: true})
		k.RevokedAt = unix(revoked)
		k.RevokedReason = revokedReason.String
		k.EffectiveRole = EffectiveKeyRole(k, auth.ParseRole(ownerRole.String), unix(ownerRoleAt), staleAfter, now)
		out = append(out, k)
	}
	return out, rows.Err()
}

// EffectiveKeyRole computes what a key may actually do right now.
//
// The rule is min(key role, owner's current role): a key can never outrank the
// person who issued it. It also lapses once the owner has not been verified for
// too long, otherwise a departed colleague's key would keep running on a stale
// role.
func EffectiveKeyRole(k APIKey, ownerRole auth.Role, ownerRoleAt time.Time,
	staleAfter time.Duration, now time.Time) auth.Role {

	if k.Revoked() || k.Expired(now) {
		return auth.RoleNone
	}
	if k.OwnerID == "" {
		return k.Role // Service-Key ohne Besitzer: noch nicht erzeugbar, aber vorgesehen
	}
	if auth.OwnerStale(ownerRoleAt, staleAfter, now) {
		return auth.RoleNone
	}
	return auth.MinRole(k.Role, ownerRole)
}

func (s *Store) RevokeAPIKey(ctx context.Context, id, ownerID, reason string, now time.Time) error {
	q := `UPDATE api_keys SET revoked_at = ?, revoked_reason = ?
		WHERE id = ? AND revoked_at IS NULL`
	args := []any{now.Unix(), reason, id}
	if ownerID != "" {
		q += ` AND owner_id = ?`
		args = append(args, ownerID)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("Key %s: %w", id, ErrNotFound)
	}
	return nil
}
