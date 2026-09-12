package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
)

var ErrNotFound = errors.New("not found")

const userColumns = `id, sub, email, display_name, cached_role, cached_role_at,
	created_at, last_login_at, deleted_at`

const userColumnsU = `u.id, u.sub, u.email, u.display_name, u.cached_role, u.cached_role_at,
	u.created_at, u.last_login_at, u.deleted_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var sub, email, name sql.NullString
	var roleAt, created, login int64
	var deleted sql.NullInt64
	var role string
	if err := row.Scan(&u.ID, &sub, &email, &name, &role, &roleAt, &created, &login, &deleted); err != nil {
		return User{}, err
	}
	u.Sub, u.Email, u.DisplayName = sub.String, email.String, name.String
	u.CachedRole = auth.ParseRole(role)
	u.CachedRoleAt = unix(sql.NullInt64{Int64: roleAt, Valid: true})
	u.CreatedAt = unix(sql.NullInt64{Int64: created, Valid: true})
	u.LastLoginAt = unix(sql.NullInt64{Int64: login, Valid: true})
	u.DeletedAt = unix(deleted)
	return u, nil
}

// UpsertUserOnLogin creates the user row on first login and refreshes it on
// every later one. There is no approval step in the app: whoever has a matching
// role at the IdP has access.
func (s *Store) UpsertUserOnLogin(ctx context.Context, sub, email, name string, role auth.Role, now time.Time) (User, error) {
	var u User
	err := s.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE sub = ?`, sub)
		existing, err := scanUser(row)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id := newID()
			_, err = tx.ExecContext(ctx, `INSERT INTO users
				(id, sub, email, display_name, cached_role, cached_role_at, created_at, last_login_at)
				VALUES (?,?,?,?,?,?,?,?)`,
				id, sub, nullString(email), nullString(name), string(role),
				now.Unix(), now.Unix(), now.Unix())
			if err != nil {
				return err
			}
			u = User{ID: id, Sub: sub, Email: email, DisplayName: name,
				CachedRole: role, CachedRoleAt: now, CreatedAt: now, LastLoginAt: now}
			return nil
		case err != nil:
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE users SET email = ?, display_name = ?,
			cached_role = ?, cached_role_at = ?, last_login_at = ? WHERE id = ?`,
			nullString(email), nullString(name), string(role), now.Unix(), now.Unix(), existing.ID)
		if err != nil {
			return err
		}
		existing.Email, existing.DisplayName = email, name
		existing.CachedRole, existing.CachedRoleAt, existing.LastLoginAt = role, now, now
		u = existing
		return nil
	})
	return u, err
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// SetCachedRole records the result of a revalidation, including auth.RoleNone
// when the provider authoritatively reports no role. A network error never
// reaches this function.
func (s *Store) SetCachedRole(ctx context.Context, userID string, role auth.Role, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET cached_role = ?, cached_role_at = ? WHERE id = ?`,
		string(role), at.Unix(), userID)
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE deleted_at IS NULL ORDER BY last_login_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserFootprint counts what hangs off a user, for the deletion dialog. No
// content is read.
type UserFootprint struct {
	SharedPrompts  int
	PrivatePrompts int
	ActiveKeys     int
	Sessions       int
}

func (s *Store) UserFootprint(ctx context.Context, userID string) (UserFootprint, error) {
	var f UserFootprint
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM prompts WHERE owner_id = ? AND deleted_at IS NULL AND visibility = 'shared'),
		(SELECT COUNT(*) FROM prompts WHERE owner_id = ? AND deleted_at IS NULL AND visibility = 'private'),
		(SELECT COUNT(*) FROM api_keys WHERE owner_id = ? AND revoked_at IS NULL),
		(SELECT COUNT(*) FROM sessions WHERE user_id = ?)`,
		userID, userID, userID, userID).Scan(&f.SharedPrompts, &f.PrivatePrompts, &f.ActiveKeys, &f.Sessions)
	return f, err
}

type DeleteUserOptions struct {
	// TransferPrivateTo hands the private prompts to this user instead of
	// deleting them. That grants read access, so it is gated on
	// ADMIN_PRIVATE_ACCESS and always audited.
	TransferPrivateTo string
}

// DeleteUser turns the user row into a tombstone: sub, email and name are
// cleared while the row stays as the target of every foreign key. Shared
// prompts survive — that is team knowledge, not personal property.
func (s *Store) DeleteUser(ctx context.Context, userID string, opts DeleteUserOptions, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if opts.TransferPrivateTo != "" {
			if _, err := tx.ExecContext(ctx,
				`UPDATE prompts SET owner_id = ?, updated_at = ?, updated_by = ?
				  WHERE owner_id = ? AND visibility = 'private' AND deleted_at IS NULL`,
				opts.TransferPrivateTo, now.Unix(), opts.TransferPrivateTo, userID); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM prompt_search WHERE prompt_id IN
				  (SELECT id FROM prompts WHERE owner_id = ? AND visibility = 'private')`,
				userID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM prompts WHERE owner_id = ? AND visibility = 'private'`, userID); err != nil {
				return err
			}
		}
		for _, q := range []string{
			`DELETE FROM api_keys WHERE owner_id = ?`,
			`DELETE FROM sessions WHERE user_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, userID); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET sub = NULL, email = NULL,
			display_name = NULL, cached_role = '', cached_role_at = 0, deleted_at = ?
			WHERE id = ? AND deleted_at IS NULL`, now.Unix(), userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("user %s: %w", userID, ErrNotFound)
		}
		return nil
	})
}
