package store

import (
	"context"
	"database/sql"
	"time"
)

const (
	ActionKeyCreated      = "key.created"
	ActionKeyRevoked      = "key.revoked"
	ActionUserDeleted     = "user.deleted"
	ActionPrivateRevealed = "prompt.private_revealed"
	ActionPrivateTransfer = "prompt.private_transferred"
)

// Audit appends an entry. The log is append-only: no code path edits or
// deletes entries, not even deleting a user.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if e.DetailJSON == "" {
		e.DetailJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log
		(at, actor_id, actor_kind, action, target_type, target_id, reason, detail_json)
		VALUES (?,?,?,?,?,?,?,?)`,
		e.At.Unix(), nullString(e.ActorID), e.ActorKind, e.Action,
		e.TargetType, e.TargetID, e.Reason, e.DetailJSON)
	return err
}

// ListAudit returns the log, newest first. affectedOwnerID narrows it to
// actions touching that user's content, so everyone can see in their own UI
// when an admin revealed one of their private prompts.
func (s *Store) ListAudit(ctx context.Context, affectedOwnerID string, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT a.at, a.actor_id, a.actor_kind, a.action, a.target_type, a.target_id,
		a.reason, a.detail_json, u.display_name, u.email, u.deleted_at
		FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id`
	var args []any
	if affectedOwnerID != "" {
		q += ` WHERE a.target_type = 'prompt' AND a.target_id IN
			(SELECT id FROM prompts WHERE owner_id = ?)`
		args = append(args, affectedOwnerID)
	}
	q += ` ORDER BY a.at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		var actorID, name, email sql.NullString
		var deleted sql.NullInt64
		if err := rows.Scan(&at, &actorID, &e.ActorKind, &e.Action, &e.TargetType,
			&e.TargetID, &e.Reason, &e.DetailJSON, &name, &email, &deleted); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		e.ActorID = actorID.String
		e.ActorName = displayName(name, email, deleted)
		out = append(out, e)
	}
	return out, rows.Err()
}
