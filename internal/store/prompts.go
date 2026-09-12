package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scope beschreibt, was ein Betrachter sehen darf. Der Filter ist bewusst an
// einer Stelle gebündelt: jede Abfrage auf prompts geht durch ihn hindurch.
//
// Ein API-Key trägt die ViewerID seines Besitzers — dadurch sieht er exakt
// dessen Bibliothek, ohne dass es dafür eine Sonderregel für Keys bräuchte.
type Scope struct {
	ViewerID      string
	SeeAllPrivate bool // nur für Admins, wenn ADMIN_PRIVATE_ACCESS=full
}

func (s Scope) clause(alias string) (string, []any) {
	if s.SeeAllPrivate {
		return "1 = 1", nil
	}
	return fmt.Sprintf("(%s.visibility = 'shared' OR %s.owner_id = ?)", alias, alias),
		[]any{s.ViewerID}
}

type ListOptions struct {
	Query          string
	Tags           []string
	Visibility     string // "", "shared" oder "private"
	IncludeDeleted bool
	Limit          int
	Offset         int
}

const promptColumns = `p.id, p.title, p.body, p.visibility, p.owner_id,
	ou.display_name, ou.email, ou.deleted_at,
	p.created_at, p.created_by, p.updated_at, p.updated_by,
	uu.display_name, uu.email, uu.deleted_at, p.deleted_at,
	(SELECT COALESCE(MAX(revision), 0) FROM prompt_revisions r WHERE r.prompt_id = p.id)`

const promptFrom = ` FROM prompts p
	JOIN users ou ON ou.id = p.owner_id
	JOIN users uu ON uu.id = p.updated_by`

func scanPrompt(row interface{ Scan(...any) error }) (Prompt, error) {
	var p Prompt
	var ownerName, ownerEmail, updName, updEmail sql.NullString
	var ownerDeleted, updDeleted, promptDeleted sql.NullInt64
	var created, updated int64
	err := row.Scan(&p.ID, &p.Title, &p.Body, &p.Visibility, &p.OwnerID,
		&ownerName, &ownerEmail, &ownerDeleted,
		&created, &p.CreatedBy, &updated, &p.UpdatedBy,
		&updName, &updEmail, &updDeleted, &promptDeleted, &p.Revision)
	if err != nil {
		return Prompt{}, err
	}
	p.OwnerName = displayName(ownerName, ownerEmail, ownerDeleted)
	p.UpdatedByName = displayName(updName, updEmail, updDeleted)
	p.CreatedAt, p.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	p.DeletedAt = unix(promptDeleted)
	return p, nil
}

func displayName(name, email sql.NullString, deleted sql.NullInt64) string {
	if deleted.Valid && deleted.Int64 > 0 {
		return TombstoneName
	}
	if name.String != "" {
		return name.String
	}
	if email.String != "" {
		return email.String
	}
	return TombstoneName
}

// ListPrompts sucht und filtert.
//
// Die Suche kombiniert zwei Wege: FTS5 findet Wortanfänge und normalisiert
// Diakritika ("ubersetz*" trifft "Übersetzung"), LIKE fängt die Teilwortsuche
// mitten im Wort ab, die FTS5 nicht kann. FTS-Treffer stehen vorn.
func (s *Store) ListPrompts(ctx context.Context, sc Scope, opts ListOptions) ([]Prompt, error) {
	if opts.Limit <= 0 || opts.Limit > 200 {
		opts.Limit = 50
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	var (
		sb   strings.Builder
		args []any
	)
	if q := strings.TrimSpace(opts.Query); q != "" {
		sb.WriteString(`WITH matched AS (
			SELECT ps.prompt_id AS id, 0 AS tier FROM prompts_fts
			  JOIN prompt_search ps ON ps.rowid = prompts_fts.rowid
			 WHERE prompts_fts MATCH ?
			UNION
			SELECT ps.prompt_id, 1 FROM prompt_search ps
			 WHERE ps.title LIKE ? ESCAPE '\' OR ps.body LIKE ? ESCAPE '\'
			    OR ps.tags LIKE ? ESCAPE '\'
		) SELECT ` + promptColumns + `, MIN(m.tier) AS tier` + promptFrom + `
		  JOIN matched m ON m.id = p.id`)
		like := "%" + escapeLike(q) + "%"
		args = append(args, ftsQuery(q), like, like, like)
	} else {
		sb.WriteString(`SELECT ` + promptColumns + `, 0 AS tier` + promptFrom)
	}

	where := []string{}
	if !opts.IncludeDeleted {
		where = append(where, "p.deleted_at IS NULL")
	}
	clause, clauseArgs := sc.clause("p")
	where = append(where, clause)
	args = append(args, clauseArgs...)

	switch opts.Visibility {
	case VisibilityShared, VisibilityPrivate:
		where = append(where, "p.visibility = ?")
		args = append(args, opts.Visibility)
	}
	for _, tag := range opts.Tags {
		where = append(where, `p.id IN (SELECT pt.prompt_id FROM prompt_tags pt
			JOIN tags t ON t.id = pt.tag_id WHERE t.name = ? COLLATE NOCASE)`)
		args = append(args, tag)
	}
	sb.WriteString(" WHERE " + strings.Join(where, " AND "))
	sb.WriteString(" GROUP BY p.id ORDER BY tier, p.updated_at DESC LIMIT ? OFFSET ?")
	args = append(args, opts.Limit, opts.Offset)

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("Prompts suchen: %w", err)
	}
	defer rows.Close()

	var out []Prompt
	for rows.Next() {
		var tier int
		var p Prompt
		var ownerName, ownerEmail, updName, updEmail sql.NullString
		var ownerDeleted, updDeleted, promptDeleted sql.NullInt64
		var created, updated int64
		if err := rows.Scan(&p.ID, &p.Title, &p.Body, &p.Visibility, &p.OwnerID,
			&ownerName, &ownerEmail, &ownerDeleted,
			&created, &p.CreatedBy, &updated, &p.UpdatedBy,
			&updName, &updEmail, &updDeleted, &promptDeleted, &p.Revision, &tier); err != nil {
			return nil, err
		}
		p.OwnerName = displayName(ownerName, ownerEmail, ownerDeleted)
		p.UpdatedByName = displayName(updName, updEmail, updDeleted)
		p.CreatedAt, p.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
		p.DeletedAt = unix(promptDeleted)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, s.loadTags(ctx, out)
}

func (s *Store) GetPrompt(ctx context.Context, sc Scope, id string) (Prompt, error) {
	clause, args := sc.clause("p")
	row := s.db.QueryRowContext(ctx,
		`SELECT `+promptColumns+promptFrom+` WHERE p.id = ? AND `+clause,
		append([]any{id}, args...)...)
	p, err := scanPrompt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Prompt{}, ErrNotFound
	}
	if err != nil {
		return Prompt{}, err
	}
	list := []Prompt{p}
	if err := s.loadTags(ctx, list); err != nil {
		return Prompt{}, err
	}
	return list[0], nil
}

func (s *Store) loadTags(ctx context.Context, prompts []Prompt) error {
	if len(prompts) == 0 {
		return nil
	}
	byID := make(map[string]*Prompt, len(prompts))
	args := make([]any, 0, len(prompts))
	for i := range prompts {
		byID[prompts[i].ID] = &prompts[i]
		args = append(args, prompts[i].ID)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pt.prompt_id, t.name FROM prompt_tags pt JOIN tags t ON t.id = pt.tag_id
		  WHERE pt.prompt_id IN (`+placeholders(len(args))+`) ORDER BY t.name`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		if p := byID[id]; p != nil {
			p.Tags = append(p.Tags, name)
		}
	}
	return rows.Err()
}

// CreatePrompt legt einen Eintrag an und schreibt gleich die erste Revision.
func (s *Store) CreatePrompt(ctx context.Context, in Prompt, actorID string, now time.Time) (Prompt, error) {
	in.ID = newID()
	in.OwnerID, in.CreatedBy, in.UpdatedBy = actorID, actorID, actorID
	in.CreatedAt, in.UpdatedAt = now, now
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO prompts
			(id, title, body, visibility, owner_id, created_at, created_by, updated_at, updated_by)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			in.ID, in.Title, in.Body, in.Visibility, in.OwnerID,
			now.Unix(), actorID, now.Unix(), actorID); err != nil {
			return err
		}
		tags, err := setTags(ctx, tx, in.ID, in.Tags)
		if err != nil {
			return err
		}
		in.Tags = tags
		if err := syncSearch(ctx, tx, in.ID, in.Title, in.Body, tags); err != nil {
			return err
		}
		return appendRevision(ctx, tx, in, "create", actorID, now)
	})
	in.Revision = 1
	return in, err
}

// UpdatePrompt ändert Titel, Text, Sichtbarkeit und Tags und legt die neue
// Fassung als Revision ab.
func (s *Store) UpdatePrompt(ctx context.Context, sc Scope, id string, in Prompt, actorID string, now time.Time) (Prompt, error) {
	var out Prompt
	err := s.tx(ctx, func(tx *sql.Tx) error {
		clause, args := sc.clause("p")
		row := tx.QueryRowContext(ctx,
			`SELECT `+promptColumns+promptFrom+` WHERE p.id = ? AND p.deleted_at IS NULL AND `+clause,
			append([]any{id}, args...)...)
		current, err := scanPrompt(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if in.Title != "" {
			current.Title = in.Title
		}
		if in.Body != "" {
			current.Body = in.Body
		}
		if in.Visibility != "" {
			current.Visibility = in.Visibility
		}
		if _, err := tx.ExecContext(ctx, `UPDATE prompts SET title = ?, body = ?,
			visibility = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
			current.Title, current.Body, current.Visibility, now.Unix(), actorID, id); err != nil {
			return err
		}
		tags := in.Tags
		if tags == nil {
			tags, err = currentTags(ctx, tx, id)
			if err != nil {
				return err
			}
		}
		if tags, err = setTags(ctx, tx, id, tags); err != nil {
			return err
		}
		current.Tags = tags
		current.UpdatedAt, current.UpdatedBy = now, actorID
		if err := syncSearch(ctx, tx, id, current.Title, current.Body, tags); err != nil {
			return err
		}
		if err := appendRevision(ctx, tx, current, "update", actorID, now); err != nil {
			return err
		}
		current.Revision++
		out = current
		return nil
	})
	return out, err
}

// DeletePrompt löscht weich: der Eintrag verschwindet aus allen Listen und aus
// dem Suchindex, bleibt aber wiederherstellbar.
func (s *Store) DeletePrompt(ctx context.Context, sc Scope, id, actorID string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		clause, args := sc.clause("p")
		row := tx.QueryRowContext(ctx,
			`SELECT `+promptColumns+promptFrom+` WHERE p.id = ? AND p.deleted_at IS NULL AND `+clause,
			append([]any{id}, args...)...)
		current, err := scanPrompt(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current.Tags, err = currentTags(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE prompts SET deleted_at = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
			now.Unix(), now.Unix(), actorID, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM prompt_search WHERE prompt_id = ?`, id); err != nil {
			return err
		}
		return appendRevision(ctx, tx, current, "delete", actorID, now)
	})
}

// RestorePrompt holt einen gelöschten Eintrag zurück, optional auf dem Stand
// einer bestimmten Revision.
func (s *Store) RestorePrompt(ctx context.Context, sc Scope, id string, revision int, actorID string, now time.Time) (Prompt, error) {
	var out Prompt
	err := s.tx(ctx, func(tx *sql.Tx) error {
		clause, args := sc.clause("p")
		row := tx.QueryRowContext(ctx,
			`SELECT `+promptColumns+promptFrom+` WHERE p.id = ? AND `+clause,
			append([]any{id}, args...)...)
		current, err := scanPrompt(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if revision > 0 {
			var tagsJSON string
			err := tx.QueryRowContext(ctx,
				`SELECT title, body, visibility, tags_json FROM prompt_revisions
				  WHERE prompt_id = ? AND revision = ?`, id, revision).
				Scan(&current.Title, &current.Body, &current.Visibility, &tagsJSON)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("Revision %d: %w", revision, ErrNotFound)
			}
			if err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(tagsJSON), &current.Tags); err != nil {
				return err
			}
		} else if current.Tags, err = currentTags(ctx, tx, id); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `UPDATE prompts SET title = ?, body = ?,
			visibility = ?, deleted_at = NULL, updated_at = ?, updated_by = ? WHERE id = ?`,
			current.Title, current.Body, current.Visibility, now.Unix(), actorID, id); err != nil {
			return err
		}
		tags, err := setTags(ctx, tx, id, current.Tags)
		if err != nil {
			return err
		}
		current.Tags = tags
		if err := syncSearch(ctx, tx, id, current.Title, current.Body, tags); err != nil {
			return err
		}
		current.DeletedAt = time.Time{}
		current.UpdatedAt, current.UpdatedBy = now, actorID
		if err := appendRevision(ctx, tx, current, "restore", actorID, now); err != nil {
			return err
		}
		current.Revision++
		out = current
		return nil
	})
	return out, err
}

func (s *Store) ListRevisions(ctx context.Context, sc Scope, id string) ([]Revision, error) {
	clause, args := sc.clause("p")
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM prompts p WHERE p.id = ? AND `+clause, append([]any{id}, args...)...).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.revision, r.title, r.body, r.visibility,
		r.tags_json, r.kind, r.changed_at, r.changed_by, u.display_name, u.email, u.deleted_at
		FROM prompt_revisions r JOIN users u ON u.id = r.changed_by
		WHERE r.prompt_id = ? ORDER BY r.revision DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var r Revision
		var tagsJSON string
		var changedAt int64
		var name, email sql.NullString
		var deleted sql.NullInt64
		if err := rows.Scan(&r.Revision, &r.Title, &r.Body, &r.Visibility, &tagsJSON,
			&r.Kind, &changedAt, &r.ChangedBy, &name, &email, &deleted); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(tagsJSON), &r.Tags)
		r.ChangedAt = time.Unix(changedAt, 0)
		r.ChangedByName = displayName(name, email, deleted)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListTags liefert alle Tags, die in für den Betrachter sichtbaren Einträgen
// vorkommen, mit Häufigkeit.
func (s *Store) ListTags(ctx context.Context, sc Scope) ([]TagCount, error) {
	clause, args := sc.clause("p")
	rows, err := s.db.QueryContext(ctx, `SELECT t.name, COUNT(*) FROM tags t
		JOIN prompt_tags pt ON pt.tag_id = t.id
		JOIN prompts p ON p.id = pt.prompt_id
		WHERE p.deleted_at IS NULL AND `+clause+`
		GROUP BY t.name ORDER BY COUNT(*) DESC, t.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TagCount
	for rows.Next() {
		var t TagCount
		if err := rows.Scan(&t.Name, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

type TagCount struct {
	Name  string
	Count int
}

func currentTags(ctx context.Context, tx *sql.Tx, promptID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT t.name FROM prompt_tags pt
		JOIN tags t ON t.id = pt.tag_id WHERE pt.prompt_id = ? ORDER BY t.name`, promptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// setTags ersetzt die Tags eines Eintrags und gibt die normalisierte Liste zurück.
func setTags(ctx context.Context, tx *sql.Tx, promptID string, tags []string) ([]string, error) {
	seen := map[string]bool{}
	clean := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 64 {
			continue
		}
		key := strings.ToLower(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		clean = append(clean, t)
	}
	sort.Slice(clean, func(i, j int) bool {
		return strings.ToLower(clean[i]) < strings.ToLower(clean[j])
	})

	if _, err := tx.ExecContext(ctx, `DELETE FROM prompt_tags WHERE prompt_id = ?`, promptID); err != nil {
		return nil, err
	}
	for _, t := range clean {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tags(name) VALUES (?)
			ON CONFLICT(name) DO NOTHING`, t); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO prompt_tags(prompt_id, tag_id)
			SELECT ?, id FROM tags WHERE name = ? COLLATE NOCASE`, promptID, t); err != nil {
			return nil, err
		}
	}
	// Verwaiste Tags aufräumen, damit die Tag-Liste nicht zumüllt.
	if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE id NOT IN
		(SELECT tag_id FROM prompt_tags)`); err != nil {
		return nil, err
	}
	return clean, nil
}

// syncSearch hält die Suchquelle aktuell; die Trigger auf prompt_search
// aktualisieren daraufhin den FTS5-Index.
func syncSearch(ctx context.Context, tx *sql.Tx, promptID, title, body string, tags []string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO prompt_search(prompt_id, title, body, tags)
		VALUES (?,?,?,?) ON CONFLICT(prompt_id) DO UPDATE
		SET title = excluded.title, body = excluded.body, tags = excluded.tags`,
		promptID, title, body, strings.Join(tags, " "))
	return err
}

func appendRevision(ctx context.Context, tx *sql.Tx, p Prompt, kind, actorID string, now time.Time) error {
	tagsJSON, err := json.Marshal(p.Tags)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO prompt_revisions
		(prompt_id, revision, title, body, visibility, tags_json, kind, changed_at, changed_by)
		SELECT ?, COALESCE(MAX(revision), 0) + 1, ?, ?, ?, ?, ?, ?, ?
		  FROM prompt_revisions WHERE prompt_id = ?`,
		p.ID, p.Title, p.Body, p.Visibility, string(tagsJSON), kind, now.Unix(), actorID, p.ID)
	return err
}

// ftsQuery baut aus einer Nutzereingabe eine FTS5-Abfrage. Jedes Wort wird
// gequotet (damit Sonderzeichen keine Syntax sind) und als Präfix gesucht.
func ftsQuery(q string) string {
	var parts []string
	for _, field := range strings.Fields(q) {
		field = strings.ReplaceAll(field, `"`, "")
		if field == "" {
			continue
		}
		parts = append(parts, `"`+field+`"*`)
	}
	if len(parts) == 0 {
		return `""`
	}
	return strings.Join(parts, " ")
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
