// Package store kapselt die SQLite-Datei einer Instanz: Schema, Migrationen
// und sämtliche Abfragen. Außerhalb dieses Pakets wird kein SQL geschrieben.
package store

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct {
	db   *sql.DB
	aead cipher.AEAD // verschlüsselt die in sessions abgelegten Provider-Tokens
}

// Open öffnet die Datenbankdatei und bringt das Schema auf den aktuellen Stand.
//
// Der Verbindungspool ist bewusst auf eine Verbindung begrenzt: eine SQLite-Datei
// verträgt ohnehin nur einen Schreiber, und bei der Last einer Prompt-Bibliothek
// kostet die Serialisierung nichts — dafür gibt es niemals "database is locked".
func Open(path string, encryptionKey []byte) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"+
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("Datenbank %s öffnen: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("Datenbank %s erreichen: %w", path, err)
	}
	aead, err := newAEAD(encryptionKey)
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, aead: aead}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB gibt das Handle für Tests frei.
func (s *Store) DB() *sql.DB { return s.db }

// migrate wendet alle noch nicht angewandten Migrationen an. Der Fortschritt
// steht in PRAGMA user_version — kein Migrations-Framework, keine Zusatztabelle.
func (s *Store) migrate() error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("Schemaversion lesen: %w", err)
	}
	for i, name := range names {
		step := i + 1
		if step <= version {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("Migration %s: %w", name, err)
		}
		// PRAGMA user_version verträgt keine Platzhalter.
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", step)); err != nil {
			tx.Rollback()
			return fmt.Errorf("Migration %s, Version setzen: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("Migration %s abschließen: %w", name, err)
		}
	}
	return nil
}

// tx führt fn in einer Transaktion aus und rollt bei Fehler oder Panic zurück.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			t.Rollback()
			panic(p)
		}
	}()
	if err := fn(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

// Cleanup entfernt abgelaufene Sessions und Login-States. Läuft periodisch im
// Hintergrund; nichts davon ist für die Korrektheit nötig, nur fürs Aufräumen.
func (s *Store) Cleanup(ctx context.Context) error {
	now := time.Now().Unix()
	for _, q := range []string{
		"DELETE FROM sessions WHERE expires_at < ?",
		"DELETE FROM oauth_states WHERE expires_at < ?",
	} {
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return err
		}
	}
	return nil
}

// nullString bildet leere Strings auf NULL ab.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullTime bildet die Nullzeit auf NULL ab.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func unix(t sql.NullInt64) time.Time {
	if !t.Valid || t.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(t.Int64, 0)
}

// placeholders liefert "?,?,?" für IN-Klauseln.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
