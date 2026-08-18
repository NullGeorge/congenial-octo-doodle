package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    rule TEXT,
    port INTEGER,
    stage INTEGER,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

CREATE TABLE IF NOT EXISTS access_rules (
    source_ip TEXT NOT NULL,
    rule TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (source_ip, rule, port, protocol)
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    rule TEXT,
    status TEXT NOT NULL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_attempts_source_ip ON attempts(source_ip);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}

	// Databases created before the stage column existed need it added. SQLite
	// has no ADD COLUMN IF NOT EXISTS, so a duplicate column is not an error.
	if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN stage INTEGER`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("add events.stage: %w", err)
	}
	return nil
}

func (s *Store) SaveEvent(event events.Event) error {
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	_, err := s.db.Exec(`
INSERT OR IGNORE INTO events(id, type, timestamp, source_ip, rule, port, stage, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Type, event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.SourceIP, event.Rule, event.Port, event.Stage, event.Message)
	return err
}

func (s *Store) SaveAttempt(timestamp time.Time, sourceIP, rule, status, message string) error {
	_, err := s.db.Exec(`
INSERT INTO attempts(timestamp, source_ip, rule, status, message)
VALUES (?, ?, ?, ?, ?)`, timestamp.UTC().Format(time.RFC3339Nano), sourceIP, rule, status, message)
	return err
}
