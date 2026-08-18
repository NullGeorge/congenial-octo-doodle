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
    country TEXT,
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

	// Databases created before a column existed need it added. SQLite has no
	// ADD COLUMN IF NOT EXISTS, so a duplicate column is not an error.
	for _, statement := range []string{
		`ALTER TABLE events ADD COLUMN stage INTEGER`,
		`ALTER TABLE events ADD COLUMN country TEXT`,
	} {
		if _, err := s.db.Exec(statement); err != nil &&
			!strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("%s: %w", statement, err)
		}
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
INSERT OR IGNORE INTO events(id, type, timestamp, source_ip, country, rule, port, stage, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Type, event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.SourceIP, event.Country, event.Rule, event.Port, event.Stage, event.Message)
	return err
}

func (s *Store) SaveAttempt(timestamp time.Time, sourceIP, rule, status, message string) error {
	_, err := s.db.Exec(`
INSERT INTO attempts(timestamp, source_ip, rule, status, message)
VALUES (?, ?, ?, ?, ?)`, timestamp.UTC().Format(time.RFC3339Nano), sourceIP, rule, status, message)
	return err
}

// AccessRule is one address the daemon believes may reach the guarded port.
// ExpiresAt comes from the lifetime written into the firewall command, so it
// is known without reading the live ruleset, which would need CAP_NET_ADMIN.
type AccessRule struct {
	SourceIP  string
	Rule      string
	Port      uint16
	Protocol  string
	State     string
	Source    string
	UpdatedAt time.Time
	ExpiresAt *time.Time
}

// Expired reports whether a granted lifetime has already run out at now.
// Rules without a known lifetime never report expired.
func (r AccessRule) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && now.After(*r.ExpiresAt)
}

func (s *Store) SaveRule(rule AccessRule) error {
	var expiresAt any
	if rule.ExpiresAt != nil {
		expiresAt = rule.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.Exec(`
INSERT INTO access_rules(source_ip, rule, port, protocol, state, source, updated_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source_ip, rule, port, protocol) DO UPDATE SET
    state = excluded.state,
    source = excluded.source,
    updated_at = excluded.updated_at,
    expires_at = excluded.expires_at`,
		rule.SourceIP, rule.Rule, rule.Port, rule.Protocol, rule.State, rule.Source,
		rule.UpdatedAt.UTC().Format(time.RFC3339Nano), expiresAt)
	return err
}

func (s *Store) ListRules() ([]AccessRule, error) {
	rows, err := s.db.Query(`
SELECT source_ip, rule, port, protocol, state, source, updated_at, expires_at
FROM access_rules ORDER BY updated_at`)
	if err != nil {
		return nil, fmt.Errorf("list access rules: %w", err)
	}
	defer rows.Close()

	var rules []AccessRule
	for rows.Next() {
		var rule AccessRule
		var updatedAt string
		var expiresAt sql.NullString
		if err := rows.Scan(&rule.SourceIP, &rule.Rule, &rule.Port, &rule.Protocol,
			&rule.State, &rule.Source, &updatedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan access rule: %w", err)
		}
		if rule.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
			return nil, fmt.Errorf("parse updated_at %q: %w", updatedAt, err)
		}
		if expiresAt.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, expiresAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse expires_at %q: %w", expiresAt.String, err)
			}
			rule.ExpiresAt = &parsed
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}
