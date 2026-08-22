package storage

import (
	"database/sql"
	"errors"
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
	const tables = `
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    country TEXT,
    rule TEXT,
    port INTEGER,
    stage INTEGER,
    message TEXT,
    ttl_seconds INTEGER,
    delivered_at TEXT
);

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
`
	if _, err := s.db.Exec(tables); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}

	// Databases created before a column existed need it added. SQLite has no
	// ADD COLUMN IF NOT EXISTS, so a duplicate column is not an error. Rows
	// written before stage existed get 0 rather than NULL, because reads scan
	// that column into a plain int.
	for _, statement := range []string{
		`ALTER TABLE events ADD COLUMN stage INTEGER DEFAULT 0`,
		`ALTER TABLE events ADD COLUMN country TEXT`,
		`ALTER TABLE events ADD COLUMN delivered_at TEXT`,
		`ALTER TABLE events ADD COLUMN ttl_seconds INTEGER`,
	} {
		if _, err := s.db.Exec(statement); err != nil &&
			!strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("%s: %w", statement, err)
		}
	}

	// Indexes are created last: the partial index over delivered_at cannot be
	// built before the ALTER TABLE above has added that column to an older
	// database, and a failure there would make the file unopenable.
	const indexes = `
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_undelivered ON events(delivered_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_attempts_source_ip ON attempts(source_ip);
`
	if _, err := s.db.Exec(indexes); err != nil {
		return fmt.Errorf("migrate sqlite indexes: %w", err)
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
INSERT OR IGNORE INTO events(id, type, timestamp, source_ip, country, rule, port, stage, ttl_seconds, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Type, event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.SourceIP, event.Country, event.Rule, event.Port, event.Stage,
		int64(event.TTL/time.Second), event.Message)
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

// CloseRules shuts every rule for one address. The firewall set holds one
// element per address, so an address is either allowed or it is not; which
// knockd section opened it does not survive the revoke.
func (s *Store) CloseRules(sourceIP string, at time.Time) error {
	_, err := s.db.Exec(`
UPDATE access_rules SET state = 'closed', updated_at = ?, expires_at = NULL
WHERE source_ip = ?`, at.UTC().Format(time.RFC3339Nano), sourceIP)
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

// UndeliveredEvents returns the oldest events not yet pushed to Telegram.
// The database doubles as the outbox, so a network outage delays alerts
// instead of losing them.
func (s *Store) UndeliveredEvents(limit int) ([]events.Event, error) {
	rows, err := s.db.Query(`
SELECT id, type, timestamp, source_ip, country, rule, port, stage, ttl_seconds, message
FROM events WHERE delivered_at IS NULL ORDER BY timestamp LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list undelivered events: %w", err)
	}
	defer rows.Close()

	var pending []events.Event
	for rows.Next() {
		var event events.Event
		var timestamp string
		var sourceIP, country, rule, message sql.NullString
		var ttlSeconds sql.NullInt64
		if err := rows.Scan(&event.ID, &event.Type, &timestamp, &sourceIP, &country,
			&rule, &event.Port, &event.Stage, &ttlSeconds, &message); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		event.TTL = time.Duration(ttlSeconds.Int64) * time.Second
		if event.Timestamp, err = time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return nil, fmt.Errorf("parse timestamp %q: %w", timestamp, err)
		}
		event.SourceIP, event.Country = sourceIP.String, country.String
		event.Rule, event.Message = rule.String, message.String
		pending = append(pending, event)
	}
	return pending, rows.Err()
}

func (s *Store) MarkDelivered(id string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE events SET delivered_at = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), id)
	return err
}

// Summary is the one-glance view behind the status command.
type Summary struct {
	Events        int
	Attempts      int
	Undelivered   int
	ActiveRules   int
	LastEventType string
	LastEventAt   time.Time
}

// Summary counts what the agent has recorded. A rule counts as active only
// while its granted lifetime still has time left at now.
func (s *Store) Summary(now time.Time) (Summary, error) {
	var summary Summary
	if err := s.db.QueryRow(`SELECT count(*) FROM events`).Scan(&summary.Events); err != nil {
		return summary, fmt.Errorf("count events: %w", err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM attempts`).Scan(&summary.Attempts); err != nil {
		return summary, fmt.Errorf("count attempts: %w", err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM events WHERE delivered_at IS NULL`).
		Scan(&summary.Undelivered); err != nil {
		return summary, fmt.Errorf("count undelivered: %w", err)
	}
	if err := s.db.QueryRow(`
SELECT count(*) FROM access_rules
WHERE state = 'open' AND (expires_at IS NULL OR expires_at > ?)`,
		now.UTC().Format(time.RFC3339Nano)).Scan(&summary.ActiveRules); err != nil {
		return summary, fmt.Errorf("count active rules: %w", err)
	}

	var lastType, lastAt sql.NullString
	if err := s.db.QueryRow(`
SELECT type, timestamp FROM events ORDER BY timestamp DESC LIMIT 1`).Scan(&lastType, &lastAt); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		return summary, fmt.Errorf("read last event: %w", err)
	}
	summary.LastEventType = lastType.String
	if lastAt.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, lastAt.String)
		if err != nil {
			return summary, fmt.Errorf("parse last event time %q: %w", lastAt.String, err)
		}
		summary.LastEventAt = parsed
	}
	return summary, nil
}

// Attempt is one recorded knock or failed sequence.
type Attempt struct {
	Timestamp time.Time
	SourceIP  string
	Rule      string
	Status    string
	Message   string
}

func (s *Store) ListAttempts(limit int) ([]Attempt, error) {
	rows, err := s.db.Query(`
SELECT timestamp, source_ip, rule, status, message
FROM attempts ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list attempts: %w", err)
	}
	defer rows.Close()

	var attempts []Attempt
	for rows.Next() {
		var attempt Attempt
		var timestamp string
		var rule, message sql.NullString
		if err := rows.Scan(&timestamp, &attempt.SourceIP, &rule, &attempt.Status, &message); err != nil {
			return nil, fmt.Errorf("scan attempt: %w", err)
		}
		if attempt.Timestamp, err = time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return nil, fmt.Errorf("parse attempt time %q: %w", timestamp, err)
		}
		attempt.Rule, attempt.Message = rule.String, message.String
		attempts = append(attempts, attempt)
	}
	return attempts, rows.Err()
}
