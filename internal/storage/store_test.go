package storage

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

// newStore opens a store on a real file. An in-memory database would hide the
// reopen and migration behaviour that every command in this repo relies on:
// the daemon and the CLI open the same file independently.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

// eventColumns counts how often each column name appears in the events table.
// A count is used rather than a set because the migration runs ALTER TABLE on
// every open, and a duplicated column would be a silent schema corruption.
func eventColumns(t *testing.T, store *Store) map[string]int {
	t.Helper()
	rows, err := store.db.Query(`SELECT name FROM pragma_table_info('events')`)
	if err != nil {
		t.Fatalf("read events columns: %v", err)
	}
	defer rows.Close()

	found := map[string]int{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		found[name]++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	return found
}

// Opening the same file twice must be safe: the agent, the status command and
// the tests all call Open, and migrate() re-runs its ALTER TABLE statements
// each time. Data written before the reopen must still be there afterwards.
func TestOpenCreatesSchemaAndIsIdempotent(t *testing.T) {
	store, path := newStore(t)

	at := time.Now().UTC().Truncate(time.Second)
	if err := store.SaveEvent(events.Event{
		ID: "boot", Type: events.KnockdStarted, Timestamp: at,
		Message: "starting up, listening on enp2s0",
	}); err != nil {
		t.Fatalf("save event: %v", err)
	}
	if err := store.SaveAttempt(at, "192.0.2.134", "openSSH", "failed",
		"192.0.2.134: openSSH: sequence timeout (stage 1)"); err != nil {
		t.Fatalf("save attempt: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	for name, want := range map[string]int{
		"id": 1, "type": 1, "timestamp": 1, "source_ip": 1, "country": 1,
		"rule": 1, "port": 1, "stage": 1, "message": 1, "ttl_seconds": 1,
		"delivered_at": 1,
	} {
		if got := eventColumns(t, reopened)[name]; got != want {
			t.Errorf("events column %q appears %d times, want %d", name, got, want)
		}
	}

	summary, err := reopened.Summary(at.Add(time.Minute))
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.Events != 1 || summary.Attempts != 1 {
		t.Errorf("after reopen events=%d attempts=%d, want 1 and 1",
			summary.Events, summary.Attempts)
	}
}

// The production upgrade path: a database written by an older build has an
// events table without stage, country, ttl_seconds or delivered_at. Open must
// add the columns and leave the recorded history intact.
func TestOpenMigratesDatabaseMissingColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := legacy.Exec(`
CREATE TABLE events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    rule TEXT,
    port INTEGER,
    message TEXT
)`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if _, err := legacy.Exec(
		`INSERT INTO events(id, type, timestamp, source_ip, rule, port, message) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"legacy", string(events.AccessGranted), at.Format(time.RFC3339Nano),
		"203.0.113.5", "openSSH", 22, "203.0.113.5: openSSH: OPEN SESAME"); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	defer store.Close()

	columns := eventColumns(t, store)
	for _, name := range []string{"stage", "country", "ttl_seconds", "delivered_at"} {
		if columns[name] != 1 {
			t.Errorf("migrated events column %q appears %d times, want 1", name, columns[name])
		}
	}

	var storedType, message string
	if err := store.db.QueryRow(
		`SELECT type, message FROM events WHERE id = 'legacy'`).Scan(&storedType, &message); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if storedType != string(events.AccessGranted) {
		t.Errorf("migrated type = %q, want %q", storedType, events.AccessGranted)
	}
	if message != "203.0.113.5: openSSH: OPEN SESAME" {
		t.Errorf("migrated message = %q, want the original knockd line", message)
	}

	// The migrated database must still be writable through the new schema.
	if err := store.SaveEvent(events.Event{
		ID: "after-migration", Type: events.KnockReceived, Timestamp: at.Add(time.Second),
		SourceIP: "203.0.113.5", Country: "RU", Rule: "openSSH", Stage: 2,
	}); err != nil {
		t.Fatalf("save into migrated database: %v", err)
	}

	// A row predating the stage column must still be readable through the
	// outbox: it has not been delivered, and scanning it into events.Event
	// is what the Telegram loop does on the first run after an upgrade.
	pending, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("read migrated rows as pending events: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending events = %d, want the legacy row and the new one", len(pending))
	}
	if pending[0].ID != "legacy" || pending[0].SourceIP != "203.0.113.5" ||
		pending[0].Rule != "openSSH" || pending[0].Port != 22 {
		t.Errorf("legacy row read back as %+v", pending[0])
	}
	if pending[0].Country != "" || pending[0].Stage != 0 || pending[0].TTL != 0 {
		t.Errorf("legacy row gained values for columns it never had: %+v", pending[0])
	}
	if !pending[0].Timestamp.Equal(at) {
		t.Errorf("legacy timestamp = %v, want %v", pending[0].Timestamp, at)
	}
}

// Open must fail rather than hand back a store with no schema when the file
// cannot be created; the daemon exits on this error at start-up.
func TestOpenRejectsUnusablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "state.db")
	store, err := Open(path)
	if err == nil {
		store.Close()
		t.Fatal("Open succeeded on a path inside a missing directory")
	}
}

// A database that cannot be altered must fail the open instead of running on a
// half-migrated schema: every later read would then hit a missing column.
func TestOpenReportsFailedColumnMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	// All three tables exist, so CREATE TABLE IF NOT EXISTS is a no-op and the
	// ALTER TABLE that adds stage is the first statement needing a write.
	if _, err := legacy.Exec(`
CREATE TABLE events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    rule TEXT,
    port INTEGER,
    message TEXT
);
CREATE TABLE access_rules (
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
CREATE TABLE attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    rule TEXT,
    status TEXT NOT NULL,
    message TEXT
);`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	// File permissions are useless here because the tests run as root, so the
	// database is reopened read-only through the SQLite URI instead.
	store, err := Open("file:" + path + "?mode=ro")
	if err == nil {
		store.Close()
		t.Fatal("Open succeeded on a read-only database needing a migration")
	}
	if !strings.Contains(err.Error(), "ALTER TABLE events ADD COLUMN stage") {
		t.Errorf("error = %v, want it to name the statement that failed", err)
	}
}

// Every field the parser can fill must survive a write and a read, including
// the three added late: Country, Stage and TTL.
func TestSaveEventRoundTripsEveryField(t *testing.T) {
	store, _ := newStore(t)

	want := events.Event{
		ID:        "203.0.113.5-openSSH-granted",
		Type:      events.AccessGranted,
		Timestamp: time.Now().UTC().Add(-time.Minute),
		SourceIP:  "203.0.113.5",
		Country:   "RU",
		Rule:      "openSSH",
		Port:      22,
		Stage:     3,
		TTL:       15 * time.Minute,
		Message:   "openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
	}
	if err := store.SaveEvent(want); err != nil {
		t.Fatalf("save event: %v", err)
	}

	pending, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("undelivered events: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("read back %d events, want 1", len(pending))
	}

	got := pending[0]
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
	got.Timestamp = want.Timestamp
	if got != want {
		t.Errorf("round trip changed the event:\n got %+v\nwant %+v", got, want)
	}
}

// Events built straight from a log line carry no id and no timestamp, and the
// outbox needs both: the id is the delivery key and the timestamp the order.
func TestSaveEventFillsMissingIDAndTimestamp(t *testing.T) {
	store, _ := newStore(t)

	before := time.Now().UTC()
	if err := store.SaveEvent(events.Event{
		Type: events.KnockReceived, SourceIP: "203.0.113.5", Rule: "openSSH", Stage: 2,
	}); err != nil {
		t.Fatalf("save event: %v", err)
	}
	after := time.Now().UTC()

	pending, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("undelivered events: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("read back %d events, want 1", len(pending))
	}
	if pending[0].ID == "" {
		t.Error("stored event kept an empty id, so it can never be marked delivered")
	}
	if pending[0].Timestamp.Before(before) || pending[0].Timestamp.After(after) {
		t.Errorf("generated timestamp %v is outside [%v, %v]",
			pending[0].Timestamp, before, after)
	}
}

// A restarted reader can replay lines it already stored. INSERT OR IGNORE must
// keep exactly one row and must not overwrite what was recorded first.
func TestSaveEventIgnoresDuplicateID(t *testing.T) {
	store, _ := newStore(t)

	at := time.Now().UTC().Truncate(time.Second)
	first := events.Event{
		ID: "replayed", Type: events.SequenceMatched, Timestamp: at,
		SourceIP: "203.0.113.5", Rule: "openSSH",
		Message: "203.0.113.5: openSSH: OPEN SESAME",
	}
	if err := store.SaveEvent(first); err != nil {
		t.Fatalf("save first: %v", err)
	}
	second := first
	second.Type = events.AccessGranted
	second.Message = "different message for the same id"
	if err := store.SaveEvent(second); err != nil {
		t.Fatalf("save duplicate: %v", err)
	}

	pending, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("undelivered events: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("stored %d rows for one id, want 1", len(pending))
	}
	if pending[0].Type != first.Type || pending[0].Message != first.Message {
		t.Errorf("duplicate overwrote the stored row: got type %q message %q",
			pending[0].Type, pending[0].Message)
	}
}

// The status command shows the most recent knocks, so ListAttempts must sort
// by recorded time rather than insertion order and honour the limit.
func TestListAttemptsNewestFirstAndLimited(t *testing.T) {
	store, _ := newStore(t)

	empty, err := store.ListAttempts(10)
	if err != nil {
		t.Fatalf("list attempts on empty table: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty table returned %d attempts", len(empty))
	}

	// Whole seconds only: the timestamp column is text, so ordering is a
	// string comparison and mixed fractional precision would sort wrongly.
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	fixtures := []struct {
		offset  time.Duration
		ip      string
		rule    string
		status  string
		message string
	}{
		// Written out of order on purpose: the oldest row goes in last.
		{2 * time.Second, "203.0.113.5", "openSSH", "knock", "203.0.113.5: openSSH: Stage 3"},
		{time.Second, "203.0.113.5", "openSSH", "knock", "203.0.113.5: openSSH: Stage 2"},
		{0, "192.0.2.134", "openSSH", "failed", "192.0.2.134: openSSH: sequence timeout (stage 1)"},
	}
	for _, fixture := range fixtures {
		if err := store.SaveAttempt(base.Add(fixture.offset), fixture.ip,
			fixture.rule, fixture.status, fixture.message); err != nil {
			t.Fatalf("save attempt %q: %v", fixture.message, err)
		}
	}

	all, err := store.ListAttempts(10)
	if err != nil {
		t.Fatalf("list attempts: %v", err)
	}
	if len(all) != len(fixtures) {
		t.Fatalf("listed %d attempts, want %d", len(all), len(fixtures))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Timestamp.After(all[i-1].Timestamp) {
			t.Errorf("attempt %d (%v) is newer than %d (%v), want newest first",
				i, all[i].Timestamp, i-1, all[i-1].Timestamp)
		}
	}

	newest := all[0]
	if !newest.Timestamp.Equal(base.Add(2 * time.Second)) {
		t.Errorf("newest attempt at %v, want %v", newest.Timestamp, base.Add(2*time.Second))
	}
	if newest.SourceIP != "203.0.113.5" || newest.Rule != "openSSH" ||
		newest.Status != "knock" || newest.Message != "203.0.113.5: openSSH: Stage 3" {
		t.Errorf("newest attempt round trip = %+v", newest)
	}
	oldest := all[len(all)-1]
	if oldest.SourceIP != "192.0.2.134" || oldest.Status != "failed" {
		t.Errorf("oldest attempt = %+v, want the timed-out sequence", oldest)
	}

	limited, err := store.ListAttempts(2)
	if err != nil {
		t.Fatalf("list attempts with limit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit 2 returned %d attempts", len(limited))
	}
	if !limited[0].Timestamp.Equal(newest.Timestamp) {
		t.Errorf("limited list starts at %v, want the newest %v",
			limited[0].Timestamp, newest.Timestamp)
	}
}

// A rule is identified by source_ip, rule, port and protocol. Re-granting the
// same access must update that row, otherwise the active count grows on every
// knock; a different port is a different rule.
func TestSaveRuleUpsertsOnKeyAndRoundTripsExpiry(t *testing.T) {
	store, _ := newStore(t)

	updated := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	expires := updated.Add(15 * time.Minute)
	rule := AccessRule{
		SourceIP: "203.0.113.5", Rule: "openSSH", Port: 22, Protocol: "tcp",
		State: "open", Source: "nft", UpdatedAt: updated, ExpiresAt: &expires,
	}
	if err := store.SaveRule(rule); err != nil {
		t.Fatalf("save rule: %v", err)
	}

	stored, err := store.ListRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("listed %d rules, want 1", len(stored))
	}
	if stored[0].SourceIP != rule.SourceIP || stored[0].Rule != rule.Rule ||
		stored[0].Port != rule.Port || stored[0].Protocol != rule.Protocol ||
		stored[0].State != rule.State || stored[0].Source != rule.Source {
		t.Errorf("rule round trip = %+v, want %+v", stored[0], rule)
	}
	if !stored[0].UpdatedAt.Equal(updated) {
		t.Errorf("updated_at = %v, want %v", stored[0].UpdatedAt, updated)
	}
	if stored[0].ExpiresAt == nil {
		t.Fatal("expires_at came back nil, want the granted lifetime")
	}
	if !stored[0].ExpiresAt.Equal(expires) {
		t.Errorf("expires_at = %v, want %v", stored[0].ExpiresAt, expires)
	}

	// Revoking the same access: same key, new state, lifetime no longer known.
	revoked := rule
	revoked.State = "closed"
	revoked.Source = "manual"
	revoked.UpdatedAt = updated.Add(time.Minute)
	revoked.ExpiresAt = nil
	if err := store.SaveRule(revoked); err != nil {
		t.Fatalf("save revoked rule: %v", err)
	}

	stored, err = store.ListRules()
	if err != nil {
		t.Fatalf("list rules after update: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("re-saving one key produced %d rules, want 1", len(stored))
	}
	if stored[0].State != "closed" || stored[0].Source != "manual" {
		t.Errorf("update kept state %q source %q, want closed and manual",
			stored[0].State, stored[0].Source)
	}
	if stored[0].ExpiresAt != nil {
		t.Errorf("expires_at = %v, want nil after the lifetime was cleared", stored[0].ExpiresAt)
	}
	if !stored[0].UpdatedAt.Equal(revoked.UpdatedAt) {
		t.Errorf("updated_at = %v, want %v", stored[0].UpdatedAt, revoked.UpdatedAt)
	}

	// Another port with the same address is a separate grant.
	other := rule
	other.Port = 2222
	other.UpdatedAt = updated.Add(2 * time.Minute)
	if err := store.SaveRule(other); err != nil {
		t.Fatalf("save second port: %v", err)
	}
	stored, err = store.ListRules()
	if err != nil {
		t.Fatalf("list rules after second port: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("listed %d rules, want 2 after a second port", len(stored))
	}
	// ListRules orders by updated_at, so the newer grant comes last.
	if stored[1].Port != 2222 {
		t.Errorf("rules ordered by updated_at gave ports %d,%d, want 22 then 2222",
			stored[0].Port, stored[1].Port)
	}
}

// The firewall set holds one element per address, so a revoke clears the whole
// address whatever section or port opened it, and only that address.
func TestCloseRulesShutsEveryRuleForOneAddress(t *testing.T) {
	store, _ := newStore(t)

	granted := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	expires := granted.Add(15 * time.Minute)
	for _, rule := range []AccessRule{
		{SourceIP: "203.0.113.5", Rule: "openSSH", Port: 22, Protocol: "tcp",
			State: "open", Source: "knockd", UpdatedAt: granted, ExpiresAt: &expires},
		{SourceIP: "203.0.113.5", Rule: "manual", Port: 2222, Protocol: "tcp",
			State: "open", Source: "knockd", UpdatedAt: granted, ExpiresAt: &expires},
		{SourceIP: "198.51.100.167", Rule: "openSSH", Port: 22, Protocol: "tcp",
			State: "open", Source: "knockd", UpdatedAt: granted, ExpiresAt: &expires},
	} {
		if err := store.SaveRule(rule); err != nil {
			t.Fatalf("save rule for %s: %v", rule.SourceIP, err)
		}
	}

	closedAt := granted.Add(time.Minute)
	if err := store.CloseRules("203.0.113.5", closedAt); err != nil {
		t.Fatalf("close rules: %v", err)
	}

	stored, err := store.ListRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(stored) != 3 {
		t.Fatalf("listed %d rules, want the 3 saved: %+v", len(stored), stored)
	}
	for _, rule := range stored {
		if rule.SourceIP == "198.51.100.167" {
			if rule.State != "open" || rule.ExpiresAt == nil {
				t.Errorf("closing one address disturbed %+v", rule)
			}
			continue
		}
		if rule.State != "closed" {
			t.Errorf("rule %+v survived the revoke as %q", rule, rule.State)
		}
		if rule.ExpiresAt != nil {
			t.Errorf("closed rule %+v still carries an expiry", rule)
		}
		if !rule.UpdatedAt.Equal(closedAt) {
			t.Errorf("updated_at = %v, want the revoke time %v", rule.UpdatedAt, closedAt)
		}
	}

	// Nothing to close is not a failure; a revoke may follow a restart.
	if err := store.CloseRules("192.0.2.77", closedAt); err != nil {
		t.Errorf("closing an address that holds nothing: %v", err)
	}
	stored, err = store.ListRules()
	if err != nil {
		t.Fatalf("list rules after a no-op close: %v", err)
	}
	if len(stored) != 3 {
		t.Errorf("a no-op close changed the row count to %d, want 3", len(stored))
	}
}

func TestAccessRuleExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Second)
	future := now.Add(15 * time.Minute)

	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		// A rule from a command without a timeout has no known lifetime, so
		// the agent must keep reporting it instead of guessing it is gone.
		{"no known lifetime", nil, false},
		{"lifetime ran out", &past, true},
		// The boundary is exclusive: at the exact instant the timeout is
		// reached the firewall still holds the element.
		{"exactly at the deadline", &now, false},
		{"lifetime still running", &future, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := AccessRule{SourceIP: "203.0.113.5", ExpiresAt: tt.expiresAt}
			if got := rule.Expired(now); got != tt.want {
				t.Errorf("Expired(%v) = %v, want %v", now, got, tt.want)
			}
		})
	}
}

// The events table is the Telegram outbox: pending alerts must come out oldest
// first so the chat reads in order, the limit must cap a backlog, and a
// delivered event must never be offered again.
func TestUndeliveredEventsAndMarkDelivered(t *testing.T) {
	store, _ := newStore(t)

	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	// Inserted newest first to prove the query orders by timestamp.
	fixtures := []events.Event{
		{ID: "third", Type: events.AccessGranted, Timestamp: base.Add(2 * time.Second)},
		{ID: "first", Type: events.KnockdStarted, Timestamp: base},
		{ID: "second", Type: events.SequenceMatched, Timestamp: base.Add(time.Second)},
	}
	for _, event := range fixtures {
		if err := store.SaveEvent(event); err != nil {
			t.Fatalf("save %s: %v", event.ID, err)
		}
	}

	ids := func(t *testing.T, limit int) []string {
		t.Helper()
		pending, err := store.UndeliveredEvents(limit)
		if err != nil {
			t.Fatalf("undelivered events: %v", err)
		}
		out := make([]string, 0, len(pending))
		for _, event := range pending {
			out = append(out, event.ID)
		}
		return out
	}

	if got := ids(t, 10); len(got) != 3 || got[0] != "first" || got[1] != "second" || got[2] != "third" {
		t.Fatalf("pending order = %v, want [first second third]", got)
	}
	if got := ids(t, 2); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("pending with limit 2 = %v, want [first second]", got)
	}

	if err := store.MarkDelivered("first", base.Add(time.Minute)); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	if got := ids(t, 10); len(got) != 2 || got[0] != "second" || got[1] != "third" {
		t.Errorf("pending after delivery = %v, want [second third]", got)
	}

	// A retry for an id that is gone must not fail the delivery loop.
	if err := store.MarkDelivered("missing", base.Add(time.Minute)); err != nil {
		t.Errorf("mark delivered for unknown id: %v", err)
	}
	if got := ids(t, 10); len(got) != 2 {
		t.Errorf("pending after marking an unknown id = %v, want 2 rows", got)
	}
}

// Summary is what the status command prints. An expired grant must not be
// counted as active, otherwise the operator is told a closed port is open.
func TestSummaryCountsAndLastEvent(t *testing.T) {
	store, _ := newStore(t)

	empty, err := store.Summary(time.Now().UTC())
	if err != nil {
		t.Fatalf("summary of an empty store: %v", err)
	}
	if empty != (Summary{}) {
		t.Errorf("summary of an empty store = %+v, want all zero", empty)
	}

	// Whole seconds: the active-rule filter compares timestamp text, so
	// mixed fractional precision would compare wrongly.
	now := time.Now().UTC().Truncate(time.Second)
	stored := []events.Event{
		{ID: "boot", Type: events.KnockdStarted, Timestamp: now.Add(-10 * time.Minute)},
		{ID: "granted", Type: events.AccessGranted, Timestamp: now.Add(-time.Minute),
			SourceIP: "203.0.113.5", Country: "RU", Rule: "openSSH", TTL: 15 * time.Minute},
	}
	for _, event := range stored {
		if err := store.SaveEvent(event); err != nil {
			t.Fatalf("save %s: %v", event.ID, err)
		}
	}
	if err := store.MarkDelivered("boot", now); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	if err := store.SaveAttempt(now.Add(-2*time.Minute), "192.0.2.134", "openSSH",
		"failed", "192.0.2.134: openSSH: sequence timeout (stage 1)"); err != nil {
		t.Fatalf("save attempt: %v", err)
	}

	past, future := now.Add(-time.Minute), now.Add(15*time.Minute)
	rules := []AccessRule{
		{SourceIP: "203.0.113.5", Rule: "openSSH", Port: 22, Protocol: "tcp",
			State: "open", Source: "nft", UpdatedAt: now, ExpiresAt: &future},
		// Lifetime already gone: still recorded, but not active.
		{SourceIP: "192.0.2.134", Rule: "openSSH", Port: 22, Protocol: "tcp",
			State: "open", Source: "nft", UpdatedAt: now, ExpiresAt: &past},
		// No known lifetime: counts until something revokes it.
		{SourceIP: "198.51.100.167", Rule: "openSSH", Port: 22, Protocol: "tcp",
			State: "open", Source: "nft", UpdatedAt: now},
		// Explicitly closed rules are history, not access.
		{SourceIP: "198.51.100.167", Rule: "closeSSH", Port: 22, Protocol: "tcp",
			State: "closed", Source: "nft", UpdatedAt: now},
	}
	for _, rule := range rules {
		if err := store.SaveRule(rule); err != nil {
			t.Fatalf("save rule %s/%s: %v", rule.SourceIP, rule.Rule, err)
		}
	}

	summary, err := store.Summary(now)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	want := Summary{
		Events: 2, Attempts: 1, Undelivered: 1, ActiveRules: 2,
		LastEventType: string(events.AccessGranted), LastEventAt: now.Add(-time.Minute),
	}
	if !summary.LastEventAt.Equal(want.LastEventAt) {
		t.Errorf("last event at %v, want %v", summary.LastEventAt, want.LastEventAt)
	}
	summary.LastEventAt = want.LastEventAt
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
}

// SQLite stores timestamps as text and does not enforce column types, so a row
// written by anything but this package can be unreadable. Reads must fail
// loudly rather than report a zero time or an empty address, which would put a
// 1970 knock from nowhere into the status output.
func TestReadsRejectCorruptRows(t *testing.T) {
	tests := []struct {
		name    string
		corrupt string
		read    func(*Store) error
	}{
		{
			name:    "event timestamp",
			corrupt: `UPDATE events SET timestamp = 'not-a-time'`,
			read: func(s *Store) error {
				_, err := s.UndeliveredEvents(10)
				return err
			},
		},
		{
			name:    "event stage",
			corrupt: `UPDATE events SET stage = 'three'`,
			read: func(s *Store) error {
				_, err := s.UndeliveredEvents(10)
				return err
			},
		},
		{
			name:    "attempt timestamp",
			corrupt: `UPDATE attempts SET timestamp = 'not-a-time'`,
			read: func(s *Store) error {
				_, err := s.ListAttempts(10)
				return err
			},
		},
		{
			name:    "rule updated_at",
			corrupt: `UPDATE access_rules SET updated_at = 'not-a-time'`,
			read: func(s *Store) error {
				_, err := s.ListRules()
				return err
			},
		},
		{
			name:    "rule expires_at",
			corrupt: `UPDATE access_rules SET expires_at = 'not-a-time'`,
			read: func(s *Store) error {
				_, err := s.ListRules()
				return err
			},
		},
		{
			// SQLite columns are not typed, so a text port really can end up
			// in the table; reading it as 0 would report the wrong service.
			name:    "rule port",
			corrupt: `UPDATE access_rules SET port = 'twenty-two'`,
			read: func(s *Store) error {
				_, err := s.ListRules()
				return err
			},
		},
		{
			// A missing address must not be read as the empty string: the
			// status output would then show a knock from nowhere.
			name: "attempt without a source address",
			corrupt: `DROP TABLE attempts;
CREATE TABLE attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    rule TEXT,
    status TEXT,
    message TEXT
);
INSERT INTO attempts(timestamp, source_ip, status) VALUES ('2026-01-01T00:00:00Z', NULL, 'knock')`,
			read: func(s *Store) error {
				_, err := s.ListAttempts(10)
				return err
			},
		},
		{
			name:    "last event timestamp",
			corrupt: `UPDATE events SET timestamp = 'not-a-time'`,
			read: func(s *Store) error {
				_, err := s.Summary(time.Now().UTC())
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newStore(t)
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(15 * time.Minute)
			if err := store.SaveEvent(events.Event{
				ID: "granted", Type: events.AccessGranted, Timestamp: now,
				SourceIP: "203.0.113.5", Rule: "openSSH", Stage: 3,
			}); err != nil {
				t.Fatalf("save event: %v", err)
			}
			if err := store.SaveAttempt(now, "203.0.113.5", "openSSH", "knock",
				"203.0.113.5: openSSH: Stage 3"); err != nil {
				t.Fatalf("save attempt: %v", err)
			}
			if err := store.SaveRule(AccessRule{
				SourceIP: "203.0.113.5", Rule: "openSSH", Port: 22, Protocol: "tcp",
				State: "open", Source: "nft", UpdatedAt: now, ExpiresAt: &expires,
			}); err != nil {
				t.Fatalf("save rule: %v", err)
			}
			if _, err := store.db.Exec(tt.corrupt); err != nil {
				t.Fatalf("corrupt row: %v", err)
			}
			if err := tt.read(store); err == nil {
				t.Error("read accepted a corrupt row, want an error")
			}
		})
	}
}

// A database whose tables were removed under the agent must produce errors,
// not an empty status report that looks like a quiet host.
func TestReadsReportMissingTables(t *testing.T) {
	tests := []struct {
		name string
		drop string
		read func(*Store) error
	}{
		{"events gone", `DROP TABLE events`, func(s *Store) error {
			_, err := s.UndeliveredEvents(10)
			return err
		}},
		{"attempts gone", `DROP TABLE attempts`, func(s *Store) error {
			_, err := s.ListAttempts(10)
			return err
		}},
		{"access_rules gone", `DROP TABLE access_rules`, func(s *Store) error {
			_, err := s.ListRules()
			return err
		}},
		{"summary without events", `DROP TABLE events`, func(s *Store) error {
			_, err := s.Summary(time.Now().UTC())
			return err
		}},
		{"summary without attempts", `DROP TABLE attempts`, func(s *Store) error {
			_, err := s.Summary(time.Now().UTC())
			return err
		}},
		{"summary without rules", `DROP TABLE access_rules`, func(s *Store) error {
			_, err := s.Summary(time.Now().UTC())
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newStore(t)
			if _, err := store.db.Exec(tt.drop); err != nil {
				t.Fatalf("drop table: %v", err)
			}
			if err := tt.read(store); err == nil {
				t.Error("read succeeded without its table, want an error")
			}
		})
	}
}
