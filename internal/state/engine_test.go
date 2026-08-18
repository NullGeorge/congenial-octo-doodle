package state

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

// A knock captured from a live knockd 0.8 host must land in the store as one
// grant, with sequence progress kept as attempts and the stage number retained.
func TestEngineAppliesRealKnockdSequence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	engine := NewEngine(store)
	lines := []string{
		"starting up, listening on enp2s0",
		"192.0.2.134: openSSH: sequence timeout (stage 1)",
		"203.0.113.209: openSSH: Stage 1",
		"203.0.113.209: openSSH: Stage 2",
		"203.0.113.209: openSSH: Stage 3",
		"203.0.113.209: openSSH: OPEN SESAME",
		"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.209 timeout 15m }",
	}

	base := time.Date(2026, 8, 18, 18, 27, 4, 0, time.UTC)
	for i, line := range lines {
		event, ok := knockd.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) ignored a real knockd line", line)
		}
		event.ID = strconv.Itoa(i)
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := engine.Apply(event); err != nil {
			t.Fatalf("apply %q: %v", line, err)
		}
	}

	rules := engine.Rules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1: %+v", len(rules), rules)
	}
	if rules[0].SourceIP != "203.0.113.209" {
		t.Errorf("rule source ip = %q, want 203.0.113.209", rules[0].SourceIP)
	}
	if rules[0].State != "open" {
		t.Errorf("rule state = %q, want open", rules[0].State)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db.Close()

	var stored int
	if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&stored); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if stored != len(lines) {
		t.Errorf("stored events = %d, want %d", stored, len(lines))
	}

	var granted int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE type = ?`, string(events.AccessGranted)).Scan(&granted); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if granted != 1 {
		t.Errorf("stored access.granted = %d, want exactly 1", granted)
	}

	var stage int
	if err := db.QueryRow(`SELECT stage FROM events WHERE message LIKE '%Stage 3'`).Scan(&stage); err != nil {
		t.Fatalf("read stage: %v", err)
	}
	if stage != 3 {
		t.Errorf("persisted stage = %d, want 3", stage)
	}

	// Stage 2 and 3 are knocks, the timed-out sequence is a failed attempt.
	var attempts int
	if err := db.QueryRow(`SELECT count(*) FROM attempts`).Scan(&attempts); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if attempts != 3 {
		t.Errorf("stored attempts = %d, want 3", attempts)
	}
}
