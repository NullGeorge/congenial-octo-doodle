package main

import (
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"
)

func newMonitor(t *testing.T, grace time.Duration, start time.Time) *monitor {
	t.Helper()
	return &monitor{
		name:      "atsos",
		grace:     grace,
		statePath: filepath.Join(t.TempDir(), "state.json"),
		lastSeen:  start,
		log:       log.New(io.Discard, "", 0),
	}
}

// The whole value of a dead-man switch is that it fires once and stays quiet
// until something changes. Repeating every tick trains you to ignore it.
func TestSilenceAlertsOnceThenStaysQuiet(t *testing.T) {
	start := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	watch := newMonitor(t, 15*time.Minute, start)

	if silent, _ := watch.check(start.Add(14 * time.Minute)); silent {
		t.Fatal("alerted inside the grace period")
	}
	if silent, _ := watch.check(start.Add(15 * time.Minute)); silent {
		t.Fatal("alerted exactly at the grace boundary, which is not yet overdue")
	}

	silent, silentFor := watch.check(start.Add(16 * time.Minute))
	if !silent {
		t.Fatal("silence past the grace period did not alert")
	}
	if silentFor != 16*time.Minute {
		t.Errorf("reported %s of silence, want 16m", silentFor)
	}

	for _, after := range []time.Duration{17, 30, 120} {
		if repeated, _ := watch.check(start.Add(after * time.Minute)); repeated {
			t.Fatalf("alerted again after %dm; one outage must produce one alert", after)
		}
	}
}

func TestPingClearsTheAlertAndReportsRecovery(t *testing.T) {
	start := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	watch := newMonitor(t, 15*time.Minute, start)

	if silent, _ := watch.check(start.Add(20 * time.Minute)); !silent {
		t.Fatal("expected an alert")
	}

	recovered, silentFor := watch.ping(start.Add(25 * time.Minute))
	if !recovered {
		t.Fatal("a ping after an alert must report recovery")
	}
	if silentFor != 25*time.Minute {
		t.Errorf("reported %s of silence, want 25m", silentFor)
	}

	// Back to normal: no alert until a fresh outage, then one again.
	if silent, _ := watch.check(start.Add(30 * time.Minute)); silent {
		t.Fatal("alerted right after recovery")
	}
	if silent, _ := watch.check(start.Add(41 * time.Minute)); !silent {
		t.Fatal("a second outage must alert again")
	}
}

// A healthy host pings well inside the grace period and must never alert.
func TestRegularPingsNeverAlert(t *testing.T) {
	start := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	watch := newMonitor(t, 15*time.Minute, start)

	for minute := 5; minute <= 120; minute += 5 {
		now := start.Add(time.Duration(minute) * time.Minute)
		if recovered, _ := watch.ping(now); recovered {
			t.Fatalf("ping at %dm reported a recovery that never happened", minute)
		}
		if silent, _ := watch.check(now.Add(time.Second)); silent {
			t.Fatalf("alerted at %dm while pings were arriving", minute)
		}
	}
}

// Restarting the watchdog must not lose an outstanding alert, otherwise the
// restart itself would re-notify about an outage already reported.
func TestStateSurvivesRestart(t *testing.T) {
	start := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	watch := newMonitor(t, 15*time.Minute, start)

	if silent, _ := watch.check(start.Add(20 * time.Minute)); !silent {
		t.Fatal("expected an alert")
	}
	watch.save()

	restarted := &monitor{
		name: "atsos", grace: 15 * time.Minute,
		statePath: watch.statePath, log: log.New(io.Discard, "", 0),
	}
	if err := restarted.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !restarted.alerted {
		t.Error("the outstanding alert was forgotten across a restart")
	}
	if !restarted.lastSeen.Equal(start) {
		t.Errorf("last seen = %s, want %s", restarted.lastSeen, start)
	}
	if repeated, _ := restarted.check(start.Add(25 * time.Minute)); repeated {
		t.Error("a restart re-alerted about an outage already reported")
	}
}

// With no state file the clock starts now, so a host that is already down is
// reported after one grace period rather than never.
func TestFirstStartArmsTheTimer(t *testing.T) {
	watch := &monitor{
		grace:     time.Minute,
		statePath: filepath.Join(t.TempDir(), "absent.json"),
		log:       log.New(io.Discard, "", 0),
	}
	if err := watch.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if watch.lastSeen.IsZero() {
		t.Fatal("last seen was left at the zero time, which would alert immediately")
	}
	if silent, _ := watch.check(watch.lastSeen.Add(2 * time.Minute)); !silent {
		t.Error("a host that never checked in was not reported")
	}
}
