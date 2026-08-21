package agent

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/geoip"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

// Real knockd 0.8 output, captured from a live Debian 12 host: one timed-out
// probe from a stranger, then a full three stage knock that opened the port.
var journalLines = []string{
	"starting up, listening on enp2s0",
	"192.0.2.134: openSSH: sequence timeout (stage 1)",
	"203.0.113.5: openSSH: Stage 1",
	"203.0.113.5: openSSH: Stage 2",
	"203.0.113.5: openSSH: Stage 3",
	"203.0.113.5: openSSH: OPEN SESAME",
	"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
	"shutting down",
}

// syncBuffer collects the agent's log. Two tests read it while Run is still
// going, so writes from the agent and reads from the test must be serialised.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lines reports the log as one entry per Printf, dropping the trailing empty
// element so an empty log is an empty slice rather than one blank line.
func (b *syncBuffer) lines() []string {
	text := b.String()
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// fakeJournalctl installs a shell script named journalctl at the front of PATH
// so the reader streams these lines instead of a real journal. keepRunning
// makes it linger like `journalctl -f`, which never exits on its own.
func fakeJournalctl(t *testing.T, lines []string, keepRunning bool) {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/sh\ncat <<'KNOCK_EOF'\n" + strings.Join(lines, "\n") + "\nKNOCK_EOF\n"
	if keepRunning {
		// exec so the sleep replaces the shell and holds the same stdout.
		body += "exec sleep 60\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(body), 0o755); err != nil {
		t.Fatalf("write fake journalctl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// runAgent runs Run off the test goroutine so an agent that never returns fails
// the test instead of wedging the package until the go test deadline.
func runAgent(t *testing.T, ctx context.Context, agent *Agent) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// waitForLog blocks until the agent has logged at least count lines, which is
// the only signal that it has started consuming the journal.
func waitForLog(t *testing.T, buf *syncBuffer, count int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if len(buf.lines()) >= count {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("agent logged %d lines, want at least %d", len(buf.lines()), count)
}

// The whole point of the daemon: a knock seen in the journal becomes a stored
// event, a recorded attempt and an open rule, with one log line per event so an
// operator tailing the agent sees exactly what knockd did.
func TestAgentRunRecordsRealKnockdSequence(t *testing.T) {
	fakeJournalctl(t, journalLines, false)

	store := newStore(t)
	engine := state.NewEngine(store)
	buf := &syncBuffer{}
	agent := New(knockd.NewLogReader(""), engine, nil, log.New(buf, "", 0))

	if err := runAgent(t, context.Background(), agent); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// A nil geoip database is what the daemon holds when none was configured,
	// so every country stays empty rather than crashing the run.
	want := []string{
		"event=knockd.started ip= country= rule= ttl=0s",
		"event=knock.sequence_failed ip=192.0.2.134 country= rule=openSSH ttl=0s",
		"event=knock.sequence_started ip=203.0.113.5 country= rule=openSSH ttl=0s",
		"event=knock.received ip=203.0.113.5 country= rule=openSSH ttl=0s",
		"event=knock.received ip=203.0.113.5 country= rule=openSSH ttl=0s",
		"event=knock.sequence_matched ip=203.0.113.5 country= rule=openSSH ttl=0s",
		"event=access.granted ip=203.0.113.5 country= rule=openSSH ttl=15m0s",
		"event=knockd.stopped ip= country= rule= ttl=0s",
	}
	got := buf.lines()
	if len(got) != len(want) {
		t.Fatalf("logged %d lines, want %d:\n%s", len(got), len(want), buf.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("log line %d = %q, want %q", i, got[i], want[i])
		}
	}

	stored, err := store.UndeliveredEvents(len(journalLines) + 1)
	if err != nil {
		t.Fatalf("list stored events: %v", err)
	}
	if len(stored) != len(journalLines) {
		t.Fatalf("stored %d events, want %d", len(stored), len(journalLines))
	}
	for i, event := range stored {
		if event.Message != journalLines[i] {
			t.Errorf("stored event %d message = %q, want %q", i, event.Message, journalLines[i])
		}
		if event.ID == "" {
			t.Errorf("stored event %d has no id, so it can never be marked delivered", i)
		}
		if event.Country != "" {
			t.Errorf("stored event %d country = %q, want empty with no geoip database", i, event.Country)
		}
	}

	rules := agent.Rules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want the single grant: %+v", len(rules), rules)
	}
	if rules[0].SourceIP != "203.0.113.5" {
		t.Errorf("rule source ip = %q, want 203.0.113.5", rules[0].SourceIP)
	}
	if rules[0].State != "open" {
		t.Errorf("rule state = %q, want open", rules[0].State)
	}
	// Rules is a pass-through to the engine: the control commands read it and
	// must never see a stale copy the agent kept for itself.
	if engineRules := engine.Rules(); !reflect.DeepEqual(rules, engineRules) {
		t.Errorf("Rules() = %+v, engine holds %+v", rules, engineRules)
	}
}

// knockd logs plenty the agent has no opinion about, and reload notices arrive
// on the same stream. Those must vanish quietly: an unrecognised line stored as
// an event would be an alert about nothing.
func TestAgentRunSkipsUnrecognisedLines(t *testing.T) {
	junk := []string{
		"reloading configuration",
		"openSSH: a message this parser has never seen",
		"203.0.113.5: openSSH: unknown chatter",
	}
	fakeJournalctl(t, junk, false)

	store := newStore(t)
	engine := state.NewEngine(store)
	buf := &syncBuffer{}
	agent := New(knockd.NewLogReader(""), engine, nil, log.New(buf, "", 0))

	if err := runAgent(t, context.Background(), agent); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if logged := buf.lines(); len(logged) != 0 {
		t.Errorf("logged %q, want nothing for unparsable lines", logged)
	}
	stored, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("list stored events: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("stored %+v, want no events", stored)
	}
	if rules := agent.Rules(); len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
}

// Ranges covering the two addresses in the fixtures, in the numeric IPv4 form
// ip-location-db publishes: 203.0.113.5 is 3405803781 and 192.0.2.134 is
// 3221226118. 198.51.100.167 is deliberately absent.
const countryFixture = `3405803776,3405804031,RU
3221225984,3221226239,BG
`

// With a database loaded, every knock carries the country that Telegram alerts
// are written around, and an address outside the table stays blank instead of
// borrowing its neighbour's code.
func TestAgentRunResolvesCountries(t *testing.T) {
	fakeJournalctl(t, []string{
		"192.0.2.134: openSSH: sequence timeout (stage 1)",
		"198.51.100.167: openSSH: Stage 2",
		"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
	}, false)

	path := filepath.Join(t.TempDir(), "country.csv")
	if err := os.WriteFile(path, []byte(countryFixture), 0o600); err != nil {
		t.Fatalf("write geoip fixture: %v", err)
	}
	geo, err := geoip.Load(path)
	if err != nil {
		t.Fatalf("load geoip: %v", err)
	}

	store := newStore(t)
	buf := &syncBuffer{}
	agent := New(knockd.NewLogReader(""), state.NewEngine(store), geo, log.New(buf, "", 0))

	if err := runAgent(t, context.Background(), agent); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stored, err := store.UndeliveredEvents(10)
	if err != nil {
		t.Fatalf("list stored events: %v", err)
	}
	countries := make(map[string]string, len(stored))
	for _, event := range stored {
		countries[event.SourceIP] = event.Country
	}
	for ip, want := range map[string]string{
		"192.0.2.134":   "BG",
		"203.0.113.5":    "RU",
		"198.51.100.167": "",
	} {
		if got, ok := countries[ip]; !ok {
			t.Errorf("no stored event for %s", ip)
		} else if got != want {
			t.Errorf("country for %s = %q, want %q", ip, got, want)
		}
	}
	if !strings.Contains(buf.String(), "ip=203.0.113.5 country=RU") {
		t.Errorf("log does not report the country:\n%s", buf.String())
	}
}

// A failing store must stop the agent loudly. Carrying on would leave knocks
// only in the log, where nothing downstream ever looks for them.
func TestAgentRunSurfacesApplyFailure(t *testing.T) {
	// The journal holds eight lines but the store rejects the first, so a Run
	// that returns success, or logs anything at all, has carried on past a
	// knock it failed to record.
	fakeJournalctl(t, journalLines, false)

	store := newStore(t)
	engine := state.NewEngine(store)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	buf := &syncBuffer{}
	agent := New(knockd.NewLogReader(""), engine, nil, log.New(buf, "", 0))

	err := runAgent(t, context.Background(), agent)
	if err == nil {
		t.Fatal("Run reported success although no event could be stored")
	}
	if !strings.Contains(err.Error(), "apply event") {
		t.Errorf("error = %v, want it to say which stage failed", err)
	}
	if !strings.Contains(err.Error(), "knockd.started") {
		t.Errorf("error = %v, want it to name the event type that failed", err)
	}
	if logged := buf.lines(); len(logged) != 0 {
		t.Errorf("logged %q, want nothing: the event was never recorded", logged)
	}
}

// SIGINT cancels the context while journalctl is mid-stream, which kills the
// subprocess and makes it exit non-zero. That is an orderly shutdown, so Run
// has to report success: anything else makes systemd log a failed unit on every
// restart.
func TestAgentRunReturnsNilWhenContextCancelled(t *testing.T) {
	fakeJournalctl(t, journalLines[:1], true)

	store := newStore(t)
	buf := &syncBuffer{}
	agent := New(knockd.NewLogReader(""), state.NewEngine(store), nil, log.New(buf, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	waitForLog(t, buf, 1)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancellation = %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// The daemon passes no logger when it has none to give, and the agent must not
// dereference nil the first time knockd says anything.
func TestNewFallsBackToDefaultLogger(t *testing.T) {
	agent := New(knockd.NewLogReader(""), state.NewEngine(newStore(t)), nil, nil)
	if agent.log != log.Default() {
		t.Error("New(nil logger) did not fall back to the standard logger")
	}
}
