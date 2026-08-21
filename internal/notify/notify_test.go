package notify

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

type senderFunc func(context.Context, int64, string) error

func (f senderFunc) SendMessage(ctx context.Context, chatID int64, text string) error {
	return f(ctx, chatID, text)
}

// Lines captured from the live atsos host: one failed sequence and one
// complete knock that ended in a grant.
var capture = []string{
	"starting up, listening on enp2s0",
	"192.0.2.134: openSSH: sequence timeout (stage 1)",
	"203.0.113.5: openSSH: Stage 1",
	"203.0.113.5: openSSH: Stage 2",
	"203.0.113.5: openSSH: Stage 3",
	"203.0.113.5: openSSH: OPEN SESAME",
	"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
}

func seed(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	engine := state.NewEngine(store)
	base := time.Date(2026, 8, 18, 18, 58, 26, 0, time.UTC)
	for i, line := range capture {
		event, ok := knockd.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) ignored a real line", line)
		}
		event.ID = strconv.Itoa(i)
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		if event.SourceIP == "203.0.113.5" {
			event.Country = "RU"
		}
		if event.SourceIP == "192.0.2.134" {
			event.Country = "BG"
		}
		if err := engine.Apply(event); err != nil {
			t.Fatalf("apply %q: %v", line, err)
		}
	}
	return store
}

func quiet() *log.Logger { return log.New(io.Discard, "", 0) }

// One knock writes seven rows but must not produce seven messages: stage
// progress is noise, and a chat full of it gets muted, which defeats the
// point of alerting at all.
func TestFlushSendsOnlyNotableEventsAndOnlyOnce(t *testing.T) {
	store := seed(t)

	var sent []string
	notifier := New(store, senderFunc(func(_ context.Context, chat int64, text string) error {
		if chat != 42 {
			t.Errorf("chat id = %d, want 42", chat)
		}
		sent = append(sent, text)
		return nil
	}), 42, quiet())

	if err := notifier.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if len(sent) != 3 {
		t.Fatalf("sent %d messages, want 3:\n%s", len(sent), strings.Join(sent, "\n---\n"))
	}
	if !strings.HasPrefix(sent[0], "knockd started") {
		t.Errorf("first message = %q", sent[0])
	}
	if !strings.HasPrefix(sent[1], "Knock sequence failed") || !strings.Contains(sent[1], "192.0.2.134 (BG)") {
		t.Errorf("second message = %q", sent[1])
	}

	grant := sent[2]
	for _, want := range []string{"Access granted", "203.0.113.5 (RU)", "openSSH", "in 15m0s", "2026-08-18T19:13:32Z"} {
		if !strings.Contains(grant, want) {
			t.Errorf("grant message missing %q:\n%s", want, grant)
		}
	}

	// A second pass must be silent, otherwise every restart replays history.
	if err := notifier.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if len(sent) != 3 {
		t.Errorf("second flush sent %d more messages, want 0", len(sent)-3)
	}
}

// Telegram being unreachable must delay alerts, never drop them.
func TestFailedSendIsRetriedLater(t *testing.T) {
	store := seed(t)

	failing := New(store, senderFunc(func(context.Context, int64, string) error {
		return io.ErrUnexpectedEOF
	}), 42, quiet())
	if err := failing.Flush(context.Background()); err == nil {
		t.Fatal("flush reported success while every send failed")
	}

	var sent []string
	recovered := New(store, senderFunc(func(_ context.Context, _ int64, text string) error {
		sent = append(sent, text)
		return nil
	}), 42, quiet())
	if err := recovered.Flush(context.Background()); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if len(sent) != 3 {
		t.Fatalf("after recovery sent %d messages, want the 3 held back", len(sent))
	}
}

func TestNotableSkipsSequenceProgress(t *testing.T) {
	noisy := []string{
		"203.0.113.5: openSSH: Stage 1",
		"203.0.113.5: openSSH: Stage 3",
		"203.0.113.5: openSSH: OPEN SESAME",
	}
	for _, line := range noisy {
		event, ok := knockd.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) ignored a real line", line)
		}
		if Notable(event.Type) {
			t.Errorf("%q would be forwarded to the chat", line)
		}
	}
}

// signalWriter is a log sink that tells the test when enough lines have been
// written, so a retry loop can be observed without sleeping for a guessed
// duration.
type signalWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	want  int
	once  sync.Once
	fired chan struct{}
}

func newSignalWriter(want int) *signalWriter {
	return &signalWriter{want: want, fired: make(chan struct{})}
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if bytes.Count(w.buf.Bytes(), []byte("\n")) >= w.want {
		w.once.Do(func() { close(w.fired) })
	}
	return n, err
}

func (w *signalWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// await fails the test if the channel stays open, which is how a hung loop
// shows up instead of as a whole-suite timeout.
func await(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Run has to drain the outbox and then stop as soon as the context ends: a
// daemon that lingers after shutdown keeps the database open and delays exit.
func TestRunDeliversBacklogThenReturnsOnCancel(t *testing.T) {
	store := seed(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var sent []string
	notifier := New(store, senderFunc(func(_ context.Context, _ int64, text string) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, text)
		if len(sent) == 3 {
			// The backlog is out; cancelling here proves Run leaves the
			// loop on its own rather than being killed by the test.
			cancel()
		}
		return nil
	}), 42, quiet())

	done := make(chan struct{})
	go func() {
		defer close(done)
		notifier.Run(ctx, 2*time.Millisecond)
	}()
	await(t, done, "Run to return after cancellation")

	if len(sent) != 3 {
		t.Fatalf("Run delivered %d messages, want the 3 notable ones:\n%s", len(sent), strings.Join(sent, "\n---\n"))
	}
	if !strings.HasPrefix(sent[0], "knockd started") {
		t.Errorf("first message = %q", sent[0])
	}
}

// A send failure is an outage, not a crash: Run must report it and keep
// ticking, and the held-back events must go out on a later flush.
func TestRunLogsSendFailureAndKeepsGoing(t *testing.T) {
	store := seed(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logged bytes.Buffer
	var mu sync.Mutex
	attempts := 0
	var sent []string
	notifier := New(store, senderFunc(func(_ context.Context, _ int64, text string) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			return io.ErrUnexpectedEOF
		}
		sent = append(sent, text)
		if len(sent) == 3 {
			cancel()
		}
		return nil
	}), 42, log.New(&logged, "", 0))

	done := make(chan struct{})
	go func() {
		defer close(done)
		notifier.Run(ctx, 2*time.Millisecond)
	}()
	await(t, done, "Run to recover and return")

	if want := "notify: send knockd.started: unexpected EOF"; !strings.Contains(logged.String(), want) {
		t.Errorf("log = %q, want it to contain %q", logged.String(), want)
	}
	if len(sent) != 3 {
		t.Fatalf("after the failure Run delivered %d messages, want 3:\n%s", len(sent), strings.Join(sent, "\n---\n"))
	}
}

// The watchdog only learns the host is alive from repeated pings, so one ping
// is not enough: the loop has to keep going until the context ends.
func TestHeartbeatPingsRepeatedlyUntilCancelled(t *testing.T) {
	var hits int64
	twice := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if atomic.AddInt64(&hits, 1) >= 2 {
			once.Do(func() { close(twice) })
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(ctx, server.URL, 2*time.Millisecond, quiet())
	}()

	await(t, twice, "a second ping")
	cancel()
	await(t, done, "Heartbeat to return after cancellation")

	if got := atomic.LoadInt64(&hits); got < 2 {
		t.Errorf("pings = %d, want at least 2", got)
	}
}

// A watchdog that answers 500 is still reachable; treating that as terminal
// would silence the alive signal for good.
func TestHeartbeatKeepsPingingAfterServerErrors(t *testing.T) {
	var hits int64
	thrice := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&hits, 1) >= 3 {
			once.Do(func() { close(thrice) })
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(ctx, server.URL, time.Millisecond, quiet())
	}()

	await(t, thrice, "a third ping despite 500 responses")
	cancel()
	await(t, done, "Heartbeat to return after cancellation")
}

// A watchdog that is down must not kill the loop either: the host may outlive
// the monitoring service, and the ping has to resume when it comes back.
func TestHeartbeatSurvivesUnreachableEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := server.URL
	server.Close() // nothing listens on that port from here on

	sink := newSignalWriter(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(ctx, dead, time.Millisecond, log.New(sink, "", 0))
	}()

	await(t, sink.fired, "a second failed ping to be reported")
	cancel()
	await(t, done, "Heartbeat to return after cancellation")

	if !strings.Contains(sink.String(), "heartbeat:") {
		t.Errorf("log = %q, want the transport failure reported", sink.String())
	}
}

// No watchdog configured is the default deployment, and it must cost nothing:
// Heartbeat returns instead of blocking on a context that is never cancelled.
func TestHeartbeatWithoutURLReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(context.Background(), "", time.Millisecond, quiet())
	}()
	await(t, done, "Heartbeat with no url to return")
}

// A malformed url is a configuration mistake no retry can fix, so it is
// reported once and the loop gives up rather than spinning on it forever.
func TestHeartbeatReportsMalformedURLAndStops(t *testing.T) {
	var logged bytes.Buffer
	writer, flags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(writer)
		log.SetFlags(flags)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A nil logger must fall back to the standard one, not panic.
		Heartbeat(context.Background(), "://watchdog", time.Millisecond, nil)
	}()
	await(t, done, "Heartbeat to reject the malformed url")

	if !strings.Contains(logged.String(), "heartbeat:") {
		t.Errorf("log = %q, want the bad url reported", logged.String())
	}
}

// New has the same nil-logger contract: Run logs through it, so the fallback
// has to be a usable logger rather than a nil pointer.
func TestNewFallsBackToTheStandardLogger(t *testing.T) {
	if got := New(nil, nil, 0, nil).log; got != log.Default() {
		t.Errorf("logger = %v, want the standard logger", got)
	}
}

// The message is the whole product of this package, so every field that can
// appear is pinned exactly: a stray newline or a missing zone is a regression
// nobody notices until the chat is unreadable.
func TestFormatRendersEveryKindOfEvent(t *testing.T) {
	base := time.Date(2026, 8, 18, 18, 58, 26, 0, time.UTC)

	tests := []struct {
		name  string
		event events.Event
		want  string
	}{
		{
			name: "grant with country, rule and ttl",
			event: events.Event{
				Type:      events.AccessGranted,
				Timestamp: base,
				SourceIP:  "203.0.113.5",
				Country:   "RU",
				Rule:      "openSSH",
				TTL:       15 * time.Minute,
			},
			want: "Access granted\nIP: 203.0.113.5 (RU)\nRule: openSSH\n" +
				"Expires: 2026-08-18T19:13:26Z (in 15m0s)\nTime: 2026-08-18T18:58:26Z",
		},
		{
			// No geoip database loaded: the address still has to show up.
			name: "revoke without country or ttl",
			event: events.Event{
				Type:      events.AccessRevoked,
				Timestamp: base,
				SourceIP:  "198.51.100.167",
				Rule:      "closeSSH",
			},
			want: "Access revoked\nIP: 198.51.100.167\nRule: closeSSH\nTime: 2026-08-18T18:58:26Z",
		},
		{
			// How far a scanner got is the interesting part of a timeout.
			name: "failed sequence carries its stage",
			event: events.Event{
				Type:      events.SequenceFailed,
				Timestamp: base,
				SourceIP:  "192.0.2.134",
				Country:   "BG",
				Rule:      "openSSH",
				Stage:     1,
			},
			want: "Knock sequence failed\nIP: 192.0.2.134 (BG)\nRule: openSSH\nStage: 1\nTime: 2026-08-18T18:58:26Z",
		},
		{
			// knockd logs the failing command from a forked child, so this
			// event has a rule but never an address.
			name: "command failure has no address",
			event: events.Event{
				Type:      events.CommandFailed,
				Timestamp: base,
				Rule:      "openSSH",
			},
			want: "knockd command failed\nRule: openSSH\nTime: 2026-08-18T18:58:26Z",
		},
		{
			name:  "daemon start is bare",
			event: events.Event{Type: events.KnockdStarted, Timestamp: base},
			want:  "knockd started\nTime: 2026-08-18T18:58:26Z",
		},
		{
			name:  "daemon stop is bare",
			event: events.Event{Type: events.KnockdStopped, Timestamp: base},
			want:  "knockd stopped\nTime: 2026-08-18T18:58:26Z",
		},
		{
			// Stage lines are filtered by Notable, but Format must still
			// degrade to the raw type instead of rendering an empty title.
			name: "untitled type falls back to its identifier",
			event: events.Event{
				Type:      events.KnockReceived,
				Timestamp: base,
				SourceIP:  "203.0.113.5",
				Rule:      "openSSH",
				Stage:     2,
			},
			want: "knock.received\nIP: 203.0.113.5\nRule: openSSH\nStage: 2\nTime: 2026-08-18T18:58:26Z",
		},
		{
			name:  "unknown type falls back too",
			event: events.Event{Type: events.Type("knockd.reloaded"), Timestamp: base},
			want:  "knockd.reloaded\nTime: 2026-08-18T18:58:26Z",
		},
		{
			// The host runs on local time; the chat must read in UTC so two
			// hosts in different zones can be compared at a glance.
			name: "local timestamps are normalised to utc",
			event: events.Event{
				Type:      events.AccessGranted,
				Timestamp: time.Date(2026, 8, 18, 21, 58, 26, 0, time.FixedZone("MSK", 3*60*60)),
				SourceIP:  "203.0.113.5",
				TTL:       time.Hour,
			},
			want: "Access granted\nIP: 203.0.113.5\nExpires: 2026-08-18T19:58:26Z (in 1h0m0s)\nTime: 2026-08-18T18:58:26Z",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Format(test.event); got != test.want {
				t.Errorf("Format() =\n%q\nwant\n%q", got, test.want)
			}
		})
	}
}

// The allow list decides what the phone buzzes for. Pin it whole: adding a
// stage type here would restore exactly the noise Notable exists to remove.
func TestNotableAllowsExactlyTheAlertingTypes(t *testing.T) {
	tests := []struct {
		eventType events.Type
		want      bool
	}{
		{events.AccessGranted, true},
		{events.AccessRevoked, true},
		{events.SequenceFailed, true},
		{events.CommandFailed, true},
		{events.KnockdStarted, true},
		{events.KnockdStopped, true},
		{events.KnockReceived, false},
		{events.SequenceStarted, false},
		{events.SequenceMatched, false},
		{events.Type("knockd.reloaded"), false},
	}

	for _, test := range tests {
		if got := Notable(test.eventType); got != test.want {
			t.Errorf("Notable(%q) = %t, want %t", test.eventType, got, test.want)
		}
	}
}

// A broken database must surface as an error, not as a quietly empty outbox:
// swallowing it would look exactly like "nothing to send" forever.
func TestFlushReportsStoreFailure(t *testing.T) {
	store := seed(t)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	notifier := New(store, senderFunc(func(context.Context, int64, string) error {
		t.Error("sent a message while the store was unreadable")
		return nil
	}), 42, quiet())

	if err := notifier.Flush(context.Background()); err == nil {
		t.Fatal("flush reported success against a closed store")
	}
}

// Cancellation landing mid-request is a shutdown, not a watchdog outage, so
// Heartbeat leaves without logging: a noisy exit hides real failures.
func TestHeartbeatReturnsQuietlyWhenCancelledMidRequest(t *testing.T) {
	inRequest := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		once.Do(func() { close(inRequest) })
		<-release
	}))
	defer server.Close()
	defer close(release) // unblock the handler first, or Close would hang

	var logged bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(ctx, server.URL, time.Hour, log.New(&logged, "", 0))
	}()

	await(t, inRequest, "the first ping to reach the watchdog")
	cancel()
	await(t, done, "Heartbeat to return mid-request")

	if logged.Len() != 0 {
		t.Errorf("shutdown logged %q, want silence", logged.String())
	}
}
