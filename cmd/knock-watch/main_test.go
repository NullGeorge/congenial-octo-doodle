package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestPingEndpointRecordsACheckIn(t *testing.T) {
	start := time.Now().UTC().Add(-time.Minute)
	watch := newMonitor(t, 15*time.Minute, start)
	mux := newMux(context.Background(), "s3cret", watch)

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ping/s3cret", nil))

	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", response.Code)
	}
	if body := response.Body.String(); body != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
	if !watch.lastSeen.After(start) {
		t.Fatalf("last seen = %s, want it moved past %s", watch.lastSeen, start)
	}

	// The check-in is persisted as it arrives, otherwise a watchdog restart
	// would resurrect an outage that has already ended.
	restarted := &monitor{statePath: watch.statePath, log: log.New(io.Discard, "", 0)}
	if err := restarted.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !restarted.lastSeen.Equal(watch.lastSeen) {
		t.Errorf("persisted last seen = %s, want %s", restarted.lastSeen, watch.lastSeen)
	}
}

// One secret URL is the entire inbound surface. Anything else answering 200
// would let a stranger keep the alert suppressed, which is the one failure this
// program exists to prevent.
func TestOnlyTheSecretPathIsServed(t *testing.T) {
	start := time.Now().UTC().Add(-time.Minute)
	watch := newMonitor(t, 15*time.Minute, start)
	mux := newMux(context.Background(), "s3cret", watch)

	for _, path := range []string{
		"/",
		"/ping",
		"/ping/",
		"/ping/wrong",
		"/ping/s3cre",
		"/ping/s3cret2",
		"/ping/s3cret/extra",
		"/PING/s3cret",
		"/healthz",
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, response.Code)
		}
	}

	if !watch.lastSeen.Equal(start) {
		t.Error("a request that did not carry the token still recorded a check-in")
	}
}

func TestPingAfterAnAlertSendsTheRecoveryMessage(t *testing.T) {
	watch := newMonitor(t, 15*time.Minute, time.Now().UTC().Add(-20*time.Minute))
	watch.alerted = true

	var sent []string
	watch.send = func(_ context.Context, text string) error {
		sent = append(sent, text)
		return nil
	}
	mux := newMux(context.Background(), "s3cret", watch)
	ping := func() {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ping/s3cret", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
	}

	ping()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want the one recovery notice: %q", len(sent), sent)
	}
	for _, want := range []string{"atsos is back", "Heartbeat resumed after 20m0s"} {
		if !strings.Contains(sent[0], want) {
			t.Errorf("recovery message = %q, want it to mention %q", sent[0], want)
		}
	}

	// The next ping is a normal heartbeat, not a second recovery.
	ping()
	if len(sent) != 1 {
		t.Errorf("sent %d messages, want 1: a healthy host must stay silent", len(sent))
	}
}

// A Telegram outage must not cost the check-in: the ping is recorded and the
// request still succeeds, because the monitored host cannot fix the Bot API.
func TestAFailedRecoverySendStillRecordsThePing(t *testing.T) {
	start := time.Now().UTC().Add(-20 * time.Minute)
	watch := newMonitor(t, 15*time.Minute, start)
	watch.alerted = true
	watch.send = func(context.Context, string) error {
		return fmt.Errorf("sendMessage: telegram error 429: Too Many Requests")
	}

	response := httptest.NewRecorder()
	newMux(context.Background(), "s3cret", watch).
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ping/s3cret", nil))

	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 even though the notification failed", response.Code)
	}
	if !watch.lastSeen.After(start) {
		t.Error("the check-in was dropped because the notification failed")
	}
	if watch.alerted {
		t.Error("the alert is still outstanding, so recovery would be announced twice")
	}
}

// Refusing to start is the correct behaviour for every one of these: a
// watchdog that runs without a secret, or without a way to reach you, is worse
// than no watchdog because it looks like one.
func TestRunRefusesToStartWithoutASecretOrCredentials(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		botEnv  string
		chatEnv string
		want    string
	}{
		{name: "no token flag", botEnv: "bot-token", chatEnv: "42", want: "-token is required"},
		{name: "empty token", args: []string{"-token", ""}, botEnv: "bot-token", chatEnv: "42", want: "-token is required"},
		{name: "bot token unset", args: []string{"-token", "s3cret"}, chatEnv: "42", want: "BOT_TOKEN is not set"},
		{name: "bot token is only whitespace", args: []string{"-token", "s3cret"}, botEnv: "  \t ", chatEnv: "42", want: "BOT_TOKEN is not set"},
		{name: "chat id unset", args: []string{"-token", "s3cret"}, botEnv: "bot-token", want: "is not a chat id"},
		{name: "chat id is not a number", args: []string{"-token", "s3cret"}, botEnv: "bot-token", chatEnv: "@atsos", want: "is not a chat id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BOT_TOKEN", tt.botEnv)
			t.Setenv("CHAT_ID", tt.chatEnv)

			err := run(tt.args)
			if err == nil {
				t.Fatalf("run(%q) started", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run(%q) error = %q, want it to mention %q", tt.args, err, tt.want)
			}
		})
	}
}

// An unrecognised flag has to stop the program. Ignoring it would silently run
// with a default the operator thought they had changed, and -grace is exactly
// the sort of thing you only notice was ignored when the alert never comes.
func TestRunRejectsAnUnknownFlag(t *testing.T) {
	quietStderr(t)
	t.Setenv("BOT_TOKEN", "bot-token")
	t.Setenv("CHAT_ID", "42")

	if err := run([]string{"-grace-period", "1h"}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
}

// A state file that cannot be understood must stop startup rather than be
// discarded, because discarding it re-arms the timer and can re-announce an
// outage that was already reported.
func TestRunRefusesToStartWithACorruptStateFile(t *testing.T) {
	t.Setenv("BOT_TOKEN", "bot-token")
	t.Setenv("CHAT_ID", "42")

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	err := run([]string{"-token", "s3cret", "-state", statePath})
	if err == nil {
		t.Fatal("run started on a corrupt state file")
	}
	if !strings.Contains(err.Error(), "parse state") {
		t.Errorf("error = %q, want it to name the unparseable state", err)
	}
}

// Failing to bind is fatal: a watchdog that is not listening would treat every
// ping as silence and alert forever.
func TestRunFailsWhenTheListenAddressIsTaken(t *testing.T) {
	quietLogs(t)
	t.Setenv("BOT_TOKEN", "bot-token")
	t.Setenv("CHAT_ID", "42")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer occupied.Close()

	err = run([]string{
		"-token", "s3cret",
		"-listen", occupied.Addr().String(),
		"-state", filepath.Join(t.TempDir(), "state.json"),
	})
	if err == nil {
		t.Fatal("run returned success although the port was taken")
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("error = %q, want it to report the bind failure", err)
	}
}

// The end to end contract, on a real listener: silence past the grace period
// produces exactly one message to the Bot API, and Ctrl+C stops the program
// without an error.
func TestRunAlertsOnSilenceAndShutsDownOnSignal(t *testing.T) {
	quietLogs(t)
	t.Setenv("BOT_TOKEN", "bot-token")
	// The chat comes from the environment here, which is how the unit file
	// supplies it; the flag is only an override.
	t.Setenv("CHAT_ID", "4242")

	type call struct{ path, chat, text string }
	calls := make(chan call, 8)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse bot api form: %v", err)
		}
		calls <- call{path: r.URL.Path, chat: r.FormValue("chat_id"), text: r.FormValue("text")}
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer api.Close()

	addr := freeAddress(t)
	done := make(chan error, 1)
	go func() {
		done <- run([]string{
			"-listen", addr,
			"-token", "s3cret",
			"-name", "atsos",
			"-grace", "25ms",
			"-check-interval", "10ms",
			"-state", filepath.Join(t.TempDir(), "state.json"),
			"-telegram-api", api.URL,
		})
	}()
	waitForListener(t, addr)

	var alert call
	select {
	case alert = <-calls:
	case err := <-done:
		t.Fatalf("run returned before alerting: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("silence past the grace period never produced an alert")
	}
	if want := "/botbot-token/sendMessage"; alert.path != want {
		t.Errorf("bot api path = %q, want %q", alert.path, want)
	}
	if want := "4242"; alert.chat != want {
		t.Errorf("chat id = %q, want %q from CHAT_ID", alert.chat, want)
	}
	if !strings.Contains(alert.text, "atsos is silent") {
		t.Errorf("alert = %q, want it to name the silent host", alert.text)
	}

	// Twenty more ticks pass here. A repeated alert would arrive in that window
	// and is the failure mode that trains you to ignore the alerts.
	select {
	case repeat := <-calls:
		t.Errorf("one outage produced a second message: %q", repeat.text)
	case <-time.After(200 * time.Millisecond):
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("signal self: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v, want a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGINT did not stop knock-watch")
	}
}

// Persisting has to work on a first run, when the state directory does not
// exist yet, and both values have to survive the trip.
func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lib", "knock-watch", "state.json")
	seen := time.Now().UTC().Add(-7 * time.Minute)

	for _, alerted := range []bool{true, false} {
		saved := &monitor{
			statePath: path,
			lastSeen:  seen,
			alerted:   alerted,
			log:       log.New(io.Discard, "", 0),
		}
		saved.save()

		loaded := &monitor{statePath: path, log: log.New(io.Discard, "", 0)}
		if err := loaded.load(); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !loaded.lastSeen.Equal(seen) {
			t.Errorf("last seen = %s, want %s", loaded.lastSeen, seen)
		}
		if loaded.alerted != alerted {
			t.Errorf("alerted = %v, want %v", loaded.alerted, alerted)
		}
	}
}

// Starting fresh on an unreadable state file would silently re-arm the timer
// and could re-announce an outage that was already reported, so a damaged file
// has to stop the program instead.
func TestLoadRejectsACorruptStateFile(t *testing.T) {
	for _, content := range []string{
		"",
		"{",
		"not json at all",
		`{"last_seen": "yesterday", "alerted": true}`,
		`{"last_seen": 12345}`,
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write state: %v", err)
		}

		watch := &monitor{statePath: path, log: log.New(io.Discard, "", 0)}
		err := watch.load()
		if err == nil {
			t.Errorf("load accepted %q as state", content)
			continue
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error = %q, want it to name %q", err, path)
		}
		if !watch.lastSeen.IsZero() {
			t.Errorf("load(%q) started the clock anyway, at %s", content, watch.lastSeen)
		}
	}
}

// A path that cannot be read at all is a misconfiguration, not a first run.
func TestLoadRejectsAnUnreadableStatePath(t *testing.T) {
	watch := &monitor{statePath: t.TempDir(), log: log.New(io.Discard, "", 0)}
	err := watch.load()
	if err == nil {
		t.Fatal("load treated a directory as state")
	}
	if !strings.Contains(err.Error(), "read state") {
		t.Errorf("error = %q, want it to mention reading the state", err)
	}
}

// save cannot fail the program, but a persistence failure that leaves no trace
// would make a lost alert impossible to explain afterwards.
func TestSaveReportsAFailureToWrite(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	tests := []struct {
		name      string
		statePath string
		want      string
	}{
		// A directory can be created but never written to as a file.
		{name: "state path is a directory", statePath: t.TempDir(), want: "write state"},
		// A regular file in the middle of the path stops the mkdir instead.
		{name: "parent is a file", statePath: filepath.Join(blocked, "state.json"), want: "create state dir"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logged strings.Builder
			watch := &monitor{
				statePath: tt.statePath,
				lastSeen:  time.Now().UTC(),
				log:       log.New(&logged, "", 0),
			}
			watch.save()

			if !strings.Contains(logged.String(), tt.want) {
				t.Errorf("log = %q, want it to mention %q", logged.String(), tt.want)
			}
		})
	}
}

// A Telegram failure must be reported and must not take the watchdog down with
// it: the alert is lost, but the program has to stay up to report the recovery.
func TestLoopReportsAFailedAlertSend(t *testing.T) {
	watch := newMonitor(t, time.Millisecond, time.Now().UTC().Add(-time.Minute))
	attempts := make(chan string, 4)
	watch.send = func(_ context.Context, text string) error {
		attempts <- text
		return fmt.Errorf("sendMessage: telegram error 502: Bad Gateway")
	}
	var logged strings.Builder
	watch.log = log.New(&logged, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		watch.loop(ctx, 5*time.Millisecond)
		close(stopped)
	}()

	select {
	case text := <-attempts:
		if !strings.Contains(text, "atsos is silent") {
			t.Errorf("alert = %q, want it to name the silent host", text)
		}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the loop never alerted about an overdue host")
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop ignored a cancelled context")
	}

	if !strings.Contains(logged.String(), "send alert:") {
		t.Errorf("log = %q, want it to report the failed send", logged.String())
	}
}

// freeAddress reserves a loopback port and hands it back, so the test does not
// depend on a fixed port being idle.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("knock-watch never listened on %s", addr)
}

// quietLogs keeps the startup banner out of the test output.
func quietLogs(t *testing.T) {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
}

// quietStderr hides the usage text a flag parse failure prints.
func quietStderr(t *testing.T) {
	t.Helper()
	real := os.Stderr
	discard, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Stderr = discard
	t.Cleanup(func() {
		os.Stderr = real
		discard.Close()
	})
}
