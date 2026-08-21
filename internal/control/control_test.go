package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
	"github.com/NullGeorge/congenial-octo-doodle/internal/telegram"
)

const ownerChat = 111111111

type fakeAPI struct {
	sent    []string
	sendErr error
}

func (f *fakeAPI) GetUpdates(context.Context, int64, time.Duration) ([]telegram.Update, error) {
	return nil, errors.New("not used")
}

func (f *fakeAPI) SendMessage(_ context.Context, _ int64, text string) error {
	f.sent = append(f.sent, text)
	return f.sendErr
}

// pollAPI scripts the long poll. poll receives the 1-based call number and the
// offset the controller asked for, which is what proves a handled update is
// never fetched a second time.
type pollAPI struct {
	fakeAPI
	poll func(ctx context.Context, call int, offset int64) ([]telegram.Update, error)

	mu       sync.Mutex
	offsets  []int64
	lastWait time.Duration
}

func (p *pollAPI) GetUpdates(ctx context.Context, offset int64, wait time.Duration) ([]telegram.Update, error) {
	p.mu.Lock()
	p.offsets = append(p.offsets, offset)
	call := len(p.offsets)
	p.lastWait = wait
	p.mu.Unlock()
	return p.poll(ctx, call, offset)
}

func (p *pollAPI) seen() ([]int64, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int64(nil), p.offsets...), p.lastWait
}

type fakeExec struct {
	calls []string
	fail  error
}

func (f *fakeExec) Allow(_ context.Context, address string, ttl time.Duration) (string, error) {
	f.calls = append(f.calls, "allow "+address+" "+ttl.String())
	if f.fail != nil {
		return "", f.fail
	}
	return "allowed " + address + " for " + ttl.String(), nil
}

func (f *fakeExec) Revoke(_ context.Context, address string) (string, error) {
	f.calls = append(f.calls, "revoke "+address)
	if f.fail != nil {
		return "", f.fail
	}
	return "revoked " + address, nil
}

func (f *fakeExec) Service(_ context.Context, verb string) (string, error) {
	f.calls = append(f.calls, "service "+verb)
	if f.fail != nil {
		return "", f.fail
	}
	return "knockd " + verb + " ok", nil
}

func newController(t *testing.T) (*Controller, *fakeAPI, *fakeExec) {
	t.Helper()
	api := &fakeAPI{}
	controller, exec := newControllerWith(t, api, io.Discard)
	return controller, api, exec
}

// newControllerWith lets a test supply its own API and watch the log, which is
// the only place a failed poll or a failed reply is reported.
func newControllerWith(t *testing.T, api API, logs io.Writer) (*Controller, *fakeExec) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	exec := &fakeExec{}
	controller := New(api, exec, state.NewEngine(store), store, ownerChat,
		15*time.Minute, log.New(logs, "", 0))
	return controller, exec
}

func message(chat int64, text string) telegram.Update {
	return telegram.Update{
		UpdateID: 1,
		Message: &telegram.Message{
			Chat: telegram.Chat{ID: chat},
			Text: text,
		},
	}
}

// The chat id is the entire security boundary. A stranger must get no reply
// and must never reach the executor.
func TestForeignChatIsIgnoredSilently(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(999, "/allow 1.2.3.4"))

	if len(exec.calls) != 0 {
		t.Errorf("executor was reached by a foreign chat: %v", exec.calls)
	}
	if len(api.sent) != 0 {
		t.Errorf("replied to a foreign chat: %v", api.sent)
	}
}

func TestAllowUsesDefaultDurationAndRecordsTheGrant(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5"))

	if len(exec.calls) != 1 || exec.calls[0] != "allow 203.0.113.5 15m0s" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
	if len(api.sent) != 1 || !strings.Contains(api.sent[0], "allowed 203.0.113.5") {
		t.Fatalf("reply = %v", api.sent)
	}

	// A manual grant bypasses knockd entirely, so unless it is recorded here
	// nothing in the system would ever know it happened.
	rules, err := controller.store.ListRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("persisted %d rules, want 1", len(rules))
	}
	if rules[0].SourceIP != "203.0.113.5" || rules[0].Rule != manualRule {
		t.Errorf("rule = %+v, want a manual grant for 203.0.113.5", rules[0])
	}
	if rules[0].ExpiresAt == nil {
		t.Error("manual grant has no expiry")
	}
}

func TestAllowAcceptsAnExplicitDuration(t *testing.T) {
	controller, _, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5 2h"))

	if len(exec.calls) != 1 || exec.calls[0] != "allow 203.0.113.5 2h0m0s" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
}

// The bot must not invent a grant record when the privileged step failed.
func TestFailedGrantIsNotRecorded(t *testing.T) {
	controller, api, exec := newController(t)
	exec.fail = errors.New("192.168.1.10 is not a routable public address")

	controller.handle(context.Background(), message(ownerChat, "/allow 192.168.1.10"))

	if len(api.sent) != 1 || !strings.HasPrefix(api.sent[0], "failed:") {
		t.Fatalf("reply = %v, want a failure", api.sent)
	}
	rules, err := controller.store.ListRules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("recorded %d rules after a failed grant", len(rules))
	}
}

func TestServiceVerbsAreForwarded(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/knockd restart"))

	if len(exec.calls) != 1 || exec.calls[0] != "service restart" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
	if len(api.sent) != 1 || !strings.Contains(api.sent[0], "restart ok") {
		t.Errorf("reply = %v", api.sent)
	}
}

func TestRulesReportsActiveGrants(t *testing.T) {
	controller, api, _ := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/rules"))
	if len(api.sent) != 1 || api.sent[0] != "no active access rules" {
		t.Fatalf("reply on empty store = %v", api.sent)
	}

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5 30m"))
	controller.handle(context.Background(), message(ownerChat, "/rules"))

	// Rounded to the second, a grant issued moments ago still reads as its
	// full lifetime, so assert the shape rather than an exact remainder.
	last := api.sent[len(api.sent)-1]
	if !strings.HasPrefix(last, "203.0.113.5 (manual) expires in ") {
		t.Errorf("rules reply = %q", last)
	}
}

// Telegram appends @botname in groups, and an unknown command must not be
// mistaken for one that exists.
func TestCommandParsing(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/knockd@examplebot status"))
	if len(exec.calls) != 1 || exec.calls[0] != "service status" {
		t.Fatalf("executor calls = %v", exec.calls)
	}

	controller.handle(context.Background(), message(ownerChat, "/flush"))
	if len(exec.calls) != 1 {
		t.Fatalf("unknown command reached the executor: %v", exec.calls)
	}
	if !strings.HasPrefix(api.sent[len(api.sent)-1], "unknown command") {
		t.Errorf("reply = %q", api.sent[len(api.sent)-1])
	}
}

// The offset is what stops Telegram from redelivering a command. If it did not
// advance, one "/knockd restart" would restart the service on every poll.
func TestRunAdvancesTheOffsetPastEachUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	api := &pollAPI{}
	api.poll = func(_ context.Context, call int, _ int64) ([]telegram.Update, error) {
		if call == 1 {
			return []telegram.Update{{
				UpdateID: 41,
				Message: &telegram.Message{
					Chat: telegram.Chat{ID: ownerChat},
					Text: "/knockd status",
				},
			}}, nil
		}
		// The second poll carries the offset under test; stop the loop there.
		cancel()
		return nil, errors.New("poller stopped")
	}

	controller, exec := newControllerWith(t, api, io.Discard)
	controller.Run(ctx)

	offsets, wait := api.seen()
	if len(offsets) != 2 {
		t.Fatalf("poll offsets = %v, want exactly two polls", offsets)
	}
	if offsets[0] != 0 {
		t.Errorf("first poll offset = %d, want 0", offsets[0])
	}
	if offsets[1] != 42 {
		t.Errorf("second poll offset = %d, want update_id+1 = 42", offsets[1])
	}
	// A zero window would turn the long poll into a hot loop.
	if wait != pollWindow {
		t.Errorf("poll window = %s, want %s", wait, pollWindow)
	}
	if len(exec.calls) != 1 || exec.calls[0] != "service status" {
		t.Errorf("executor calls = %v, want the command handled exactly once", exec.calls)
	}
}

// Telegram returns 5xx and resets connections routinely. A failed poll is a
// pause, not the end of the daemon.
func TestRunRetriesAfterAPollError(t *testing.T) {
	previous := retryDelay
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = previous })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	api := &pollAPI{}
	api.poll = func(_ context.Context, call int, _ int64) ([]telegram.Update, error) {
		switch call {
		case 1:
			return nil, errors.New("telegram: 502 bad gateway")
		case 2:
			return []telegram.Update{{
				UpdateID: 8,
				Message: &telegram.Message{
					Chat: telegram.Chat{ID: ownerChat},
					Text: "/knockd status",
				},
			}}, nil
		}
		cancel()
		return nil, errors.New("poller stopped")
	}

	var logs bytes.Buffer
	controller, exec := newControllerWith(t, api, &logs)
	controller.Run(ctx)

	if len(exec.calls) != 1 || exec.calls[0] != "service status" {
		t.Errorf("executor calls = %v, want the command served after the failed poll", exec.calls)
	}
	// Silent retries would hide a wrong token or a revoked bot for ever.
	if !strings.Contains(logs.String(), "502 bad gateway") {
		t.Errorf("log = %q, want the poll failure in it", logs.String())
	}
}

func TestRunReturnsWhenTheContextIsCancelled(t *testing.T) {
	t.Run("cancelled before the first poll", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		api := &pollAPI{poll: func(context.Context, int, int64) ([]telegram.Update, error) {
			t.Error("polled although the context was already cancelled")
			return nil, nil
		}}
		controller, _ := newControllerWith(t, api, io.Discard)
		controller.Run(ctx)
	})

	// Shutdown lands while a poll is hanging open, which is the usual case:
	// the window is 25 seconds and systemd will not wait that long.
	t.Run("cancelled while a poll is in flight", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		api := &pollAPI{poll: func(ctx context.Context, _ int, _ int64) ([]telegram.Update, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		controller, _ := newControllerWith(t, api, io.Discard)

		done := make(chan struct{})
		go func() {
			controller.Run(ctx)
			close(done)
		}()

		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after its context was cancelled")
		}
	})

	// Shutdown must not have to sit out the pause that follows a failed poll,
	// or systemd's stop timeout decides how long the daemon takes to die.
	t.Run("cancelled while waiting out a retry", func(t *testing.T) {
		previous := retryDelay
		retryDelay = time.Minute
		t.Cleanup(func() { retryDelay = previous })

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		api := &pollAPI{poll: func(context.Context, int, int64) ([]telegram.Update, error) {
			time.AfterFunc(10*time.Millisecond, cancel)
			return nil, errors.New("telegram: connection reset by peer")
		}}
		controller, _ := newControllerWith(t, api, io.Discard)

		done := make(chan struct{})
		go func() {
			controller.Run(ctx)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run sat out the whole retry pause instead of shutting down")
		}
		if offsets, _ := api.seen(); len(offsets) != 1 {
			t.Errorf("polls = %d, want the loop to stop after the failure", len(offsets))
		}
	})
}

// Channel posts, edited messages and poll answers arrive with no message at
// all; a sticker arrives with a message object that carries no text field, so
// Message is non-nil and Text is empty. None of them is a command.
func TestUpdatesWithoutUsableTextAreIgnored(t *testing.T) {
	controller, api, exec := newController(t)

	sticker := telegram.Update{
		UpdateID: 8,
		Message:  &telegram.Message{Chat: telegram.Chat{ID: ownerChat}},
	}
	controller.handle(context.Background(), telegram.Update{UpdateID: 7})
	controller.handle(context.Background(), sticker)
	controller.handle(context.Background(), message(ownerChat, "   "))

	if len(exec.calls) != 0 || len(api.sent) != 0 {
		t.Fatalf("executor calls = %v, replies = %v, want neither", exec.calls, api.sent)
	}
	if reply := controller.dispatch(context.Background(), "   "); reply != "" {
		t.Errorf("dispatch of blank text = %q, want no reply", reply)
	}
}

// Ordinary chatter, including a mistyped non-ASCII word from the real chat,
// must come back as the unknown command reply and reach nothing privileged.
func TestPlainChatterGetsTheUnknownCommandReply(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "пгпшоз"))

	if len(api.sent) != 1 || !strings.HasPrefix(api.sent[0], "unknown command") {
		t.Fatalf("reply = %v, want the unknown command notice", api.sent)
	}
	if !strings.Contains(api.sent[0], "/allow <ipv4>") {
		t.Errorf("reply = %q, want the help text appended", api.sent[0])
	}
	if len(exec.calls) != 0 {
		t.Errorf("chatter reached the executor: %v", exec.calls)
	}
}

func TestHelpNeverReachesTheExecutor(t *testing.T) {
	for _, command := range []string{"/help", "/start", "/help@examplebot"} {
		controller, api, exec := newController(t)
		controller.handle(context.Background(), message(ownerChat, command))

		if len(api.sent) != 1 || api.sent[0] != help {
			t.Errorf("%s reply = %v, want the help text", command, api.sent)
		}
		if len(exec.calls) != 0 {
			t.Errorf("%s reached the executor: %v", command, exec.calls)
		}
	}
}

// Argument shape is checked before anything privileged runs: a typo must come
// back as a usage line, never as a call into the root helper.
func TestMalformedCommandsNeverReachTheExecutor(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"/allow", "usage: /allow"},
		{"/allow 203.0.113.5 15m spare", "usage: /allow"},
		{"/allow 203.0.113.5 tomorrow", `"tomorrow" is not a duration`},
		{"/revoke", "usage: /revoke"},
		{"/revoke 203.0.113.5 now", "usage: /revoke"},
		{"/knockd", "usage: /knockd"},
		{"/knockd restart now", "usage: /knockd"},
	}

	for _, testCase := range cases {
		t.Run(testCase.text, func(t *testing.T) {
			controller, api, exec := newController(t)
			controller.handle(context.Background(), message(ownerChat, testCase.text))

			if len(api.sent) != 1 || !strings.HasPrefix(api.sent[0], testCase.want) {
				t.Fatalf("reply = %v, want it to start with %q", api.sent, testCase.want)
			}
			if len(exec.calls) != 0 {
				t.Errorf("executor was reached with malformed arguments: %v", exec.calls)
			}
		})
	}
}

func TestRevokeClosesTheRuleItRecorded(t *testing.T) {
	controller, api, exec := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5 30m"))
	controller.handle(context.Background(), message(ownerChat, "/revoke 203.0.113.5"))

	if len(exec.calls) != 2 || exec.calls[1] != "revoke 203.0.113.5" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
	if last := api.sent[len(api.sent)-1]; last != "revoked 203.0.113.5" {
		t.Errorf("reply = %q, want the helper output", last)
	}
	// The revoke has to close the very rule the grant opened, otherwise /rules
	// keeps advertising access that no longer exists.
	if reply := controller.rules(); reply != "no active access rules" {
		t.Errorf("rules after a revoke = %q", reply)
	}
}

// A failed privileged step is reported as such and leaves no audit record
// claiming it happened.
func TestExecutorFailuresAreReportedNotRecorded(t *testing.T) {
	cases := []struct {
		text string
		call string
	}{
		{"/revoke 203.0.113.5", "revoke 203.0.113.5"},
		{"/knockd restart", "service restart"},
	}

	for _, testCase := range cases {
		t.Run(testCase.text, func(t *testing.T) {
			controller, api, exec := newController(t)
			exec.fail = errors.New("helper: operation not permitted")

			controller.handle(context.Background(), message(ownerChat, testCase.text))

			if len(exec.calls) != 1 || exec.calls[0] != testCase.call {
				t.Fatalf("executor calls = %v, want %q", exec.calls, testCase.call)
			}
			if len(api.sent) != 1 || api.sent[0] != "failed: helper: operation not permitted" {
				t.Fatalf("reply = %v, want the helper error", api.sent)
			}
			rules, err := controller.store.ListRules()
			if err != nil {
				t.Fatalf("list rules: %v", err)
			}
			if len(rules) != 0 {
				t.Errorf("recorded %d rules although the helper failed", len(rules))
			}
		})
	}
}

// Telegram rate limits and goes down; a failed reply is logged and the poller
// carries on, because the privileged action already happened.
func TestReplyFailureIsLoggedAndSurvived(t *testing.T) {
	api := &fakeAPI{sendErr: errors.New("telegram: 429 too many requests")}
	var logs bytes.Buffer
	controller, exec := newControllerWith(t, api, &logs)

	controller.handle(context.Background(), message(ownerChat, "/knockd status"))

	if len(exec.calls) != 1 || exec.calls[0] != "service status" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
	if !strings.Contains(logs.String(), "429 too many requests") {
		t.Errorf("log = %q, want the reply failure in it", logs.String())
	}
}

// The logger is optional at construction, so the first thing worth logging
// must not dereference a nil one.
func TestNewFallsBackToTheDefaultLogger(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	controller := New(&fakeAPI{}, &fakeExec{}, state.NewEngine(store), store,
		ownerChat, 15*time.Minute, nil)
	if controller.log == nil {
		t.Fatal("New left the logger nil")
	}
}

// Two grants must arrive as two lines: joined onto one they are unreadable and
// the operator cannot tell whose access is about to lapse.
func TestRulesListsEveryOpenGrantOnItsOwnLine(t *testing.T) {
	controller, api, _ := newController(t)

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5 30m"))
	controller.handle(context.Background(), message(ownerChat, "/allow 198.51.100.167 1h"))
	controller.handle(context.Background(), message(ownerChat, "/rules"))

	lines := strings.Split(api.sent[len(api.sent)-1], "\n")
	if len(lines) != 2 {
		t.Fatalf("rules reply = %q, want one line per grant", api.sent[len(api.sent)-1])
	}
	// The listing is ordered by update time, and both grants share a moment,
	// so assert the contents rather than the order.
	listed := strings.Join(lines, " ")
	for _, address := range []string{"203.0.113.5", "198.51.100.167"} {
		if !strings.Contains(listed, address) {
			t.Errorf("rules reply = %q, want %s in it", listed, address)
		}
	}
	for i, line := range lines {
		if !strings.Contains(line, "(manual) expires in ") {
			t.Errorf("line %d = %q, want the rule name and the remaining time", i, line)
		}
	}
}

// The database can go away under the daemon (a full disk, a deleted state
// file). The privileged action still happened, so it is still reported; only
// the audit trail is lost, and that loss has to be visible in the log.
func TestStorageFailuresAreReportedNotHidden(t *testing.T) {
	controller, api, exec := newController(t)
	var logs bytes.Buffer
	controller.log = log.New(&logs, "", 0)
	if err := controller.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	controller.handle(context.Background(), message(ownerChat, "/allow 203.0.113.5 30m"))
	if len(exec.calls) != 1 || exec.calls[0] != "allow 203.0.113.5 30m0s" {
		t.Fatalf("executor calls = %v", exec.calls)
	}
	if len(api.sent) != 1 || api.sent[0] != "allowed 203.0.113.5 for 30m0s" {
		t.Errorf("reply = %v, want the helper output despite the failed record", api.sent)
	}
	if !strings.Contains(logs.String(), "record access.granted") {
		t.Errorf("log = %q, want the lost record in it", logs.String())
	}

	controller.handle(context.Background(), message(ownerChat, "/rules"))
	if last := api.sent[len(api.sent)-1]; !strings.HasPrefix(last, "failed: ") {
		t.Errorf("rules reply = %q, want the read failure surfaced", last)
	}
}
