package control

import (
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
	"github.com/NullGeorge/congenial-octo-doodle/internal/telegram"
)

const ownerChat = 111111111

type fakeAPI struct {
	sent []string
}

func (f *fakeAPI) GetUpdates(context.Context, int64, time.Duration) ([]telegram.Update, error) {
	return nil, errors.New("not used")
}

func (f *fakeAPI) SendMessage(_ context.Context, _ int64, text string) error {
	f.sent = append(f.sent, text)
	return nil
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
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	api, exec := &fakeAPI{}, &fakeExec{}
	controller := New(api, exec, state.NewEngine(store), store, ownerChat,
		15*time.Minute, log.New(io.Discard, "", 0))
	return controller, api, exec
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
