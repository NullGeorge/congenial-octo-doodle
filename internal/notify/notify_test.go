package notify

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
