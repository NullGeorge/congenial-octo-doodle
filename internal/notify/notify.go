// Package notify pushes noteworthy knock events out to Telegram and keeps an
// external watchdog fed, so that a dead host is distinguishable from a quiet
// one. Delivery state lives in the database, which doubles as the outbox.
package notify

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

// batchSize bounds one flush so a long backlog cannot stall the loop.
const batchSize = 50

// Sender is the slice of the Bot API this package needs.
type Sender interface {
	SendMessage(ctx context.Context, chatID int64, text string) error
}

type Notifier struct {
	store  *storage.Store
	sender Sender
	chatID int64
	log    *log.Logger
}

func New(store *storage.Store, sender Sender, chatID int64, logger *log.Logger) *Notifier {
	if logger == nil {
		logger = log.Default()
	}
	return &Notifier{store: store, sender: sender, chatID: chatID, log: logger}
}

// Run flushes the outbox until the context ends. A failed send is retried on
// the next tick rather than dropped, and order is preserved.
func (n *Notifier) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := n.Flush(ctx); err != nil && ctx.Err() == nil {
			n.log.Printf("notify: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Flush delivers pending events in timestamp order. Events that are not worth
// a message are marked delivered anyway, so the queue keeps moving.
func (n *Notifier) Flush(ctx context.Context) error {
	pending, err := n.store.UndeliveredEvents(batchSize)
	if err != nil {
		return err
	}

	for _, event := range pending {
		if Notable(event.Type) {
			if err := n.sender.SendMessage(ctx, n.chatID, Format(event)); err != nil {
				return fmt.Errorf("send %s: %w", event.Type, err)
			}
		}
		if err := n.store.MarkDelivered(event.ID, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

// Notable filters out sequence progress. A single knock produces a handful of
// stage lines, and forwarding each one would make the chat useless.
func Notable(eventType events.Type) bool {
	switch eventType {
	case events.AccessGranted, events.AccessRevoked, events.SequenceFailed,
		events.CommandFailed, events.KnockdStarted, events.KnockdStopped:
		return true
	default:
		return false
	}
}

var titles = map[events.Type]string{
	events.AccessGranted:  "Access granted",
	events.AccessRevoked:  "Access revoked",
	events.SequenceFailed: "Knock sequence failed",
	events.CommandFailed:  "knockd command failed",
	events.KnockdStarted:  "knockd started",
	events.KnockdStopped:  "knockd stopped",
}

func Format(event events.Event) string {
	title, ok := titles[event.Type]
	if !ok {
		title = string(event.Type)
	}

	var text strings.Builder
	text.WriteString(title)
	if event.SourceIP != "" {
		text.WriteString("\nIP: ")
		text.WriteString(event.SourceIP)
		if event.Country != "" {
			text.WriteString(" (")
			text.WriteString(event.Country)
			text.WriteString(")")
		}
	}
	if event.Rule != "" {
		text.WriteString("\nRule: ")
		text.WriteString(event.Rule)
	}
	if event.Stage > 0 {
		fmt.Fprintf(&text, "\nStage: %d", event.Stage)
	}
	if event.TTL > 0 {
		text.WriteString("\nExpires: ")
		text.WriteString(event.Timestamp.Add(event.TTL).UTC().Format(time.RFC3339))
		text.WriteString(" (in ")
		text.WriteString(event.TTL.String())
		text.WriteString(")")
	}
	text.WriteString("\nTime: ")
	text.WriteString(event.Timestamp.UTC().Format(time.RFC3339))
	return text.String()
}

// Heartbeat pings an external watchdog on a schedule. Silence longer than the
// watchdog's grace period is what tells you the host died, which the agent
// itself can never report.
func Heartbeat(ctx context.Context, url string, interval time.Duration, logger *log.Logger) {
	if url == "" {
		return
	}
	if logger == nil {
		logger = log.Default()
	}
	client := &http.Client{Timeout: 15 * time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			logger.Printf("heartbeat: %v", err)
			return
		}
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("heartbeat: %v", err)
		} else {
			response.Body.Close()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
