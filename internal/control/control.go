// Package control turns Telegram messages into the handful of privileged
// actions the operator may take. Commands are accepted from exactly one chat;
// everything else is ignored without a reply, so an unknown sender learns
// nothing about the bot.
package control

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
	"github.com/NullGeorge/congenial-octo-doodle/internal/telegram"
)

// pollWindow is how long a single getUpdates call is allowed to hang open.
const pollWindow = 25 * time.Second

// API is the slice of the Bot API this package needs.
type API interface {
	GetUpdates(ctx context.Context, offset int64, wait time.Duration) ([]telegram.Update, error)
	SendMessage(ctx context.Context, chatID int64, text string) error
}

// Executor performs the privileged work. Every implementation must validate
// its own arguments: this package hands over operator input.
type Executor interface {
	Allow(ctx context.Context, address string, ttl time.Duration) (string, error)
	Revoke(ctx context.Context, address string) (string, error)
	Service(ctx context.Context, verb string) (string, error)
}

type Controller struct {
	api        API
	exec       Executor
	engine     *state.Engine
	store      *storage.Store
	chatID     int64
	defaultTTL time.Duration
	log        *log.Logger
	offset     int64
}

func New(api API, exec Executor, engine *state.Engine, store *storage.Store,
	chatID int64, defaultTTL time.Duration, logger *log.Logger) *Controller {
	if logger == nil {
		logger = log.Default()
	}
	return &Controller{
		api: api, exec: exec, engine: engine, store: store,
		chatID: chatID, defaultTTL: defaultTTL, log: logger,
	}
}

// Run long polls for commands until the context ends.
func (c *Controller) Run(ctx context.Context) {
	for ctx.Err() == nil {
		updates, err := c.api.GetUpdates(ctx, c.offset, pollWindow)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Printf("control: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for _, update := range updates {
			c.offset = update.UpdateID + 1
			c.handle(ctx, update)
		}
	}
}

func (c *Controller) handle(ctx context.Context, update telegram.Update) {
	if update.Message == nil || strings.TrimSpace(update.Message.Text) == "" {
		return
	}
	// Authorisation is the whole security boundary of this package. An
	// unauthorised chat gets silence, not an error, so probing tells nothing.
	if update.Message.Chat.ID != c.chatID {
		c.log.Printf("control: ignoring message from chat %d", update.Message.Chat.ID)
		return
	}

	reply := c.dispatch(ctx, update.Message.Text)
	if reply == "" {
		return
	}
	if err := c.api.SendMessage(ctx, c.chatID, reply); err != nil {
		c.log.Printf("control: reply: %v", err)
	}
}

func (c *Controller) dispatch(ctx context.Context, text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	// Telegram appends @botname when several bots share a group.
	command := strings.ToLower(fields[0])
	if at := strings.IndexByte(command, '@'); at >= 0 {
		command = command[:at]
	}
	args := fields[1:]

	switch command {
	case "/allow":
		return c.allow(ctx, args)
	case "/revoke":
		return c.revoke(ctx, args)
	case "/rules":
		return c.rules()
	case "/knockd":
		return c.knockd(ctx, args)
	case "/help", "/start":
		return help
	default:
		return "unknown command. " + help
	}
}

const help = `Commands:
/allow <ipv4> [duration] - open ssh for one address, default duration applies when omitted
/revoke <ipv4> - close it again
/rules - who currently has access
/knockd <start|stop|restart|status> - control the knockd service`

func (c *Controller) allow(ctx context.Context, args []string) string {
	if len(args) < 1 || len(args) > 2 {
		return "usage: /allow <ipv4> [duration]"
	}
	ttl := c.defaultTTL
	if len(args) == 2 {
		parsed, err := time.ParseDuration(args[1])
		if err != nil {
			return fmt.Sprintf("%q is not a duration, try 15m or 2h", args[1])
		}
		ttl = parsed
	}

	output, err := c.exec.Allow(ctx, args[0], ttl)
	if err != nil {
		return "failed: " + err.Error()
	}

	// A manual grant never passes through knockd, so nothing would record it
	// unless it is recorded here. Same event shape as a knocked grant, marked
	// with its own rule name so the origin stays visible.
	c.record(events.Event{
		Type:     events.AccessGranted,
		SourceIP: args[0],
		Rule:     manualRule,
		TTL:      ttl,
		Message:  "manual grant via telegram",
	})
	return strings.TrimSpace(output)
}

func (c *Controller) revoke(ctx context.Context, args []string) string {
	if len(args) != 1 {
		return "usage: /revoke <ipv4>"
	}
	output, err := c.exec.Revoke(ctx, args[0])
	if err != nil {
		return "failed: " + err.Error()
	}
	c.record(events.Event{
		Type:     events.AccessRevoked,
		SourceIP: args[0],
		Rule:     manualRule,
		Message:  "manual revoke via telegram",
	})
	return strings.TrimSpace(output)
}

const manualRule = "manual"

func (c *Controller) knockd(ctx context.Context, args []string) string {
	if len(args) != 1 {
		return "usage: /knockd <start|stop|restart|status>"
	}
	output, err := c.exec.Service(ctx, args[0])
	if err != nil {
		return "failed: " + err.Error()
	}
	return strings.TrimSpace(output)
}

func (c *Controller) rules() string {
	rules, err := c.store.ListRules()
	if err != nil {
		return "failed: " + err.Error()
	}

	now := time.Now().UTC()
	var text strings.Builder
	shown := 0
	for _, rule := range rules {
		if rule.Expired(now) || rule.State != "open" {
			continue
		}
		if shown > 0 {
			text.WriteString("\n")
		}
		fmt.Fprintf(&text, "%s (%s)", rule.SourceIP, rule.Rule)
		if rule.ExpiresAt != nil {
			fmt.Fprintf(&text, " expires in %s", rule.ExpiresAt.Sub(now).Round(time.Second))
		}
		shown++
	}
	if shown == 0 {
		return "no active access rules"
	}
	return text.String()
}

// record stores a manual action so it shows up in /rules and the CLI, and so
// the audit trail does not depend on the chat history.
func (c *Controller) record(event events.Event) {
	event.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	event.Timestamp = time.Now().UTC()
	if err := c.engine.Apply(event); err != nil {
		c.log.Printf("control: record %s: %v", event.Type, err)
	}
}
