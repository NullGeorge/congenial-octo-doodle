// Command knock-watch is the other half of the heartbeat: it runs somewhere
// else, waits for the agent to check in, and tells you when it stops. A dead
// host cannot report its own death, which is the one thing the agent can never
// do for itself.
//
// Nothing about the monitored host is trusted here, and nothing is sent to it.
// The only inbound surface is one secret URL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/telegram"
	"github.com/NullGeorge/congenial-octo-doodle/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("knock-watch " + version.String())
		return
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("knock-watch", flag.ContinueOnError)
	listen := fs.String("listen", ":9000", "address to listen on")
	token := fs.String("token", "", "secret path segment; required, the ping url is /ping/<token>")
	name := fs.String("name", "knockd-agent", "name of the monitored host, used in alerts")
	grace := fs.Duration("grace", 15*time.Minute, "silence tolerated before alerting")
	every := fs.Duration("check-interval", 30*time.Second, "how often silence is evaluated")
	statePath := fs.String("state", "/var/lib/knock-watch/state.json", "where last-seen is persisted")
	chatID := fs.Int64("telegram-chat-id", 0, "chat that receives alerts")
	apiURL := fs.String("telegram-api", telegram.DefaultBaseURL, "Bot API base url; override only for testing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// An open ping endpoint would let anyone keep the alert suppressed, which
	// is precisely the failure this program exists to prevent.
	if *token == "" {
		return fmt.Errorf("-token is required: without it anyone could silence the alert")
	}

	botToken := strings.TrimSpace(os.Getenv("BOT_TOKEN"))
	if botToken == "" {
		return fmt.Errorf("BOT_TOKEN is not set")
	}
	chat := *chatID
	if chat == 0 {
		raw := strings.TrimSpace(os.Getenv("CHAT_ID"))
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("CHAT_ID %q is not a chat id: %w", raw, err)
		}
		chat = parsed
	}

	api := telegram.New(botToken, *apiURL)
	watch := &monitor{
		name:      *name,
		grace:     *grace,
		statePath: *statePath,
		log:       log.Default(),
		send: func(ctx context.Context, text string) error {
			return api.SendMessage(ctx, chat, text)
		},
	}
	if err := watch.load(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mux := newMux(ctx, *token, watch)

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	go watch.loop(ctx, *every)

	log.Printf("knock-watch %s", version.String())
	log.Printf("listening on %s, alerting after %s of silence from %s", *listen, *grace, *name)
	if err := server.ListenAndServe(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// newMux is the entire inbound surface: one secret path and nothing else. It
// is a named function so the routing can be exercised without binding a port.
func newMux(ctx context.Context, token string, watch *monitor) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping/"+token, func(w http.ResponseWriter, r *http.Request) {
		watch.handlePing(ctx, time.Now().UTC())
		w.Write([]byte("ok\n"))
	})
	return mux
}

// monitor is the dead-man switch. The decisions are kept apart from the
// transport so they can be tested without a clock or a network.
type monitor struct {
	mu        sync.Mutex
	name      string
	grace     time.Duration
	statePath string
	lastSeen  time.Time
	alerted   bool
	send      func(context.Context, string) error
	log       *log.Logger
}

type persisted struct {
	LastSeen time.Time `json:"last_seen"`
	Alerted  bool      `json:"alerted"`
}

// load restores last-seen so a restart of the watchdog neither forgets an
// outstanding alert nor raises a duplicate one.
func (m *monitor) load() error {
	raw, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing has ever checked in: start the clock now, so a host that
			// is already down is reported after one grace period.
			m.lastSeen = time.Now().UTC()
			return nil
		}
		return fmt.Errorf("read state: %w", err)
	}
	var state persisted
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("parse state %s: %w", m.statePath, err)
	}
	m.lastSeen, m.alerted = state.LastSeen, state.Alerted
	return nil
}

func (m *monitor) save() {
	raw, err := json.Marshal(persisted{LastSeen: m.lastSeen, Alerted: m.alerted})
	if err != nil {
		m.log.Printf("encode state: %v", err)
		return
	}
	if dir := filepath.Dir(m.statePath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			m.log.Printf("create state dir: %v", err)
			return
		}
	}
	if err := os.WriteFile(m.statePath, raw, 0o600); err != nil {
		m.log.Printf("write state: %v", err)
	}
}

// ping records a check-in and reports whether it ended an outstanding alert.
func (m *monitor) ping(now time.Time) (recovered bool, silentFor time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.alerted {
		recovered, silentFor = true, now.Sub(m.lastSeen)
		m.alerted = false
	}
	m.lastSeen = now
	return recovered, silentFor
}

// check reports whether silence has just crossed the grace period. It returns
// true exactly once per outage, so a continuing outage does not repeat.
func (m *monitor) check(now time.Time) (silent bool, silentFor time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	silentFor = now.Sub(m.lastSeen)
	if m.alerted || silentFor <= m.grace {
		return false, silentFor
	}
	m.alerted = true
	return true, silentFor
}

func (m *monitor) handlePing(ctx context.Context, now time.Time) {
	recovered, silentFor := m.ping(now)
	m.save()
	if !recovered {
		return
	}
	text := fmt.Sprintf("%s is back\nHeartbeat resumed after %s of silence",
		m.name, silentFor.Round(time.Second))
	if err := m.send(ctx, text); err != nil {
		m.log.Printf("send recovery: %v", err)
	}
}

func (m *monitor) loop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		silent, silentFor := m.check(time.Now().UTC())
		if !silent {
			continue
		}
		m.save()
		text := fmt.Sprintf("%s is silent\nNo heartbeat for %s, tolerated %s",
			m.name, silentFor.Round(time.Second), m.grace)
		if err := m.send(ctx, text); err != nil {
			m.log.Printf("send alert: %v", err)
		}
	}
}
