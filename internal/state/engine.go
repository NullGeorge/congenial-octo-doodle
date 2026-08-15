package state

import (
	"strings"
	"sync"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

type AccessRule struct {
	SourceIP  string
	Rule      string
	Port      uint16
	Protocol  string
	State     string
	Source    string
	UpdatedAt time.Time
	ExpiresAt *time.Time
}

type Engine struct {
	store *storage.Store
	mu    sync.RWMutex
	rules map[string]AccessRule
}

func NewEngine(store *storage.Store) *Engine {
	return &Engine{store: store, rules: make(map[string]AccessRule)}
}

func (e *Engine) Apply(event events.Event) error {
	if err := e.store.SaveEvent(event); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if event.SourceIP == "" {
		return nil
	}

	status := "observed"
	switch event.Type {
	case events.AccessGranted:
		status = "open"
	case events.AccessRevoked:
		status = "closed"
	}

	if event.Type == events.AccessGranted || event.Type == events.AccessRevoked {
		key := ruleKey(event.SourceIP, event.Rule, event.Port)
		e.rules[key] = AccessRule{
			SourceIP: event.SourceIP,
			Rule: event.Rule,
			Port: event.Port,
			Protocol: "tcp",
			State: status,
			Source: "knockd",
			UpdatedAt: event.Timestamp,
		}
	}

	if event.Type == events.KnockReceived || event.Type == events.SequenceFailed {
		return e.store.SaveAttempt(event.Timestamp, event.SourceIP, event.Rule, strings.ToLower(string(event.Type)), event.Message)
	}
	return nil
}

func (e *Engine) Rules() []AccessRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]AccessRule, 0, len(e.rules))
	for _, rule := range e.rules {
		result = append(result, rule)
	}
	return result
}

func ruleKey(ip, rule string, port uint16) string {
	return ip + "|" + rule + "|" + string(rune(port))
}
