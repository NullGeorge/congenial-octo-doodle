package state

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
	"github.com/NullGeorge/congenial-octo-doodle/internal/storage"
)

// AccessRule is defined by the storage layer so the in-memory view and the
// persisted row cannot drift apart.
type AccessRule = storage.AccessRule

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
		rule := AccessRule{
			SourceIP:  event.SourceIP,
			Rule:      event.Rule,
			Port:      event.Port,
			Protocol:  "tcp",
			State:     status,
			Source:    "knockd",
			UpdatedAt: event.Timestamp,
		}
		// The firewall command states how long it grants access for, so the
		// lapse is known up front and never has to be read back from nftables.
		if event.Type == events.AccessGranted && event.TTL > 0 {
			expiresAt := event.Timestamp.Add(event.TTL)
			rule.ExpiresAt = &expiresAt
		}
		e.rules[ruleKey(event.SourceIP, event.Rule, event.Port)] = rule
		if err := e.store.SaveRule(rule); err != nil {
			return err
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

	now := time.Now().UTC()
	result := make([]AccessRule, 0, len(e.rules))
	for _, rule := range e.rules {
		if rule.State == "open" && rule.Expired(now) {
			rule.State = "expired"
		}
		result = append(result, rule)
	}
	return result
}

func ruleKey(ip, rule string, port uint16) string {
	return ip + "|" + rule + "|" + strconv.FormatUint(uint64(port), 10)
}
