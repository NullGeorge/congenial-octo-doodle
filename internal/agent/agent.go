package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/NullGeorge/congenial-octo-doodle/internal/geoip"
	"github.com/NullGeorge/congenial-octo-doodle/internal/knockd"
	"github.com/NullGeorge/congenial-octo-doodle/internal/state"
)

type Agent struct {
	reader *knockd.LogReader
	state  *state.Engine
	geo    *geoip.DB
	log    *log.Logger
}

// New builds the agent. geo may be nil, in which case events carry no country.
func New(reader *knockd.LogReader, state *state.Engine, geo *geoip.DB, logger *log.Logger) *Agent {
	if logger == nil {
		logger = log.Default()
	}
	return &Agent{reader: reader, state: state, geo: geo, log: logger}
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.reader.Follow(ctx, func(line string) error {
		event, ok := knockd.ParseLine(line)
		if !ok {
			return nil
		}
		event.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		event.Timestamp = time.Now().UTC()
		event.Country = a.geo.Country(event.SourceIP)
		if err := a.state.Apply(event); err != nil {
			return fmt.Errorf("apply event %s: %w", event.Type, err)
		}
		a.log.Printf("event=%s ip=%s country=%s rule=%s ttl=%s",
			event.Type, event.SourceIP, event.Country, event.Rule, event.TTL)
		return nil
	}); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func (a *Agent) Rules() []state.AccessRule { return a.state.Rules() }
