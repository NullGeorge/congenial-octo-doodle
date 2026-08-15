package knockd

import (
	"context"
	"fmt"
	"os/exec"
)

type Manager struct {
	service string
}

func NewManager(service string) *Manager {
	if service == "" {
		service = "knockd"
	}
	return &Manager{service: service}
}

func (m *Manager) Status(ctx context.Context) error {
	return m.run(ctx, "is-active", m.service)
}

func (m *Manager) Start(ctx context.Context) error {
	return m.run(ctx, "start", m.service)
}

func (m *Manager) Stop(ctx context.Context) error {
	return m.run(ctx, "stop", m.service)
}

func (m *Manager) Restart(ctx context.Context) error {
	return m.run(ctx, "restart", m.service)
}

func (m *Manager) run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, err, output)
	}
	return nil
}
