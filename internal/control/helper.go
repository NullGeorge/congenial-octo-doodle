package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const sudoPath = "/usr/bin/sudo"

// Helper runs the privileged binary. The daemon itself holds no capabilities,
// so root is borrowed for the duration of one command and nothing longer.
// Argument validation lives in the helper, which is the only component that
// ever runs as root.
type Helper struct {
	Path string
}

func (h Helper) Allow(ctx context.Context, address string, ttl time.Duration) (string, error) {
	return h.run(ctx, "allow", address, ttl.String())
}

func (h Helper) Revoke(ctx context.Context, address string) (string, error) {
	return h.run(ctx, "revoke", address)
}

func (h Helper) Service(ctx context.Context, verb string) (string, error) {
	return h.run(ctx, "service", verb)
}

func (h Helper) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var command *exec.Cmd
	if os.Geteuid() == 0 {
		command = exec.CommandContext(ctx, h.Path, args...)
	} else {
		// -n never prompts: a hung password prompt would wedge the poller.
		command = exec.CommandContext(ctx, sudoPath, append([]string{"-n", h.Path}, args...)...)
	}

	// Kept apart on purpose: sudo writes warnings to stderr even on success
	// (for instance when it cannot reach the audit subsystem), and those must
	// not end up quoted back into the chat as if they were the result.
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if failure := strings.TrimSpace(stderr.String()); failure != "" {
			return "", errors.New(failure)
		}
		return "", fmt.Errorf("%s %s: %w", h.Path, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}
