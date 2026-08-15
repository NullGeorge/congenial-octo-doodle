package knockd

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
)

// LogReader streams knockd's journal output. Parsing is deliberately kept
// separate so the reader can later be used with syslog or another source.
type LogReader struct {
	service string
}

func NewLogReader(service string) *LogReader {
	if service == "" {
		service = "knockd"
	}
	return &LogReader{service: service}
}

func (r *LogReader) Follow(ctx context.Context, handle func(string) error) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-u", r.service, "-o", "cat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if err := handle(scanner.Text()); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("read journalctl: %w", err)
	}
	return cmd.Wait()
}
