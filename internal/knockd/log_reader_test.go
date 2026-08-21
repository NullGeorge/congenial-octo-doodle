package knockd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real knockd 0.8 output, captured from a live Debian 12 host. Follow must hand
// every line over untouched and in order: classification happens a layer up, so
// a reader that drops or reorders a line turns a matched sequence into a
// half-recorded one that no later code can repair.
var journalLines = []string{
	"starting up, listening on enp2s0",
	"192.0.2.134: openSSH: sequence timeout (stage 1)",
	"203.0.113.5: openSSH: Stage 1",
	"203.0.113.5: openSSH: Stage 2",
	"203.0.113.5: openSSH: Stage 3",
	"203.0.113.5: openSSH: OPEN SESAME",
	"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.5 timeout 15m }",
	"shutting down",
}

// fakeExecutable installs a shell script named name at the front of PATH, so
// code that shells out reaches the script instead of the real binary. Neither
// journalctl nor systemctl exists in the test container, and the real ones
// would need a live systemd, so standing them in is the only way to test the
// two types in this package that are nothing but a subprocess.
func fakeExecutable(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// printLines builds a fake journalctl body. keepRunning makes it linger like
// the real `journalctl -f`, which never exits on its own: only a kill or a
// cancelled context ends it.
func printLines(lines []string, keepRunning bool) string {
	body := "cat <<'KNOCK_EOF'\n" + strings.Join(lines, "\n") + "\nKNOCK_EOF\n"
	if keepRunning {
		// exec so the sleep replaces the shell and holds the same stdout;
		// otherwise killing the shell would leave a grandchild on the pipe.
		body += "exec sleep 60\n"
	}
	return body
}

// runFollow runs Follow off the test goroutine so a reader that never returns
// fails this test instead of wedging the package until the go test deadline.
func runFollow(t *testing.T, ctx context.Context, reader *LogReader, handle func(string) error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- reader.Follow(ctx, handle) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("Follow did not return")
		return nil
	}
}

func TestFollowDeliversEveryLineInOrder(t *testing.T) {
	fakeExecutable(t, "journalctl", printLines(journalLines, false))

	var seen []string
	err := runFollow(t, context.Background(), NewLogReader("knockd"), func(line string) error {
		seen = append(seen, line)
		return nil
	})
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	if len(seen) != len(journalLines) {
		t.Fatalf("delivered %d lines, want %d: %q", len(seen), len(journalLines), seen)
	}
	for i, line := range journalLines {
		if seen[i] != line {
			t.Errorf("line %d = %q, want %q", i, seen[i], line)
		}
	}
}

// A handler failure means the agent could not record the knock, for instance
// because the database is gone. Follow has to stop and surface that error
// rather than keep reading and lose the rest of the sequence silently.
func TestFollowReturnsHandlerError(t *testing.T) {
	// The fake lingers on purpose: Follow must not wait for journalctl to end.
	fakeExecutable(t, "journalctl", printLines(journalLines, true))

	failure := errors.New("store is closed")
	var seen int
	err := runFollow(t, context.Background(), NewLogReader("knockd"), func(string) error {
		seen++
		if seen == 2 {
			return failure
		}
		return nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("Follow error = %v, want %v", err, failure)
	}
	if seen != 2 {
		t.Errorf("handler saw %d lines, want 2: Follow kept reading past the failure", seen)
	}
}

// The daemon shuts down by cancelling the context while journalctl is still
// following. Follow has to come back promptly; a hang here would keep the
// process alive after SIGINT and need a SIGKILL from systemd.
func TestFollowStopsOnContextCancel(t *testing.T) {
	fakeExecutable(t, "journalctl", printLines([]string{journalLines[0]}, true))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var seen []string
	err := runFollow(t, ctx, NewLogReader("knockd"), func(line string) error {
		seen = append(seen, line)
		// Cancel from inside the handler: the fake is still sleeping, so this
		// is the same race the daemon hits on SIGINT mid-stream.
		cancel()
		return nil
	})
	if len(seen) != 1 {
		t.Fatalf("delivered %q, want just the one line the fake printed", seen)
	}
	// Killing journalctl makes Wait report the signal. That non-nil error is
	// why Agent.Run checks ctx.Err() before treating a failure as one.
	if err == nil {
		t.Error("Follow reported success after its subprocess was killed")
	}
	if ctx.Err() == nil {
		t.Error("context was not cancelled")
	}
}

// The unit name decides which journal the agent reads. Getting the default
// wrong yields a daemon that runs happily and never sees a single knock.
func TestNewLogReaderUnitArguments(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    string
	}{
		{
			name:    "an unset service falls back to knockd",
			service: "",
			want:    "-f -n 0 -u knockd -o cat",
		},
		{
			name:    "a configured service is followed verbatim",
			service: "knockd-lan",
			want:    "-f -n 0 -u knockd-lan -o cat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The fake reports its own argv, which is the only way to observe
			// the command line Follow assembled.
			fakeExecutable(t, "journalctl", "echo \"$@\"\n")

			var seen []string
			err := runFollow(t, context.Background(), NewLogReader(tt.service), func(line string) error {
				seen = append(seen, line)
				return nil
			})
			if err != nil {
				t.Fatalf("Follow: %v", err)
			}
			if len(seen) != 1 {
				t.Fatalf("fake journalctl printed %q, want one argv line", seen)
			}
			if seen[0] != tt.want {
				t.Errorf("journalctl args = %q, want %q", seen[0], tt.want)
			}
		})
	}
}

// A missing journalctl must be reported, not mistaken for an empty journal:
// otherwise a misconfigured host looks exactly like a quiet one.
func TestFollowReportsMissingJournalctl(t *testing.T) {
	// An empty directory as the whole PATH: nothing is resolvable.
	t.Setenv("PATH", t.TempDir())

	err := runFollow(t, context.Background(), NewLogReader(""), func(string) error {
		t.Error("handler ran without a journalctl binary")
		return nil
	})
	if err == nil {
		t.Fatal("Follow reported success with no journalctl on PATH")
	}
	if !strings.Contains(err.Error(), "journalctl") {
		t.Errorf("error = %v, want it to name journalctl", err)
	}
}

// A line the scanner cannot hold has to be reported. Handing over the part
// that fitted would feed the parser a truncated command line, and an nftables
// grant cut in half parses as something else entirely.
func TestFollowReportsUnreadableLine(t *testing.T) {
	// 70000 bytes with no newline, just past the scanner's 64 KiB limit and
	// still small enough that the writer drains rather than blocking on the
	// pipe once the scanner gives up.
	fakeExecutable(t, "journalctl", "dd if=/dev/zero bs=1000 count=70 2>/dev/null | tr '\\0' 'x'\n")

	var seen int
	err := runFollow(t, context.Background(), NewLogReader(""), func(string) error {
		seen++
		return nil
	})
	if err == nil {
		t.Fatal("Follow reported success on a line it could not read")
	}
	if !strings.Contains(err.Error(), "read journalctl") {
		t.Errorf("error = %v, want a read failure", err)
	}
	if seen != 0 {
		t.Errorf("handler saw %d lines, want none: a truncated line was delivered", seen)
	}
}

// Every Manager method is one systemctl verb. Mixing two of them up would
// restart the daemon when the operator only asked whether it was running.
func TestManagerVerbsAndUnit(t *testing.T) {
	tests := []struct {
		name    string
		service string
		call    func(*Manager, context.Context) error
		want    string
	}{
		{
			name:    "status asks systemd whether the unit is active",
			service: "",
			call:    (*Manager).Status,
			want:    "is-active knockd",
		},
		{
			name:    "start starts the configured unit",
			service: "knockd",
			call:    (*Manager).Start,
			want:    "start knockd",
		},
		{
			name:    "stop stops the configured unit",
			service: "knockd",
			call:    (*Manager).Stop,
			want:    "stop knockd",
		},
		{
			name:    "restart names the unit it was built with",
			service: "knockd-lan",
			call:    (*Manager).Restart,
			want:    "restart knockd-lan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := filepath.Join(t.TempDir(), "argv")
			fakeExecutable(t, "systemctl", "echo \"$@\" > "+record+"\n")

			if err := tt.call(NewManager(tt.service), context.Background()); err != nil {
				t.Fatalf("call: %v", err)
			}
			argv, err := os.ReadFile(record)
			if err != nil {
				t.Fatalf("read recorded argv: %v", err)
			}
			if got := strings.TrimSpace(string(argv)); got != tt.want {
				t.Errorf("systemctl args = %q, want %q", got, tt.want)
			}
		})
	}
}

// systemctl explains a refusal on its output, so that text has to reach the
// operator. An error that only says "exit status 5" is not actionable.
func TestManagerReportsSystemctlOutput(t *testing.T) {
	const reason = "Failed to start knockd.service: Unit knockd.service not found."
	fakeExecutable(t, "systemctl", "echo '"+reason+"' >&2\nexit 5\n")

	err := NewManager("").Start(context.Background())
	if err == nil {
		t.Fatal("Start reported success after systemctl exited non-zero")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("error = %v, want it to carry %q", err, reason)
	}
	if !strings.Contains(err.Error(), "start") {
		t.Errorf("error = %v, want it to name the verb that failed", err)
	}
}
