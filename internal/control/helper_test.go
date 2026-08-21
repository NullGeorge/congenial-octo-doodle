package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireRoot guards the tests that drive Helper.run directly. As root the
// helper is executed as given; otherwise run() prepends /usr/bin/sudo and a
// stub script is no longer what gets executed.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Helper shells out through sudo unless the test runs as root")
	}
}

// stubHelper writes an executable stand-in for the privileged binary and
// returns its path plus the path it records its argv into.
func stubHelper(t *testing.T, body string) (binary, argv string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "knockd-helper")
	argv = filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argv + "\n" + body + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub helper: %v", err)
	}
	return binary, argv
}

func recordedArgv(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// The helper is the only component that runs as root, so the argv it receives
// is a contract: a wrong verb or a dropped address would change what gets
// opened in the firewall.
func TestHelperPassesTheExpectedArgv(t *testing.T) {
	requireRoot(t)

	cases := []struct {
		name string
		call func(context.Context, Helper) (string, error)
		want []string
	}{
		{
			name: "allow carries the address and the ttl as a duration string",
			call: func(ctx context.Context, h Helper) (string, error) {
				return h.Allow(ctx, "203.0.113.5", 15*time.Minute)
			},
			want: []string{"allow", "203.0.113.5", "15m0s"},
		},
		{
			name: "revoke carries only the address",
			call: func(ctx context.Context, h Helper) (string, error) {
				return h.Revoke(ctx, "192.0.2.134")
			},
			want: []string{"revoke", "192.0.2.134"},
		},
		{
			name: "service carries the verb",
			call: func(ctx context.Context, h Helper) (string, error) {
				return h.Service(ctx, "restart")
			},
			want: []string{"service", "restart"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			binary, argv := stubHelper(t, "echo '  done  '")

			output, err := testCase.call(context.Background(), Helper{Path: binary})
			if err != nil {
				t.Fatalf("run helper: %v", err)
			}
			if output != "done" {
				t.Errorf("output = %q, want the stdout trimmed to %q", output, "done")
			}

			got := recordedArgv(t, argv)
			if len(got) != len(testCase.want) {
				t.Fatalf("argv = %q, want %q", got, testCase.want)
			}
			for i := range testCase.want {
				if got[i] != testCase.want[i] {
					t.Errorf("argv[%d] = %q, want %q", i, got[i], testCase.want[i])
				}
			}
		})
	}
}

// The helper validates its own input, so its complaint is the only useful
// thing to report back to the operator.
func TestHelperFailureReportsStderr(t *testing.T) {
	requireRoot(t)
	binary, _ := stubHelper(t, "echo '192.168.1.10 is not a routable public address' >&2\nexit 3")

	output, err := Helper{Path: binary}.Allow(context.Background(), "192.168.1.10", time.Minute)
	if err == nil {
		t.Fatal("a helper exiting 3 produced no error")
	}
	if err.Error() != "192.168.1.10 is not a routable public address" {
		t.Errorf("error = %q, want the stderr text verbatim", err)
	}
	if output != "" {
		t.Errorf("output = %q, want empty on failure", output)
	}
}

// A silent non-zero exit still has to say what was run, otherwise the chat
// gets "failed: exit status 7" with no clue which command produced it.
func TestHelperSilentFailureNamesTheCommand(t *testing.T) {
	requireRoot(t)
	binary, _ := stubHelper(t, "exit 7")

	_, err := Helper{Path: binary}.Allow(context.Background(), "203.0.113.5", 15*time.Minute)
	if err == nil {
		t.Fatal("a helper exiting 7 without stderr produced no error")
	}
	for _, want := range []string{binary, "allow 203.0.113.5 15m0s", "exit status 7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// sudo writes warnings to stderr even when the command succeeds (an
// unresolvable hostname, an unreachable audit subsystem). Those used to be
// quoted back into the chat as if they were the result of the action.
func TestHelperDropsStderrOnSuccess(t *testing.T) {
	requireRoot(t)
	binary, _ := stubHelper(t, "echo 'sudo: unable to resolve host atsos' >&2\necho 'allowed 203.0.113.5 for 15m0s'")

	output, err := Helper{Path: binary}.Allow(context.Background(), "203.0.113.5", 15*time.Minute)
	if err != nil {
		t.Fatalf("run helper: %v", err)
	}
	if output != "allowed 203.0.113.5 for 15m0s" {
		t.Errorf("output = %q, want only the stdout line", output)
	}
	if strings.Contains(output, "sudo:") {
		t.Errorf("output = %q, want no stderr warning in it", output)
	}
}

// A wedged helper must never wedge the poller. run() caps every call with its
// own timeout; cancelling the caller's context is the same path and does not
// cost the test twenty seconds.
func TestHelperStopsWhenTheContextIsCancelled(t *testing.T) {
	requireRoot(t)
	binary, _ := stubHelper(t, "sleep 60")

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		output string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := Helper{Path: binary}.Service(ctx, "status")
		done <- result{output, err}
	}()

	cancel()
	select {
	case got := <-done:
		if got.err == nil {
			t.Fatalf("a killed helper returned output %q and no error", got.output)
		}
		if got.output != "" {
			t.Errorf("output = %q, want empty when the command was killed", got.output)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Service did not return after its context was cancelled")
	}
}
