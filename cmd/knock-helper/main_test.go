package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NullGeorge/congenial-octo-doodle/internal/version"
)

// The whole point of this binary is that a caller argument can never become
// nft syntax. These cases are the ones that would matter if it could.
func TestAllowArgsRejectsAnythingButAPublicIPv4(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "injection attempt with a brace", address: "1.2.3.4 } ; flush ruleset ; {"},
		{name: "injection attempt with a newline", address: "1.2.3.4\nflush ruleset"},
		{name: "hostname", address: "example.com"},
		{name: "ipv6", address: "2001:4860:4860::8888"},
		{name: "cidr range", address: "1.2.3.0/24"},
		{name: "private address", address: "192.168.1.10"},
		{name: "loopback", address: "127.0.0.1"},
		{name: "empty", address: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := allowArgs(tt.address, "15m"); err == nil {
				t.Fatalf("allowArgs accepted %q", tt.address)
			}
		})
	}
}

func TestAllowArgsBuildsAFixedTemplate(t *testing.T) {
	argv, err := allowArgs("203.0.113.5", "15m")
	if err != nil {
		t.Fatalf("allowArgs: %v", err)
	}
	want := "add element inet portknock ssh_allowed { 203.0.113.5 timeout 900s }"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

// A grant must not be permanent, and must not be so short it is pointless.
func TestAllowArgsBoundsTheLifetime(t *testing.T) {
	tests := []struct {
		duration string
		ok       bool
	}{
		{duration: "15m", ok: true},
		{duration: "1m", ok: true},
		{duration: "24h", ok: true},
		{duration: "30s"},
		{duration: "25h"},
		{duration: "8760h"},
		{duration: "-15m"},
		{duration: "forever"},
		{duration: ""},
	}

	for _, tt := range tests {
		_, err := allowArgs("203.0.113.5", tt.duration)
		if tt.ok && err != nil {
			t.Errorf("allowArgs rejected %q: %v", tt.duration, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("allowArgs accepted %q", tt.duration)
		}
	}
}

func TestRevokeArgs(t *testing.T) {
	argv, err := revokeArgs("198.51.100.167")
	if err != nil {
		t.Fatalf("revokeArgs: %v", err)
	}
	want := "delete element inet portknock ssh_allowed { 198.51.100.167 }"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
	if _, err := revokeArgs("; flush ruleset"); err == nil {
		t.Fatal("revokeArgs accepted a non-address")
	}
}

// systemctl must only ever be reached with a whitelisted verb and this one
// unit, so no argument can select another service.
func TestServiceArgs(t *testing.T) {
	for verb, want := range map[string]string{
		"start":   "start knockd",
		"stop":    "stop knockd",
		"restart": "restart knockd",
		"status":  "is-active knockd",
	} {
		argv, err := serviceArgs(verb)
		if err != nil {
			t.Fatalf("serviceArgs(%q): %v", verb, err)
		}
		if got := strings.Join(argv, " "); got != want {
			t.Errorf("serviceArgs(%q) = %q, want %q", verb, got, want)
		}
	}

	for _, verb := range []string{"", "reboot", "isolate", "start sshd", "daemon-reload", "--version"} {
		if _, err := serviceArgs(verb); err == nil {
			t.Errorf("serviceArgs accepted %q", verb)
		}
	}
}

// A malformed invocation must be refused before anything is executed. This is
// the difference between a helper that only ever runs one nft command and one
// that can be talked into running something else.
func TestRunRejectsBadInvocationsWithoutExecutingAnything(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	useStubs(t,
		fakeBinary(t, dir, "nft", log, "", 0),
		fakeBinary(t, dir, "systemctl", log, "", 0))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", args: nil, want: "usage: knock-helper <allow"},
		{name: "unknown verb", args: []string{"flush"}, want: "usage: knock-helper <allow"},
		// The switch is on an exact string, so a differently cased verb is not
		// a near miss to be helpful about.
		{name: "wrong case", args: []string{"Allow", "203.0.113.5", "15m"}, want: "usage: knock-helper <allow"},
		{name: "flag instead of a verb", args: []string{"--help"}, want: "usage: knock-helper <allow"},
		{name: "allow without arguments", args: []string{"allow"}, want: "usage: knock-helper allow"},
		{name: "allow without a duration", args: []string{"allow", "203.0.113.5"}, want: "usage: knock-helper allow"},
		{name: "allow with a trailing extra", args: []string{"allow", "203.0.113.5", "15m", "now"}, want: "usage: knock-helper allow"},
		{name: "revoke without an address", args: []string{"revoke"}, want: "usage: knock-helper revoke"},
		{name: "revoke with two addresses", args: []string{"revoke", "203.0.113.5", "198.51.100.167"}, want: "usage: knock-helper revoke"},
		{name: "service without a verb", args: []string{"service"}, want: "usage: knock-helper service"},
		{name: "service with an extra word", args: []string{"service", "start", "knockd"}, want: "usage: knock-helper service"},
		// Argument validation happens before the command is built, so a bad
		// address is refused even though the argument count is right.
		{name: "allow with a private address", args: []string{"allow", "192.168.1.10", "15m"}, want: "not a routable public address"},
		{name: "allow with an unusable duration", args: []string{"allow", "203.0.113.5", "99h"}, want: "outside the allowed range"},
		{name: "revoke with an injection attempt", args: []string{"revoke", "1.2.3.4 } ; flush ruleset ; {"}, want: "is not an ip address"},
		{name: "service with an unlisted verb", args: []string{"service", "reboot"}, want: "unknown verb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args)
			if err == nil {
				t.Fatalf("run(%q) succeeded", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run(%q) error = %q, want it to mention %q", tt.args, err, tt.want)
			}
		})
	}

	if calls := readCalls(t, log); len(calls) != 0 {
		t.Errorf("a rejected invocation still executed something: %q", calls)
	}
}

func TestRunAllowExecutesTheBuiltNftCommand(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	useStubs(t, fakeBinary(t, dir, "nft", log, "", 0), filepath.Join(dir, "absent"))

	out := captureStdout(t, func() {
		if err := run([]string{"allow", "203.0.113.5", "15m"}); err != nil {
			t.Fatalf("run allow: %v", err)
		}
	})

	want := "add element inet portknock ssh_allowed { 203.0.113.5 timeout 900s }"
	if calls := readCalls(t, log); len(calls) != 1 || calls[0] != want {
		t.Errorf("nft calls = %q, want exactly one %q", calls, want)
	}
	if !strings.Contains(out, "allowed 203.0.113.5 for 15m") {
		t.Errorf("stdout = %q, want it to confirm the grant", out)
	}
}

func TestRunRevokeExecutesTheBuiltNftCommand(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	useStubs(t, fakeBinary(t, dir, "nft", log, "", 0), filepath.Join(dir, "absent"))

	out := captureStdout(t, func() {
		if err := run([]string{"revoke", "198.51.100.167"}); err != nil {
			t.Fatalf("run revoke: %v", err)
		}
	})

	want := "delete element inet portknock ssh_allowed { 198.51.100.167 }"
	if calls := readCalls(t, log); len(calls) != 1 || calls[0] != want {
		t.Errorf("nft calls = %q, want exactly one %q", calls, want)
	}
	if !strings.Contains(out, "revoked 198.51.100.167") {
		t.Errorf("stdout = %q, want it to confirm the revocation", out)
	}
}

// A firewall command that fails must not be reported as a grant, and the
// operator needs nft's own complaint to work out why.
func TestRunReportsAFailedNftCommand(t *testing.T) {
	tests := []struct {
		verb string
		args []string
		want string
	}{
		{verb: "allow", args: []string{"allow", "203.0.113.5", "15m"}, want: "add element"},
		{verb: "revoke", args: []string{"revoke", "203.0.113.5"}, want: "delete element"},
	}

	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			useStubs(t, fakeBinary(t, dir, "nft", log, "Error: No such file or directory", 1),
				filepath.Join(dir, "absent"))

			err := run(tt.args)
			if err == nil {
				t.Fatalf("run %s succeeded although nft failed", tt.verb)
			}
			for _, want := range []string{"nft", tt.want, "exit status 1", "Error: No such file or directory"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestRunServiceStartsTheUnit(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	useStubs(t, filepath.Join(dir, "absent"), fakeBinary(t, dir, "systemctl", log, "", 0))

	out := captureStdout(t, func() {
		if err := run([]string{"service", "restart"}); err != nil {
			t.Fatalf("run service restart: %v", err)
		}
	})

	if calls := readCalls(t, log); len(calls) != 1 || calls[0] != "restart knockd" {
		t.Errorf("systemctl calls = %q, want exactly one %q", calls, "restart knockd")
	}
	if !strings.Contains(out, "knockd restart ok") {
		t.Errorf("stdout = %q, want it to confirm the restart", out)
	}
}

func TestRunServiceReportsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	useStubs(t, filepath.Join(dir, "absent"),
		fakeBinary(t, dir, "systemctl", log, "Failed to start knockd.service: Unit not found.", 5))

	err := run([]string{"service", "start"})
	if err == nil {
		t.Fatal("run service start succeeded although systemctl failed")
	}
	for _, want := range []string{"systemctl start", "exit status 5", "Unit not found."} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// systemctl is-active exits non-zero for a stopped unit. That is the answer to
// the question, not a failure to answer it, so status must still print it and
// succeed.
func TestRunServiceStatusReportsAStoppedUnit(t *testing.T) {
	tests := []struct {
		name   string
		output string
		status int
		want   string
	}{
		{name: "running", output: "active", status: 0, want: "active\n"},
		{name: "stopped", output: "inactive", status: 3, want: "inactive\n"},
		{name: "failed", output: "failed", status: 3, want: "failed\n"},
		// A silent systemctl leaves nothing to print, and an empty line would
		// read as a missing answer rather than an unknown one.
		{name: "no output at all", output: "", status: 4, want: "unknown\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			useStubs(t, filepath.Join(dir, "absent"),
				fakeBinary(t, dir, "systemctl", log, tt.output, tt.status))

			out := captureStdout(t, func() {
				if err := run([]string{"service", "status"}); err != nil {
					t.Fatalf("run service status: %v", err)
				}
			})
			if out != tt.want {
				t.Errorf("stdout = %q, want %q", out, tt.want)
			}
			if calls := readCalls(t, log); len(calls) != 1 || calls[0] != "is-active knockd" {
				t.Errorf("systemctl calls = %q, want exactly one %q", calls, "is-active knockd")
			}
		})
	}
}

func TestRunVersionPrintsTheBuildIdentity(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"version"}); err != nil {
			t.Fatalf("run version: %v", err)
		}
	})
	if want := "knock-helper " + version.String() + "\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestExecuteSucceedsSilently(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	binary := fakeBinary(t, dir, "nft", log, "this output is discarded on success", 0)

	if err := execute(binary, []string{"add", "element"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls := readCalls(t, log); len(calls) != 1 || calls[0] != "add element" {
		t.Errorf("calls = %q, want exactly one %q", calls, "add element")
	}
}

// The error is the only diagnostic the operator gets, so it has to name the
// binary, the arguments and whatever the binary said before it gave up.
func TestExecuteCarriesTheBinaryAndItsOutput(t *testing.T) {
	dir := t.TempDir()
	binary := fakeBinary(t, dir, "nft", filepath.Join(dir, "calls"),
		"Error: Could not process rule: No such file or directory", 1)

	err := execute(binary, []string{"delete", "element", "inet", "portknock"})
	if err == nil {
		t.Fatal("execute reported success for a failing binary")
	}
	for _, want := range []string{binary, "delete element inet portknock", "exit status 1", "Could not process rule"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func TestExecuteReportsAMissingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nft")
	err := execute(missing, []string{"add", "element"})
	if err == nil {
		t.Fatal("execute reported success although the binary does not exist")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error = %q, want it to name %q", err, missing)
	}
}

// useStubs points the helper at stand-in binaries for one test and puts the
// real absolute paths back afterwards.
func useStubs(t *testing.T, nft, systemctl string) {
	t.Helper()
	realNft, realSystemctl := nftPath, systemctlPath
	nftPath, systemctlPath = nft, systemctl
	t.Cleanup(func() { nftPath, systemctlPath = realNft, realSystemctl })
}

// fakeBinary writes an executable that appends its own arguments to logPath,
// prints output and exits with status, standing in for nft or systemctl.
func fakeBinary(t *testing.T, dir, name, logPath, output string, status int) string {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(logPath) + "\n"
	if output != "" {
		script += "printf '%s\\n' " + shellQuote(output) + "\n"
	}
	script += "exit " + strconv.Itoa(status) + "\n"

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
	return path
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readCalls returns one entry per stub invocation. A missing log file means the
// stub was never run, which several tests assert.
func readCalls(t *testing.T, logPath string) []string {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// captureStdout collects what fn prints, because the confirmation text is the
// only thing the caller of this binary sees on success.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	real := os.Stdout
	os.Stdout = file
	// Restoring through Cleanup too, so a t.Fatalf inside fn cannot leave the
	// rest of the run writing into this temp file.
	t.Cleanup(func() { os.Stdout = real })

	fn()

	os.Stdout = real
	if err := file.Close(); err != nil {
		t.Fatalf("close stdout file: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(raw)
}
