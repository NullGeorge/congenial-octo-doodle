package main

import (
	"strings"
	"testing"
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
