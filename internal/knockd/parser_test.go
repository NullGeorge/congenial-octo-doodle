package knockd

import (
	"testing"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

// The recognised lines below are verbatim knockd output captured from a live
// Debian 12 host running knockd 0.8-2+b4 with nftables.
func TestParseLine(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		ok    bool
		typ   events.Type
		ip    string
		rule  string
		stage int
	}{
		{
			name: "first stage", line: "203.0.113.209: openSSH: Stage 1", ok: true,
			typ: events.SequenceStarted, ip: "203.0.113.209", rule: "openSSH", stage: 1,
		},
		{
			name: "later stage", line: "203.0.113.209: openSSH: Stage 3", ok: true,
			typ: events.KnockReceived, ip: "203.0.113.209", rule: "openSSH", stage: 3,
		},
		{
			name: "sequence matched", line: "203.0.113.209: openSSH: OPEN SESAME", ok: true,
			typ: events.SequenceMatched, ip: "203.0.113.209", rule: "openSSH",
		},
		{
			name: "sequence timeout", line: "192.0.2.134: openSSH: sequence timeout (stage 1)", ok: true,
			typ: events.SequenceFailed, ip: "192.0.2.134", rule: "openSSH", stage: 1,
		},
		{
			name: "close sequence stage", line: "203.0.113.209: closeSSH: Stage 1", ok: true,
			typ: events.SequenceStarted, ip: "203.0.113.209", rule: "closeSSH", stage: 1,
		},
		{
			name: "grant via nftables",
			line: "openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.209 timeout 15m }",
			ok:   true, typ: events.AccessGranted, ip: "203.0.113.209", rule: "openSSH",
		},
		{
			name: "revoke via nftables",
			line: "closeSSH: running command: /usr/sbin/nft delete element inet portknock ssh_allowed { 203.0.113.209 }",
			ok:   true, typ: events.AccessRevoked, ip: "203.0.113.209", rule: "closeSSH",
		},
		{
			name: "grant via iptables",
			line: "openSSH: running command: /sbin/iptables -A INPUT -s 203.0.113.7 -p tcp --dport 22 -j ACCEPT",
			ok:   true, typ: events.AccessGranted, ip: "203.0.113.7", rule: "openSSH",
		},
		{
			name: "revoke via iptables",
			line: "closeSSH: running command: /sbin/iptables -D INPUT -s 203.0.113.7 -p tcp --dport 22 -j ACCEPT",
			ok:   true, typ: events.AccessRevoked, ip: "203.0.113.7", rule: "closeSSH",
		},
		{
			name: "command failed", line: "closeSSH: command returned non-zero status code (1)", ok: true,
			typ: events.CommandFailed, rule: "closeSSH",
		},
		{
			name: "daemon started", line: "starting up, listening on enp2s0", ok: true,
			typ: events.KnockdStarted,
		},
		{
			name: "daemon stopped", line: "shutting down", ok: true,
			typ: events.KnockdStopped,
		},
		// Anything knockd does not describe stays unclassified on purpose.
		{name: "firewall tool error", line: "Error: Could not process rule: No such file or directory"},
		{name: "command is neither grant nor revoke", line: "openSSH: running command: /usr/local/bin/notify 203.0.113.209"},
		{name: "unrelated message", line: "daemon started without an address"},
		{name: "blank", line: "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ParseLine(%q) ok = %v, want %v", tt.line, ok, tt.ok)
			}
			if !tt.ok {
				if got != (events.Event{}) {
					t.Fatalf("ParseLine(%q) = %#v, want zero Event", tt.line, got)
				}
				return
			}
			if got.Type != tt.typ {
				t.Errorf("type = %q, want %q", got.Type, tt.typ)
			}
			if got.SourceIP != tt.ip {
				t.Errorf("source ip = %q, want %q", got.SourceIP, tt.ip)
			}
			if got.Rule != tt.rule {
				t.Errorf("rule = %q, want %q", got.Rule, tt.rule)
			}
			if got.Stage != tt.stage {
				t.Errorf("stage = %d, want %d", got.Stage, tt.stage)
			}
			if got.Message != tt.line {
				t.Errorf("message = %q, want %q", got.Message, tt.line)
			}
		})
	}
}

// Section names are operator-chosen, so "openSSH" shows up in every line of a
// sequence. Classifying on that substring reported one knock as five grants
// and reported timeouts as grants too; a whole sequence must yield exactly one.
func TestParseLineSequenceYieldsSingleGrant(t *testing.T) {
	sequence := []string{
		"203.0.113.209: openSSH: Stage 1",
		"203.0.113.209: openSSH: Stage 2",
		"203.0.113.209: openSSH: Stage 3",
		"203.0.113.209: openSSH: OPEN SESAME",
		"openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 203.0.113.209 timeout 15m }",
	}

	counts := make(map[events.Type]int, len(sequence))
	for _, line := range sequence {
		event, ok := ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) ignored a real knockd line", line)
		}
		counts[event.Type]++
	}

	if counts[events.AccessGranted] != 1 {
		t.Errorf("access.granted = %d, want exactly 1", counts[events.AccessGranted])
	}
	if counts[events.SequenceMatched] != 1 {
		t.Errorf("sequence matched = %d, want exactly 1", counts[events.SequenceMatched])
	}
	if counts[events.SequenceFailed] != 0 {
		t.Errorf("sequence failed = %d, want 0", counts[events.SequenceFailed])
	}
}

// A sequence that never completed must not grant anything.
func TestParseLineTimeoutNeverGrants(t *testing.T) {
	event, ok := ParseLine("192.0.2.134: openSSH: sequence timeout (stage 1)")
	if !ok {
		t.Fatal("ParseLine() ignored a real timeout line")
	}
	if event.Type == events.AccessGranted {
		t.Fatal("a timed-out sequence was reported as access.granted")
	}
	if event.Type != events.SequenceFailed {
		t.Fatalf("type = %q, want %q", event.Type, events.SequenceFailed)
	}
}
