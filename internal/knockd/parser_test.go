package knockd

import (
	"testing"
	"time"

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
		ttl   time.Duration
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
			ttl: 15 * time.Minute,
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
			if got.TTL != tt.ttl {
				t.Errorf("ttl = %s, want %s", got.TTL, tt.ttl)
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

// The lifetime written into the grant command is the only way to know when
// access lapses without CAP_NET_ADMIN, so both the nftables spelling (15m)
// and the ipset spelling (bare seconds) have to parse.
func TestParseCommandTTL(t *testing.T) {
	tests := []struct {
		spec string
		want time.Duration
		ok   bool
	}{
		{spec: "15m", want: 15 * time.Minute, ok: true},
		{spec: "900s", want: 15 * time.Minute, ok: true},
		{spec: "900", want: 15 * time.Minute, ok: true},
		{spec: "1d2h3m4s", want: 26*time.Hour + 3*time.Minute + 4*time.Second, ok: true},
		// Rejected: a zero lifetime, a unit with no number, an unknown unit,
		// nothing at all, and a value too large to be a real firewall grant.
		{spec: "0m"},
		{spec: "m"},
		{spec: "15x"},
		{spec: ""},
		{spec: "99999999999999999999d"},
	}

	for _, tt := range tests {
		got, ok := parseCommandTTL(tt.spec)
		if ok != tt.ok {
			t.Errorf("parseCommandTTL(%q) ok = %v, want %v", tt.spec, ok, tt.ok)
			continue
		}
		if got != tt.want {
			t.Errorf("parseCommandTTL(%q) = %s, want %s", tt.spec, got, tt.want)
		}
	}
}

// A log line is untrusted input: knockd interpolates whatever the kernel
// reported, and the shape-matching regexes are deliberately loose. These are
// the branches that keep a malformed line from becoming a malformed event.
func TestParseLineRejectsMalformedAddresses(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		typ  events.Type
		ip   string
	}{
		{
			// The prefix regex matches four dotted numbers, which is not the
			// same as matching an address.
			name: "octet out of range in the client prefix",
			line: "999.1.1.1: openSSH: Stage 1",
		},
		{
			name: "octet out of range inside a command",
			line: "openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { 300.1.2.3 timeout 15m }",
			ok:   true, typ: events.AccessGranted, ip: "",
		},
		{
			// A grant with no address at all is still a grant; it just cannot
			// be attributed. Dropping it would hide a firewall change.
			name: "command carries no address",
			line: "openSSH: running command: /usr/sbin/nft add element inet portknock ssh_allowed { }",
			ok:   true, typ: events.AccessGranted, ip: "",
		},
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
		})
	}
}

// A stage number too large for an int must not take the parser down. The
// sequence is still recognised, only the number is dropped.
func TestParseLineSurvivesAnAbsurdStageNumber(t *testing.T) {
	const line = "203.0.113.5: openSSH: Stage 99999999999999999999"
	got, ok := ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine(%q) gave up on an oversized stage", line)
	}
	if got.Stage != 0 {
		t.Errorf("stage = %d, want 0 for a number that does not fit", got.Stage)
	}
	if got.Type != events.SequenceStarted {
		t.Errorf("type = %q, want %q", got.Type, events.SequenceStarted)
	}
}

// Units are summed, so a lifetime can cross the ceiling part way through the
// spec rather than in a single component.
func TestParseCommandTTLRejectsAnAccumulatedOverflow(t *testing.T) {
	if ttl, ok := parseCommandTTL("300d300d"); ok {
		t.Errorf("parseCommandTTL(\"300d300d\") = %s, want a refusal past the one year ceiling", ttl)
	}
}
