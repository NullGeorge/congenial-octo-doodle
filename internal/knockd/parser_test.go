package knockd

import (
	"testing"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		typ  events.Type
		ip   string
	}{
		{"matched", "sequence matched from 192.0.2.10", true, events.SequenceMatched, "192.0.2.10"},
		{"open", "open ssh for 192.0.2.10", true, events.AccessGranted, "192.0.2.10"},
		{"failed", "sequence failed from 198.51.100.5", true, events.SequenceFailed, "198.51.100.5"},
		{"started", "starting knockd", true, events.KnockdStarted, ""},
		{"knock", "knock from 203.0.113.7 on port 1234", true, events.KnockReceived, "203.0.113.7"},
		{"unknown", "daemon started without an address", false, "", ""},
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
			if got.Type != tt.typ || got.SourceIP != tt.ip {
				t.Fatalf("ParseLine() = %#v, want type=%q ip=%q", got, tt.typ, tt.ip)
			}
		})
	}
}
