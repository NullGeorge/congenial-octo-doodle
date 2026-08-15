package knockd

import (
	"testing"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		typ  events.Type
		ip   string
	}{
		{"matched", "sequence matched from 192.0.2.10", events.SequenceMatched, "192.0.2.10"},
		{"open", "open ssh for 192.0.2.10", events.AccessGranted, "192.0.2.10"},
		{"failed", "sequence failed from 198.51.100.5", events.SequenceFailed, "198.51.100.5"},
		{"unknown", "daemon started without an address", events.KnockdStarted, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseLine(tt.line)
			if !ok {
				t.Fatalf("ParseLine() did not recognize %q", tt.line)
			}
			if got.Type != tt.typ || got.SourceIP != tt.ip {
				t.Fatalf("ParseLine() = %#v, want type=%q ip=%q", got, tt.typ, tt.ip)
			}
		})
	}
}
