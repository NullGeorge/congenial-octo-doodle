package knockd

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// ParseLine performs conservative parsing of common knockd log messages.
// Unknown messages are intentionally ignored rather than guessed.
func ParseLine(line string) (events.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return events.Event{}, false
	}

	ip := extractIP(line)
	lower := strings.ToLower(line)

	switch {
	case strings.Contains(lower, "starting knockd") || strings.Contains(lower, "server started"):
		return events.Event{Type: events.KnockdStarted, Message: line}, true
	case strings.Contains(lower, "stopping knockd") || strings.Contains(lower, "server stopped"):
		return events.Event{Type: events.KnockdStopped, Message: line}, true
	case strings.Contains(lower, "open") && ip != "":
		return events.Event{Type: events.AccessGranted, SourceIP: ip, Message: line}, true
	case strings.Contains(lower, "close") && ip != "":
		return events.Event{Type: events.AccessRevoked, SourceIP: ip, Message: line}, true
	case strings.Contains(lower, "sequence") && strings.Contains(lower, "matched"):
		return events.Event{Type: events.SequenceMatched, SourceIP: ip, Message: line}, true
	case strings.Contains(lower, "sequence") && (strings.Contains(lower, "failed") || strings.Contains(lower, "invalid")):
		return events.Event{Type: events.SequenceFailed, SourceIP: ip, Message: line}, true
	case ip != "":
		return events.Event{Type: events.KnockReceived, SourceIP: ip, Message: line}, true
	default:
		return events.Event{}, false
	}
}

func extractIP(line string) string {
	candidate := ipPattern.FindString(line)
	if candidate == "" {
		return ""
	}
	if _, err := netip.ParseAddr(candidate); err != nil {
		return ""
	}
	return candidate
}
