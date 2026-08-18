package knockd

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/NullGeorge/congenial-octo-doodle/internal/events"
)

// knockd writes one of three shapes to its log:
//
//	<source-ip>: <section>: <message>   per-client sequence progress
//	<section>: <message>                commands run once a sequence matched
//	<daemon message>                    lifecycle notices
//
// Section names are chosen by the operator (openSSH, closeSSH, ...) and carry
// no meaning on their own, so classification never looks at them: a matched
// sequence is reported as such, and grant versus revoke is decided by the
// firewall command knockd actually executed.
var (
	ipPattern       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	clientLine      = regexp.MustCompile(`^((?:\d{1,3}\.){3}\d{1,3}): ([^:]+): (.+)$`)
	sectionLine     = regexp.MustCompile(`^([^:]+): (.+)$`)
	stageMessage    = regexp.MustCompile(`^Stage (\d+)$`)
	timeoutMessage  = regexp.MustCompile(`^sequence timeout \(stage (\d+)\)$`)
	statusMessage   = regexp.MustCompile(`^command returned non-zero status code \(\d+\)$`)
	grantingCommand = regexp.MustCompile(`(?:^|\s)(?:add|insert|-A|-I)(?:\s|$)`)
	revokingCommand = regexp.MustCompile(`(?:^|\s)(?:delete|del|remove|-D)(?:\s|$)`)
)

const runningCommand = "running command: "

// ParseLine performs conservative parsing of knockd log messages.
// Unknown messages are intentionally ignored rather than guessed.
func ParseLine(line string) (events.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return events.Event{}, false
	}

	// Lifecycle notices carry neither a source address nor a section.
	switch {
	case strings.HasPrefix(line, "starting up"):
		return events.Event{Type: events.KnockdStarted, Message: line}, true
	case strings.HasPrefix(line, "shutting down"):
		return events.Event{Type: events.KnockdStopped, Message: line}, true
	}

	event := events.Event{Message: line}
	var message string
	if m := clientLine.FindStringSubmatch(line); m != nil {
		if _, err := netip.ParseAddr(m[1]); err != nil {
			return events.Event{}, false
		}
		event.SourceIP, event.Rule, message = m[1], m[2], m[3]
	} else if m := sectionLine.FindStringSubmatch(line); m != nil {
		event.Rule, message = m[1], m[2]
	} else {
		return events.Event{}, false
	}

	// Command lines have no address prefix; knockd interpolates it into the
	// command itself, which is also the only reliable grant/revoke signal.
	if command, ok := strings.CutPrefix(message, runningCommand); ok {
		if event.SourceIP == "" {
			event.SourceIP = extractIP(command)
		}
		granting := grantingCommand.MatchString(command)
		revoking := revokingCommand.MatchString(command)
		switch {
		case granting && !revoking:
			event.Type = events.AccessGranted
		case revoking && !granting:
			event.Type = events.AccessRevoked
		default:
			return events.Event{}, false
		}
		return event, true
	}

	if message == "OPEN SESAME" {
		event.Type = events.SequenceMatched
		return event, true
	}
	if m := stageMessage.FindStringSubmatch(message); m != nil {
		event.Stage = parseStage(m[1])
		if event.Stage > 1 {
			event.Type = events.KnockReceived
		} else {
			event.Type = events.SequenceStarted
		}
		return event, true
	}
	if m := timeoutMessage.FindStringSubmatch(message); m != nil {
		event.Stage = parseStage(m[1])
		event.Type = events.SequenceFailed
		return event, true
	}
	if statusMessage.MatchString(message) {
		event.Type = events.CommandFailed
		return event, true
	}
	return events.Event{}, false
}

// parseStage reports the stage number, or 0 when it does not fit an int.
func parseStage(digits string) int {
	stage, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return stage
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
