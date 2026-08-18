package events

import "time"

type Type string

const (
	KnockReceived   Type = "knock.received"
	SequenceStarted Type = "knock.sequence_started"
	SequenceMatched Type = "knock.sequence_matched"
	SequenceFailed  Type = "knock.sequence_failed"
	AccessGranted   Type = "access.granted"
	AccessRevoked   Type = "access.revoked"
	CommandFailed   Type = "command.failed"
	KnockdStarted   Type = "knockd.started"
	KnockdStopped   Type = "knockd.stopped"
)

type Event struct {
	ID        string    `json:"id"`
	Type      Type      `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	Stage     int       `json:"stage,omitempty"`
	Message   string    `json:"message,omitempty"`
}
