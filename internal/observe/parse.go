// Package observe parses journalctl JSON output from sshd and classifies
// each event into one of four tiers (success / targeted / noise / unmatched)
// per REQUIREMENTS.md LOG-05.
//
// Phase 1 scope is purely structural — the classifier decides the tier from
// the log line's shape alone. Phase 2 layers external lookups on top (is
// the user in the managed set? is the source IP in the firewall allowlist?)
// to refine "targeted" vs "noise" beyond the single-word sshd distinction.
//
// Parsing lives here; the journalctl shell-out (cursor-file handling, the
// --since/--until window, retention compaction) lands in Phase 2 via
// internal/service.ObserverService and internal/sysops.ReadSshJournal.
package observe

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// SshdEvent is the parsed form of a single journalctl JSON line from the
// `ssh` unit. Raw is the unchanged MESSAGE field so LOG-04's raw-line
// drill-down can show the original text.
type SshdEvent struct {
	Timestamp  time.Time
	PID        int
	Raw        string // MESSAGE field verbatim
	Identifier string // SYSLOG_IDENTIFIER (e.g. "sshd")
	Priority   string // PRIORITY (syslog level, kept as string — journald sends "5", "6", ...)
}

// journalJSONLine is the subset of journalctl --output=json fields we
// consume. journalctl emits timestamps as microseconds-since-epoch encoded
// as a decimal string; _PID is likewise a string. All other fields tolerated
// missing.
type journalJSONLine struct {
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Message           string `json:"MESSAGE"`
	PID               string `json:"_PID"`
	Identifier        string `json:"SYSLOG_IDENTIFIER"`
	Priority          string `json:"PRIORITY"`
}

// Parse decodes one journalctl --output=json line into an SshdEvent.
// Returns a non-nil error for malformed JSON or a missing MESSAGE field.
// Timestamp conversion failures degrade to a zero time.Time but do not
// fail the parse — the raw message is the primary payload.
func Parse(line []byte) (SshdEvent, error) {
	var j journalJSONLine
	if err := json.Unmarshal(line, &j); err != nil {
		return SshdEvent{}, fmt.Errorf("observe.Parse: %w", err)
	}
	if j.Message == "" {
		return SshdEvent{}, fmt.Errorf("observe.Parse: missing MESSAGE")
	}
	var ts time.Time
	if j.RealtimeTimestamp != "" {
		micros, err := strconv.ParseInt(j.RealtimeTimestamp, 10, 64)
		if err == nil {
			ts = time.Unix(0, micros*int64(time.Microsecond)).UTC()
		}
	}
	pid, _ := strconv.Atoi(j.PID)
	return SshdEvent{
		Timestamp:  ts,
		PID:        pid,
		Raw:        j.Message,
		Identifier: j.Identifier,
		Priority:   j.Priority,
	}, nil
}
