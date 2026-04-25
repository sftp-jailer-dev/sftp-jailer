package observe

import (
	"encoding/json"
	"fmt"
	"io"
)

// Phase is one of the typed JSON progress events emitted by Runner.Run to
// stdout per CONTEXT.md D-02. The set is closed: read | classify | compact
// | skipped | done.
type Phase string

// Phase values per D-02 stdout JSON contract.
const (
	PhaseRead     Phase = "read"
	PhaseClassify Phase = "classify"
	PhaseCompact  Phase = "compact"
	PhaseSkipped  Phase = "skipped"
	PhaseDone     Phase = "done"
)

// Progress is the line-delimited JSON envelope emitted by JSONEmitter.
// Field omitempty discipline keeps unrelated fields out of any single
// phase's emit (e.g. `read` only carries `count`, not `kept`).
type Progress struct {
	Phase         Phase       `json:"phase"`
	Count         int         `json:"count,omitempty"`
	Kept          int         `json:"kept,omitempty"`
	Compacted     int         `json:"compacted,omitempty"`
	Dropped       int         `json:"dropped,omitempty"`
	CountersAdded int         `json:"counters_added,omitempty"`
	Reason        string      `json:"reason,omitempty"`
	Summary       *RunSummary `json:"summary,omitempty"`
}

// Emitter is the seam used by Runner to push progress events. Two
// implementations ship here: JSONEmitter for production use; NopEmitter
// for tests that want to inspect Progress values without parsing JSON.
type Emitter interface {
	Emit(Progress) error
}

// JSONEmitter serializes each Progress to a single line of NDJSON on W.
// When Quiet is true, only the terminal phases (`done`, `skipped`) are
// emitted — useful for systemd-timer runs that only want a final summary
// line in journald.
type JSONEmitter struct {
	W     io.Writer
	Quiet bool
}

// Emit writes p as a single JSON line to e.W.
func (e *JSONEmitter) Emit(p Progress) error {
	if e.Quiet && p.Phase != PhaseDone && p.Phase != PhaseSkipped {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("observe.JSONEmitter marshal: %w", err)
	}
	if _, err := e.W.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("observe.JSONEmitter write: %w", err)
	}
	return nil
}

// NopEmitter records every Progress in Calls so tests can assert on the
// sequence without parsing JSON.
type NopEmitter struct{ Calls []Progress }

// Emit appends p to e.Calls.
func (e *NopEmitter) Emit(p Progress) error {
	e.Calls = append(e.Calls, p)
	return nil
}

// EmitSkipped is a convenience for the cobra observe-run subcommand to emit
// a single `{"phase":"skipped","reason":…}` line when the lockfile is
// already held by another process. Kept here (rather than inside the cobra
// package) so the runner package owns the entire D-02 stdout contract.
func EmitSkipped(w io.Writer, reason string) error {
	return (&JSONEmitter{W: w}).Emit(Progress{Phase: PhaseSkipped, Reason: reason})
}
