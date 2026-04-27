// Package lockdown contains the progressive-lockdown flow's proposal
// generator (proposal.go in Plan 04-07), admin-IP detector (admin_ip.go
// in Plan 04-07), and a re-export of the SAFE-04 reverse-command
// renderer.
//
// The renderer itself lives in internal/revert (Plan 04-04) because
// it's conceptually about the revert payload. We re-export it under
// the lockdown package name because D-S04-09 step 2 names the caller
// path as `internal/lockdown.RenderReverseCommands`.
//
// This file is intentionally thin — the production logic lives in
// internal/revert/render_reverse.go. Tests for the renderer live there
// too (revert/render_reverse_test.go); the shim itself is exercised
// transitively by the M-ADD-RULE / M-DELETE-RULE / S-LOCKDOWN modal
// tests (plans 04-05 / 04-06 / 04-08).
package lockdown

import (
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
)

// PendingMutation is re-exported from internal/revert for callers that
// import the lockdown package directly (M-ADD-RULE, M-DELETE-RULE,
// S-LOCKDOWN commit).
type PendingMutation = revert.PendingMutation

// MutationOp is re-exported from internal/revert.
type MutationOp = revert.MutationOp

// OpAdd / OpDelete are re-exported from internal/revert.
const (
	OpAdd    = revert.OpAdd
	OpDelete = revert.OpDelete
)

// RenderReverseCommands re-exports revert.RenderReverseCommands.
// Per D-S04-09 step 2 the lockdown package is the named caller path
// for the reverse-command renderer; the implementation lives in
// internal/revert because it's conceptually about the revert payload.
func RenderReverseCommands(mutations []PendingMutation) []string {
	return revert.RenderReverseCommands(mutations)
}
