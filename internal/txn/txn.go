// Package txn is the apply+compensate (saga) framework for sftp-jailer's
// multi-step mutations. Per D-01..D-04 the framework is intentionally
// minimal: in-memory step stack, per-step compensators, abort-on-first-
// error, no persistent journal. Crash mid-Apply leaves the filesystem
// in whatever state the OS persisted; SAFE-03 backup + sshd -t + the
// doctor screen are the recovery path.
//
// Phase 4's 10-min systemd-run auto-revert (SAFE-04) is a SEPARATE
// mechanism layered on top via a wrapper Step that schedules the
// revert unit (D-05). This package itself stays pure.
//
// Compensator idempotency: per saga literature, compensators may run
// more than once if a higher-level wrapper retries a whole txn. Each
// Step constructor in steps.go documents whether its Compensate is
// idempotent (most are: re-running userdel after success returns
// an "unknown user" error which is treated as success at the call site).
package txn

import (
	"context"
	"errors"
	"fmt"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// Step is a single unit of work in a transactional batch.
type Step interface {
	// Name returns a short identifier used in error messages and audit
	// logs. Must be stable across runs (no embedded random IDs).
	Name() string

	// Apply performs the mutation. Returns nil on success; non-nil
	// triggers rollback of all prior Apply'd steps in reverse order.
	Apply(ctx context.Context, ops sysops.SystemOps) error

	// Compensate reverses the effect of Apply. Called in reverse order
	// for steps whose Apply previously returned nil. The Step whose
	// Apply failed is NOT compensated (its mutation is presumed not to
	// have taken effect — the contract for Apply is "atomic or no-op").
	Compensate(ctx context.Context, ops sysops.SystemOps) error
}

// Tx orchestrates the apply+compensate flow over a sysops.SystemOps.
// Single-use: do not call Apply twice on the same Tx — construct a new
// one per batch.
type Tx struct {
	ops     sysops.SystemOps
	applied []int // indices into the steps slice for which Apply returned nil
}

// New constructs a fresh Tx bound to ops.
func New(ops sysops.SystemOps) *Tx { return &Tx{ops: ops} }

// Apply runs steps sequentially. On the first non-nil Apply error, runs
// Compensate in reverse on the already-applied steps and returns the
// ORIGINAL error joined with any compensator errors via errors.Join.
//
// ctx-cancellation is checked before each Step.Apply; cancellation
// before the first step returns ctx.Err() with no mutations attempted.
// Cancellation between steps triggers rollback of the prior steps.
func (t *Tx) Apply(ctx context.Context, steps []Step) error {
	if len(steps) == 0 {
		return nil
	}
	for i, s := range steps {
		if err := ctx.Err(); err != nil {
			return t.rollback(ctx, steps, err)
		}
		if err := s.Apply(ctx, t.ops); err != nil {
			wrapped := fmt.Errorf("txn.Apply step %s: %w", s.Name(), err)
			return t.rollback(ctx, steps, wrapped)
		}
		t.applied = append(t.applied, i)
	}
	return nil
}

// rollback runs Compensate in reverse on the applied steps. Returns the
// original error joined with any compensator errors (errors.Join, Go
// 1.20+ stdlib). Compensator errors do NOT abort the rollback — the
// remaining compensators still run (best-effort cleanup).
func (t *Tx) rollback(ctx context.Context, steps []Step, applyErr error) error {
	var compErrs []error
	for i := len(t.applied) - 1; i >= 0; i-- {
		idx := t.applied[i]
		if idx < 0 || idx >= len(steps) {
			continue
		}
		// Compensators receive the original ctx. Per D-04 the framework
		// is intentionally minimal: we don't synthesize a fresh context
		// to "rescue" a cancelled rollback. sysops typed wrappers that
		// do not actually issue syscalls (Chmod/Chown/MkdirAll/RemoveAll)
		// tolerate a cancelled ctx; subprocess wrappers (Useradd/Tar)
		// will fail fast and the partial-rollback failure is captured
		// in compErrs and joined into the returned error.
		if err := steps[idx].Compensate(ctx, t.ops); err != nil {
			compErrs = append(compErrs, fmt.Errorf("compensate %s: %w", steps[idx].Name(), err))
		}
	}
	if len(compErrs) > 0 {
		return errors.Join(applyErr, errors.Join(compErrs...))
	}
	return applyErr
}
