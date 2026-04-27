// Package revert owns the SAFE-04 armed-revert state — the in-process
// singleton + on-disk pointer file (D-S04-06). The TUI reads the
// current state via Get(); txn Steps mutate via Set/Clear. Survives
// TUI crashes via Restore() on next startup.
//
// Architectural invariants:
//   - All filesystem reads/writes go through sysops.SystemOps — this
//     package never imports os.
//   - PointerPath is in the sysops AtomicWriteFile allowlist (Plan
//     04-01 added /var/lib/sftp-jailer/ as a prefix).
//   - Watcher implicitly satisfies the txn.RevertWatcher adapter
//     interface (Plan 04-02). A compile-time check lives in
//     watcher_test.go (TestWatcher_satisfies_txn_RevertWatcher_interface)
//     so a future signature drift on either side surfaces immediately.
package revert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// pointerPath is the on-disk JSON pointer file. Tests redirect via
// SetPointerPathForTest. Production value is /var/lib/sftp-jailer/revert.active
// (allowlisted by sysops.AtomicWriteFile per Plan 04-01).
var (
	pointerPathMu sync.Mutex
	pointerPath   = "/var/lib/sftp-jailer/revert.active"
)

// PointerPath returns the current pointer-file path (production default
// or test-overridden via SetPointerPathForTest).
func PointerPath() string {
	pointerPathMu.Lock()
	defer pointerPathMu.Unlock()
	return pointerPath
}

// State is the JSON shape persisted to PointerPath.
//
// The reverseCmds slice is intentionally NOT serialized — it is baked
// into the systemd-run unit's ExecStart (D-S04-08), so it is already
// authoritative there. Restore() therefore does not repopulate
// ReverseCommands(); the next Set call reseeds it.
type State struct {
	UnitName       string `json:"unit"`
	DeadlineUnixNs int64  `json:"deadline_unix_ns"`
}

// Watcher is the in-process singleton tracking the active SAFE-04
// revert window. Construct once via New; share across the TUI program.
//
// Thread safety: all methods are mutex-guarded. Get / ReverseCommands
// return defensive copies so callers cannot mutate internal state.
type Watcher struct {
	mu          sync.Mutex
	ops         sysops.SystemOps
	state       *State
	reverseCmds []string // surfaced to countdown UI for "View countdown"
}

// New constructs a Watcher with the given sysops handle. Does NOT
// restore prior state — call Restore explicitly at TUI startup.
func New(ops sysops.SystemOps) *Watcher {
	return &Watcher{ops: ops}
}

// Set arms a new revert. Writes pointer file (atomic) + sets in-process
// state. Idempotent: overwrites prior pointer (the SAFE-04 concurrent-
// mutation guard in D-S04-07 prevents this from happening in normal
// operation, but Force-unlock leaves it valid).
func (w *Watcher) Set(ctx context.Context, unitName string, deadline time.Time, reverseCmds []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	st := State{
		UnitName:       unitName,
		DeadlineUnixNs: deadline.UnixNano(),
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("revert.Set marshal: %w", err)
	}
	if err := w.ops.AtomicWriteFile(ctx, PointerPath(), data, 0o600); err != nil {
		return fmt.Errorf("revert.Set write pointer %s: %w", PointerPath(), err)
	}
	w.state = &st
	// Defensive copy of the slice so the caller can't mutate it.
	w.reverseCmds = append([]string(nil), reverseCmds...)
	return nil
}

// Clear removes the pointer file + clears in-process state. Safe to
// call when nothing is armed (no-op).
func (w *Watcher) Clear(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove pointer if it exists; ENOENT is fine.
	if err := w.ops.RemoveAll(ctx, PointerPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("revert.Clear remove pointer %s: %w", PointerPath(), err)
	}
	w.state = nil
	w.reverseCmds = nil
	return nil
}

// Get returns a defensive copy of the current state, or nil when no
// revert is armed. Read-only — does not need a context.
func (w *Watcher) Get() *State {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == nil {
		return nil
	}
	s := *w.state
	return &s
}

// ReverseCommands returns a copy of the reverseCmds slice for the
// current armed revert (nil when nothing armed or no commands set).
// Callers may mutate the returned slice freely.
func (w *Watcher) ReverseCommands() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.reverseCmds) == 0 {
		return nil
	}
	return append([]string(nil), w.reverseCmds...)
}

// Restore reads the on-disk pointer at TUI startup and reconciles the
// in-process state.
//
// Returns:
//   - (false, nil): pointer not found (clean state) OR pointer found
//     and unit still active (state restored).
//   - (true, nil):  pointer found but unit is no longer active — the
//     transient unit fired (timer expired) OR was killed externally.
//     The pointer file is auto-cleared. Caller should surface a toast
//     "Revert window fired — pre-change rules restored" + rebuild the
//     FW-08 mirror.
//   - (true, err):  the pointer file was unreadable as JSON (corrupt /
//     orphaned). The pointer is best-effort cleared and `fired=true`
//     so the caller treats this as "the box state may be off; rebuild
//     and surface to admin." The wrapped error preserves the unmarshal
//     failure for diagnostic logging.
//   - (false, err): underlying ReadFile / SystemctlIsActive surfaced
//     a real I/O or exec error.
//
// The reverseCmds field is NOT restored from the pointer (the
// pointer-file format intentionally omits the reverse cmds — they are
// baked into the systemd-run unit's ExecStart, so they're already
// authoritative there). After Restore, ReverseCommands() returns nil
// until the next Set call.
func (w *Watcher) Restore(ctx context.Context) (fired bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := w.ops.ReadFile(ctx, PointerPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // clean state
		}
		return false, fmt.Errorf("revert.Restore read: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		// Corrupted pointer — treat as orphan, Clear it, surface as
		// fired (admin needs to know the box state may be off).
		if cerr := w.ops.RemoveAll(ctx, PointerPath()); cerr != nil && !errors.Is(cerr, fs.ErrNotExist) {
			return true, fmt.Errorf("revert.Restore corrupt pointer + cleanup failed: unmarshal=%v cleanup=%v", err, cerr)
		}
		return true, fmt.Errorf("revert.Restore corrupted pointer: %w", err)
	}
	active, err := w.ops.SystemctlIsActive(ctx, st.UnitName)
	if err != nil {
		return false, fmt.Errorf("revert.Restore systemctl is-active: %w", err)
	}
	if active {
		// Unit still running — restore in-process state.
		w.state = &st
		return false, nil
	}
	// Unit no longer active — fired or killed. Clear the pointer.
	if err := w.ops.RemoveAll(ctx, PointerPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true, fmt.Errorf("revert.Restore fired+cleanup failed: %w", err)
	}
	return true, nil
}
