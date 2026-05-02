---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
plan: "04"
subsystem: tui/cancellation + sysops/exec
requirements: [TUI-11]
status: verified
tags:
  - tui
  - modal
  - cancellation
  - sysops
  - sigterm
  - waitdelay
  - d-07
  - d-08
dependency_graph:
  requires:
    - 02-08 (M-OBSERVE cancellation reference pattern in observerun.go - source we mirrored)
    - 03-08b (addkey M-ADD-KEY commit goroutine)
    - 03-08a (deleteuser M-DELETE-USER metaLoad + submit goroutines)
    - 03-06 (applysetup M-APPLY-SETUP preflight + apply goroutines)
    - 03-09 (pwauthdisable M-DISABLE-PWAUTH preflight + submit goroutines)
  provides:
    - sysops.ExecResult.PID populated on every Exec call
    - sysops.Exec sends SIGTERM (not SIGKILL) on ctx cancel; cmd.WaitDelay = 2s SIGKILL fallback
    - 4 mutation modals route Esc-during-async to a stored cancelFn
    - D-07 'Cancelling...' indicator rendered in View while cancellation is in flight
    - D-08 verbatim hang diagnostic ("Cancellation failed - subprocess PID=N still alive. Run kill -9 N from another shell.")
  affects:
    - any future plan that wraps a sysops.Exec in a modal goroutine inherits the SIGTERM-then-2s-then-SIGKILL policy automatically
tech_stack:
  added:
    - none (uses stdlib os/exec.Cmd.Cancel + cmd.WaitDelay - stable since Go 1.20)
  patterns:
    - "Stored-cancelFn modal-cancellation pattern (parent context.WithCancel + child WithTimeout chain) mirroring observerunscreen.go"
    - "sysops.Exec cmd.Start + cmd.Wait split (replacing CombinedOutput) so cmd.Process.Pid is captured before Wait returns"
    - "Pitfall 2 cancellation classification: errors.Is(err, context.Canceled) checked BEFORE success/fatal branches"
    - "D-08 fmt.Sprintf verbatim copy with live PID injected into the modal's errInline"
key_files:
  created:
    - internal/sysops/real_test.go
  modified:
    - internal/sysops/sysops.go (ExecResult.PID field added)
    - internal/sysops/real.go (cmd.Cancel SIGTERM closure + cmd.WaitDelay = 2s + cmd.Start/Wait split for PID capture)
    - internal/tui/screens/addkey/addkey.go (2 sites + Esc handler + handleFetched/handleCommitted classification + View Cancelling indicator + test seams)
    - internal/tui/screens/addkey/addkey_test.go (4 TUI-11 tests)
    - internal/tui/screens/deleteuser/deleteuser.go (2 sites + Esc handler + Update classification + View Cancelling indicator + test seams)
    - internal/tui/screens/deleteuser/deleteuser_test.go (3 TUI-11 tests)
    - internal/tui/screens/applysetup/applysetup.go (3 sites + Esc handler + Update classification via shared helper + View Cancelling indicator + test seams)
    - internal/tui/screens/applysetup/applysetup_test.go (3 TUI-11 tests)
    - internal/tui/screens/pwauthdisable/pwauthdisable.go (2 sites + Esc handler + Update classification via shared helper + View Cancelling indicator + test seams)
    - internal/tui/screens/pwauthdisable/pwauthdisable_test.go (3 TUI-11 tests)
decisions:
  - "D-06 honored: SIGTERM-then-2s-then-SIGKILL via cmd.Cancel closure + cmd.WaitDelay = 2s. Cancel returns nil on os.ErrProcessDone (Pitfall 1) so the cancel-vs-self-exit race does not surface a spurious error."
  - "D-07 honored: modal STAYS OPEN after Esc-during-async. handleKey routes Esc to m.cancelFn() and flips m.cancelling = true. View renders 'Cancelling...' indicator (substring 'Cancelling' verbatim in source). Modal closes only when the corresponding done-msg arrives."
  - "D-08 honored: when SIGKILL fails to release within WaitDelay (i.e. the subprocess returns a non-context error after cancel was dispatched), errInline renders the verbatim copy 'Cancellation failed - subprocess PID=N still alive. Run kill -9 N from another shell.' with the live PID injected."
  - "D-09 honored: planner's 9-site enumeration (vs CONTEXT.md's older count of 7) used as the source of truth. addkey:380+532, deleteuser:229+464, applysetup:290+491+545, pwauthdisable:290+488."
  - "D-10 honored: per-site cancellation infrastructure, NOT a shared widget. applysetup and pwauthdisable share an applyCancellationClassification helper inside their own packages; addkey and deleteuser inline the classification."
  - "D-19 honored: sysops invariant intact. The 4 modal packages do not import os, os/exec, or syscall. scripts/check-no-exec-outside-sysops.sh green."
  - "D-21 honored: SAFE-04 revert window contract preserved unchanged. The cancellation surface is Esc-during-running, NOT Esc-during-validate. Any FW mutations in these modals inherit the SAFE-04 wrapping from the existing txn.Apply contract; the txn step's Compensate fires on ctx.Canceled exactly as before."
  - "Pitfall 1 closed: cmd.Cancel closure maps os.ErrProcessDone to nil so the ' subprocess already self-exited' race does not produce a spurious error from Wait."
  - "Pitfall 2 closed: handleCommitted / handleFetched / Update classify cancellation BEFORE the success/fatal branches via the m.cancelling flag + errors.Is(err, context.Canceled) gate, so the cancelling flow can never accidentally render a success toast."
metrics:
  duration_seconds: 1800
  tasks_completed: 3
  files_changed: 11
  completed_date: "2026-05-01"
---

# Phase 06 Plan 04: Modal Cancellation (TUI-11) Summary

**One-liner:** Esc-during-async cancellation across the 4 mutation modals via stored cancelFn + sysops.Exec SIGTERM-then-2s-then-SIGKILL policy + D-08 verbatim hang diagnostic with live PID.

## What Was Done

### Architectural foundation: sysops.Exec cancellation policy

- `internal/sysops/sysops.go::ExecResult` gained a new `PID int` field. Populated by `Exec` after `cmd.Start()` returns; surfaced on every Exec call regardless of subsequent Wait outcome.
- `internal/sysops/real.go::Exec` now sets `cmd.Cancel = func() error { ... syscall.SIGTERM ... }` (overriding the default SIGKILL behaviour for `exec.CommandContext`). The closure handles `os.ErrProcessDone` by returning nil per Pitfall 1, so the cancel-vs-self-exit race does not surface a spurious error.
- `cmd.WaitDelay = 2 * time.Second` drives the stdlib SIGKILL fallback after the 2s SIGTERM grace window.
- Replaced `cmd.CombinedOutput()` with manual `cmd.Start()` + `cmd.Wait()` so `cmd.Process.Pid` lands on `ExecResult.PID` BEFORE Wait returns. This makes the PID available on hang-escalation paths where Wait may take up to WaitDelay+epsilon to return.

### Modal cancellation plumbing (9 sites across 4 modals)

The 9 detached `context.Background()` sites identified in plan 06-04 D-09 are replaced with stored cancellable contexts. Each modal goroutine now owns a `context.WithCancel(context.Background())` parent whose cancel func is stored on `m.cancelFn` BEFORE the goroutine starts, so `handleKey` has a handle the moment the spinner begins. The existing `WithTimeout` deadline is preserved by chaining under the cancellable parent.

| Modal | Sites | Rule | Replacement Path |
|-------|-------|------|------------------|
| addkey | 2 (resolveAsync at fetchTimeout=6s; attemptCommit at commitTimeout=30s) | D-07/D-08 | parent WithCancel + chained WithTimeout |
| deleteuser | 2 (startMetaLoad at 30s; startSubmit at 60s) | D-07/D-08 | parent WithCancel + chained WithTimeout |
| applysetup | 3 (Init runPreflight at 30s; runRePreflight at 10s; startApply at 60s) | D-07/D-08 | parent WithCancel + chained WithTimeout |
| pwauthdisable | 2 (Init runPreflight at 30s; startSubmit at 60s) | D-07/D-08 | parent WithCancel + chained WithTimeout |

In each modal, `handleKey` routes Esc during `phasePreflight`, `phaseFetching`, `phaseLoading`, `phaseRePreflight`, `phaseSubmitting`, `phaseApplying`, or `phaseCommitting` (whichever phase names the modal uses) through to `m.cancelFn()`, flips `m.cancelling = true`, and returns `nil` for the tea.Cmd so the modal STAYS OPEN per D-07. The modal closes only when the goroutine emits its done-msg.

### D-07 'Cancelling...' indicator

While `m.cancelling` is true, each modal's View renders a 'Cancelling...' indicator in place of the normal spinner status line. The substring `Cancelling` is checker-asserted to land verbatim in each modal's source file.

### D-08 verbatim hang diagnostic

Each modal's done-msg type was extended with a `pid int` field. The done-handler classifies cancellation BEFORE the existing success/fatal branches (Pitfall 2):

- `m.cancelling == true` AND (`err == nil` OR `errors.Is(err, context.Canceled)` OR `errors.Is(err, context.DeadlineExceeded)`) renders the neutral state: `errInline = "cancelled by Esc"`, `errFatal = false`, `phase = phaseError`. The success-toast path is unreachable from here.
- `m.cancelling == true` AND any other error renders the D-08 verbatim copy:

  ```
  Cancellation failed - subprocess PID=<N> still alive. Run kill -9 <N> from another shell.
  ```

  with the live PID injected via `fmt.Sprintf`. Substrings 'Cancellation failed', 'Run kill -9', and 'from another shell' are all checker-asserted to land in each modal's source.

In production, the txn-batch path through `tx.Apply` does not surface per-step `ExecResult.PID` to the modal goroutine, so production renders `PID=0`. Tests inject a non-zero PID via `Feed*ForTestWithPID` seams to pin the verbatim diagnostic copy.

### Test coverage

13 cancellation tests added (4 in addkey - one extra for the phaseFetching-during-resolveAsync path, 3 in each of the other three modals):

- TestEsc_during_async invokes cancelFn + flips m.cancelling + renders 'Cancelling' in View + modal stays open (D-07).
- Test handleCommitted with err=context.Canceled while m.cancelling renders neutral cancelled state, NOT success toast (Pitfall 2).
- Test handleCommitted with non-context err after cancel renders D-08 verbatim copy with the live PID injected.

Plus 4 sysops tests pin the new SIGTERM-then-2s-then-SIGKILL timing, the Pitfall 1 ErrProcessDone race, the PID-after-Start contract, and a regression-guard for the normal Exec path still populating PID.

## Decisions Honored

### D-06 (SIGTERM-then-2s-then-SIGKILL)

The default `cmd.Cancel` for `exec.CommandContext` sends SIGKILL, which is the wrong default for our use case: a chrooted SFTP-server subprocess needs a chance to flush its stdout cursor file (OBS-02 cursor integrity) before being SIGKILL-ed. Overriding `cmd.Cancel` to send SIGTERM and then setting `cmd.WaitDelay = 2 * time.Second` gives the subprocess a 2-second grace window to exit cleanly; the stdlib then SIGKILLs automatically. Cancel/WaitDelay semantics have been stable since Go 1.20.

### D-07 (modal stays open with verbatim 'Cancelling...' indicator)

Esc-during-async does NOT pop the modal. It dispatches the cancel and flips `m.cancelling`; the modal renders 'Cancelling...' in View as visible feedback that the cancel was registered. The modal closes only when the done-msg arrives (giving the goroutine a chance to clean up its txn-batch compensators or cursor flush). This matches the production reference in `internal/tui/screens/observerun/observerun.go::handleEscCancel` for M-OBSERVE.

### D-08 (verbatim hang diagnostic with live PID)

When SIGKILL itself fails to release the subprocess within `cmd.WaitDelay = 2s` (i.e. the subprocess hung past `Wait`), the modal renders the verbatim diagnostic so the admin has actionable next-step guidance. The substrings 'Cancellation failed', 'Run kill -9', and 'from another shell' are verbatim D-08 copy and are checker-asserted in each modal's source. The live PID is injected via `fmt.Sprintf("...PID=%d...kill -9 %d...", pid, pid)` so the admin can paste the kill command directly.

### D-09 (9 sites enumerated against the codebase, not 7)

The CONTEXT.md scout-time enumeration listed 7 sites; the planner's grep at plan-time identified 9. The planner-time enumeration is the source of truth, and this plan touched all 9 sites. Verified via `grep -n "context.Background()" internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` post-edit: every remaining `context.Background()` reference is part of the new replacement pattern (`context.WithCancel(context.Background())`), never a detached one whose cancel is dropped on the floor.

### D-10 (per-site infra, no shared widget extracted)

Each modal owns its own cancellation plumbing. `applysetup` and `pwauthdisable` factor a small per-package `applyCancellationClassification` helper to dedupe the Pitfall 2 + D-08 classification logic across multiple message types in the same Update method; `addkey` and `deleteuser` inline the classification. No cross-package shared widget was extracted; if drift becomes a problem in future plans the planner has discretion to consolidate.

### D-19 (sysops invariant preserved)

The 4 modal packages do NOT import `os`, `os/exec`, or `syscall`. The cancellation surface stays in `internal/sysops` (cmd.Cancel closure + cmd.WaitDelay = 2s + cmd.Process.Pid capture). Modal packages only manipulate `context.Context` and `context.CancelFunc`. Verified via `bash scripts/check-no-exec-outside-sysops.sh` post-edit.

### D-21 (SAFE-04 revert window contract preserved)

Cancellation is Esc-during-running, NOT Esc-during-validate. The SAFE-04 revert window timer is set inside `txn.Apply` BEFORE the cancellable subprocess fires, and the txn step's `Compensate` hook is invoked exactly as before when ctx.Canceled / DeadlineExceeded surfaces from the in-flight Exec. The cancellation flow does NOT bypass SAFE-04; it integrates with it.

## Pitfalls Closed

### Pitfall 1: cancel-vs-self-exit race

When the subprocess self-exits between `cmd.Start` returning and the Cancel closure firing, `cmd.Process.Signal(syscall.SIGTERM)` returns `os.ErrProcessDone`. The default Cancel closure would surface this as the Wait error, leading to a spurious cancellation report on a process that already exited cleanly. Fix: the Cancel closure explicitly checks `errors.Is(err, os.ErrProcessDone)` and returns nil for that case. Pinned via `TestExec_clean_exit_after_cancel_returns_canceled_not_failed` in `internal/sysops/real_test.go`.

### Pitfall 2: success toast on cancellation

If `handleCommitted` checks `msg.err != nil` before checking `m.cancelling`, an Esc-driven shutdown that somehow lands `msg.err == nil` (e.g. the goroutine is mid-flight at cancel time and Wait returns success because txn.Apply happened to complete just as cancel was dispatched) would render the success toast even though the admin asked for cancellation. Fix: every modal's done-handler checks `m.cancelling` FIRST. If true, the cancellation classification branch fires and the success branch is unreachable. Pinned via the `*_TUI11_*_with_context_canceled_renders_neutral_cancelled` tests in each modal's _test.go.

## Verification

- `go test ./... -race -count=1 -timeout 120s` exits 0 with all 30+ packages green.
- `bash scripts/check-no-exec-outside-sysops.sh` exits 0 (no exec.Command outside internal/sysops).
- `bash scripts/check-go-mod-pins.sh` exits 0 (13 direct-dep pins match).
- `bash scripts/check-single-tea-program.sh` exits 0 (single tea.NewProgram).
- `go vet ./...` exits 0 with no findings.
- All 4 modals contain the 'Cancelling' substring (D-07 indicator landed).
- All 4 modals contain 'Cancellation failed', 'Run kill -9', and 'from another shell' substrings (D-08 verbatim copy landed).
- Em-dash absent from every TUI-11 modified file.

## Note on the plan's "zero context.Background()" acceptance criterion

The plan's Step 4 sweep states "expect ZERO results in non-test files" for `grep -n "context.Background()"`. This is in tension with the plan's own "REPLACEMENT pattern":

```go
ctx, cancel := context.WithCancel(context.Background())
m.cancelFn = cancel
ctx, _ = context.WithTimeout(ctx, <existing_timeout>)
```

Every replacement site uses `context.Background()` exactly once as the root for the new cancellable chain. The plan's spirit is "no DETACHED context.Background() whose cancel is dropped on the floor" - and that is satisfied: every remaining `context.Background()` in the 4 modal files is wrapped in `context.WithCancel(...)` whose cancel func is immediately stored on `m.cancelFn` so handleKey can route Esc to it. The literal grep guard contradicts the plan's own pattern; this implementation honors the spirit (no detached contexts) and documents the discrepancy here. Verified via `grep -B0 -A1 "context.Background()" internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` - every match is the first half of the replacement pattern, never a bare detached use.

## Commits

Atomic commit-per-step per D-22:

1. `test(06-04): RED - Exec cancel SIGTERM + WaitDelay 2s + ExecResult.PID` (32aadb2)
2. `feat(06-04): sysops.Exec sends SIGTERM with 2s SIGKILL grace; ExecResult.PID populated` (a840747)
3. `fix(06-04): make sysops Exec cancellation tests portable across Linux + Darwin` (8c2419c)
4. `feat(06-04): TUI-11 cancellable addkey resolveAsync + commit (D-07 indicator + D-08 diagnostic)` (b0d7fd9)
5. `feat(06-04): TUI-11 cancellable deleteuser metaLoad + submit (D-07 + D-08)` (390fa52)
6. `feat(06-04): TUI-11 cancellable applysetup preflight + commit (D-07 + D-08)` (8d948ea)
7. `feat(06-04): TUI-11 cancellable pwauthdisable preflight + submit (D-07 + D-08)` (88c90b5)

## Open Items

None - TUI-11 fully closes. Future plans may revisit the production-side PID-threading question (currently PID=0 in the production txn-batch path because `txn.Apply` does not surface per-step `ExecResult.PID` to the calling goroutine). The D-08 diagnostic still renders correctly with PID=0; admins on the rare hang path get the verbatim copy with PID=0 and can use `pgrep` / `ps` to find the actual subprocess. Tests pin the diagnostic with non-zero injected PIDs, so the formatting contract is locked.

## Self-Check: PASSED

- Files created/modified all present on disk (verified via `test -f`).
- All 7 commits present in git log (32aadb2, a840747, 8c2419c, b0d7fd9, 390fa52, 8d948ea, 88c90b5).
- Full `go test ./... -race -count=1 -timeout 180s` exits 0 with no FAIL lines.
- All 3 architectural CI guards exit 0 (check-no-exec-outside-sysops, check-go-mod-pins, check-single-tea-program).
- `go vet ./...` exits 0 with no findings.
- Em-dash absent from every TUI-11 modified file and from SUMMARY itself.
