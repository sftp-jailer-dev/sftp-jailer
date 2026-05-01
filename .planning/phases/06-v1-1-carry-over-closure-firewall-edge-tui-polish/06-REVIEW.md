---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
reviewed: 2026-05-01T00:00:00Z
depth: standard
files_reviewed: 30
files_reviewed_list:
  - cmd/sftp-jailer/main.go
  - docs/uat/06-fw09-uat.md
  - internal/config/config.go
  - internal/config/config_test.go
  - internal/firewall/enumerate_test.go
  - internal/firewall/mutate_test.go
  - internal/firewall/testdata/ufw-status-numbered-v6-only.txt
  - internal/firewall/testdata/ufw-status-numbered-v6-source.txt
  - internal/store/queries.go
  - internal/store/queries_test.go
  - internal/sysops/real.go
  - internal/sysops/real_test.go
  - internal/sysops/sysops.go
  - internal/tui/screens/addkey/addkey.go
  - internal/tui/screens/addkey/addkey_test.go
  - internal/tui/screens/applysetup/applysetup.go
  - internal/tui/screens/applysetup/applysetup_test.go
  - internal/tui/screens/deleteuser/deleteuser.go
  - internal/tui/screens/deleteuser/deleteuser_test.go
  - internal/tui/screens/logs/logs.go
  - internal/tui/screens/pwauthdisable/pwauthdisable.go
  - internal/tui/screens/pwauthdisable/pwauthdisable_test.go
  - internal/tui/screens/settings/settings.go
  - internal/tui/screens/settings/settings_test.go
  - internal/tui/screens/userlog/userlog.go
  - internal/tui/screens/userlog/userlog_test.go
  - internal/tui/screens/users/users.go
  - internal/tui/screens/users/users_test.go
  - internal/txn/steps_test.go
findings:
  critical: 1
  warning: 2
  info: 3
  total: 6
status: issues_found
---

# Phase 6: Code Review Report

**Reviewed:** 2026-05-01
**Depth:** standard
**Files Reviewed:** 30
**Status:** issues_found

## Summary

Phase 6 closes four v1.1 carry-over items (FW-09 dual-family/v6-only ufw edge, TUI-09 password aging knobs in S-SETTINGS, TUI-10 per-user log modal, TUI-11 cancellable mutation modals). The code is well-structured, heavily commented with decision references, and accompanied by thorough teatest coverage. The sysops invariant is preserved (no exec.Command outside internal/sysops). No em-dashes detected. SQL queries use parameterized placeholders consistently.

The most significant concern is **CR-01**, a structural defect in TUI-11's D-08 hang-escalation diagnostic: the production code path always renders `Run kill -9 0`, which on Linux/POSIX means "kill the entire process group of the caller." The PID-plumbing infrastructure is inert in production because `tx.Apply()` does not expose per-step `ExecResult.PID`; only test seams populate non-zero PIDs. While the test suite asserts the verbatim copy with synthetic PIDs (12345, 54321, 31415, 99001), an admin who hits the genuine hang path receives misleading and potentially dangerous instructions.

Two warning-level findings track architectural debt: the same incomplete D-08 plumbing (WR-01) and a stale-config pitfall where new TUI-09 / TUI-10 fields edited in S-SETTINGS do not refresh the in-process `usersCfg` reference (WR-02). Three info items cover read-only goroutines that are not cancelled on modal pop (IN-01), a misleading hang-diagnostic edge in addkey's HTTP/file fetch path (IN-02), and a minor `rows.Err()` ordering nit in `queries.go` (IN-03).

The FW-09 deliverables (Plan 06-01) are clean: tests pin v6-only and v6-source behavior with independent assertions, the UAT runbook respects the D-17 placeholder rule (no `m1.linuxbe.com`), and fixtures match testdata files verbatim. The TUI-09 password aging rows (Plan 06-02) integrate cleanly with the existing `fieldKind` iota chain and reuse the inline-edit + `config.Validate` path with the new max=3650 cap. The TUI-10 modal (Plan 06-03) extends `PerUserBreakdown` with a `sinceNs` filter (mirroring `FilterEvents.SinceNs`) so the header tier counts match the windowed row list, closing Pitfall 5.

## Critical Issues

### CR-01: D-08 hang-escalation diagnostic instructs admin to run `kill -9 0` in production

**File:** `internal/tui/screens/addkey/addkey.go:624`, `internal/tui/screens/applysetup/applysetup.go:645`, `internal/tui/screens/deleteuser/deleteuser.go:585`, `internal/tui/screens/pwauthdisable/pwauthdisable.go:577,590,607,615,617`

**Issue:** All four mutation-modal goroutines hardcode `pid: 0` (or omit the field, which zero-defaults) in the `committedMsg` / `applyDoneMsg` / `submitDoneMsg` they emit because `tx.Apply()` does not expose per-step `ExecResult.PID`. When the cancellation classifier hits the D-08 branch (non-context error after Esc), it renders:

```
Cancellation failed - subprocess PID=0 still alive. Run kill -9 0 from another shell.
```

`kill -9 0` on Linux/POSIX semantics (`kill(2)` man page: "If pid is 0, then sig is sent to every process in the process group of the calling process.") means "SIGKILL every process in the calling shell's process group." If an admin literally copy-pastes this command from a TTY where they backgrounded `sftp-jailer`, they could DoS their own session. Even when run from a separate terminal the message is misleading: PID 0 is the kernel scheduler, not a "subprocess still alive."

The verbatim D-08 contract is satisfied only in the test suite — `FeedCommittedMsgForTestWithPID(err, 12345)`, `FeedSubmitDoneForTestWithPID(err, 54321)`, etc. — by passing synthetic PIDs to bypass the production goroutine.

**Fix:** Either (a) plumb the most-recent `ExecResult.PID` out of `tx.Apply()` so the goroutines can populate the field for real (matches Plan 06-04's stated intent: "the goroutine captures the most-recent ExecResult.PID into the local lastPID variable"), or (b) when no real PID is available, render a substitute diagnostic that does not include `kill -9 0`. Suggested copy when PID is unavailable:

```go
if msg.pid <= 0 {
    m.errInline = "Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. " +
        "Inspect `ps -ef | grep <child-binary>` from another shell to identify the live PID."
} else {
    m.errInline = fmt.Sprintf(
        "Cancellation failed - subprocess PID=%d still alive. Run kill -9 %d from another shell.",
        msg.pid, msg.pid)
}
```

Apply the gate in all four modal `handleCommitted` / `handleSubmitDone` / `handleApplyDone` cancellation branches. The test suite continues to exercise the non-zero-PID path; add a parallel test that pins the PID=0 fallback string (so a future regression that re-introduces `kill -9 0` is caught).

## Warnings

### WR-01: D-08 PID-plumbing is structurally inert in production

**File:** `internal/tui/screens/addkey/addkey.go:586-625`, `internal/tui/screens/applysetup/applysetup.go:622-647`, `internal/tui/screens/deleteuser/deleteuser.go:560-588`, `internal/tui/screens/pwauthdisable/pwauthdisable.go:547-619`

**Issue:** Plan 06-04 specifies that "the goroutine captures the most-recent ExecResult.PID into the local lastPID variable on each Exec call; whichever Exec was mid-flight at Esc time is the one whose PID surfaces on the done-msg." The implementation declares `lastPID int` on each model and adds a `pid int` field to the done-msg types, but no code path actually writes a non-zero PID:

- `addkey.go:624` — `return committedMsg{err: err, pid: 0}` (comment acknowledges PID=0 in production)
- `applysetup.go:645` — `return applyDoneMsg{err: tx.Apply(ctx, steps), pid: 0}` (same)
- `deleteuser.go:585` — `return submitDoneMsg{err: err, pid: 0}` (same)
- `pwauthdisable.go:577,590,607,615` — multiple `submitDoneMsg{err: ...}` returns without `pid:` (zero-defaults)

`tx.Apply(ctx, steps)` returns only an `error`; per-step `ExecResult.PID` is not exposed through the txn batch interface. The `m.lastPID` field on each model is never written to from a goroutine.

**Fix:** Either remove the dead `lastPID` field and document the production limitation explicitly, or extend `txn.Tx.Apply` to expose the most-recent step's `ExecResult.PID` (e.g., return `(*ExecResult, error)` or invoke a callback per step). The latter aligns the implementation with Plan 06-04's stated contract; the former at least removes the misleading dead code. Pair with CR-01's fallback diagnostic.

### WR-02: S-SETTINGS save does not refresh in-process `usersCfg` referenced by S-USERS and M-USER-LOG

**File:** `cmd/sftp-jailer/main.go:284-291,401,424`, `internal/tui/screens/settings/settings.go:380`

**Issue:** `main.go` constructs a single `usersCfg := config.Defaults()` (line 284), populates it from disk via `config.Load`, and hands `&usersCfg` to:

- `usersscreen.NewWithConfig(..., &usersCfg, ...)` (line 401) — drives the password-aging color buckets
- `userlog.New(username, queries, &usersCfg)` (line 424) — drives `LockdownProposalWindowDays` for both the windowed tier strip AND the row list `SinceNs` filter

When the admin opens S-SETTINGS, edits `password_aging_days` / `password_stale_days` / `lockdown.proposal_window_days`, and saves, the screen's `Update` for `savedMsg` updates `m.settings = msg.settings` (settings.go:380) — but `m.settings` is a private copy. The `&usersCfg` reference in `main.go` is never refreshed. Subsequent pushes of S-USERS or M-USER-LOG read stale values until the TUI restarts.

This is a Phase 6 regression: TUI-09 added editable rows for these knobs (closing the "admins must edit config.yaml directly" gap), but the in-process propagation gap means saves take effect only on the underlying file, not on already-running screens. The disk write succeeds; the live TUI silently disagrees.

**Fix:** Two options, in order of cost:

1. (Cheap) Add a documented "TUI restart required" hint to the post-save toast, e.g., `"saved password_aging_days · restart sftp-jailer to apply"`. This is honest and matches the existing Save semantics.

2. (Better) Have settings.go publish a `configUpdatedMsg{settings: candidate}` after `savedMsg` succeeds, and have `main.go` (or an app-level coordinator) write through to `usersCfg` so subsequent pushes see fresh values. The existing factory closures capture `&usersCfg` by pointer, so a single write to `*(&usersCfg) = msg.settings` would propagate. Note: this needs to run on the main loop to avoid a data race.

Pick (1) for v1.2 to ship without UI plumbing complexity; track (2) for v1.3.

## Info

### IN-01: userlog read-only goroutines are not cancelled on modal pop

**File:** `internal/tui/screens/userlog/userlog.go:188-201,206-222`

**Issue:** `loadBreakdown` and `loadEvents` create `context.WithTimeout(context.Background(), 30*time.Second)` inside the goroutine. If the admin pops the M-USER-LOG modal (Esc / q) before the queries return, the goroutines run to completion with no signal to abort. Worst case is 30s of wasted SQLite query time per pop, plus the message that the now-unreferenced model produces is dispatched into the void by Bubble Tea.

This is the same anti-pattern TUI-11 closed for the four mutation modals, but TUI-11 explicitly scopes itself to mutation paths because cancellation interacts with SAFE-04. M-USER-LOG is read-only, so the impact is performance-only, not correctness. Worth tracking for the next round of cancellation hygiene.

**Fix:** Mirror the TUI-11 pattern — store `cancelFn` on the model, invoke from `handleKey` Esc, route through a `popMsg` that the Update loop processes after cancel.

### IN-02: addkey hang diagnostic for HTTP/file fetch references "subprocess PID=0"

**File:** `internal/tui/screens/addkey/addkey.go:533-541`

**Issue:** The `handleFetched` cancellation classifier on the resolveAsync (HTTP `gh:` + `ops.ReadFile` for `file:`) path renders:

```go
m.errInline = fmt.Sprintf(
    "Cancellation failed - subprocess PID=%d still alive. Run kill -9 %d from another shell.",
    0, 0)
```

The comment at line 534 explains the intent ("Fetching path has no PID surface (HTTP, not subprocess) so PID=0 is the honest report"), but the rendered string still says "subprocess PID=0 still alive" — there is no subprocess. The user-facing copy is technically dishonest. This compounds CR-01: even if CR-01 is fixed for the txn paths, this branch needs its own diagnostic.

**Fix:** Distinguish HTTP/file cancellation hang from subprocess cancellation hang. Suggested copy: `"Cancellation failed - in-flight HTTP / file read did not abort within 2s. Modal stays open until the request returns."` (Note: in practice `keys.FetchGitHub` honors ctx via `http.Request.WithContext`, so this branch should rarely fire.)

### IN-03: queries.PerUserBreakdown calls rows.Err() after rows.Close()

**File:** `internal/store/queries.go:243-246`

**Issue:**

```go
_ = rows.Close()
if err := rows.Err(); err != nil {
    return ub, fmt.Errorf("queries.PerUserBreakdown tiers rows.Err: %w", err)
}
```

The conventional Go pattern is `rows.Err()` before `rows.Close()` (or skip `Err()` if using `defer rows.Close()` and trusting the iterator). Per `database/sql` docs, `rows.Close()` is idempotent and `rows.Err()` returns the error encountered during iteration; calling Err() after Close() is technically valid but unconventional. No functional bug.

**Fix:** Reorder for consistency with the rest of `queries.go` (e.g., `FilterEvents` at line 175-177 uses the conventional `defer rows.Close()` + `rows.Err()` pattern):

```go
if err := rows.Err(); err != nil {
    _ = rows.Close()
    return ub, fmt.Errorf("queries.PerUserBreakdown tiers rows.Err: %w", err)
}
_ = rows.Close()
```

Or use `defer` and skip the manual close.

---

_Reviewed: 2026-05-01_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
