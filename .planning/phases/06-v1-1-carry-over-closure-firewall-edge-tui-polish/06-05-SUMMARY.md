---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
plan: "05"
subsystem: tui/cancellation (gap closure)
requirements: [TUI-11]
status: verified
gap_closure: true
tags:
  - tui
  - modal
  - cancellation
  - d-08
  - safety
  - gap-closure
  - cr-01
  - in-02
  - wr-01
dependency_graph:
  requires:
    - 06-04 (the source plan whose hang-diagnostic gap this plan closes; introduced the D-08 verbatim copy and Feed*ForTestWithPID seams)
  provides:
    - production-safe PID=0 fallback diagnostic across all 4 mutation modals (addkey, applysetup, deleteuser, pwauthdisable)
    - HTTP/file-fetch-specific cancellation hang copy in addkey (no subprocess wording, no kill instruction)
    - dead lastPID field removed from 4 modal Model structs
  affects:
    - any future plan that wraps a modal goroutine inherits the same PID=0 fallback discipline (the live-PID branch is the exception, not the default)
tech_stack:
  added: []
  patterns:
    - "PID-availability gate: if msg.pid <= 0 selects subprocess-free fallback; preserves verbatim D-08 copy on live-PID branch (pid > 0)"
    - "Subsystem-specific hang copy: addkey's HTTP/file-fetch path renders distinct fallback (no subprocess wording, no kill instruction)"
key_files:
  modified:
    - internal/tui/screens/addkey/addkey.go (CR-01 handleCommitted gate + IN-02 handleFetched copy + WR-01 lastPID removal + ErrFatalForTest export)
    - internal/tui/screens/applysetup/applysetup.go (CR-01 applyCancellationClassification gate + call sites + WR-01 lastPID removal)
    - internal/tui/screens/deleteuser/deleteuser.go (CR-01 metaLoadedMsg + submitDoneMsg inline gates + WR-01 lastPID removal)
    - internal/tui/screens/pwauthdisable/pwauthdisable.go (CR-01 applyCancellationClassification gate + call site + WR-01 lastPID removal)
    - internal/tui/screens/addkey/addkey_test.go (3 new tests: CR-01 PID=0 fallback, regression guard, IN-02 fetch fallback)
    - internal/tui/screens/applysetup/applysetup_test.go (2 new tests: CR-01 PID=0 fallback + regression guard)
    - internal/tui/screens/deleteuser/deleteuser_test.go (4 new tests: CR-01 PID=0 fallback + regression guard per arm x2)
    - internal/tui/screens/pwauthdisable/pwauthdisable_test.go (2 new tests: CR-01 PID=0 fallback + regression guard)
decisions:
  - "path (B) chosen over path (A): gating the existing D-08 copy behind if msg.pid <= 0 is pure-additive and carries no signature change risk. Path (A) - threading PID through tx.Apply - was rejected for v1.2 because addkey's commit path uses sysops.SshdTWithContext inside a verifier closure (not sysops.Exec), so even threading PID through Apply would not fix addkey without additional sysops surface changes (per 06-04-SUMMARY.md note); tx.Apply runs multiple steps and 'the most recent PID' requires either a callback param or a stateful tx, both of which compound the surface area; the production hang path is rare and the fallback copy provides actionable guidance (ps -ef | grep) that does not depend on knowing the PID."
  - "lastPID field deleted (WR-01): the field was never written from any goroutine on path (B). Storing a model field that is declared-but-never-written is misleading code; deletion is honest. If v1.3 ships path (A), the field will be re-added with explicit goroutine writes at that time."
  - "D-06..D-10, D-19, D-21, D-22 inherited from 06-04 unchanged: this plan adds no new decisions. The verbatim live-PID copy ('Cancellation failed - subprocess PID=%d still alive. Run kill -9 %d from another shell.') is preserved for D-08 contract compliance on the test-seam path (Feed*ForTest seams always inject non-zero PIDs)."
metrics:
  duration_minutes: 45
  tasks_completed: 4
  files_modified: 8
  new_tests: 11
  commits: 7
  completed: 2026-05-01
---

# Phase 06 Plan 05: TUI-11 Gap Closure - CR-01 + IN-02 + WR-01 Summary

**One-liner:** Close TUI-11 must-have #8 by gating the D-08 hang diagnostic on PID availability so production never renders `Run kill -9 0` (kill(2) PID 0 = SIGKILL the calling process group).

## What Was Done

This plan addresses three findings from 06-REVIEW.md that were left open after 06-04 landed the core D-08 hang diagnostic:

### CR-01: Production Safety Hazard - PID=0 in Hang Diagnostic

The D-08 hang diagnostic rendered `Run kill -9 0` when the production code path produced `msg.pid == 0` (because `tx.Apply` does not surface `ExecResult.PID`). `kill(2)` with PID 0 sends SIGKILL to the entire calling process group - if an admin copy-pasted the instruction from a TTY where `sftp-jailer` was backgrounded, they would SIGKILL their own shell session.

Fix applied to all 4 mutation modals using the same `if msg.pid <= 0` gate:

- **addkey.go** `handleCommitted`: wrapped the existing `fmt.Sprintf` in `if msg.pid <= 0 { subprocess-free fallback } else { verbatim D-08 copy }`
- **applysetup.go** `applyCancellationClassification`: added the same gate to the shared helper; updated `preflightLoadedMsg` and `rePreflightLoadedMsg` call sites from `m.lastPID` (dead, always 0) to the literal `0` to make the production path explicit
- **deleteuser.go** `metaLoadedMsg` + `submitDoneMsg`: both inline classification arms got the gate independently
- **pwauthdisable.go** `applyCancellationClassification`: same helper-level gate as applysetup; updated `preflightLoadedMsg` call site from `m.lastPID` to `0`

The verbatim D-08 live-PID copy is preserved unchanged for the `msg.pid > 0` branch. The existing `Feed*ForTestWithPID` test seams always inject non-zero PIDs (12345, 31415, 54321, 99001), so they continue to exercise the live-PID branch.

**Fallback copy (verbatim):**
```
Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef | grep <child-binary>` from another shell to identify the live PID.
```

### IN-02: Misleading Subprocess Wording on HTTP/File-Fetch Path

`addkey.go`'s `handleFetched` hang branch rendered `"Cancellation failed - subprocess PID=0 still alive. Run kill -9 0 from another shell."` - but the fetching path uses HTTP (gh:) or file-read (file:), not a subprocess. There is no process to kill. The wording was dishonest and the kill instruction was both dangerous and inapplicable.

Fix: replaced the entire block with fetch-specific copy:
```
Cancellation failed - in-flight HTTP / file read did not abort within 2s. Modal stays open until the request returns.
```

This correctly describes the actual failure mode (an HTTP request or file read that did not cancel within 2s) and does not instruct the admin to run any kill command.

### WR-01: Dead lastPID Field Removal

With path (B) chosen (no goroutine writes `m.lastPID`), the field was declared but never populated. Removed from all 4 Model structs along with the doc-comment lines that described the "best-effort breadcrumb only" design (path-A language that never shipped).

## Path Chosen and Rationale

**path (B) fallback diagnostic** was chosen over path (A) (threading PID through `tx.Apply`):

- Pure-additive: 1 `if msg.pid <= 0` branch each in already-existing classification helpers / Update arms.
- No `txn.Tx.Apply` signature change. The existing contract `Apply(ctx, steps) error` stays untouched.
- No race risk: no goroutine writes to `m.lastPID`.
- addkey's commit path uses `sysops.SshdTWithContext` inside a verifier closure, not `sysops.Exec`, so threading PID through Apply would not fix addkey without additional sysops surface changes.
- The production hang path is rare and the fallback copy (`ps -ef | grep`) provides actionable guidance without knowing the PID.

Path (A) is tracked as a v1.3 follow-up.

## Test Contract Additions

11 new regression tests across the 4 modal `_test.go` files:

| Test | Modal | Coverage |
|------|-------|----------|
| TestAddkey_handleCommitted_PID0Fallback_does_not_render_kill_minus_9_zero | addkey | CR-01 safety assertion (no "Run kill -9" on PID=0 path) |
| TestAddkey_handleCommitted_LivePID_still_renders_kill_minus_9_pid | addkey | regression guard for live-PID branch |
| TestAddkey_handleFetched_HTTPHang_does_not_reference_subprocess_or_kill | addkey | IN-02 fetch-specific copy; no subprocess/kill wording |
| TestApplysetup_applyDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero | applysetup | CR-01 safety assertion |
| TestApplysetup_applyDoneMsg_LivePID_still_renders_kill_minus_9_pid | applysetup | regression guard |
| TestPwauthdisable_submitDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero | pwauthdisable | CR-01 safety assertion |
| TestPwauthdisable_submitDoneMsg_LivePID_still_renders_kill_minus_9_pid | pwauthdisable | regression guard |
| TestDeleteuser_metaLoadedMsg_PID0Fallback_does_not_render_kill_minus_9_zero | deleteuser | CR-01 metaLoaded arm |
| TestDeleteuser_metaLoadedMsg_LivePID_still_renders_kill_minus_9_pid | deleteuser | regression guard metaLoaded arm |
| TestDeleteuser_submitDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero | deleteuser | CR-01 submitDone arm |
| TestDeleteuser_submitDoneMsg_LivePID_still_renders_kill_minus_9_pid | deleteuser | regression guard submitDone arm |

Each PID=0 fallback test asserts both presence ("refused SIGTERM and SIGKILL within 2s", "ps -ef | grep") and absence ("Run kill -9", "PID=0"). Each live-PID regression guard asserts the verbatim D-08 copy still renders with the injected PID.

## Findings Addressed

- **CR-01** (closed): all 4 modal hang branches now gate on `pid <= 0` before rendering the subprocess-free fallback
- **IN-02** (closed): addkey `handleFetched` renders HTTP/file-fetch-specific copy with no subprocess or kill wording
- **WR-01** (closed): dead `lastPID int` field removed from all 4 Model structs; surrounding doc-comment lines pruned

## Findings Deferred

Three 06-REVIEW.md findings are explicitly NOT addressed in this plan:

- **WR-02** (`cmd/sftp-jailer/main.go` + `internal/tui/screens/settings/settings.go`): S-SETTINGS save updates the screen's private `m.settings` but does not refresh the shared `usersCfg` reference. The disk write succeeds; the live TUI sees stale values until restart. Per 06-REVIEW.md recommendation, ships in v1.3 with a "TUI restart required" toast hint as the cheap v1.2 mitigation.
- **IN-01** (`internal/tui/screens/userlog/userlog.go`): read-only `loadBreakdown` and `loadEvents` goroutines are not cancelled on modal pop. Up to 30s of wasted SQLite query time per pop. Performance-only, not correctness.
- **IN-03** (`internal/store/queries.go`): `rows.Err()` is called after `rows.Close()` instead of the conventional Go ordering. No functional bug, stylistic only.

Path (A) v1.3 candidate: extending `txn.Tx.Apply` to surface per-step `*sysops.ExecResult` so production hang diagnostics can render the live PID. Not required for v1.2 ship.

## Verification

- Full `-race` suite: green (all packages pass including the 4 modal packages with 11 new tests)
- `scripts/check-no-exec-outside-sysops.sh`: green (no new exec sites)
- `scripts/check-go-mod-pins.sh`: green
- `scripts/check-single-tea-program.sh`: green
- `go vet ./...`: green
- "refused SIGTERM and SIGKILL within 2s" present in all 4 modal source files
- "in-flight HTTP / file read" present in addkey only
- "Run kill -9 %d" verbatim live-PID copy preserved in all 4 modal source files
- "lastPID" absent from all 4 modal source files

## Open Items

None. TUI-11 fully closes for v1.2. Path (A) tracked for v1.3 (threading PID through `tx.Apply` enhancement).

**Verification re-run expectation:** TUI-11 status flips from `partially-satisfied` to `satisfied` on next gsd-verifier run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing export] Added ErrFatalForTest to addkey.go**
- **Found during:** Task 1 RED step - the new tests used `m.ErrFatalForTest()` but the export did not exist in addkey.go (it exists in other modal packages but not addkey)
- **Fix:** Added `func (m *Model) ErrFatalForTest() bool { return m.errFatal }` as a test export to addkey.go, committed in the RED commit alongside the failing tests
- **Files modified:** `internal/tui/screens/addkey/addkey.go`
- **Commit:** ce389b2

None - all other plan instructions executed exactly as written.

## Threat Flags

None - no new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- SUMMARY.md exists at `.planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-05-SUMMARY.md`: FOUND
- TUI-11 referenced: FOUND
- CR-01, IN-02, WR-01 (closed findings): FOUND
- WR-02, IN-01, IN-03 (deferred findings): FOUND
- path (B) and path (A) documented: FOUND
- Em-dash absent from SUMMARY and all source/test files: PASS
- All 7 task commits verified in git log: PASS
- Full -race suite: green
- All 3 architectural CI guards: green
