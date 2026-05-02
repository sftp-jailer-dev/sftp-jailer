---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
reviewed: 2026-05-01T12:00:00Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - internal/tui/screens/addkey/addkey.go
  - internal/tui/screens/addkey/addkey_test.go
  - internal/tui/screens/applysetup/applysetup.go
  - internal/tui/screens/applysetup/applysetup_test.go
  - internal/tui/screens/deleteuser/deleteuser.go
  - internal/tui/screens/deleteuser/deleteuser_test.go
  - internal/tui/screens/pwauthdisable/pwauthdisable.go
  - internal/tui/screens/pwauthdisable/pwauthdisable_test.go
findings:
  critical: 0
  warning: 0
  info: 2
  total: 2
status: issues_found
---

# Phase 6 (re-review after plan 06-05 gap-closure): Code Review Report

**Reviewed:** 2026-05-01
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found (2 info-only items; CR-01, IN-02, WR-01 from prior review all resolved)

## Summary

This re-review covers the 8 files modified by plan 06-05 ("gap-closure for prior CR-01"). Scope is the four cancellable-mutation modals (addkey, applysetup, deleteuser, pwauthdisable) and their tests. Findings on plans 06-01..06-04 from the previous 06-REVIEW.md are out of scope and remain as recorded there.

**Verification of prior findings:**

- **CR-01 (production safety hazard: `Run kill -9 0` rendered when msg.pid is 0)** is fixed. All four production cancellation classifiers now gate on `pid <= 0` and emit the subprocess-free fallback ("Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef | grep <child-binary>` from another shell to identify the live PID.") when no live PID is available. The verbatim D-08 copy is preserved on the live-PID branch. Implementations live at `addkey.go:706-716`, `applysetup.go:678-685`, `deleteuser.go:392-400` and `:428-435`, and `pwauthdisable.go:732-739`. The fallback string is byte-identical across all four modals.
- **IN-02 (HTTP/file-fetch hang copy referenced "subprocess" / `kill -9` though no subprocess exists)** is fixed at `addkey.go:528-538`. The fetching path now renders a fetch-specific copy: "Cancellation failed - in-flight HTTP / file read did not abort within 2s. Modal stays open until the request returns." The new test `TestAddkey_handleFetched_HTTPHang_does_not_reference_subprocess_or_kill` (addkey_test.go:1086-1111) pins that "subprocess", "Run kill -9", and "PID=" never appear on this path.
- **WR-01 (dead `lastPID` field on all 4 model structs)** is fixed. `lastPID` is fully removed from the four production files (verified by `grep -rn lastPID internal/`; remaining hits are only in `.claude/worktrees/`, which are agent worktrees, not the live tree). Comments referencing the field have been updated.

**Test coverage of the gap-closure** is thorough. Each modal gains two paired tests: a `*_PID0Fallback_does_not_render_kill_minus_9_zero` test that asserts the absence of `Run kill -9` AND the presence of the canonical fallback text, and a `*_LivePID_still_renders_kill_minus_9_pid` regression guard that asserts the verbatim D-08 copy still appears when pid > 0. deleteuser additionally pins both metaLoad and submit paths. addkey adds the IN-02 fetch-specific test.

**Build + tests:** `go build` and `go test` pass for all four packages.

The two info items below are minor: a slightly stale comment on the addkey fetch-fallback ("Modal stays open until the request returns" - we are already past the goroutine's return), and a minor inconsistency where `deleteuser.Model` does not carry an `errFatal` field that the other three modals do (a pre-existing inconsistency unchanged by 06-05, but worth recording for future hygiene).

## Info

### IN-01: addkey fetch-fallback copy is slightly stale - the request HAS already returned by the time it renders

**File:** `internal/tui/screens/addkey/addkey.go:533-534`

**Issue:** The fetch-cancellation hang fallback reads "Cancellation failed - in-flight HTTP / file read did not abort within 2s. **Modal stays open until the request returns.**" But by the time `handleFetched` runs we are processing the `fetchedMsg` *returned* by the goroutine; the request has already returned (otherwise no message would have arrived). The "Modal stays open until the request returns" wording is a copy-paste from the in-flight `Cancelling...` indicator that *is* shown while waiting. After that wait completes with a non-context error, the modal lands in `phaseError` with this fallback - the request has already returned by definition.

**Severity rationale:** Info-only because the message is still useful (admin understands cancellation didn't take effect cleanly), and the inline error is brief enough that the wording subtlety is unlikely to confuse. Not worth a follow-up unless the modal copy is being polished broadly.

**Fix suggestion:** Reword to describe the post-return state. Example:

```go
m.errInline = "Cancellation failed - in-flight HTTP / file read did not abort within 2s; " +
    "the request returned with an unexpected error after the cancel signal."
```

Alternatively, keep the current wording but move the assignment into the `Cancelling...` indicator render path so it actually describes the wait window.

### IN-02: deleteuser.Model omits errFatal field that the other three modals carry

**File:** `internal/tui/screens/deleteuser/deleteuser.go:121-153` (Model struct)

**Issue:** `addkey.Model`, `applysetup.Model`, and `pwauthdisable.Model` all carry a private `errFatal bool` field that controls the `styledErr`/Critical-vs-Warn rendering selection. `deleteuser.Model` does not - it always renders errInline as `styles.Critical` (deleteuser.go:669) regardless of whether the error is recoverable (e.g., "type the username verbatim to confirm" - which is a recoverable validation gate, not a fatal state) or fatal (e.g., "delete failed: ...").

This is a pre-existing inconsistency unrelated to plan 06-05's CR-01/IN-02/WR-01 fixes. It is recorded here only because the four modals are now closely parallel in their D-07/D-08 cancellation handling; the missing `errFatal` field stands out as a structural divergence.

In particular, deleteuser's "cancelled by Esc" neutral state at `:383` and `:421` lands in `phaseError` and is rendered via `styles.Critical` even though it is logically a neutral, non-fatal cancellation - the same condition in addkey/applysetup/pwauthdisable would render via `styles.Warn`.

**Severity rationale:** Info-only. The visual difference is minor (Critical vs Warn lipgloss color), the cancellation tests do not assert on the styled severity, and the user-facing meaning remains clear. Worth noting for a future pass that homogenises the four modals' Model shape, but no behavioral defect.

**Fix suggestion:** When the four modals are next cleaned up, add `errFatal bool` to `deleteuser.Model`, set it in the cancellation classifier (false for "cancelled by Esc", true for the SIGKILL-hang fallback), and update `View()` to call a `m.styledErr(s)` helper mirroring addkey.go:819-824.

---

_Reviewed: 2026-05-01_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Scope: 8 files modified by plan 06-05 (gap-closure for prior CR-01 / IN-02 / WR-01)_
