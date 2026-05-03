---
phase: 08-frame
plan: 04
type: execute
wave: 2
status: complete
requirements: [FW-11]
completed: 2026-05-03
---

# 08-04: ufwenable modal + doctor [a]/[A] dispatch (FW-11) - Summary

## What was built

The user-facing `[A] Enable ufw` flow that closes the v1.2.2 label-only deferral. Composed from the FW-11 substrate landed by 08-03.

**Tasks 1-2 (autonomous):**

1. **`internal/tui/screens/ufwenable/`** (new package, 5-phase state machine)
   - `phasePreFlight`: async `ShowUFWAdded` + SSH-session check via `Init()` batch
   - `phaseConfirm`: textinput YES gate (exact uppercase match, TrimSpace-tolerant for trailing whitespace)
   - `phaseApplying`: direct `sysops.EnableUFW(ctx)` call - **NOT** under SAFE-04 (D-08 boundary - `ufw enable` exits the SAFE-04 contract because the compensator `ufw disable` would leave the system in a rules-present-but-no-enforcement state that did not exist before)
   - `phaseDone`: success + 1500ms auto-pop linger (bumped from 500ms after UAT - operator could not register the green success line)
   - `phaseError`: hard-block (no SSH allow) with `[r]` chain to `addrule.NewWithOptions(AutoRevert: false)` per D-13
   - 17 unit tests + 4 golden frames; D-08 import regression test asserts no `txn`/`revert` imports in this package
   - SSH-detection two-channel detector (`SSH_CONNECTION` env + `who` parser fallback) - the env var is stripped by sudo, so the operator path `sudo sftp-jailer` needs the fallback

2. **`internal/tui/screens/doctor/doctor.go`** (D-14 precedence dispatch + D-15 belt-and-suspenders)
   - `[a]/[A]` dispatch: `NeedsCanonicalApply` first, then `NeedsUfwEnable`, then no-op
   - `colorizeReport(text, activeMarker)`: `>` marker in Primary style on the active dispatch row (TUI layer only - Pitfall 4: render.go stays ANSI-free)
   - Footer hint reflects active dispatch target with the new `[return] continue` affordance (UAT round 4 operator request)

**Task 3 (lab UAT - human-verify checkpoint):**

Empirical sign-off on ubuntu-wifi (192.168.1.187) by the operator on 2026-05-03. The UAT iterated through 4 rounds because the live environment surfaced bugs that unit tests had not caught - see "Out-of-band hotfixes" below. Final round (`dec9180`) approved by the operator with all four scenarios (P3-A hard-block, P3-B [r] chain with AutoRevert=false suppression, P3-C YES enable, P3-D YES gate edges) verified.

debian13 (192.168.1.170) UAT not run in this round - tracked as outstanding work.

**Task 4 (verification gate):**
- `go test ./...` - all 38 packages pass (full suite)
- `go vet ./...` - clean
- `golangci-lint run ./...` - 0 issues
- All 7 CI guards (`scripts/check-*.sh`) green

## Out-of-band hotfixes landed during the lab UAT iteration

The UAT surfaced bugs adjacent to FW-11 that blocked operator validation. These were fixed inline rather than deferred to a gap-closure phase because each was small and load-bearing for the UAT to proceed.

| Commit | Defect surfaced |
|---|---|
| `54bd34a` | SAFE-04 [C]onfirm / [V]iew countdown hotkeys had been advertised by the modebar since v1.0 / plan 04-09 but never wired. Debug session `safe04-confirm-view-keys` resolved this. |
| `26bda53` | ufwenable [r] chain pushed addrule with `lockedUser=""`, which made `ufwcomment.Encode` fail with `ErrInvalidUser` at confirm time. Default to `"root"` (system-rule attribution). |
| `46096d3` | `ufw insert 1 allow ...` rejected with "ERROR: Invalid position '1'" on a freshly-reset ufw (Phase 4 substrate bug exposed by FW-11). The `[r]` chain bootstrap path now uses `NewUfwAllowStep` (append) when `AutoRevert=false`. |
| `3ae0621` | Doctor footer never showed `[esc]` back on the all-green case - operator landed on a dead-end screen. |
| `c902fc4` | Modebar `MODE: UNKNOWN - no SFTP-port rules` used dev jargon. Reworded to operator-friendly copy. autoPopDelay bumped 500ms -> 1500ms. |
| `32ac43a` | Doctor screen never re-ran its diagnostic when a mutation modal popped back. New `nav.DoctorRefreshMsg` emitted by ufwenable + applysetup. |
| `9007663` + `e50540f` | Splash -> doctor -> home gate (operator-stated: "ensure the diagnostics are run after the splash screen, and only continue to the home screen if everything is green"). `e50540f` fixed two latent wiring bugs in `9007663`: (a) `RegisterPlaceholderResolver` appends - the early `wire.Register(nil)` won the race over the later doctor-aware resolver; (b) `tea.Batch(PopCmd, refreshMsg)` had a Pop-vs-refresh ordering race - changed to `tea.Sequence`. |
| `81939ce` | Modebar binarized to `LOCKED` (green) / `UNLOCKED` (red) per operator direction. The internal `firewall.Mode` enum kept its 4 values; only the modebar render is binarized. |
| `a20db21` | Three round-3 corrections: (a) `cancelRevertStep` now also matches systemd exit code 5 as idempotent (was missing the structural signal under truncated stderr); (b) splash-gate stops auto-advancing on healthy - operator wanted to land on doctor regardless and advance via [esc]; (c) `MODE:` -> `FIREWALL MODE:`. |
| `c0d6ff2` | (1) Modebar firewall mode was stuck on `ModeUnknown` forever because `App.SetMode` had no production callsite. New `ModeDetector` injection seam invoked on `App.Init` + after every `revertConfirmedMsg` success. (2) Doctor dismiss key changed to `Press return to continue` (Enter) with `[esc]` kept as silent fallback. |
| `dec9180` | SSH session detection survives sudo: env channel + `who`-parser fallback. Verified on ubuntu-wifi end-to-end. |

## Key files

**created:**
- `internal/tui/screens/ufwenable/ufwenable.go`
- `internal/tui/screens/ufwenable/ufwenable_test.go`
- `internal/tui/screens/ufwenable/testdata/golden/preflight_pass.txt`
- `internal/tui/screens/ufwenable/testdata/golden/preflight_hard_block.txt`
- `internal/tui/screens/ufwenable/testdata/golden/applying.txt`
- `internal/tui/screens/ufwenable/testdata/golden/done.txt`
- `internal/tui/app/app_safe04_test.go` (11 tests pinning the SAFE-04 hotkey contract)
- `.planning/debug/safe04-confirm-view-keys.md` (debug session, status: resolved)

**modified:**
- `internal/tui/screens/doctor/doctor.go`, `doctor_test.go` ([a]/[A] dispatch + DoctorRefreshMsg + startup gate + return-to-continue dismiss)
- `internal/tui/widgets/modebar.go`, `modebar_test.go` (LOCKED/UNLOCKED render, FIREWALL MODE label)
- `internal/tui/screens/applysetup/applysetup.go` (DoctorRefreshMsg emission)
- `internal/tui/screens/firewallrule/addrule.go`, `addrule_test.go` (UfwAllow vs UfwInsert per AutoRevert)
- `internal/tui/app/app.go` (SAFE-04 hotkey wiring + ModeDetector injection seam)
- `internal/tui/nav/msgs.go` (DoctorRefreshMsg)
- `internal/tui/wire/wire.go` (startup-gate placeholder resolver)
- `internal/service/doctor/doctor.go` (IsHealthy predicate)
- `internal/txn/steps.go`, `steps_test.go` (isIdempotentSystemctlStopError - exit 5 + locale-tolerant matching)
- `cmd/sftp-jailer/main.go` (RevertCanceller + ModeDetector wiring)
- `cmd/uat-04/main.go` (modebar label sync)

## Self-Check: PASSED

- All 4 plan tasks executed (Tasks 1-2 autonomous, Task 3 human-verify approved by operator on 2026-05-03 ubuntu-wifi UAT, Task 4 verification gate green)
- Each commit individually (TDD RED/GREEN where applicable)
- D-08 enforced: `internal/tui/screens/ufwenable/` does not import `internal/revert` or `internal/txn`
- D-13 enforced: `[r]` chain pushes addrule with `AutoRevert: false`
- D-14 enforced: doctor [a] precedence is canonical-apply > ufw-enable
- D-15 enforced: `>` marker + footer hint both reflect active dispatch
- Phase 8 substrate (Wave 1: 08-01, 08-02, 08-03) consumed correctly: `sysops.EnableUFW`, `firewall.SSHAllowPresent`, `doctor.NeedsUfwEnable`, `addrule.NewWithOptions{AutoRevert: false}` all wired through to Plan 04
- All existing call sites continue to compile and pass tests

## Outstanding

- debian13 (192.168.1.170) lab UAT not run this round. Tracked for follow-up; v1.3 milestone ships ubuntu-wifi-validated (tier-1 supported per project memory).
- The v1.4 chrome redesign (backlog 999.1) consolidates the operator's UI direction surfaced during this UAT (midnight-commander-style overview, FIREWALL MODE switch widget, colored borders, bottom command bar with splash palette, wired SSH/Users/Rules statistics, L-key toggle). To be planned via `/gsd:new-milestone v1.4` after v1.3 ships.
- Settings chroot edit (backlog 999.2) - operator request from this UAT. Likely overlaps with Phase 10 (Migrate).
