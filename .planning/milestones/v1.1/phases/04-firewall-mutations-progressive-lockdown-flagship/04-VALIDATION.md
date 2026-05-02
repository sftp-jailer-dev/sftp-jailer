---
phase: 04
slug: firewall-mutations-progressive-lockdown-flagship
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-29
---

# Phase 04 — Validation Strategy

> Retroactive Nyquist audit. Phase 04 (firewall mutations + progressive lockdown flagship) shipped 13 plans + 1 empirical UAT helper before this validation contract was written. This document reconstructs the verification map from PLAN/SUMMARY artifacts and cross-references against the existing Go test suite.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go 1.25 stdlib `testing` + `github.com/stretchr/testify v1.11.1` |
| **Config file** | `go.mod` (no separate test config) |
| **Quick run command** | `go test -count=1 ./internal/firewall/... ./internal/txn/... ./internal/lockdown/... ./internal/sysops/... ./internal/revert/...` |
| **Full suite command** | `make test` (`go test -race -count=1 ./...`) |
| **Estimated runtime** | ~25–40s full suite (race-enabled), ~5s quick subset |
| **TUI integration tests** | `github.com/charmbracelet/x/exp/teatest/v2` for screens/widgets |
| **Test files (count)** | 61 across 38 packages |
| **Suite status** | GREEN (verified 2026-04-29) |

---

## Sampling Rate

- **After every task commit:** `go test -count=1 ./<package-touched>/...`
- **After every plan wave:** `make test` (full race-enabled suite)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~40s (full suite)

---

## Per-Task Verification Map

| Plan | Requirement | Description | Impl Files | Test File / Function | Automated Command | Status |
|------|-------------|-------------|------------|----------------------|-------------------|--------|
| 04-01 | SAFE-04 | SystemOps mutation surface (UfwAllow/Insert/Delete/Reload, HasPublicIPv6, RewriteUfwIPV6, SystemdRunOnActive, SystemctlStop/IsActive) + AtomicWriteFile allowlist | `internal/sysops/{sysops,real,fake,atomic}.go` | `sysops_test.go`, `real_phase4_test.go`, `fake_phase4_test.go`, `atomic_test.go` | `go test ./internal/sysops/...` | ✅ green |
| 04-01 | FW-02 | UfwInsert wrapper for firewall CRUD | `internal/sysops/real.go` | `real_phase4_test.go::TestReal_UfwInsert_*` | `go test -run TestReal_UfwInsert ./internal/sysops/...` | ✅ green |
| 04-01 | FW-03 | UfwDelete with `--force` flag for TTY-less exit mapping | `internal/sysops/real.go` | `real_phase4_test.go::TestReal_UfwDelete_uses_force_flag_in_argv` | `go test -run TestReal_UfwDelete ./internal/sysops/...` | ✅ green |
| 04-01 | FW-06 | HasPublicIPv6 + RewriteUfwIPV6 for IPv6 leak hard-block | `internal/sysops/real.go` | `real_phase4_test.go` | `go test ./internal/sysops/...` | ✅ green |
| 04-01 | SAFE-07 | Reverse-command infrastructure (Watcher storage path allowlist) | `internal/sysops/atomic.go` | `atomic_test.go` | `go test ./internal/sysops/...` | ✅ green |
| 04-02 | FW-02 | `txn.NewUfwInsertStep` with SetAssignedID seam | `internal/txn/steps.go` | `steps_test.go::TestNewUfwInsertStep_*` | `go test -run TestNewUfwInsertStep ./internal/txn/...` | ✅ green |
| 04-02 | FW-03 | `txn.NewUfwDeleteStep` with idempotent Compensate | `internal/txn/steps.go` | `steps_test.go::TestNewUfwDeleteStep_*` | `go test -run TestNewUfwDeleteStep ./internal/txn/...` | ✅ green |
| 04-02 | SAFE-04 | `txn.NewScheduleRevertStep` + `NewCancelRevertStep` (D-S04-09 ordering) | `internal/txn/steps.go` | `steps_test.go::TestNewScheduleRevertStep_*`, `TestNewCancelRevertStep_*` | `go test -run "TestNew(Schedule\|Cancel)RevertStep" ./internal/txn/...` | ✅ green |
| 04-02 | SAFE-07 | RevertWatcher adapter interface (txn package dep avoidance) | `internal/txn/steps.go` | `steps_test.go::fakeRevertWatcher` | `go test ./internal/txn/...` | ✅ green |
| 04-03 | FW-02 | `firewall.AddRule` single writer (D-FW-01) | `internal/firewall/mutate.go` | `mutate_test.go::TestAddRule_*` | `go test -run TestAddRule ./internal/firewall/...` | ✅ green |
| 04-03 | FW-03 | `firewall.DeleteRule` + `ResolveRuleIDByCommentSource` three-mode resolver | `internal/firewall/mutate.go` | `mutate_test.go::TestDeleteRule_*`, `TestResolveRuleIDByCommentSource_*` | `go test -run "TestDeleteRule\|TestResolveRuleIDByCommentSource" ./internal/firewall/...` | ✅ green |
| 04-03 | FW-07 | `UfwInsert` position=1 discipline (D-FW-02) | `internal/firewall/mutate.go` | `mutate_test.go::TestAddRule_calls_UfwInsert_*_returns_assigned_id` | `go test -run TestAddRule_calls_UfwInsert ./internal/firewall/...` | ✅ green |
| 04-03 | FW-08 | SQLite mirror table (`003_user_ips.sql`) + `RebuildUserIPs`/`UserIPs` queries | `internal/store/migrations/003_user_ips.sql`, `internal/store/queries.go` | `queries_test.go::TestRebuildUserIPs_*`, `TestUserIPs_*` | `go test -run "TestRebuildUserIPs\|TestUserIPs" ./internal/store/...` | ✅ green |
| 04-03 | LOCK-08 | `firewall.DetectMode` 4-state classifier (Open/Staging/Locked/Unknown) | `internal/firewall/mode.go` | `mode_test.go::TestDetectMode_*` | `go test -run TestDetectMode ./internal/firewall/...` | ✅ green |
| 04-04 | SAFE-04 | `revert.Watcher` singleton + on-disk pointer + `Restore` reconciliation | `internal/revert/watcher.go` | `watcher_test.go::TestWatcher_*` | `go test ./internal/revert/...` | ✅ green |
| 04-04 | SAFE-07 | `lockdown.RenderReverseCommands` (D-S04-09 step-2 reverse-cmd renderer) | `internal/revert/render_reverse.go`, `internal/lockdown/render_reverse.go` | `render_reverse_test.go::TestRenderReverseCommands_*` | `go test -run TestRenderReverseCommands ./internal/...` | ✅ green |
| 04-05 | FW-02 | M-ADD-RULE modal state machine (phaseInput → phaseReview → phaseCommitting → phaseDone) | `internal/tui/screens/firewallrule/addrule.go` | `addrule_test.go::TestAttemptParse_*`, `TestNew_locked_user_path`, `TestWantsRawKeys_*` | `go test ./internal/tui/screens/firewallrule/...` | ✅ green |
| 04-05 | FW-05 | All firewall mutations under SAFE-04 revert window | `internal/tui/screens/firewallrule/addrule.go::commitCmd` | `addrule_test.go` (composition via `NewScheduleRevertStep`) | `go test ./internal/tui/screens/firewallrule/...` | ✅ green |
| 04-05 | FW-06 | M-FW-IPV6-FIX modal (HasPublicIPv6 ∧ IPV6=no leak detection + rewrite batch) | `internal/tui/screens/firewallrule/ipv6_preflight.go` | `ipv6_preflight_test.go::TestNewIPv6Fix_*`, `TestIPv6Fix_*` | `go test -run TestIPv6Fix ./internal/tui/screens/firewallrule/...` | ✅ green |
| 04-05 | BOOTSTRAP | `main.go` factory injection for M-ADD-RULE via `SetAddRuleFactory` (L-keybind deferred to 04-08) | `cmd/sftp-jailer/main.go` | (bootstrap wired by suite-wide green) | `make test` | ✅ green |
| 04-06 | FW-03 | M-DELETE-RULE three-mode modal (by-id / by-user / by-source) | `internal/tui/screens/firewallrule/deleterule.go` | `deleterule_test.go::TestNewDelete*`, `TestDeleteModel_*` | `go test ./internal/tui/screens/firewallrule/...` | ✅ green |
| 04-06 | FW-08 | `RebuildUserIPs` post-delete (mirror's second consumer) | `internal/tui/screens/firewallrule/deleterule.go::deleteCmd` | `deleterule_test.go::TestDeleteModel_post_commit_enumerate_runs` | `go test -run TestDeleteModel_post_commit_enumerate_runs ./internal/tui/screens/firewallrule/...` | ✅ green |
| 04-06 | BOOTSTRAP | `main.go` bootstrap for M-DELETE-RULE via mode-dispatch factory | `cmd/sftp-jailer/main.go` | (bootstrap wired by suite-wide green) | `make test` | ✅ green |
| 04-07 | LOCK-02 | `lockdown.Generator` observation→proposal pivot (window cutoff + tier filter) | `internal/lockdown/proposal.go` | `proposal_test.go::TestGenerate_*` | `go test ./internal/lockdown/...` | ✅ green |
| 04-07 | LOCK-03 | `lockdown.DetectAdminIP` SSH_CONNECTION + who-am-i fallback chain | `internal/lockdown/admin_ip.go` | `admin_ip_test.go::TestDetectAdminIP_*` | `go test -run TestDetectAdminIP ./internal/lockdown/...` | ✅ green |
| 04-07 | LOCK-04 | `lockdown.proposal_window_days` koanf knob (default 90, range [1, 3650]) | `internal/config/config.go` | `config_test.go::TestConfig_LockdownProposalWindowDays_*`, `settings_test.go::TestLockdownWindow_*` | `go test ./internal/config/... ./internal/tui/screens/settings/...` | ✅ green |
| 04-08 | LOCK-03 | S-LOCKDOWN admin-IP guard banner (`adminIPCovered` check) | `internal/tui/screens/lockdown/lockdown.go` | `lockdown_test.go::TestAdminIPCovered_*`, `TestAugmentWithZeroConnUsers_*` | `go test ./internal/tui/screens/lockdown/...` | ✅ green |
| 04-08 | LOCK-05 | M-DRY-RUN modal (two-section preview: rule diff + command plan) | `internal/tui/screens/lockdown/dryrun.go` | `dryrun_test.go::TestRender*`, `TestRenderPlanText_*` | `go test ./internal/tui/screens/lockdown/...` | ✅ green |
| 04-08 | LOCK-06 | S-LOCKDOWN `commitCmd` SAFE-04-wrapped batch (Schedule + InsertSteps + DeleteCatchAll + Reload) | `internal/tui/screens/lockdown/lockdown.go` | `lockdown_test.go::TestCommitCmd_*` | `go test -run TestCommitCmd ./internal/tui/screens/lockdown/...` | ✅ green (post-04-13 fix) |
| 04-08 | LOCK-08 | S-LOCKDOWN `rollbackCmd` (re-add catch-all via signature-grep under SAFE-04) | `internal/tui/screens/lockdown/lockdown.go` | `lockdown_test.go::TestRollbackCmd_*` | `go test -run TestRollbackCmd ./internal/tui/screens/lockdown/...` | ✅ green |
| 04-08 | LOCK-09 | S-LOCKDOWN staged-promotion flow (OPEN→LOCKED + STAGING→LOCKED both delete catch-all) | `internal/tui/screens/lockdown/lockdown.go::buildPendingMutations` | `lockdown_test.go::TestBuildPendingMutations_*` | `go test -run TestBuildPendingMutations ./internal/tui/screens/lockdown/...` | ✅ green (post-04-13 fix) |
| 04-08 | BOOTSTRAP | home `L`-keybind + S-LOCKDOWN factory injection | `internal/tui/screens/home/home.go`, `cmd/sftp-jailer/main.go` | `home_test.go::TestHome_L_*` | `go test -run TestHome_L ./internal/tui/screens/home/...` | ✅ green |
| 04-09 | SAFE-04 | `ModeBar` widget global countdown banner (REVERTING IN M:SS override) | `internal/tui/widgets/modebar.go` | `modebar_test.go::TestModeBar_renders_*`, `TestFormatDuration_*` | `go test ./internal/tui/widgets/...` | ✅ green |
| 04-09 | LOCK-08 | MODE banner (global OPEN/STAGING/LOCKED/UNKNOWN visibility) | `internal/tui/app/app.go` | `app_test.go::TestApp_View_modebar_renders_*`, `TestApp_SetMode_*` | `go test ./internal/tui/app/...` | ✅ green |
| 04-09 | BOOTSTRAP | `main.go` `revertWatcher.Restore(ctx)` at TUI startup + `app.SetWatcher` wiring | `cmd/sftp-jailer/main.go` | (bootstrap wired by suite-wide green) | `make test` | ✅ green |
| 04-10 | EMPIRICAL-UAT | `cmd/uat-04` four-scenario helper (SAFE-04 timer-fires + FW-06 hard-block + LOCK-06 commit + LOCK-08 rollback) | `cmd/uat-04/main.go` | Empirical: `ubuntu-wifi` 2026-04-28 23:36 CEST — 4/4 PASS (logged in `04-10-SUMMARY.md`) | `sudo ./uat-04 --scenario all` (manual; see Manual-Only) | ✅ green (empirical) |
| 04-11 | SAFE-04 | `cancelRevertStep.Apply` stops BOTH `.timer` and `.service` (BUG-04-D fix) | `internal/txn/steps.go::cancelRevertStep` | `steps_test.go::TestNewCancelRevertStep_apply_stops_timer_BEFORE_service` | `go test -run TestNewCancelRevertStep_apply_stops_timer ./internal/txn/...` | ✅ green |
| 04-12 | FW-07 | `txn.NewUfwDeleteCatchAllByEnumerateStep` (position-independent dual-family catch-all deletion, BUG-04-A/C foundation) | `internal/txn/steps.go` | `steps_test.go::TestUfwDeleteCatchAllByEnumerate_*` | `go test -run TestUfwDeleteCatchAllByEnumerate ./internal/txn/...` | ✅ green |
| 04-12 | TEST-INFRA | `sysops.Fake.ExecResponseQueue` FIFO seam (stateful `Enumerate` test scripting) | `internal/sysops/fake.go` | `fake_test.go::TestFake_ExecResponseQueue_*` | `go test -run TestFake_ExecResponseQueue ./internal/sysops/...` | ✅ green |
| 04-13 | LOCK-06 | S-LOCKDOWN `commitCmd` wires `NewUfwDeleteCatchAllByEnumerateStep` (user-visible BUG-04-A + BUG-04-C closure) | `internal/tui/screens/lockdown/lockdown.go::commitCmd` | `lockdown_test.go::TestCommitCmd_OPEN_mode_appends_NewUfwDeleteCatchAllByEnumerateStep`, `TestBuildPendingMutations_emits_only_OpAdd_in_OPEN_mode_post_BUG_04_A` | `go test -run "TestCommitCmd_OPEN_mode_appends\|TestBuildPendingMutations_emits_only_OpAdd" ./internal/tui/screens/lockdown/...` | ✅ green |

*Status legend: ✅ green · ❌ red · ⚠️ flaky · ⬜ pending*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No Wave 0 stub work needed:
- Go stdlib `testing` was already in place pre-phase.
- `testify` was already a dep.
- `teatest/v2` was already integrated for TUI screens.
- `sysops.Fake.ExecResponseQueue` (Plan 04-12) is the only new test seam — it shipped as a feature commit alongside the test that exercises it.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end SAFE-04 timer-fires-on-crash → rules restored | `cmd/uat-04` scenario 1 | Requires real `systemd-run --on-active`, real `ufw`/`nft` state, root privileges, and a TUI process that gets killed mid-window. Cannot be unit-tested. | `sudo bin/uat-04 --scenario safe04-timer-fires` on a fresh Ubuntu 24.04 VM. Verify via `journalctl -u sftp-jailer-revert-*.service`. Last green: 2026-04-28 on `ubuntu-wifi`. |
| FW-06 IPv6 leak hard-block on dual-stack host | `cmd/uat-04` scenario 2 | Requires public IPv6 connectivity + `IPV6=no` in `/etc/default/ufw`. CI does not have public IPv6. | `sudo bin/uat-04 --scenario fw06-ipv6-leak` on Ubuntu 24.04 with public IPv6. Verify modal blocks until `IPV6=yes` rewrite + ufw reload. |
| LOCK-06 OPEN→LOCKED transition deletes catch-alls (v4 + v6) | `cmd/uat-04` scenario 3 | Requires real ufw v4+v6 rule state, real position-shift behavior of `ufw insert 1`. Stateful unit-tested via `ExecResponseQueue` (`TestUfwDeleteCatchAllByEnumerate_*`) but full empirical pass needs a VM. | `sudo bin/uat-04 --scenario lock06-commit` on Ubuntu 24.04. Verify `ufw status numbered` shows no `Anywhere ALLOW` rules post-commit. |
| LOCK-08 rollback re-adds catch-all via signature-grep | `cmd/uat-04` scenario 4 | Same as above — empirical state machine on real ufw. | `sudo bin/uat-04 --scenario lock08-rollback` on Ubuntu 24.04. Verify catch-all rule restored to position 1. |
| BUG-04-B (`ufw insert 1` against empty v4 list) | Plan 04-08 deferral | Dormant — modal-majority hosts (those with at least one prior allow) are not affected. Documented for **v1.2** scope. No Phase 04 test asserts the empty-list case. | Open `cmd/uat-04` scenario for empty-v4-list case in v1.2 milestone. Reference: `04-10-SUMMARY.md` BUG-04-B section. |

---

## Validation Sign-Off

- [x] All tasks have automated `<verify>` commands or are documented as manual-only with empirical UAT evidence
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every plan committed test artifacts)
- [x] Wave 0 covers all MISSING references — none required, infrastructure pre-existed
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 60s (full race-enabled suite ≈ 25–40s)
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Empirical UAT (`cmd/uat-04`, 4/4 scenarios) validated on Ubuntu 24.04 dual-stack — 2026-04-28
- [x] All four discovered production bugs (BUG-04-A/B/C/D) addressed: 3 fixed (04-11/12/13), 1 deferred to v1.2 with documented scope (BUG-04-B)

**Approval:** approved 2026-04-29

---

## Validation Audit 2026-04-29

| Metric | Count |
|--------|-------|
| Requirements analyzed | 40 |
| COVERED | 40 (37 direct + 3 post-fix-pinned via 04-11/12/13) |
| PARTIAL | 0 |
| MISSING | 0 |
| Manual-only items | 5 (4 empirical UAT scenarios + 1 deferred bug) |
| Suite status | GREEN |
| Gaps filled this audit | 0 (no test code generated — coverage was already complete) |
