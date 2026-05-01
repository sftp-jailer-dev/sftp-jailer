---
phase: 02
slug: observation-pipeline-read-only-screens
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-01
---

# Phase 02 - Validation Strategy

> Retroactive Nyquist audit. Phase 02 (observation pipeline + read-only feature screens) shipped 12 plans before this validation contract was written. This document reconstructs the verification map from PLAN/SUMMARY/VERIFICATION artifacts and cross-references against the existing Go test suite.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go 1.25 stdlib `testing` + `github.com/stretchr/testify v1.11.1` |
| **Config file** | `go.mod` (no separate test config) |
| **Quick run command** | `go test -count=1 ./internal/observe/... ./internal/store/... ./internal/firewall/... ./internal/users/... ./internal/config/... ./internal/sysops/... ./internal/tui/screens/logs/... ./internal/tui/screens/users/... ./internal/tui/screens/firewall/... ./internal/tui/screens/settings/... ./internal/tui/screens/observerun/...` |
| **Full suite command** | `make test` (`go test -race -count=1 ./...`) |
| **Estimated runtime** | ~30-45s full suite (race-enabled), ~12s quick subset |
| **TUI integration tests** | `github.com/charmbracelet/x/exp/teatest/v2` for screens |
| **Test files (count)** | 26 across 12 packages (Phase 2 package subset) |
| **Suite status** | GREEN (verified 2026-05-01) |

---

## Sampling Rate

- **After every task commit:** `go test -count=1 ./<package-touched>/...`
- **After every plan wave:** `make test` (full race-enabled suite)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~45s (full suite)

---

## Per-Task Verification Map

| Plan | Requirement | Description | Impl Files | Test File / Function | Automated Command | Status |
|------|-------------|-------------|------------|----------------------|-------------------|--------|
| 02-01 | OBS-04 | `store.PeekUserVersion` read-only peek + `ExpectedSchemaVersion=2` constant for schema-drift gate | `internal/store/store.go` | `store_test.go::TestPeekUserVersion_*`, `TestMigrate_advances_to_expected_version` | `go test ./internal/store/...` | ✅ green |
| 02-01 | LOG-01 | `store.Queries.FilterEvents` parameterized query (user/tier/source/time filters) seeds S-LOGS filterable view | `internal/store/queries.go` | `queries_test.go::TestQueries_FilterEvents_*` (6 cases) | `go test -run TestQueries_FilterEvents ./internal/store/...` | ✅ green |
| 02-01 | LOG-03 | `FilterEvents.Limit=500` cap + parameterized-SQL discipline (injection regression test) | `internal/store/queries.go` | `queries_test.go::TestQueries_FilterEvents_pagination`, `TestQueries_FilterEvents_parameterized_no_injection` | `go test -run TestQueries_FilterEvents_pagination ./internal/store/...` | ✅ green |
| 02-01 | LOG-04 | `store.Queries.StatusRow` + schema-drift branch for S-LOGS status row | `internal/store/queries.go` | `queries_test.go::TestQueries_StatusRow_*` (2 cases) | `go test -run TestQueries_StatusRow ./internal/store/...` | ✅ green |
| 02-01 | LOG-06 | `store.Queries.PerUserBreakdown` 3-round-trip aggregation for per-user breakdown | `internal/store/queries.go` | `queries_test.go::TestQueries_PerUserBreakdown`, `TestPerUserBreakdown_*` | `go test -run TestQueries_PerUserBreakdown ./internal/store/...` | ✅ green |
| 02-01 | USER-01 | `store.Queries.LastLoginPerUser` join (excludes empty usernames in SQL) | `internal/store/queries.go` | `queries_test.go::TestQueries_LastLoginPerUser_*` | `go test ./internal/store/...` | ✅ green |
| 02-02 | OBS-02 | `sysops.AcquireRunLock` flock(LOCK_EX|LOCK_NB) + ErrLockHeld sentinel for no-miss-no-dup | `internal/sysops/lock.go` | `lock_test.go::TestAcquireRunLock_*` (5 tests) | `go test ./internal/sysops/...` | ✅ green |
| 02-02 | OBS-03 | `observe.Classify` 4-tier classifier: 9 EventType constants + split per-method regexes (pubkey-fail, sftp-subsystem) | `internal/observe/classify.go` | `classify_test.go::TestClassify_*` (10 tests) | `go test ./internal/observe/...` | ✅ green |
| 02-02 | OBS-04 | `schemaCheck` + `osExit` seam: schema-drift gate in `observe-run` cobra cmd (exit 2 when DB newer than binary) | `cmd/sftp-jailer/observe.go` | `observe_test.go::TestObserveRunCmd_OBS04_*` | `go test ./cmd/sftp-jailer/...` | ✅ green |
| 02-02 | OBS-05 | `observe.Runner` pipeline: `compact` + `pruneToCap` + config-driven `RunOpts` (CompactAfterDays + DBMaxSizeMB) | `internal/observe/runner.go` | `runner_test.go::TestRunner_compaction_*`, `TestRunner_two_consecutive_runs_*` | `go test -run TestRunner_compaction ./internal/observe/...` | ✅ green |
| 02-02 | OBS-06 | `sysops.ObserveRunStream` typed subprocess shim (fixed argv, T-OBS-06 mitigation) | `internal/sysops/journalctl.go` | `journalctl_test.go::TestObserveRunStream_*` | `go test ./internal/sysops/...` | ✅ green |
| 02-02 | LOG-02 | `sysops.JournalctlFollowCmd` returns unstarted `*exec.Cmd` for `tea.ExecProcess` live-tail hand-off | `internal/sysops/journalctl.go` | `journalctl_test.go::TestJournalctlFollowCmd_*` | `go test -run TestJournalctlFollowCmd ./internal/sysops/...` | ✅ green |
| 02-03 | FW-01 | `firewall.Enumerate` typed reader over `ufw status numbered` - parses Rule{Proto, Port, Source, Action, RawComment, User, ParseErr} | `internal/firewall/enumerate.go` | `enumerate_test.go::TestEnumerate_*` (7 tests) | `go test ./internal/firewall/...` | ✅ green |
| 02-03 | FW-04 | `firewall.Rule.User` field + `ErrBadVersion` forward-compat surface (ParseErr on v=2+ comments) | `internal/firewall/enumerate.go` | `enumerate_test.go::TestEnumerate_parses_sftpj_comment`, `TestEnumerate_bad_version_forward_compat` | `go test -run TestEnumerate ./internal/firewall/...` | ✅ green |
| 02-03 | USER-01 | `users.Enumerate` D-10 union: sftp* group users + ChrootDirectory home users + D-12 INFO pseudo-rows | `internal/users/enumerate.go` | `enumerate_test.go::TestEnumerate_*` (8 tests) | `go test ./internal/users/...` | ✅ green |
| 02-03 | USER-02 | `users.Enumerator` data model seeds S-USERS fuzzy-search corpus and sort axes | `internal/users/enumerate.go` | `enumerate_test.go::TestEnumerate_returns_sorted_by_username`, `TestEnumerate_info_rows` | `go test ./internal/users/...` | ✅ green |
| 02-03 | OBS-05 | `config.Load/Save/Validate/Defaults` koanf-based config (CompactAfterDays, DetailRetentionDays, DBMaxSizeMB) | `internal/config/config.go` | `config_test.go::TestValidate_*`, `TestLoad_*` (10 tests) | `go test ./internal/config/...` | ✅ green |
| 02-04 | USER-01 | S-USERS Bubble Tea v2 screen: 8-column table (username/UID/chroot/pwd-age/keys/last-login/first-seen-IP/allowlist) | `internal/tui/screens/users/users.go` | `users_test.go::TestSUsers_*` (14 tests) | `go test ./internal/tui/screens/users/...` | ✅ green |
| 02-04 | USER-02 | S-USERS `/` fuzzy search (applySortAndFilter), 5-axis sort cycle, j/k vim nav, OSC 52 copy | `internal/tui/screens/users/users.go` | `users_test.go::TestSUsers_sort_*`, `TestSUsers_search_*`, `TestSUsers_jk_*` | `go test -run TestSUsers ./internal/tui/screens/users/...` | ✅ green |
| 02-04 | BOOTSTRAP | `cmd/sftp-jailer/main.go` runTUI bootstrap: ops + store.Open + Migrate + NewQueries + users.New factory wiring | `cmd/sftp-jailer/main.go` | (bootstrap validated by suite-wide green) | `make test` | ✅ green |
| 02-05 | FW-01 | S-FIREWALL Bubble Tea v2 screen: flat mode renders id/proto/port/source/user/comment columns | `internal/tui/screens/firewall/firewall.go` | `firewall_test.go::TestSFirewall_*` | `go test ./internal/tui/screens/firewall/...` | ✅ green |
| 02-05 | FW-04 | S-FIREWALL `g` toggle switches to by-user view (groups rules per sftpj-tagged user) | `internal/tui/screens/firewall/firewall.go` | `firewall_test.go::TestSFirewall_g_toggles_by_user_view` | `go test -run TestSFirewall_g ./internal/tui/screens/firewall/...` | ✅ green |
| 02-06 | LOG-01 | S-LOGS Bubble Tea v2 screen: filterable log viewer with tier filter (`t` key cycles tiers) | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_tier_filter_*` | `go test ./internal/tui/screens/logs/...` | ✅ green |
| 02-06 | LOG-02 | S-LOGS `F` key invokes `tea.ExecProcess(m.ops.JournalctlFollowCmd("ssh"), ...)` live-tail hand-off | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_F_dispatches_exec_process` | `go test -run TestLogsScreen_F ./internal/tui/screens/logs/...` | ✅ green |
| 02-06 | LOG-03 | S-LOGS pagination via FilterEvents Limit=500; `/` search activates Search widget | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_search_*` | `go test -run TestLogsScreen_search ./internal/tui/screens/logs/...` | ✅ green |
| 02-06 | LOG-04 | S-LOGS wide-mode (>=120 cols) split-pane detail view: ts/user/source/event/tier per entry via `RenderDetail` | `internal/tui/screens/logs/logs.go`, `internal/tui/screens/logs/detailpane.go` | `logs_test.go::TestLogsScreen_detail_pane_*`, `TestRenderDetail_*` | `go test ./internal/tui/screens/logs/...` | ✅ green |
| 02-06 | LOG-05 | S-LOGS 4-tier classification surfaced: glyphs + `colorByTier` styles (Success/Critical/Info/Warn) | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_tier_colors_*`, `TestLogsScreen_renders_tier_glyph` | `go test ./internal/tui/screens/logs/...` | ✅ green |
| 02-06 | LOG-06 | S-LOGS status row: `Queries.StatusRow` health + `Queries.PerUserBreakdown` data layer wired; per-user-detail modal deferred per REQUIREMENTS.md | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_LoadStatusForTest_*` | `go test -run TestLogsScreen_LoadStatusForTest ./internal/tui/screens/logs/...` | ✅ green |
| 02-07 | OBS-05 | S-SETTINGS write surface: `AtomicWriteFile`-backed config save; retention knob visible in settings rows | `internal/tui/screens/settings/settings.go` | `settings_test.go::TestSettingsScreen_save_*`, `TestSettingsScreen_LoadSettingsForTest_renders_all_field_rows` | `go test ./internal/tui/screens/settings/...` | ✅ green |
| 02-07 | OBS-05 | `scripts/check-no-raw-config-write.sh` CI guard: config.yaml writes only flow through internal/config + internal/sysops | `scripts/check-no-raw-config-write.sh` | CI enforcement (`.github/workflows/ci.yml`) | `bash scripts/check-no-raw-config-write.sh` | ✅ green |
| 02-07 | LOG-04 | S-SETTINGS `WantsRawKeys-true-while-editing` pattern (first write-form screen; reusable for future TUI write surfaces) | `internal/tui/screens/settings/settings.go` | `settings_test.go::TestSettingsScreen_WantsRawKeys_false_when_not_editing`, `TestSettingsScreen_esc_in_edit_cancels` | `go test -run TestSettingsScreen_WantsRawKeys ./internal/tui/screens/settings/...` | ✅ green |
| 02-08 | OBS-06 | M-OBSERVE modal closes OBS-06: `r` in S-LOGS pushes observerun screen; goroutine + program.Send bridges subprocess stdout into tea event loop | `internal/tui/screens/observerun/observerun.go` | `observerun_test.go::TestObserveRunScreen_*` (10 tests) | `go test ./internal/tui/screens/observerun/...` | ✅ green |
| 02-08 | LOG-06 | `internal/tui/nav/msgs.go` cross-screen message types: `StatusRefreshMsg` + `ObserveRunCompleteToast` consumed by S-LOGS | `internal/tui/nav/msgs.go` | `observerun_test.go::TestObserveRunScreen_done_emits_pop_status_refresh_and_complete_toast` | `go test -run TestObserveRunScreen_done ./internal/tui/screens/observerun/...` | ✅ green |
| 02-09 | OBS-01 | `packaging/systemd/sftp-jailer-observer.service` + `.timer` - OBS-01 half (a): unit files in tree with `OnCalendar=weekly`, `Persistent=true` | `packaging/systemd/sftp-jailer-observer.service`, `packaging/systemd/sftp-jailer-observer.timer` | Empirical: `systemd-analyze verify` on Ubuntu 24.04 (see Manual-Only) | Manual-only (see below) | ✅ green (files present) |
| 02-10 | LOG-01 | S-LOGS `applyFilter()` client-side fuzzy filter: `m.filtered` slice narrows on User+SourceIP+EventType+Tier corpus via `sahilm/fuzzy.Find` | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_search_narrows_visible_events_by_user`, `TestLogsScreen_search_narrows_by_source_ip_and_event_type_and_tier` | `go test -run TestLogsScreen_search_narrows ./internal/tui/screens/logs/...` | ✅ green |
| 02-10 | LOG-03 | S-LOGS search composes with tier filter; cursor clamps to `len(m.filtered)`; copy/detail-pane index `m.filtered` | `internal/tui/screens/logs/logs.go` | `logs_test.go::TestLogsScreen_search_clamps_cursor_to_filtered_length`, `TestLogsScreen_search_composes_with_tier_filter` | `go test -run TestLogsScreen_search_clamps ./internal/tui/screens/logs/...` | ✅ green |
| 02-11 | USER-01 | `sysops.ReadShadow` typed getter (lstchg + maxDays from /etc/shadow fields 3+5); `users.FormatPasswordAge` truth-table helper (5 buckets: unknown/indefinite/fresh/aging/stale) | `internal/sysops/real.go`, `internal/users/format.go` | `format_test.go::TestFormatPasswordAge_truth_table` (12 boundary cases); `sysops_test.go::TestFake_ReadShadow_*` | `go test ./internal/users/... ./internal/sysops/...` | ✅ green |
| 02-11 | USER-01 | `users.Enumerator.enrichPasswordAge` fail-silent enricher; `usersscreen.NewWithConfig` threshold-aware legend; `config.Settings.PasswordAgingDays/PasswordStaleDays` | `internal/users/enumerate.go`, `internal/tui/screens/users/users.go`, `internal/config/config.go` | `users_test.go::TestSUsers_*` (14 tests); `config_test.go::TestValidate_*` | `go test ./internal/tui/screens/users/... ./internal/config/...` | ✅ green |
| 02-12 | OBS-05 | `observe.Runner.pruneDetail`: parameterized `DELETE FROM observations WHERE ts_unix_ns < ?`; pipeline order locked: compact -> pruneDetail -> pruneToCap; zero-guard parity with pruneToCap | `internal/observe/runner.go` | `runner_test.go::TestRunner_pruneDetail_*` (4 tests including pipeline-ordering invariant) | `go test -run TestRunner_pruneDetail ./internal/observe/...` | ✅ green |

*Status legend: ✅ green - ❌ red - ⚠️ flaky - ⬜ pending*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No Wave 0 stub work needed:
- Go stdlib `testing` was already in place pre-phase (Phase 1 baseline).
- `testify` was already a dep since Phase 1.
- `teatest/v2` was already integrated for TUI screens (Phase 1 doctor screen).
- `sahilm/fuzzy` was already a pin-keeper dep since Phase 1 (02-04 was the first production consumer).
- `github.com/dustin/go-humanize` was promoted to direct in 02-02 as a real consumer.
- `koanf v2` landed as part of 02-02's go.mod batch (retiring the 02-03 `koanf_landed` build-tag gate).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `systemd-analyze verify packaging/systemd/sftp-jailer-observer.service` and `… .timer` both exit 0 with no warnings | OBS-01 half (a) | `systemd-analyze` is not available on macOS dev boxes; Phase 5 CI runs on ubuntu-latest. Unit files ship as static packaging artifacts (verified by Phase 5 CI `systemd-analyze` step). | On Ubuntu 24.04: `systemd-analyze verify packaging/systemd/sftp-jailer-observer.service packaging/systemd/sftp-jailer-observer.timer`. Expect exit 0 + no warnings. |
| OBS-01 half (b): `postinst` enables + starts the timer at install time | OBS-01 | Deferred to Phase 5 / DIST-04 per ROADMAP/REQUIREMENTS.md row 231. Requires `.deb` install on real Ubuntu 24.04 with systemd + root. | Install `.deb` built by Phase 5; verify `systemctl list-timers | grep observer` shows next run within ~1h7d. Phase 5 UAT runbook step 2.4 covers this. |
| `tea.ExecProcess` live-tail subprocess hand-off (`F` key in S-LOGS) | LOG-02 | `tea.ExecProcess` subprocess hand-off is a real-terminal behavior requiring a live `tea.Program`; cannot be integration-tested without a real tty and journald. | On Ubuntu 24.04 with `sftp-jailer` running: press `l` to open S-LOGS, then `F`. TUI should suspend cleanly into `journalctl -u ssh -f`. Press Ctrl-C; TUI should restore to S-LOGS frame with no rendering artefacts. |
| M-OBSERVE goroutine+program.Send bridge: live progress streams from `observe-run` subprocess; Esc cancels gracefully | OBS-06 | Goroutine + `program.Send` pattern requires a live `tea.Program`; integration is timing-sensitive. Unit tests cover the state machine via `ApplyProgressForTest/ApplyDoneForTest` seams. | On Ubuntu 24.04: press `l` then `r`. M-OBSERVE opens; spinner animates; phase counters update live; either wait for `done` (auto-pop) or press Esc to send SIGTERM. Status row in S-LOGS rebuilds with new event/counter/last-run values. |
| S-LOGS `/` search live demo: filter by `alice`, observe header switches to `F of N events`, list narrows; clear search, observe restoration | LOG-01, LOG-03 | Visual narrowing is unit-tested via `View()` substring assertions in `TestLogsScreen_search_*`; final UX verification on a real terminal is warranted for the full user experience. | On Ubuntu 24.04 with events loaded: open S-LOGS, type `/alice`. Header should read `X of N events`. Clear search with Esc; full list restores. |
| S-USERS pwd-age legend live demo: open S-USERS with /etc/shadow readable on Ubuntu 24.04 | USER-01 | Real `/etc/shadow` content is host-specific; truth-table is unit-tested at boundary values in `TestFormatPasswordAge_truth_table`. Real rendering requires a live Ubuntu 24.04 host with `/etc/shadow` accessible. | On Ubuntu 24.04: open S-USERS; verify `Nd (fresh/aging/stale)` for real users, `∞` for system accounts, `—` for unreadable rows. Legend below table reads `pwd age: ∞ = no expiry policy - fresh < 180d - aging < 365d - stale >= 365d`. |
| OBS-05 pruneDetail live demo: set `detail_retention_days: 1`; run `observe-run`; verify `events_dropped > 0` | OBS-05 | Requires real journald event history and a populated DB with >1 day of detail rows. | On Ubuntu 24.04 with observations: set `detail_retention_days: 1` in `/etc/sftp-jailer/config.yaml`; run `sftp-jailer observe-run`; verify `events_dropped > 0` in JSON summary. |
| OSC 52 paste from S-USERS / S-FIREWALL / S-LOGS in a real SSH session | USER-01, FW-01, LOG-01 | OSC 52 capability depends on the terminal emulator; cannot be asserted in unit tests. | In a real SSH session with OSC 52 support: press `c` in S-USERS/S-FIREWALL/S-LOGS; verify clipboard receives the row text. Toast "copied via OSC 52" confirms dispatch. |
| Running `observe-run` twice in quick succession does not duplicate events (cursor-file integrity) | OBS-02 | Requires real journald (two concurrent invocations against a live journal). | On Ubuntu 24.04: run `sftp-jailer observe-run &; sftp-jailer observe-run`; second run should emit `skipped - another run in progress` (ErrLockHeld path) or run cleanly after the first finishes. `observation_runs` table must not show duplicate rows for the same cursor range. |

---

## Deferred to Later Phases

| Deferred Item | Requirement | Phase Addressed | Evidence |
|---------------|-------------|-----------------|---------|
| OBS-01 half (b): `postinst` enables + starts the timer at install time | OBS-01 | Phase 5 (DIST-04) | `02-VERIFICATION.md` frontmatter `deferred[0]`; ROADMAP/REQUIREMENTS.md row 231 explicitly state OBS-01 split into half (a) - unit files in tree (02-09) - and half (b) - postinst install+enable+start (Phase 5/DIST-04). Phase 5 UAT runbook step 2.4 covers the deferred half. `05-VALIDATION.md` records DIST-04 as COVERED. |

---

## Validation Sign-Off

- [x] All tasks have automated `<verify>` commands or are documented as manual-only with empirical rationale
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every plan committed test artifacts)
- [x] Wave 0 covers all MISSING references - none required, infrastructure pre-existed (Phase 1 + wave-2 go.mod batch in 02-02)
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 60s (full race-enabled suite ~30-45s)
- [x] `nyquist_compliant: true` set in frontmatter
- [x] 9 manual-only items documented: 1 deferred to Phase 5 (OBS-01b), 1 real-terminal tea.ExecProcess, 1 goroutine+Send bridge, 5 human-UAT surfaces (search UX, pwd-age legend, retention demo, OSC 52, cursor integrity)
- [x] All 16 Phase 2 requirements (OBS-01..06, LOG-01..06, USER-01..02, FW-01, FW-04) at COVERED status (OBS-01 with documented half-deferral to Phase 5 accepted from ROADMAP.md row 231)

**Approval:** approved 2026-05-01

---

## Validation Audit 2026-05-01

| Metric | Count |
|--------|-------|
| Requirements analyzed | 38 (16 requirements x multi-plan entries per requirement) |
| COVERED | 38 (all rows green; 16 base requirements all COVERED) |
| PARTIAL | 0 |
| MISSING | 0 |
| Manual-only items | 8 (1 deferred timer-enable, 1 ExecProcess live-tail, 1 goroutine-Send bridge, 5 human-UAT surfaces) |
| Suite status | GREEN (verified 2026-05-01) |
| Gaps filled this audit | 0 (no test code generated - coverage was already complete per 02-VERIFICATION.md) |
