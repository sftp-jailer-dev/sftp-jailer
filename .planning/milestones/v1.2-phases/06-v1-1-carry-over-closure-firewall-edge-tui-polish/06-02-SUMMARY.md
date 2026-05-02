---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
plan: "02"
subsystem: tui-settings
tags:
  - tui
  - settings
  - config
  - validate
  - password-aging
  - tui-09
requirements: [TUI-09]
status: verified
dependency_graph:
  requires:
    - internal/config.Validate (existing strict-ordering check from 02-11)
    - internal/config.Save (existing atomic write through sysops.AtomicWriteFile)
    - internal/tui/screens/settings inline-edit + textinput pattern (used by fieldDetail / fieldDBMax / fieldCompact / fieldLockdownWindow)
  provides:
    - Two new editable S-SETTINGS rows (password_aging_days, password_stale_days)
    - max=3650 cap on PasswordAgingDays / PasswordStaleDays in config.Validate
  affects: []
tech_stack:
  added: []
  patterns:
    - D-11 inline-edit + textinput row (NOT dispatch) - mirrors fieldLockdownWindow
    - D-12 single-source-of-truth validation in config.Validate (range + strict ordering)
    - D-13 round-trip persistence via config.Save -> sysops.AtomicWriteFile
key_files:
  created: []
  modified:
    - internal/config/config.go
    - internal/config/config_test.go
    - internal/tui/screens/settings/settings.go
    - internal/tui/screens/settings/settings_test.go
decisions:
  - "D-11: Two new S-SETTINGS rows route through the standard inline-edit + textinput path (NOT the fieldPasswordAuthN dispatch idiom). 5 switch arms extended (name, hint, currentValue, valueFor, attemptSave); fieldPasswordAuthN code path untouched."
  - "D-12: config.Validate is the single source of truth for password aging/stale rules. Tightened to enforce [1, 3650] cap on each (mirrors detail_retention_days and lockdown.proposal_window_days), in addition to the existing strict-ordering rule (0 < aging < stale)."
  - "D-13: Persistence reuses config.Save which routes through sysops.AtomicWriteFile (tmp+fsync+rename). Round-trip on TUI restart picks up the new value."
metrics:
  duration: "~10 min"
  completed: "2026-05-01T00:00:00Z"
  tasks_completed: 3
  files_created: 0
  files_modified: 4
---

# Phase 06 Plan 02: TUI-09 Settings Password-Aging Rows Summary

**One-liner:** Two new editable S-SETTINGS rows (password_aging_days, password_stale_days) with inline-edit + textinput, range [1, 3650], strict ordering aging < stale, atomic Save round-trip.

## What Was Done

- Tightened `internal/config/config.go::Validate` so `PasswordAgingDays` and `PasswordStaleDays` each enforce the documented [1, 3650] range, in addition to the existing strict-ordering rule (`0 < aging < stale`). Mirrors the `detail_retention_days` and `lockdown.proposal_window_days` idioms.
- Added 5 new test cases under `TestConfig_PasswordAging_max_3650` covering: aging-above-cap, stale-above-cap, boundary (aging=1, stale=3650), zero-aging regression guard, equal aging/stale strict-ordering regression guard.
- Inserted 2 new `fieldKind` iota constants (`fieldPasswordAgingDays`, `fieldPasswordStaleDays`) BEFORE `fieldKindCount` in `internal/tui/screens/settings/settings.go`, with doc comments matching the `fieldLockdownWindow` style.
- Extended 5 switch arms (`name`, `hint`, `currentValue`, `valueFor`, `attemptSave`) with the two new cases each. Total: 10 new case lines.
- Added 2 test-export indices (`PasswordAgingDaysRowIndexForTest`, `PasswordStaleDaysRowIndexForTest`) so tests can SetCursor without depending on iota drift.
- Authored 6 new teatest cases under `--- Phase 6 TUI-09 ---` mirroring the existing `fieldLockdownWindow` test shape:
  - `TestSettings_password_aging_days_cursor_visible` (View renders both labels + defaults)
  - `TestSettings_password_aging_days_save_via_config` (SetCursor -> edit -> 200 -> save -> AtomicWriteFile + toast)
  - `TestSettings_password_stale_days_save_via_config` (same shape, type 400 to preserve ordering)
  - `TestSettings_password_aging_days_invalid_input_surfaces_error` ("abc" surfaces parse error, no write)
  - `TestSettings_password_aging_days_strict_ordering_error` (aging=400 against stale=365 surfaces strict-order error, no write)
  - `TestSettings_password_stale_days_max_3650_error` (stale=5000 surfaces the cap, no write)
- The `fieldPasswordAuthN` dispatch path (M-DISABLE-PWAUTH push) is untouched - the new rows follow the standard inline-edit shape exclusively.

## Key Decisions Implemented

### D-11: Inline-edit pattern, NOT dispatch

Both new rows route through the existing inline-edit + textinput mechanic that `fieldDetail` / `fieldDBMax` / `fieldCompact` / `fieldLockdownWindow` already use. Pressing `e` or `enter` on either row enters edit mode (not a modal push). The `fieldPasswordAuthN` dispatch idiom is intentionally NOT reused - it is reserved for the rare case where the value lives outside `config.yaml` and a preflight gate is required (D-16).

### D-12: Single-source-of-truth validation in config.Validate

`config.Validate` carries the entire ruleset. The TUI's `attemptSave` builds a candidate Settings struct, calls `Validate`, and surfaces `errs[0]` inline on failure. Three rules cover the new fields:

1. `PasswordAgingDays` must be in [1, 3650] (new this plan).
2. `PasswordStaleDays` must be in [1, 3650] (new this plan).
3. `PasswordStaleDays > PasswordAgingDays` (existing, preserved verbatim for the regression guard).

The existing strict-ordering message format is preserved verbatim because the regression test asserts on it.

### D-13: Atomic Save round-trip

`config.Save` continues to be the only write path. It runs `Validate` first (a second gate after the TUI's check), marshals via koanf, and writes via `sysops.AtomicWriteFile` (tmp+fsync+rename in same dir, POSIX-atomic on rename). The S-SETTINGS screen's behaviour on save is unchanged: clear edit mode, replace `m.settings`, flash a toast `saved <field-name>`. On TUI restart, `config.Load` reads back the persisted YAML and `overlayDefaults` (untouched - already covers both fields from 02-11) supplies fall-backs.

## Files Modified

- `internal/config/config.go`: tightened `Validate` with two new range checks (aging cap, stale cap); preserved the existing zero-check / strict-ordering check.
- `internal/config/config_test.go`: added `TestConfig_PasswordAging_max_3650` with 5 sub-cases.
- `internal/tui/screens/settings/settings.go`: 2 new iota constants, 5 extended switch arms, 2 test-export indices.
- `internal/tui/screens/settings/settings_test.go`: 6 new teatest cases.

## Commits

In order:

1. `bc782b2 test(06-02): RED - config.Validate aging/stale max=3650 bound`
2. `d987da4 feat(06-02): config.Validate enforces password aging/stale max=3650`
3. `2bf2bad test(06-02): RED - settings teatest for password_aging/stale rows`
4. `484b550 feat(06-02): TUI-09 password_aging/stale rows in S-SETTINGS`
5. `docs(06-02): plan 06-02 SUMMARY (TUI-09 verified)` (this commit)

## Verification

- `go test ./internal/config/... -count=1` passes.
- `go test ./internal/tui/screens/settings/... -count=1` passes.
- `go test ./... -count=1` passes (no regression elsewhere).
- `go build ./...` succeeds.
- `bash scripts/check-no-exec-outside-sysops.sh` reports `OK: no exec.Command outside internal/sysops`.
- `fieldPasswordAuthN` dispatch path NOT modified (regression-guarded by `TestSettings_enter_on_pwAuth_pushes_modal_*`).
- Em-dash absent in all touched files.
- 5 atomic commits land with prefixes `test(06-02):`, `feat(06-02):`, `docs(06-02):`.

## Deviations from Plan

None - plan executed exactly as written. The optional 6th teatest case (`TestSettings_password_stale_days_max_3650_error`) was implemented as well so the new D-12 cap has surface coverage in the TUI layer alongside the data-layer coverage in `internal/config/config_test.go`.

## Open Items

None. TUI-09 fully closes:

- Admins can edit `password_aging_days` and `password_stale_days` from S-SETTINGS without leaving the TUI.
- Validation is shared with `config.Save` (single source of truth).
- Round-trip on restart works because both fields were already in the `Settings` struct + `overlayDefaults` since 02-11.

## Self-Check: PASSED

- `internal/config/config.go` exists; the new `between 1 and 3650` cap messages are present for both fields.
- `internal/config/config_test.go` exists; `TestConfig_PasswordAging_max_3650` is defined.
- `internal/tui/screens/settings/settings.go` exists; both iota constants and both test-export indices are present; 5 switch arms wired (`grep -c "fieldPasswordAgingDays:"` = 5; same for stale).
- `internal/tui/screens/settings/settings_test.go` exists; all 6 new test names are present.
- All 4 atomic test/feat commits are reachable in `git log` (`bc782b2`, `d987da4`, `2bf2bad`, `484b550`).
