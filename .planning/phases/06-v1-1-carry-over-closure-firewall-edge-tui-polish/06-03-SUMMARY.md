---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
plan: 03
subsystem: tui
tags: [tui, users, modal, observations, query, osc52, lockdown-window]

# Dependency graph
requires:
  - phase: 02
    provides: "store.Queries.PerUserBreakdown + FilterEvents (LOG-01 / LOG-06)"
  - phase: 02
    provides: "internal/tui/screens/logs row formatter (displayN/colorByTier/tierGlyph)"
  - phase: 03
    provides: "users.go handleKey dispatch with d/D/k/Enter cases"
  - phase: 04
    provides: "deleteUserFwRulesFactory injection seam mirrored by this plan"
  - phase: 04
    provides: "config.LockdownProposalWindowDays koanf knob (D-L0204-01)"
provides:
  - "internal/tui/screens/userlog package - M-USER-LOG modal (Init/Update/View/KeyMap)"
  - "store.Queries.PerUserBreakdown extended signature (ctx, user, sinceNs int64)"
  - "logs.DisplayN / ColorByTier / TierGlyph cross-package row formatter exports"
  - "userLogFactory + SetUserLogFactory injection seam in usersscreen"
  - "Plan 06-03 / TUI-10 D-01..D-05 contract enforced in code + tests"
affects: [phase-07, future-tui-09-keybind-help, future-tui-11-row-detail-modal]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-screen factory injection (mirror of deleteUserFwRulesFactory)"
    - "SQL sentinel-arg filter idiom extended to PerUserBreakdown (sinceNs=0 disables)"
    - "Single window source drives both PerUserBreakdown(sinceNs) AND FilterEvents(SinceNs)"

key-files:
  created:
    - "internal/tui/screens/userlog/userlog.go - M-USER-LOG model"
    - "internal/tui/screens/userlog/userlog_test.go - 6 model tests"
    - ".planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-03-SUMMARY.md"
  modified:
    - "internal/store/queries.go - PerUserBreakdown sinceNs extension + SQL update"
    - "internal/store/queries_test.go - 2 new sinceNs tests + existing caller updated"
    - "internal/tui/screens/logs/logs.go - DisplayN / ColorByTier / TierGlyph re-exports"
    - "internal/tui/screens/users/users.go - userLogFactory + case L + KeyMap.UserLog"
    - "internal/tui/screens/users/users_test.go - 4 new L-keybind tests (incl. W-03 guards)"
    - "cmd/sftp-jailer/main.go - usersscreen.SetUserLogFactory wiring"

key-decisions:
  - "D-01 honored: uppercase L on S-USERS pushes M-USER-LOG; lowercase d (S-USER-DETAIL via M-DELETE-USER) and uppercase D (M-DELETE-RULE-byUser) regression-guarded."
  - "D-02 honored: 5-col row layout reuses logsscreen.DisplayN/ColorByTier/TierGlyph via cross-package re-exports - single source of truth for the row formatter."
  - "D-03 honored: header strip renders LOG-06 tier counters via Queries.PerUserBreakdown."
  - "D-04 honored: time window read from config.LockdownProposalWindowDays (default 90, range [1, 3650]) - no new config knob added."
  - "D-05 honored verbatim: empty-state copy 'No login attempts for <user> in the last <N> days.'"
  - "Pitfall 5 closed: PerUserBreakdown gained sinceNs int64 (0 disables) so windowed tier counts match the row list's window. Both queries derive sinceNs from the same windowDays value in userlog.Model."
  - "Threat T-06-03-03 mitigated: FilterEvents Limit=20 enforced at the userlog query layer; modal never holds more than 20 events."

patterns-established:
  - "Pattern: cross-package logsscreen helpers re-exported as DisplayN / ColorByTier / TierGlyph - any future per-user modal that wants S-LOGS row parity reuses these without duplicating the formatter."
  - "Pattern: PerUserBreakdown sentinel-zero filter mirrors FilterEvents.SinceNs convention - non-breaking source change with explicit 0 at every existing call site."

requirements-completed: [TUI-10]

# Metrics
duration: 10min
completed: 2026-05-01
---

# Phase 6 Plan 03: TUI-10 M-USER-LOG Modal Summary

**Per-user observation slice modal: uppercase L on S-USERS opens M-USER-LOG with windowed tier counters and the last 20 raw events in S-LOGS-style 5-col layout, OSC 52 row-copy supported.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-05-01T01:57:59Z
- **Completed:** 2026-05-01T02:07:36Z
- **Tasks:** 3/3 complete
- **Files modified:** 7 (1 SUMMARY + 4 created/modified Go files + 2 test files)

## Accomplishments

- New `internal/tui/screens/userlog` package implements the M-USER-LOG modal: header strip with username + windowed tier counts, 20-row table reusing the S-LOGS wide-mode formatter, OSC 52 'c' copy, j/k navigation, esc/q pop. Modal frame uses NormalBorder + Padding(0, 2) per RESEARCH Pattern 3.
- `store.Queries.PerUserBreakdown` signature extended with a `sinceNs int64` parameter; sentinel zero disables the filter (mirrors `FilterEvents.SinceNs`). Closes Pitfall 5: the displayed tier counts now match the "Last N days" header assertion.
- `internal/tui/screens/logs/logs.go` exports `DisplayN`, `ColorByTier`, `TierGlyph` so the userlog modal renders rows in the same 5-col layout as S-LOGS without duplicating the formatter.
- `usersscreen.userLogFactory` + `SetUserLogFactory` injection seam mirrors the Plan 04-06 `deleteUserFwRulesFactory` pattern; case "L" in handleKey pushes the factory-built screen.
- `cmd/sftp-jailer/main.go` wires `usersscreen.SetUserLogFactory` at TUI bootstrap, capturing the `*store.Queries` handle and `&usersCfg` so the modal's window comes from `LockdownProposalWindowDays`.

## Task Commits

Each task was committed atomically (TDD RED → GREEN cadence):

1. **Task 1 RED:** `1b5f63b` - test(06-03): RED - PerUserBreakdown sinceNs filter
2. **Task 1 GREEN:** `9b9ada7` - feat(06-03): PerUserBreakdown accepts sinceNs filter (0 disables)
3. **Task 2 RED:** `d10b6e2` - test(06-03): RED - userlog package teatest assertions
4. **Task 2 GREEN:** `caad47e` - feat(06-03): M-USER-LOG modal renders header + 20 rows with OSC 52 copy
5. **Task 3 RED:** `f1e1185` - test(06-03): RED - S-USERS uppercase L dispatch tests
6. **Task 3 GREEN:** `1d466c9` - feat(06-03): TUI-10 uppercase L pushes M-USER-LOG modal

**Plan metadata:** SUMMARY commit lands in this commit.

## Files Created/Modified

### Created

- `internal/tui/screens/userlog/userlog.go` - M-USER-LOG model (`Model`, `New`, `Init`, `Update`, `View`, `KeyMap`, helpers). 320+ lines of substantive logic; pure Go; no MCP dependencies.
- `internal/tui/screens/userlog/userlog_test.go` - 6 unit tests covering nav.Screen contract, header+rows render, empty state copy, OSC 52 copy payload, window source, 20-row cap.
- `.planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-03-SUMMARY.md` - this file.

### Modified

- `internal/store/queries.go` - `perUserTiersSQL` extended with the `(? = 0 OR ts_unix_ns >= ?)` sentinel-zero idiom; `PerUserBreakdown` signature gains `sinceNs int64` arg with new doc-comment explaining the convention.
- `internal/store/queries_test.go` - 2 new tests (`TestPerUserBreakdown_with_since_ns_filters`, `TestPerUserBreakdown_since_ns_zero_disables_filter`); existing `TestQueries_PerUserBreakdown` updated to pass explicit `0`.
- `internal/tui/screens/logs/logs.go` - 3 cross-package re-exports (`DisplayN`, `ColorByTier`, `TierGlyph`) added without changing any existing private helper - preserves all Phase 2 behaviour.
- `internal/tui/screens/users/users.go` - `userLogFactory` + `SetUserLogFactory` package-level seam; new `case "L"` handler in handleKey; `KeyMap.UserLog` binding + ShortHelp/FullHelp updates.
- `internal/tui/screens/users/users_test.go` - 4 new tests (uppercase L push, lowercase d W-03 guard, uppercase D W-03 guard, nil-factory no-op).
- `cmd/sftp-jailer/main.go` - new `userlog` import; new `usersscreen.SetUserLogFactory(...)` call at TUI bootstrap immediately after `SetDeleteUserFwRulesFactory`.

## Decisions Made

D-01..D-05 from the plan's `must_haves.truths` were all honored verbatim. Two implementation refinements documented inline:

1. **`PerUserBreakdown` left first-seen IP / last-success-ns scans unfiltered.** D-03 needs windowed tier counts; the "first seen" / "last success" chips answer "ever" questions and remain unbounded. Documented in the queries.go doc-comment.
2. **`Title()` returns the username** so the breadcrumb surfaces whose log is being viewed - matches the M-OBSERVE / M-PASSWORD per-screen-title convention rather than hard-coding "user-log".

## Deviations from Plan

None - plan executed exactly as written. The "alternative considered and rejected" line in the plan's interfaces block (factor helpers into `internal/tui/widgets/eventrow`) was rejected up-front; option (a) - re-export from logsscreen - was implemented as the plan specified.

## Verification

All verification gates from the plan's `<verification>` block pass:

- `go test ./internal/store/... ./internal/tui/screens/userlog/... ./internal/tui/screens/users/... ./internal/tui/screens/logs/... -count=1` - all green.
- `go test ./... -count=1` - 39 packages green; no failures, no skips.
- `go build ./...` - clean.
- `go vet ./...` - clean.
- `bash scripts/check-no-exec-outside-sysops.sh` - "OK: no exec.Command outside internal/sysops".
- W-03 keybind regression guards explicitly tested: lowercase `d` still pushes `*deleteuser.Model`, uppercase `D` still dispatches via `deleteUserFwRulesFactory`.
- `PerUserBreakdown` signature change is non-breaking source-wise: the only existing caller (`TestQueries_PerUserBreakdown`) was updated to pass explicit `0`. No production caller existed prior to this plan, so no behaviour drift.
- Em-dash absent across all touched files (verified via `LC_ALL=C grep -P '[\xe2][\x80][\x94\x93]'`).
- 6 atomic commits with prefixes `test(06-03):` and `feat(06-03):` plus this SUMMARY commit (`docs(06-03):`).

## Pitfall Closures

- **Pitfall 5 (PROJECT discussion log):** PerUserBreakdown previously returned lifetime tier counts; the M-USER-LOG header strip would have asserted "Last 90 days" while displaying counts spanning 200+ days. Closed by extending the signature with `sinceNs` and threading the same `windowDays` value through both the breakdown and the FilterEvents call from `userlog.Model.sinceNs()`. Tests `TestUserLog_window_read_from_config` and `TestPerUserBreakdown_with_since_ns_filters` pin the closure.

## Threat Mitigations

| Threat ID | Disposition | Implementation |
|-----------|-------------|----------------|
| T-06-03-01 (windowed-vs-displayed mismatch) | mitigate | `PerUserBreakdown.sinceNs` + identical `FilterEvents.SinceNs` derived from the same `windowDays`. |
| T-06-03-02 (SQL placeholder discipline) | mitigate | `(? = 0 OR ts_unix_ns >= ?)` idiom keeps `sinceNs` parameterized; no `fmt.Sprintf` into SQL. |
| T-06-03-03 (DoS via unbounded list) | mitigate | `EventLimit = 20` constant in `userlog.go`; FilterEvents Limit=20 enforced before the rows reach the model. |
| T-06-03-04 (factory-injection nil path) | mitigate | `case "L"` handler short-circuits when `userLogFactory == nil`; mirrors the existing nil-factory guard for `deleteUserFwRulesFactory`. |
| T-06-03-05 (OSC 52 row copy) | accept | Admin pastes a row they can already see; no new disclosure beyond S-LOGS' existing `c` keybind. |

## Open Items

None. The plan's success criteria are fully satisfied:

- [x] Queries.PerUserBreakdown signature extended with sinceNs (0 disables) and 2 new tests pin the behaviour.
- [x] internal/tui/screens/userlog package created with model + 5+ passing tests.
- [x] logs helpers re-exported as DisplayN / ColorByTier / TierGlyph.
- [x] users.go gains userLogFactory + SetUserLogFactory + case "L"; W-03 d/D regression guards pass.
- [x] main.go wires usersscreen.SetUserLogFactory at TUI bootstrap.
- [x] 06-03-SUMMARY.md authored documenting D-01..D-05 honored and Pitfall 5 closed.

## Self-Check: PASSED

- Created files exist:
  - `internal/tui/screens/userlog/userlog.go` - FOUND
  - `internal/tui/screens/userlog/userlog_test.go` - FOUND
- Modified files exist:
  - `internal/store/queries.go` - FOUND
  - `internal/store/queries_test.go` - FOUND
  - `internal/tui/screens/logs/logs.go` - FOUND
  - `internal/tui/screens/users/users.go` - FOUND
  - `internal/tui/screens/users/users_test.go` - FOUND
  - `cmd/sftp-jailer/main.go` - FOUND
- Commits exist (verified via `git log --oneline`):
  - `1b5f63b` test(06-03): RED - PerUserBreakdown sinceNs filter - FOUND
  - `9b9ada7` feat(06-03): PerUserBreakdown accepts sinceNs filter (0 disables) - FOUND
  - `d10b6e2` test(06-03): RED - userlog package teatest assertions - FOUND
  - `caad47e` feat(06-03): M-USER-LOG modal renders header + 20 rows with OSC 52 copy - FOUND
  - `f1e1185` test(06-03): RED - S-USERS uppercase L dispatch tests - FOUND
  - `1d466c9` feat(06-03): TUI-10 uppercase L pushes M-USER-LOG modal - FOUND
