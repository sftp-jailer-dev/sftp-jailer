---
phase: 09-data-layer
plan: 02
subsystem: database
tags: [log-10, migrations, schema-version, covering-index, migrate-progress, sqlite, modernc-sqlite, phase-09]

# Dependency graph
requires:
  - phase: 02-observation-storage
    provides: observations / observation_runs schema (001_init.sql, 002_add_indexes.sql)
  - phase: 04-firewall-cache
    provides: 003_user_ips.sql migration + ExpectedSchemaVersion=3 baseline
provides:
  - Migration 004_add_dedup_index.sql shipping the 4-column covering index idx_observations_dedup ON observations(source_ip, user, ts_unix_ns DESC, tier) plus ANALYZE observations
  - ExpectedSchemaVersion bumped 3 -> 4 with all 5 ASSERTION sites + 3 DOC-COMMENT sites + 1 cross-package consumer pin updated atomically
  - WithProgress(fn func(label string)) functional-option API on store.Migrate for Phase 12 splash UI consumption (D-15)
  - migrationLabel(name) internal helper mapping each migration filename to its locked human-friendly label
  - D-26 row-count-preservation invariant pinned by TestMigrate_004_preserves_observations_row_count
affects: [09-03-data-layer, 12-launch-state-machine]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Functional-option API for store.Migrate (variadic MigrateOption ...) - backwards-compatible with all existing 1-arg call sites
    - Migration file containing ANALYZE as last statement (first occurrence; load-bearing for EQP regression test, not just performance)
    - Strong-form D-26 row-count invariant test: stand up v(N-1) manually, seed rows, run Migrate, assert COUNT unchanged + new index present

key-files:
  created:
    - internal/store/migrations/004_add_dedup_index.sql
    - internal/store/migrations_test.go
  modified:
    - internal/store/store.go
    - internal/store/migrations.go
    - internal/store/store_test.go
    - internal/store/queries_test.go
    - internal/tui/screens/logs/logs_test.go

key-decisions:
  - "4-column index shape (source_ip, user, ts_unix_ns DESC, tier) per RQ-9 option B: resolves D-16 + D-18 conflict; tier appended so dedup query's outer GROUP BY scan reads as USING COVERING INDEX while drill-down query keeps prefix-match (raw_message/raw_json projections preclude covering form regardless)"
  - "ANALYZE observations as last statement of migration 004: load-bearing for plan 09-03's EQP regression test, not merely a perf tune; without sqlite_stat1 the planner choice between idx_observations_dedup (4-col) and idx_observations_ip (2-col) is documented as 'arbitrary' per sqlite.org/queryplanner.html"
  - "Locked progress labels per migration (D-15): 001 -> Creating observation tables..., 002 -> Creating observation indexes..., 003 -> Creating user-IP cache table..., 004 -> Upgrading observation index... (Phase 12 splash will render the 004 label during multi-second migrations on noisy lab hosts)"
  - "Variadic MigrateOption signature change is backwards-compatible: existing 1-arg s.Migrate(ctx) calls continue to compile and behave identically (zero options applied -> zero progress callback installed)"
  - "TestExpectedSchemaVersion_is_3 -> _is_4 rename mirrors the existing _is_N convention (test name encodes current target schema version)"
  - "TestExpectedSchemaVersion_constant + TestMigrate_applies_001_init_and_002_indexes names kept stable per D-22 grep-history invariant despite scope drift"

patterns-established:
  - "Functional-option API on store.Migrate (MigrateOption + WithProgress) - reusable shape for future cross-cutting Migrate concerns (timeout, dry-run, etc.)"
  - "ANALYZE as a load-bearing migration statement (not just tuning): document the rationale in the migration's header SQL comment so a future contributor doesn't simplify it away"
  - "Strong-form invariant test pattern for cross-version schema transitions: manually apply prior migrations, seed fixture rows, run Migrate (which applies only the new migration), then assert both the data invariant AND that the new artifact (index) is present"

requirements-completed: [LOG-10]

# Metrics
duration: 9min
completed: 2026-05-04
---

# Phase 9 Plan 02: Data Layer LOG-10 Migration + WithProgress Hook Summary

**Migration 004_add_dedup_index.sql ships the 4-column covering index idx_observations_dedup ON observations(source_ip, user, ts_unix_ns DESC, tier) with ANALYZE; ExpectedSchemaVersion bumped 3 -> 4 across all 9 pin sites; store.Migrate now accepts WithProgress(fn) for the Phase 12 splash UI.**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-05-04T00:13:35Z
- **Completed:** 2026-05-04T00:22:26Z
- **Tasks:** 4 (3 commits + 1 verification-only)
- **Files modified:** 7 (2 new, 5 modified)

## Accomplishments

- Migration 004_add_dedup_index.sql created with 4-column covering index + ANALYZE + 30+ line design-doc header documenting D-16 typo correction, RQ-9 4-column resolution rationale, and RQ-4 ANALYZE-as-load-bearing rationale
- ExpectedSchemaVersion bumped 3 -> 4 across all enumerated pin sites: 1 const, 5 ASSERTION sites, 3 DOC-COMMENT sites, plus 1 cross-package consumer pin (logs screen schema-drift test) caught by `go test ./...` and fixed under deviation Rule 1
- TestExpectedSchemaVersion_is_3 -> TestExpectedSchemaVersion_is_4 rename with literal bump and doc-comment rewrite (Phase 4 / migration 003 -> Phase 9 / migration 004)
- want slice in TestMigrate_applies_001_init_and_002_indexes extended from 7 to 8 indexes (idx_observations_dedup appended)
- store.Migrate signature extended to variadic (ctx, opts ...MigrateOption); zero call-site breakage (all existing 1-arg callers unaffected)
- WithProgress(fn) functional-option helper exported; nil-safe; fires callback exactly once per APPLIED migration with locked human-friendly labels; on already-migrated DB callback does NOT fire
- 4 new tests in internal/store/migrations_test.go: progress_callback_fires (4 labels in order on fresh DB), progress_callback_skips_already_migrated (zero callbacks on no-op), progress_nil_callback_is_safe (no panic), 004_preserves_observations_row_count (strong-form D-26 invariant: setup v3 manually, seed N rows, run Migrate, assert COUNT unchanged + idx_observations_dedup present)

## Task Commits

Each task was committed atomically:

1. **Task 1: Write 004_add_dedup_index.sql with 4-column index + ANALYZE + design-doc header** - `2c50776` (migrate)
2. **Task 2: Bump ExpectedSchemaVersion 3 -> 4 + update all test pins atomically** - `6b42ec2` (schema; includes Rule-1 fix to logs_test.go schema-drift assertion)
3. **Task 3: Add WithProgress functional-option API to store.Migrate; ship hook for Phase 12 consumer** - `33b34e7` (feat)
4. **Task 4: Final lint + full-repo build gate; verify CI guards stay GREEN** - verification-only, no commit per plan

## Files Created/Modified

- `internal/store/migrations/004_add_dedup_index.sql` (NEW, 49 lines): 4-column covering index on observations + ANALYZE + load-bearing design-doc header
- `internal/store/migrations_test.go` (NEW, 162 lines): WithProgress callback tests + D-26 strong-form row-count invariant test
- `internal/store/store.go` (modified): ExpectedSchemaVersion 3 -> 4; doc-comment extended with Phase 9 lineage
- `internal/store/migrations.go` (modified): MigrateOption type, WithProgress helper, migrationLabel helper, variadic Migrate signature, progress-callback firing inside the loop
- `internal/store/store_test.go` (modified): 3 ASSERTION sites + 2 DOC-COMMENT sites updated; want slice extended 7 -> 8 indexes
- `internal/store/queries_test.go` (modified): 1 ASSERTION literal + 1 doc-comment + TestExpectedSchemaVersion_is_3 -> _is_4 rename
- `internal/tui/screens/logs/logs_test.go` (modified, Rule-1 fix): schema-drift test "binary expects v3" -> "v4" with doc-comment carry-forward

## Decisions Made

All decisions tracked in frontmatter `key-decisions`. Highlights:

- **Locked the 4-column index shape** (RQ-9 option B) over the 3-column shape originally specified by D-16: necessary so the dedup query's outer GROUP BY scan matches USING COVERING INDEX (D-18 lock). Drill-down query falls back to USING INDEX prefix-match (acceptable; raw_message/raw_json projections preclude any covering form regardless).
- **ANALYZE as load-bearing**, not perf tune: documented in the migration's header SQL comment so a future contributor doesn't simplify it away. Without sqlite_stat1 populated, plan 09-03's EQP regression test would be flaky because SQLite's planner choice between idx_observations_dedup (4-col) and idx_observations_ip (2-col) is "arbitrary" per the SQLite query-planner docs.
- **Variadic MigrateOption signature** rather than a separate MigrateWithProgress entrypoint: keeps the API surface small, backwards-compatible by construction, extensible for future Phase-12-or-later cross-cutting concerns.

## Corrections Carried Forward

Three corrections documented in commits + this summary (per plan `<corrections>` block):

1. **D-16 typo carry-forward** (already documented; carried in Task 1 commit message): ROADMAP.md success criterion 4 and REQUIREMENTS.md LOG-10 say `observation_runs(source_ip, username, ts_unix_ns DESC)` but the actual table is `observations` and the actual column is `user`. Migration 004 honors the empirical schema; both ROADMAP and REQUIREMENTS LOG-10 need a separate cleanup pass (not in this plan's scope).
2. **D-06 byte-count typo** (carried per 09-01 plan; no implementation surface in 09-02): D-06 says longest subnet shape `link-local` is 38 bytes; empirical check (researcher RQ-12 Pitfall 1) shows it is 40 bytes (`operator` is 38). Plan 09-01 carries the corrected numbers in its byte-cap test. Plan 09-02 has no byte-count exposure but documents the correction here so the phase SUMMARY captures both fixes.
3. **D-16 + D-18 4-column index resolution** (planner judgment per RQ-9): documented in the migration's design-doc SQL comment + Task 1 commit message + frontmatter `key-decisions`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Cross-package schema-drift test pin missed in plan's interfaces inventory**
- **Found during:** Task 2 (after the const bump, `go test ./...` surfaced TestLogsScreen_LoadStatusForTest_schema_drift assertion `binary expects v3` failing because the rendered string now contains `v4`)
- **Issue:** The plan's `<interfaces>` block enumerated 5 ASSERTION sites + 3 DOC-COMMENT sites, all in the `internal/store/` package. It missed one cross-package consumer pin in `internal/tui/screens/logs/logs_test.go:192` that asserts the literal `binary expects v3` string emitted by the logs-screen schema-drift renderer (which itself reads `store.ExpectedSchemaVersion`).
- **Fix:** Updated the assertion literal `v3` -> `v4` and extended the surrounding doc-comment to mention the Phase 9 bump alongside the existing Phase 4 bump reference.
- **Files modified:** internal/tui/screens/logs/logs_test.go
- **Verification:** `go test ./...` now passes (41/41 packages green); `golangci-lint run ./...` still clean.
- **Committed in:** 6b42ec2 (Task 2 commit, alongside the const bump and the in-package pin updates - this is the natural commit boundary because the cross-package pin and the in-package pins must move in lockstep with the const)

**2. [Rule 2 - Missing Critical] migrations.go file-naming-convention example list missed migration 004**
- **Found during:** Task 2 (while editing migrations.go for Task 3 prep, noticed the doc-comment example list at lines 35-37 enumerated 001/002/003 but stopped there)
- **Issue:** The example list teaches future contributors the numeric-prefix-IS-target-user_version convention. Leaving 004 out would have made the example stale on day one.
- **Fix:** Appended `migrations/004_add_dedup_index.sql -> user_version = 4` as the 4th entry. No code-path change.
- **Files modified:** internal/store/migrations.go
- **Verification:** Doc-comment only; `go vet ./...` clean.
- **Committed in:** 6b42ec2 (Task 2 commit, alongside other doc-comment updates)

---

**Total deviations:** 2 auto-fixed (1 Rule-1 bug, 1 Rule-2 missing-critical doc).
**Impact on plan:** Both deviations are tightly scoped - keeping pinned literals and doc-comments aligned with the new ExpectedSchemaVersion lineage. No scope creep; no new tests or dependencies; no architectural change.

## Issues Encountered

None. All 4 tasks executed in plan order. Local CI gate (8 checks) GREEN at end of Task 4.

## Verification Summary (Task 4 gate, no commit)

| Gate | Result |
|------|--------|
| `go build ./...` | exit 0 |
| `go test ./... -count=1` | 41/41 packages PASS, 0 FAIL |
| `go vet ./...` | exit 0 |
| `golangci-lint run ./...` | 0 issues |
| `bash scripts/check-no-exec-outside-sysops.sh` | OK: no exec.Command outside internal/sysops |
| `bash scripts/check-go-mod-pins.sh` | OK: all 13 direct-dep pins match (D-23 zero new deps verified) |
| `bash scripts/check-single-tea-program.sh` | OK: single tea.NewProgram (D-24 verified) |
| `bash scripts/check-no-raw-config-write.sh` | OK: no raw config-write outside internal/sysops + internal/config |

## Cross-Phase Notes

- **Phase 12 launch state machine** is the consumer of `WithProgress`; it will plumb the callback into the splash/doctor handoff to render `Upgrading observation index...` during multi-second migrations on noisy lab hosts (per 09-CONTEXT.md D-15). 09-02 ships the hook only; the consumer wiring lands later.
- **Plan 09-03** consumes the new index via `Queries.DedupRows` + `Queries.EventsForPair` and asserts `USING COVERING INDEX idx_observations_dedup` for the dedup query and `USING INDEX idx_observations_dedup` for the drill-down (per RQ-9 differentiation; the drill-down can't be covering due to raw_message/raw_json projections). 09-03 is Wave 2 dependent on this plan's index existing.
- **Lab UAT P2-D** (migration latency on `ubuntu-wifi`) is operator-gated and runs after the binary is installed on the lab host. It is NOT a CI gate; it is a release gate per STATE.md "Empirical UAT acceptance gates" P2-D. Capture results here once executed: target wall-time <= 1.5s for first launch with migration 004 applied (D-15 documented threshold).

## Lab UAT P2-D (pending)

| Step | Acceptance | Status |
|------|-----------|--------|
| 1. Baseline `PRAGMA user_version` on `ubuntu-wifi` (192.168.1.187) | reports 3 (pre-09-02) | pending operator |
| 2. Capture baseline `SELECT COUNT(*) FROM observations` | record value (>=10k for noise-gated host) | pending operator |
| 3. Install v1.3 .deb (built via `goreleaser snapshot` from this branch) | postinst ok | pending operator |
| 4. `sudo time sftp-jailer` first-launch wall time | <= 1.5s | pending operator |
| 5. `Upgrading observation index...` label appears in splash | appears (Phase 12 wiring; if Phase 12 not yet landed, label won't render but migration must still complete) | pending operator |
| 6. `PRAGMA user_version` reports 4 | yes | pending operator |
| 7. `.indexes observations` includes `idx_observations_dedup` | yes | pending operator |
| 8. Row count delta vs step 2 | 0 (D-26 invariant) | pending operator |

## Next Phase Readiness

- Plan 09-02 complete; idx_observations_dedup landed; ExpectedSchemaVersion=4; WithProgress hook ready for Phase 12 consumption.
- Plan 09-03 (Wave 2) unblocked: can now author Queries.DedupRows + Queries.EventsForPair against the new index and pin the EQP regression test (`USING COVERING INDEX idx_observations_dedup` for dedup; `USING INDEX idx_observations_dedup` for drill-down).
- ROADMAP success criterion 4 (covering index ships in Phase 9) on track; criterion text references the wrong table+column names per D-16 typo carry-forward and should be edited at phase verification time, not piecemeal here.

## Self-Check: PASSED

All 8 created/modified files verified present on disk. All 3 task commits (2c50776, 6b42ec2, 33b34e7) verified present in git log.

---
*Phase: 09-data-layer*
*Plan: 02*
*Completed: 2026-05-04*
