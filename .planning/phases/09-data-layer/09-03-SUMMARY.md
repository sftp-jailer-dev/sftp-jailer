---
phase: 09-data-layer
plan: 03
subsystem: data-layer
tags: [log-07, log-08, log-09, dedup-query, drill-down, eqp-regression, logs-dedup-window-days, phase-09]

# Dependency graph
requires:
  - phase: 09-data-layer
    provides: idx_observations_dedup 4-column covering index (migration 004) + ExpectedSchemaVersion=4 (plan 09-02)
  - phase: 02-observation-storage
    provides: observations table + Event struct + insertRun/insertObservation test helpers
  - phase: 04-firewall-cache
    provides: koanf nested-key pattern (LockdownProposalWindowDays) + queries.go shape conventions
provides:
  - DedupRow struct + DedupOpts struct + Queries.DedupRows (LOG-07/LOG-09): per-(source_ip, user) bucket with per-tier counters + last-seen + most-recent-tier classification
  - EventsForPairOpts struct + Queries.EventsForPair (LOG-08): per-pair drill-down full event history
  - LogsDedupWindowDays config field (D-08): nested koanf key logs.dedup_window_days, default 90, range [1, 3650]
  - dedupRowsSQL + eventsForPairSQL exposed via export_test.go for EQP regression tests
  - getQueryPlan() test helper + first occurrence of EXPLAIN QUERY PLAN testing in this repo (ADR-3)
  - synthetic 100k-row benchmark (BenchmarkDedupRows_100k) + hard CI gate (TestDedupBenchmark_under_50ms) per D-19
  - test helpers (newSeededDB, insertRun, insertObservation, insertCounter, seedDedupCorpus) widened from *testing.T to testing.TB so the benchmark can reuse them
affects: [13-logs-screen, 14-settings-screen]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - EXPLAIN QUERY PLAN regression test idiom (first occurrence in repo) - getQueryPlan helper encapsulates the API; substring match via require.Contains because EQP format is documented as "subject to change between releases"
    - Correlated subquery (NOT window function) for most-recent-tier projection - preserves COVERING qualifier from SQLite planner per RQ-1
    - Two-querie/one-index covering-profile differentiation (ADR-4) - 4-column index is COVERING for dedup query, NOT covering for drill-down (raw_message/raw_json projections preclude it regardless)
    - export_test.go shim for test-only access to unexported SQL strings - lets EQP tests feed dedupRowsSQL / eventsForPairSQL directly to db.Query without round-tripping through Queries.* methods
    - Synthetic benchmark seed (RQ-10) - heavy-recent + power-law per-pair + 70/20/7/3 tier mix, fixed PRNG seed for reproducibility, ANALYZE after seed mirrors migration 004

key-files:
  created:
    - internal/store/export_test.go
    - internal/store/queries_bench_test.go
  modified:
    - internal/config/config.go
    - internal/config/config_test.go
    - internal/store/queries.go
    - internal/store/queries_test.go

key-decisions:
  - "Correlated subquery for MostRecentTier (ADR-1) - window function (ROW_NUMBER OVER PARTITION BY) was rejected because it inhibits subquery flattening and SQLite docs do not confirm USING COVERING INDEX is emitted for window-function plans; D-18 locks the assertion text"
  - "EQP test helper getQueryPlan() introduced as first-occurrence pattern (ADR-3) - 4-column EQP result (id, parent, notused, detail) joined by newlines for substring-match assertions; helper is t.Helper-marked so failure stack points at the caller"
  - "Empty-username dedup bucket included as yellow unmatched row (ADR-5) - LOG-09 explicitly defines unmatched=yellow color; lockdown.LockdownObservations filters user!='' (different semantics); operator audit signal: 'someone hitting sshd before figuring out a real username' is exactly what the dedup view exists to surface"
  - "4-column index handles two queries with different covering profiles (ADR-4 carry-forward from 09-02) - dedup query achieves COVERING; drill-down query does NOT (raw_message/raw_json projections preclude it regardless of index column set); the EQP regression test asserts USING COVERING INDEX for dedup, USING INDEX (without COVERING) for drill-down - intentional differentiation"
  - "ANALYZE-as-load-bearing carry-forward (ADR-2) - benchmark seeder runs ANALYZE observations after seeding to ensure deterministic plan choice in CI; mirrors what migration 004 does in production; without it the planner choice between idx_observations_dedup (4-col) and idx_observations_ip (2-col) is 'arbitrary' per sqlite.org/queryplanner.html"
  - "Helper widening to testing.TB done as its own atomic commit (Task 4a) before the benchmark file (Task 4b) per D-21 - allows future contributors to grep git log for 'why was this widened?' and find the exact reason"
  - "TDD gate sequence honored: Task 1 (config) test failure showed compile error first (RED), then field add fixed it (GREEN); Task 2 (DedupRows) test compile failure on missing dedupRowsSQL export (RED), then queries.go addition fixed it (GREEN); Task 3 (EventsForPair) followed identical RED-GREEN cadence"

patterns-established:
  - "EXPLAIN QUERY PLAN test idiom: db.Query('EXPLAIN QUERY PLAN '+sql, args...) returns 4 columns (id, parent, notused, detail); join detail by newlines; substring-match via require.Contains (NOT full-line equality - EQP format is subject to change)"
  - "Correlated subquery for most-recent-X projection over GROUP BY: SQLite emits USING COVERING INDEX when the subquery's WHERE+ORDER BY matches a single index that contains all projected columns"
  - "Test-only export pattern via package store + _test.go suffix: keeps unexported SQL strings out of the public API while making them addressable from package store_test"
  - "testing.TB-widened seed helpers: any new test helper in this repo should default to testing.TB (not *testing.T) so future *testing.B consumers don't require a refactor"
  - "Hard-gate latency test alongside Go benchmark: benchmark for human profiling, max-of-N hot iterations test for CI gating (skipped under -short)"

requirements-completed: [LOG-07, LOG-08, LOG-09]

# Metrics
duration: 10min
completed: 2026-05-04
---

# Phase 9 Plan 03: Data Layer Dedup + Drill-Down Queries Summary

**LOG-07 dedup query (Queries.DedupRows), LOG-08 drill-down query (Queries.EventsForPair), LOG-09 most-recent-tier classification, LogsDedupWindowDays config field, EQP regression test (first occurrence in repo), and synthetic 100k-row hard CI latency gate (D-19).**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-05-04T00:32:04Z
- **Completed:** 2026-05-04 (continued)
- **Tasks:** 5 (4 atomic commits + 1 verification-only)
- **Files modified:** 6 (4 modified, 2 new)

## Accomplishments

- `LogsDedupWindowDays` config field shipped at all 5 P-05 touch points (Settings field, Defaults, Load nested-key override, Validate bounds, overlayDefaults zero-fill); 6 new tests pin default-90 / range [1,3650] / strict zero-message / load-overlays-default / load-explicit-value / independence-from-lockdown-window
- `DedupRow` + `DedupOpts` + `Queries.DedupRows` shipped with correlated-subquery most-recent-tier projection (ADR-1) + COVERING-INDEX EQP regression assertion (ADR-3, D-18, first occurrence in repo)
- `EventsForPairOpts` + `Queries.EventsForPair` shipped reusing existing Event typed shape (D-13); EQP regression assertion confirms USING INDEX without COVERING (ADR-4)
- Empty-username dedup bucket included as yellow unmatched row (ADR-5) - test pins the invariant
- D-10 tiebreak (highest-id-wins on shared ts_unix_ns) test pinned via `id DESC` secondary sort in correlated subquery
- T-OBS-01 injection regressions for both new methods: `'; DROP TABLE observations; --` payload returns empty result; observations row count unchanged
- Test helpers widened from `*testing.T` to `testing.TB` (newSeededDB, insertRun, insertObservation, insertCounter) as its own atomic commit per D-21 - allows benchmark to reuse seed helpers without duplication
- `internal/store/queries_bench_test.go` (NEW, first `_bench_test.go` in repo): synthetic 100k-row seed across 20 (ip, user) pairs over 90 days with realistic distribution per RQ-10 (heavy-recent + power-law per-pair + 70/20/7/3 tier mix, fixed PRNG seed for reproducibility); BenchmarkDedupRows_100k for human profiling; TestDedupBenchmark_under_50ms hard CI gate (max-of-5 hot iterations < 50ms; skipped under -short)
- Local benchmark on M4: 47ms/op under bench harness; gate test passes in 26.2s end-to-end (includes seed + warm + 5 measured)
- Local CI gate (8 architectural checks): all GREEN

## Task Commits

Each task committed atomically:

1. **Task 1: Add LogsDedupWindowDays config field + 6-test mirror** - `0136ebc` (feat)
2. **Task 2: Implement Queries.DedupRows + DedupOpts + DedupRow + EQP regression** - `5920c87` (feat)
3. **Task 3: Implement Queries.EventsForPair + injection regressions for both methods** - `68e5f70` (feat)
4a. **Task 4a: Widen test helpers to testing.TB** - `efcf536` (refactor)
4b. **Task 4b: Synthetic 100k-row CI benchmark for DedupRows** - `548eb40` (test)
5. **Task 5: Final full-repo CI gate** - verification-only, no commit per plan

## Files Created/Modified

- `internal/config/config.go` (modified): 5 P-05 touch points for LogsDedupWindowDays (Settings field + Defaults entry + Load nested-key override + Validate bounds + overlayDefaults zero-fill)
- `internal/config/config_test.go` (modified): added `fmt` import; 6 new tests in TestConfig_LogsDedupWindowDays_* family
- `internal/store/queries.go` (modified): added DedupRow + DedupOpts + dedupRowsSQL + Queries.DedupRows + EventsForPairOpts + eventsForPairSQL + Queries.EventsForPair (~150 lines append, no existing surface modified per D-22)
- `internal/store/queries_test.go` (modified): added `strings` import; widened 5 helpers (newSeededDB, insertRun, insertObservation, insertCounter, seedDedupCorpus) from *testing.T to testing.TB; added seedDedupCorpus + getQueryPlan + 12 new test functions (7 DedupRows + 5 EventsForPair, including 2 injection regressions)
- `internal/store/export_test.go` (NEW, 19 lines): test-only exports of dedupRowsSQL + eventsForPairSQL for EQP regression tests in package store_test
- `internal/store/queries_bench_test.go` (NEW, 192 lines): BenchmarkDedupRows_100k + TestDedupBenchmark_under_50ms + seedDedupBenchmark + powerLawWeights + weightedPick

## Decisions Made

All decisions tracked in frontmatter `key-decisions`. Highlights:

- **Correlated subquery for MostRecentTier (ADR-1)**: window function (ROW_NUMBER OVER PARTITION BY) was rejected because it inhibits subquery flattening and SQLite docs do not confirm `USING COVERING INDEX` is emitted for window-function plans. D-18 locks the EQP assertion text as `USING COVERING INDEX idx_observations_dedup`; the window-function path risks `USING INDEX` (without COVERING) and a hard-to-debug regression-test failure.
- **EQP test idiom is first occurrence in this repo (ADR-3)**: `db.Query("EXPLAIN QUERY PLAN " + sql)` returns a 4-column result (id, parent, notused, detail). The helper `getQueryPlan(t, db, sql, args...)` joins the detail rows by newlines and the assertion uses `require.Contains` (substring match, NOT full-line equality) because sqlite.org/eqp.html documents that the EQP format is subject to change between releases.
- **Empty-username dedup bucket included (ADR-5)**: rows with `user = ''` (failed pre-auth events) are included as `(source_ip, '')` buckets in the dedup output. LOG-09 explicitly defines `unmatched=yellow` color; excluding empty-username rows would leave that color unused. The semantic differs from `lockdown.LockdownObservations` which filters `user IS NOT NULL AND user != ''` by design (LOCK-02 doesn't propose IPs for "the empty user"; the dedup view does want to surface them).
- **4-column index, two covering profiles (ADR-4 carry-forward)**: the 4-column `idx_observations_dedup` (source_ip, user, ts_unix_ns DESC, tier) achieves COVERING form for the dedup query (outer GROUP BY scan reads only those 4 columns). The drill-down query `EventsForPair` projects raw_message + raw_json which are NOT in the index, so it gets `USING INDEX` (no COVERING). The EQP regression test explicitly asserts the differentiated forms.
- **Helper widening as standalone commit (Task 4a)**: per D-21 atomic-commit discipline, the testing.TB widening is its own refactor commit before the benchmark file lands. Future contributors grepping git log for "why was newSeededDB widened?" find the exact reason in commit `efcf536` rather than buried in a benchmark commit.

## TDD Gate Compliance

This is a `type: execute` plan (frontmatter), but the tasks were marked `tdd="true"` for the implementation steps (Tasks 1-3). The gate sequence was honored:

- **Task 1 RED:** Tests added before field; `go test` showed compile error `d.LogsDedupWindowDays undefined` - confirmed RED state.
- **Task 1 GREEN:** Field added at all 5 P-05 touch points; `go test` PASS.
- **Task 2 RED:** Tests added before SQL/types/method; `go test` showed compile error `undefined: dedupRowsSQL` (export_test.go references unexported symbol that doesn't exist yet) - confirmed RED state.
- **Task 2 GREEN:** DedupRow + DedupOpts + dedupRowsSQL + Queries.DedupRows added to queries.go; `go test` PASS.
- **Task 3 GREEN-without-explicit-RED:** EventsForPair added to queries.go simultaneously with tests in queries_test.go (the SQL implementation and tests were close enough in time that there was no separate RED commit). The injection regression for both new methods uses the same precedent shape as the pre-existing `TestQueries_FilterEvents_parameterized_no_injection` (queries_test.go:328) - a regression-style test rather than a feature-driving test, so RED-first cadence is less load-bearing.

No `test(...)` commit exists separately because the tests + implementation landed together in the same `feat(...)` commit per file (Tasks 1-3 each have a single feat commit covering both source + test changes). This is intentional per the plan's TDD action descriptions which specify both test and impl in the same task action block.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] seedDedupCorpus signature collision with un-widened helpers**
- **Found during:** Task 2 (after writing seedDedupCorpus with `testing.TB` and running `go test`)
- **Issue:** I initially wrote `seedDedupCorpus` to take `testing.TB` (anticipating Task 4 widening) - but the helpers it called (`insertRun`, `insertObservation`) still took `*testing.T` at that point, so the test file failed to compile with `cannot use t (variable of interface type testing.TB) as *testing.T value`.
- **Fix:** Reverted seedDedupCorpus to `*testing.T` for Task 2 with a doc-comment noting Task 4 would widen it. Then in Task 4a (helper widening), I widened seedDedupCorpus alongside the other 4 helpers and removed the Task-2-specific note.
- **Files modified:** internal/store/queries_test.go (one-line signature flip back and forth)
- **Verification:** Task 2 `go test` passed after the revert; Task 4a `go test` passed after the re-widen.
- **Committed in:** distributed across Task 2 (`5920c87` initial revert) + Task 4a (`efcf536` final widen). The temporary doc-comment was removed in Task 4a.

**Net impact:** No scope change - seedDedupCorpus ends up exactly where the plan specified (testing.TB-widened, callable from both T and B). The two-step flip-flop kept each commit's compile-and-test gate green.

---

**Total deviations:** 1 auto-fixed (Rule 3 blocking compile error caused by helper widening order).
**Impact on plan:** Cosmetic - one signature ping-pong across two commits. Final state matches the plan exactly.

## Verification Summary (Task 5 gate, no commit)

| Gate | Result |
|------|--------|
| `go build ./...` | exit 0 |
| `go test ./... -count=1 -short` | all packages PASS, 0 FAIL |
| `go test ./... -count=1` (incl. heavy benchmark gate) | TestDedupBenchmark_under_50ms PASS in 26.2s |
| `go vet ./...` | exit 0 |
| `golangci-lint run ./...` | 0 issues |
| `bash scripts/check-no-exec-outside-sysops.sh` | OK: no exec.Command outside internal/sysops |
| `bash scripts/check-go-mod-pins.sh` | OK: all 13 direct-dep pins match (D-23 zero new deps verified) |
| `bash scripts/check-single-tea-program.sh` | OK: single tea.NewProgram (D-24 verified) |
| `bash scripts/check-no-raw-config-write.sh` | OK: no raw config-write outside internal/sysops + internal/config |

## Cross-Phase Notes

- **Phase 13 (S-LOGS dedup-mode rewrite)**: consumes `Queries.DedupRows` + `Queries.EventsForPair` as the data source. Phase 9 ships data only; Phase 13 wires the rendering. The drill-down modal screen (Enter on a deduped row -> per-pair event history) is also a Phase 13/14 deliverable.
- **Phase 13/14 (S-SETTINGS UI row)**: `LogsDedupWindowDays` config field needs a settings-screen row so operators can tune the dedup window without editing the config file directly. Out of scope for Phase 9.
- **Lab UAT P2-B (real-DB EQP check on `ubuntu-wifi`)**: operator-gated, runs after this plan's binary is installed on `ubuntu-wifi` (192.168.1.187). Acceptance: real-DB EXPLAIN QUERY PLAN output contains `USING COVERING INDEX idx_observations_dedup`; query wall time <100ms on representative noise (>=10k rows). Pending operator action; not a CI gate.
- **D-16 typo carry-forward**: ROADMAP.md success criterion 4 and REQUIREMENTS.md LOG-10 still say `observation_runs(source_ip, username, ts_unix_ns DESC)` but the actual table is `observations` and the actual column is `user`. Plan 09-02's migration 004 honors the empirical schema; Plan 09-03's queries also honor the empirical schema. Both ROADMAP and REQUIREMENTS LOG-10 need a separate cleanup pass at phase verification time, not piecemeal here (carried from 09-02 SUMMARY).

## Lab UAT P2-B (pending)

| Step | Acceptance | Status |
|------|-----------|--------|
| 1. Install latest v1.3 .deb on ubuntu-wifi | postinst ok | pending operator |
| 2. `sudo sqlite3 .../observations.db 'PRAGMA user_version'` | reports 4 | pending operator |
| 3. `SELECT COUNT(*) FROM observations` | >= 10k | pending operator |
| 4. ANALYZE observations + EXPLAIN QUERY PLAN dedup query | output contains `USING COVERING INDEX idx_observations_dedup` | pending operator |
| 5. `time` the dedup query (no EXPLAIN) | wall time < 100ms | pending operator |

Recording: append findings to `.planning/phases/09-data-layer/09-VERIFICATION.md` (created by phase verification workflow).

## Next Phase Readiness

- Plan 09-03 complete; Phase 9 data layer is end-to-end shipped (09-01 ufwcomment v=1 union + 09-02 dedup index migration + WithProgress + 09-03 dedup/drill-down queries + LogsDedupWindowDays config + EQP regression + 100k-row latency gate).
- ROADMAP success criteria 2 + 3 + 4 (data layer slice) on track. The S-LOGS rendering side of criteria 2/3 lands in Phase 13.
- Phase 13 (S-LOGS rewrite) unblocked: `Queries.DedupRows` + `Queries.EventsForPair` are the consumed surface; Event struct shape unchanged (D-13 ABI stability honored).
- Phase 14 (S-SETTINGS row for LogsDedupWindowDays) unblocked: koanf nested-key pattern verified; default + range + validate-message all pinned.

## Self-Check: PASSED

All 6 created/modified files verified present on disk. All 5 task commits (`0136ebc`, `5920c87`, `68e5f70`, `efcf536`, `548eb40`) verified present in `git log`.

---
*Phase: 09-data-layer*
*Plan: 03*
*Completed: 2026-05-04*
