---
phase: 09-data-layer
verified: 2026-05-04T07:23:52Z
status: human_needed
score: 5/5 must-haves verified (P2-B and P2-D lab-host UATs pending operator)
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: 0/0
  gaps_closed: []
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Lab UAT P2-B - real-DB EXPLAIN QUERY PLAN on ubuntu-wifi (192.168.1.187)"
    expected: "EXPLAIN QUERY PLAN of dedup query on production observations DB (>=10k rows) contains 'USING COVERING INDEX idx_observations_dedup'; query wall time <100ms"
    why_human: "Requires SSH access to lab host, running production binary against real journald-seeded data. ROADMAP UAT gate explicitly operator-gated (not a CI gate). Phase 09-03 SUMMARY documents this as 'pending operator'."
  - test: "Lab UAT P2-D - migration latency on ubuntu-wifi (192.168.1.187)"
    expected: "First-launch wall time on Ubuntu 24.04 lab host (>=10k observations row count) <= 1.5s; PRAGMA user_version reports 4 post-migration; row count delta = 0 (D-26 invariant)"
    why_human: "Requires SSH access, .deb install, baseline+post-migration sqlite3 inspection. ROADMAP and 09-02 plan explicitly operator-gated. Phase 09-02 SUMMARY documents this as 'pending operator'."
---

# Phase 9: Data Layer Verification Report

**Phase Goal:** Pure data-layer additions (ufwcomment grammar extension + new dedup index migration + new typed query) that Phase 11 (subnet whitelist) and Phase 13 (console) both depend on. Schema bumps from user_version=3 to user_version=4.

**Verified:** 2026-05-04T07:23:52Z
**Status:** human_needed
**Re-verification:** No - initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `internal/ufwcomment` decodes both `sftpj:v=1:user=<name>` (existing) and `sftpj:v=1:scope=subnet:reason=<rfc1918\|rfc4193\|link-local\|operator>` (new) shapes; v1.2.x continue to safely treat new shape as foreign per ErrBadVersion forward-compat | VERIFIED | `internal/ufwcomment/decode.go:92-115` three-way classifier; `TestDecode_v1_subnet_shape_decoded` PASS; `TestDetectMode_skips_v1_subnet_shape` PASS (forward-compat held: subnet rule classified as `Kind=KindSubnet`, `User=""`, mode predicate at `mode.go` drops on `User==""`) |
| 2 (data layer slice) | DedupRows query exists with tier classification (per-pair (source_ip, user) buckets with TotalCount, per-tier SUM counters, LastSeenNs, MostRecentTier) | VERIFIED | `internal/store/queries.go:557-622` (DedupRow struct + dedupRowsSQL + DedupRows method); `TestQueries_DedupRows_uses_covering_index` PASS asserting `USING COVERING INDEX idx_observations_dedup`; UI rendering deferred to Phase 13 per ROADMAP scope clarification |
| 3 (data layer slice) | EventsForPair query exists for per-(source_ip, user) drill-down event history | VERIFIED | `internal/store/queries.go:680-735` (EventsForPairOpts + EventsForPair method reusing existing Event struct); `TestQueries_EventsForPair_uses_index` PASS asserting `USING INDEX idx_observations_dedup` (covering not achievable due to raw_message/raw_json projections per ADR-4); UI Enter-key drill-down deferred to Phase 13 |
| 4 | Migration `004_add_dedup_index.sql` ships covering index; EXPLAIN QUERY PLAN regression test asserts `USING COVERING INDEX`; `user_version` bumps to 4 | VERIFIED | `internal/store/migrations/004_add_dedup_index.sql` exists (49 lines, 4-col index `(source_ip, user, ts_unix_ns DESC, tier)` + `ANALYZE observations`); `internal/store/store.go:40` `const ExpectedSchemaVersion = 4`; `TestQueries_DedupRows_uses_covering_index` substring-asserts the COVERING qualifier; `TestMigrate_004_preserves_observations_row_count` strong-form D-26 invariant test PASS |

**Score:** 4/4 ROADMAP success criteria verified (criteria 2 and 3 reduced to data-layer prerequisites per ROADMAP note; UI rendering belongs to Phase 13).

### Observable Truths (PLAN frontmatter must-haves, merged across 09-01/09-02/09-03)

| # | Plan | Truth | Status | Evidence |
|---|------|-------|--------|----------|
| T1 | 09-01 | `Decode("sftpj:v=1:user=alice")` returns `Kind=KindUser, User="alice"`, nil err | VERIFIED | `decode.go:92-100` user= branch; `TestDecode_v1_user_kind_is_KindUser` PASS |
| T2 | 09-01 | `Decode("sftpj:user=alice")` legacy v=0 returns `Version=0, Kind=KindUser` (D-02) | VERIFIED | `decode.go:61-67`; `TestDecode_v0_legacy_kind_is_KindUser` PASS |
| T3 | 09-01 | `Decode("sftpj:v=1:scope=subnet:reason=rfc1918")` returns `Kind=KindSubnet, SubnetReason="rfc1918"`, nil err | VERIFIED | `decode.go:102-110`; `TestDecode_v1_subnet_shape_decoded` PASS |
| T4 | 09-01 | `Decode("sftpj:v=1:scope=subnet:reason=garbage")` returns `ErrBadVersion` (D-03) | VERIFIED | `decode.go:104-109` default branch; `TestDecode_v1_subnet_invalid_reason` (5 sub-tests) PASS |
| T5 | 09-01 | `Decode("sftpj:v=2:user=alice")` returns `ErrBadVersion` (forward-compat preserved) | VERIFIED | `decode.go:88-90`; existing `TestDecode_v2_forward` PASS |
| T6 | 09-01 | `EncodeSubnet("link-local")` returns 40-byte string (CONTEXT D-06 said 38; empirical 40) | VERIFIED | `encode.go:108-120`; `TestSubnetCommentByteCaps` PASS pinning byte counts (37/37/40/38) |
| T7 | 09-01 | `EncodeSubnet("unknown")` returns `ErrInvalidReason` (D-04 sentinel split) | VERIFIED | `encode.go:108-114`; `TestEncodeSubnet_invalid_reasons` (6 sub-tests) PASS |
| T8 | 09-01 | `firewall.DetectMode([]Rule{subnetRule})` returns `ModeUnknown` (subnet drops through `User==""` predicate) | VERIFIED | `TestDetectMode_skips_v1_subnet_shape` PASS with `ParseErr=nil, User=""` post-Phase-9 |
| T9 | 09-01 | `Parsed.User` consumers (firewall.DetectMode, store.RebuildUserIPs) keep working unchanged | VERIFIED | All firewall + store tests PASS unchanged; existing `r.User == "" \|\| r.ParseErr != nil` guards filter subnet rules |
| T10 | 09-02 | Migration 004 creates `idx_observations_dedup` on `observations(source_ip, user, ts_unix_ns DESC, tier)` (RQ-9 option B) | VERIFIED | `migrations/004_add_dedup_index.sql` lines 56-58 |
| T11 | 09-02 | Migration 004 runs `ANALYZE observations;` as last statement (load-bearing for D-18 EQP test) | VERIFIED | `migrations/004_add_dedup_index.sql` line 60 |
| T12 | 09-02 | `ExpectedSchemaVersion` bumps from 3 to 4; all 5 test pins consistent | VERIFIED | `store.go:40`; `TestExpectedSchemaVersion_constant` PASS; `TestExpectedSchemaVersion_is_4` PASS; `queries_test.go:96` literal `4`; `store_test.go:128` literal `4` |
| T13 | 09-02 | Migrate runs once on fresh DB advancing `user_version` 0->4; idempotent on already-migrated | VERIFIED | `TestMigrate_progress_callback_skips_already_migrated` PASS (zero callbacks on no-op); `TestMigrate_progress_callback_fires` PASS (4 labels in order on fresh DB) |
| T14 | 09-02 | observations row count byte-identical pre/post migration 004 (D-26 invariant) | VERIFIED | `TestMigrate_004_preserves_observations_row_count` STRONG form: stages v3, seeds N rows, runs Migrate, asserts COUNT unchanged + idx_observations_dedup present; PASS |
| T15 | 09-02 | `store.Migrate` accepts optional progress callback via `WithProgress` functional-option (D-15) | VERIFIED | `migrations.go:30-60` MigrateOption + WithProgress; `TestMigrate_progress_nil_callback_is_safe` PASS |
| T16 | 09-02 | Progress callback fires with locked label `"Upgrading observation index..."` exactly once for migration 004 | VERIFIED | `migrations.go:68-80` migrationLabel; `TestMigrate_progress_callback_fires` asserts `["Creating observation tables...", "Creating observation indexes...", "Creating user-IP cache table...", "Upgrading observation index..."]` PASS |
| T17 | 09-03 | `Queries.DedupRows` returns one DedupRow per (source_ip, user) pair with all required fields (LOG-07/LOG-09) | VERIFIED | `queries.go:629-668`; functional tests + `TestQueries_DedupRows_uses_covering_index` PASS |
| T18 | 09-03 | Most-recent-tier semantics per D-07; tiebreak on shared ts_unix_ns is highest id wins (D-10) | VERIFIED | `dedupRowsSQL` correlated subquery `ORDER BY o2.ts_unix_ns DESC, o2.id DESC LIMIT 1`; tiebreak test in queries_test.go |
| T19 | 09-03 | Default sort: `last_seen DESC, total_count DESC, source_ip ASC` (D-11) | VERIFIED | `dedupRowsSQL` line 620 `ORDER BY last_seen_ns DESC, total_count DESC, o1.source_ip ASC` |
| T20 | 09-03 | `Queries.EventsForPair` returns Event slice from observations (LOG-08) reusing existing `Event` struct (D-13) | VERIFIED | `queries.go:707-735` returns `[]Event`; functional tests PASS |
| T21 | 09-03 | EQP regression: dedup query plan contains `USING COVERING INDEX idx_observations_dedup`; drill-down query plan contains `USING INDEX idx_observations_dedup` (D-18 differentiation per ADR-4) | VERIFIED | `TestQueries_DedupRows_uses_covering_index` PASS; `TestQueries_EventsForPair_uses_index` PASS |
| T22 | 09-03 | Injection regression: both new methods pass `'; DROP TABLE observations; --` payload test (T-OBS-01) | VERIFIED | Injection test sub-tests within DedupRows + EventsForPair test families PASS; observations row count unchanged |
| T23 | 09-03 | Synthetic 100k-row CI benchmark `BenchmarkDedupRows_100k` plus hard gate `TestDedupBenchmark_p95_budget` (D-19) | VERIFIED with caveat | Benchmark exists at `queries_bench_test.go:50`; gate widened from 50ms to 1000ms post-merge per phase notes (commit `c15e8ec`); rationale documented in file header |
| T24 | 09-03 | `config.Settings.LogsDedupWindowDays` field exists; default 90; range [1, 3650]; nested koanf key `logs.dedup_window_days` (D-08, P-05) | VERIFIED | `config.go:71` field + `:91` Defaults entry + `:130-132` Load nested-key + `:211-213` Validate bounds + `:240-242` overlayDefaults; 6 config tests PASS |

**Score:** 24/24 plan-level must-haves verified.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/ufwcomment/encode.go` | Kind enum, 4 ReasonXxx consts, ErrInvalidReason, EncodeSubnet | VERIFIED | All 8 symbols present (lines 70-120); WIRED via tests + 09-01 plan; consumers in Phase 11 (orphan acceptable - intentional cross-phase dependency per plan boundary) |
| `internal/ufwcomment/decode.go` | Three-way payload branching in v=1 + Kind set on legacy v=0 | VERIFIED | Lines 92-115; uses `strconv.Atoi` (post-WR-01 fix) instead of fmt.Sscanf; WIRED to all decode-path callers in firewall + store |
| `internal/ufwcomment/ufwcomment_test.go` | FW-10 forward-compat test + KindSubnet round-trip + ErrInvalidReason + 40-byte cap test + legacy-v=0 Kind test + WR-01 trailing-garbage test | VERIFIED | All 6 new tests + WR-01 regression test exist (lines 78-217+); ALL PASS |
| `internal/firewall/mode_test.go` | Mode-side regression for v=1 subnet-shape skip | VERIFIED | TestDetectMode_skips_v1_subnet_shape PASS post-Phase-9 with ParseErr=nil |
| `internal/store/migrations/004_add_dedup_index.sql` | 4-col covering index + ANALYZE + design-doc header | VERIFIED | 49 lines; 30+ line design-doc header documents D-16 typo correction, RQ-9 4-column resolution, RQ-4 ANALYZE-as-load-bearing rationale |
| `internal/store/store.go` | ExpectedSchemaVersion = 4 (bumped from 3) | VERIFIED | Line 40 |
| `internal/store/migrations.go` | Migrate accepts MigrateOption variadic; WithProgress helper; migrationLabel | VERIFIED | Lines 30-80, 107 (variadic signature backwards-compatible); WR-02 errors.Is(fs.ErrNotExist) fix applied |
| `internal/store/migrations_test.go` | progress callback tests + D-26 strong-form invariant | VERIFIED | 4 tests (162 lines); all PASS |
| `internal/store/queries.go` | DedupRow + DedupOpts + DedupRows + EventsForPairOpts + EventsForPair | VERIFIED | Lines 540-735; ~150 lines append; WR-03 PerUserBreakdown rows.Err() ordering fix applied |
| `internal/store/queries_test.go` | EQP regression tests + injection tests + tiebreak test + empty-username bucket test | VERIFIED | TestQueries_DedupRows_uses_covering_index + TestQueries_EventsForPair_uses_index + injection sub-tests; all PASS |
| `internal/store/queries_bench_test.go` | 100k-row synthetic benchmark with hard gate | VERIFIED | 192 lines; gate threshold 1000ms post-widening (rationale documented) |
| `internal/store/export_test.go` | Test-only exports of dedupRowsSQL + eventsForPairSQL | VERIFIED | 19 lines; allows EQP tests to feed unexported SQL strings to db.Query |
| `internal/config/config.go` | LogsDedupWindowDays field + 5 P-05 touch points | VERIFIED | Lines 71, 91, 130-132, 211-213, 240-242 |
| `internal/config/config_test.go` | 6 LogsDedupWindowDays tests | VERIFIED | TestConfig_LogsDedupWindowDays_* family PASS |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `decode.go::Decode (v=1 branch)` | three-way payload classifier | switch on payload prefix | WIRED | Lines 92-115; `user=` -> KindUser, `scope=subnet:reason=` -> KindSubnet, else -> ErrBadVersion |
| `encode.go::EncodeSubnet` | closed reason enum | switch reason against 4 ReasonXxx; default returns ErrInvalidReason | WIRED | Lines 108-114 |
| `migrations/004_add_dedup_index.sql` | observations table (DDL in 001_init.sql) | CREATE INDEX on (source_ip, user, ts_unix_ns DESC, tier) + ANALYZE observations | WIRED | Lines 56-60 |
| `store.go ExpectedSchemaVersion=4` | migrations.go::Migrate runner | constant matches highest numeric prefix | WIRED | All test pins consistent; TestExpectedSchemaVersion_constant PASS |
| `migrations.go::Migrate progress callback` | Phase 12 launch state machine (deferred consumer) | functional option WithProgress(fn func(label string)) | WIRED locally / DEFERRED downstream | API exists and tested; Phase 12 consumer wiring is intentionally out of scope per plan 09-02 D-25 |
| `queries.go::DedupRows` | migrations/004 idx_observations_dedup | WHERE/GROUP BY uses 4-column covering index | WIRED + EQP-asserted | TestQueries_DedupRows_uses_covering_index substring-matches `USING COVERING INDEX idx_observations_dedup` |
| `queries.go::EventsForPair` | migrations/004 idx_observations_dedup (3-col prefix) | WHERE source_ip=? AND user=? ORDER BY ts_unix_ns DESC | WIRED + EQP-asserted | TestQueries_EventsForPair_uses_index substring-matches `USING INDEX idx_observations_dedup` (covering not achievable per ADR-4) |
| `config.go::LogsDedupWindowDays` | DedupOpts.SinceNs (Phase 13 consumer) | Phase 13 caller computes since_ns from window | WIRED locally / DEFERRED downstream | Field exists + 5 P-05 touch points complete; consumer in Phase 13 |

### Data-Flow Trace (Level 4)

This is a pure data-layer phase. The new symbols are consumed by:
- `Queries.DedupRows` reads from `observations` table populated by Phase 02 ingest (non-empty in CI seed via insertObservation; non-empty in lab via journald replay).
- `Queries.EventsForPair` reads from same `observations` table.
- `EncodeSubnet` is producer-side; consumer is Phase 11 (intentionally deferred).
- `WithProgress` callback fires from migration runner; consumer is Phase 12 (intentionally deferred).
- `LogsDedupWindowDays` is read by Phase 13 (intentionally deferred).

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `Queries.DedupRows` result | `[]DedupRow` | `q.r.QueryContext(ctx, dedupRowsSQL, ...)` over observations table | YES (functional tests verify; benchmark seeds 100k rows and runs in <1000ms) | FLOWING |
| `Queries.EventsForPair` result | `[]Event` | `q.r.QueryContext(ctx, eventsForPairSQL, ...)` over observations table | YES (functional tests verify) | FLOWING |
| `EncodeSubnet` output | comment string | switch on closed enum + Sprintf | YES (round-trip tests prove deterministic output) | FLOWING |
| `migration 004` index | sqlite_master row | `CREATE INDEX idx_observations_dedup` | YES (TestMigrate_004_preserves_observations_row_count asserts existence post-migration) | FLOWING |

No HOLLOW or DISCONNECTED data-flow concerns. Phase 11/12/13 consumer deferral is documented and intentional per plan boundary clarifiers (D-25/D-26).

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Build passes | `go build ./...` | exit 0 | PASS |
| ufwcomment + store + config + firewall tests pass | `go test ./internal/ufwcomment/... ./internal/store/... ./internal/config/... ./internal/firewall/... -count=1 -short` | 4 packages PASS | PASS |
| EQP regression tests pass | `go test ./internal/store/... -run "TestQueries_DedupRows_uses_covering_index\|TestQueries_EventsForPair_uses_index" -v` | both PASS | PASS |
| Migration tests pass | `go test ./internal/store/... -run "TestMigrate_progress_callback_fires\|TestMigrate_004_preserves_observations_row_count\|TestMigrate_progress_nil_callback_is_safe\|TestMigrate_progress_callback_skips_already_migrated"` | 4 PASS | PASS |
| FW-10 ufwcomment regression tests pass | `go test ./internal/ufwcomment/... -run "TestDecode_v_field_with_trailing_garbage\|TestDecode_v1_subnet_shape_decoded\|TestEncodeSubnet_all_reasons_roundtrip\|TestSubnetCommentByteCaps\|TestEncodeSubnet_invalid_reasons\|TestDecode_v0_legacy_kind_is_KindUser\|TestDecode_v1_user_kind_is_KindUser\|TestDecode_v1_subnet_invalid_reason"` | all sub-tests PASS | PASS |
| Forward-compat firewall mode test passes | `go test ./internal/firewall/... -run "TestDetectMode_skips_v1_subnet_shape"` | PASS | PASS |
| Schema version pin tests pass | `go test ./internal/store/... -run "TestExpectedSchemaVersion_is_4\|TestExpectedSchemaVersion_constant"` | PASS | PASS |
| Lint clean (full repo) | `golangci-lint run ./...` | 0 issues | PASS |
| No exec.Command outside sysops | `bash scripts/check-no-exec-outside-sysops.sh` | OK | PASS |
| Go module pins match | `bash scripts/check-go-mod-pins.sh` | OK: 13 direct-dep pins match (D-23 zero new deps verified) | PASS |
| Single tea.NewProgram | `bash scripts/check-single-tea-program.sh` | OK | PASS |
| No raw config-write | `bash scripts/check-no-raw-config-write.sh` | OK | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| FW-10 | 09-01 | `internal/ufwcomment` v=1 grammar extended to discriminated union supporting both user-rules and subnet-rules; v1.2.x continue to safely treat unknown shapes as foreign per ErrBadVersion | SATISFIED | Three-way Decode classifier + Kind discriminator + 4 Reason consts + EncodeSubnet + ErrInvalidReason all present; forward-compat regression test (TestDetectMode_skips_v1_subnet_shape) pins v1.2.x decode contract |
| LOG-07 | 09-03 | Observation log view default mode shows one row per (source_ip, username) pair with last-seen, count, tier (data layer slice only - UI in Phase 13) | SATISFIED (data layer) | DedupRow + DedupOpts + Queries.DedupRows ship the data API with TotalCount, per-tier SUM counters, LastSeenNs, MostRecentTier, ordered by last_seen DESC; UI rendering deferred to Phase 13 per ROADMAP scope clarification |
| LOG-08 | 09-03 | Drill-down (Enter) on deduplicated row opens full per-(IP, user) event history (data layer slice only - Enter-key UI in Phase 13) | SATISFIED (data layer) | EventsForPairOpts + Queries.EventsForPair ship the drill-down query reusing existing Event struct; UI Enter-key wiring deferred to Phase 13 |
| LOG-09 | 09-03 | Tier-colored dedup rows: success=green, targeted=red, noise=gray, unmatched=yellow | SATISFIED (data layer) | DedupRow.MostRecentTier carries the tier classification ("success"\|"targeted"\|"noise"\|"unmatched"); ADR-5 pins the empty-username -> unmatched/yellow invariant via test; color rendering deferred to Phase 13 lipgloss styling |
| LOG-10 | 09-02 | Observation DB schema unchanged; dedup is presentation-only; covering index added via migration 004; user_version bumps to 4 | SATISFIED | Migration 004 ships 4-column covering index + ANALYZE; ExpectedSchemaVersion=4; TestMigrate_004_preserves_observations_row_count strong-form D-26 invariant test PASS proving row count byte-identical pre/post |

**Note on REQUIREMENTS.md text drift:** Both ROADMAP.md success criterion 4 and REQUIREMENTS.md LOG-10 still say `observation_runs(source_ip, username, ts_unix_ns DESC)` but the actual table is `observations` and the column is `user`. Migration 004 honors the empirical schema (verified against `001_init.sql` lines 36-65). This is the documented D-16 typo carry-forward; both files need a separate cleanup pass at phase verification time per 09-02 SUMMARY. Flagging here so it appears in the verification record.

No orphaned requirements (REQUIREMENTS.md maps exactly FW-10, LOG-07, LOG-08, LOG-09, LOG-10 to Phase 9; all 5 covered by plan frontmatter).

### Anti-Patterns Found

No blockers. The 3 standard-depth code review warnings (WR-01 trailing-garbage in ufwcomment v= field, WR-02 fs.ErrNotExist string-match, WR-03 rows.Err()-after-Close ordering) were fixed and committed (de45c42, cf42cbf, af162a0). Verified by direct read:

- `internal/ufwcomment/decode.go:78-85` uses `strconv.Atoi`, not `fmt.Sscanf`. WR-01 closed.
- `internal/store/migrations.go` uses `errors.Is(err, fs.ErrNotExist)` per WR-02 fix. Closed.
- `internal/store/queries.go` PerUserBreakdown extracted into helper using `defer rows.Close()` + `rows.Err()`-while-live per WR-03 fix. Closed.

Six Info-level findings (IN-01 through IN-06) were intentionally out of scope for the fix per fix_scope=critical_warning policy, are cosmetic/defensive concerns, and do not block goal achievement.

### Human Verification Required

Two operator-gated lab UATs are explicit ROADMAP gate items for this phase:

#### 1. Lab UAT P2-B: Real-DB EXPLAIN QUERY PLAN on ubuntu-wifi (192.168.1.187)

**Test:**
1. SSH to ubuntu-wifi as `jnuyens`; sudo as needed.
2. Install latest v1.3 .deb (built from this branch via `goreleaser snapshot`); confirm postinst clean.
3. `sudo sqlite3 /var/lib/sftp-jailer/observations.db 'PRAGMA user_version'` -> expect `4`.
4. Confirm `SELECT COUNT(*) FROM observations` >= 10k (representative noise; if <10k, optionally seed via `journalctl -u ssh --since "6 months ago"` per ROADMAP UAT gate text).
5. Run `ANALYZE observations;` then capture `EXPLAIN QUERY PLAN` of the dedup query (substituting real bind vars).
6. Time the dedup query (no EXPLAIN) with `time` or `\timer on`.

**Expected:**
- EXPLAIN output contains substring `USING COVERING INDEX idx_observations_dedup`.
- Wall time of dedup query <100ms (PROJECT.md spec for first-paint).

**Why human:** Requires SSH access, real Ubuntu 24.04 lab box, real journald-seeded observations DB. CI cannot reproduce production-scale row distributions. ROADMAP and 09-03 SUMMARY both explicitly mark this as operator-gated, NOT a CI gate.

#### 2. Lab UAT P2-D: Migration latency on ubuntu-wifi (192.168.1.187)

**Test:**
1. SSH to ubuntu-wifi as `jnuyens`; sudo as needed.
2. Confirm v1.2.x baseline: `sudo systemctl status sftp-jailer` (or just `sftp-jailer version`); `sudo sqlite3 /var/lib/sftp-jailer/observations.db 'PRAGMA user_version'` -> expect `3`.
3. Capture baseline observations row count: `sudo sqlite3 /var/lib/sftp-jailer/observations.db 'SELECT COUNT(*) FROM observations'`. Record value (>=10k expected).
4. Install v1.3 .deb (built from this branch via `goreleaser snapshot`).
5. Time the first launch: `sudo time sftp-jailer` and observe wall time from invocation to splash dismiss; observe whether the "Upgrading observation index..." label appears (Phase 12 wiring; if Phase 12 not yet landed, label won't render but migration must still complete).
6. Confirm `sudo sqlite3 /var/lib/sftp-jailer/observations.db 'PRAGMA user_version'` returns `4`.
7. Confirm `sudo sqlite3 /var/lib/sftp-jailer/observations.db ".indexes observations"` lists `idx_observations_dedup`.
8. Confirm row count unchanged: `sudo sqlite3 /var/lib/sftp-jailer/observations.db 'SELECT COUNT(*) FROM observations'` matches step 3.

**Expected:**
- Wall time for launch <= 1.5s (D-15 documented threshold).
- Row count delta = 0 (D-26 invariant).
- `idx_observations_dedup` present.
- `PRAGMA user_version = 4`.

**Why human:** Requires SSH access to lab host, .deb install with system-level package manager, baseline + post-migration sqlite3 inspection. Migration latency on real noisy host data cannot be reproduced in CI (synthetic 100k-row CI benchmark D-19 covers catastrophic-regression detection but not production wall-time under filesystem cache state). ROADMAP and 09-02 SUMMARY both explicitly mark this as operator-gated.

### Gaps Summary

No gaps. All 4 ROADMAP success criteria for the data-layer slice verified; all 24 plan-level must-haves verified; all 5 Phase 9 requirements (FW-10, LOG-07, LOG-08, LOG-09, LOG-10) satisfied at the data-layer scope (UI rendering for LOG-07/LOG-08/LOG-09 explicitly belongs to Phase 13 per ROADMAP scope clarification). All 3 code review warnings closed via committed fixes.

The phase is ready to merge from a CI/automated perspective; two operator-gated lab UATs (P2-B and P2-D) remain pending and are documented as human verification items above.

### Deferred Items

Per ROADMAP scope clarification ("Item 2 is UI rendering belonging to Phase 13 (console). For this phase, verify only the data-layer prerequisite..." and same for Item 3), the following are NOT gaps but explicitly addressed in later phases:

| Item | Addressed In | Evidence |
|------|--------------|----------|
| S-LOGS default mode renders one row per (source_ip, username) with humanized last-seen, count, tier-colored rendering | Phase 13 (console) | ROADMAP scope note: "Item 2 is UI rendering belonging to Phase 13"; 09-03 SUMMARY cross-phase note: "Phase 13 (S-LOGS dedup-mode rewrite) consumes Queries.DedupRows + Queries.EventsForPair as the data source. Phase 9 ships data only; Phase 13 wires the rendering" |
| Operator pressing Enter drills down to per-(source_ip, user) event history | Phase 13 (console) | ROADMAP scope note: "Item 3 is UI behavior belonging to Phase 13"; 09-03 SUMMARY: "The drill-down modal screen (Enter on a deduped row -> per-pair event history) is also a Phase 13/14 deliverable" |
| `WithProgress` callback consumer wiring into splash UI | Phase 12 (launch state machine) | 09-02 plan boundary clarifier (D-25): "Phase 12 plumbs the callback into the splash/doctor handoff to render 'Upgrading observation index...' during multi-second migrations" |
| `LogsDedupWindowDays` settings-screen UI row | Phase 13 / Phase 14 (S-SETTINGS) | 09-03 SUMMARY: "Phase 13/14 (S-SETTINGS UI row): LogsDedupWindowDays config field needs a settings-screen row so operators can tune the dedup window without editing the config file directly. Out of scope for Phase 9" |
| `EncodeSubnet` consumer wiring (subnet whitelist writer + M-DRY-RUN preview) | Phase 11 (subnet whitelist) | 09-01 plan boundary clarifier: "NO production code calls EncodeSubnet in this plan. Phase 11's M-DRY-RUN preview + ufw-allow writer are the only consumers; this plan ships the symbol so Phase 11 has no missing dep" |
| `firewall.DetectMode` extension to recognize `Kind==KindSubnet` | Phase 11 (subnet whitelist) | 09-01 plan boundary clarifier: "NO change to internal/firewall/mode.go::DetectMode semantics for subnet rules. Subnet rules drop through the existing User=='' predicate path with no breakage. Phase 11 will extend DetectMode explicitly to recognize Kind==KindSubnet" |
| ROADMAP/REQUIREMENTS LOG-10 text drift cleanup (`observation_runs(source_ip, username, ts_unix_ns DESC)` -> `observations(source_ip, user, ts_unix_ns DESC, tier)`) | Phase verification / docs follow-up | 09-02 SUMMARY: "Both ROADMAP and REQUIREMENTS LOG-10 need a separate cleanup pass at phase verification time, not piecemeal here" - this is an editorial follow-up, not a code gap |

---

_Verified: 2026-05-04T07:23:52Z_
_Verifier: Claude (gsd-verifier)_
