-- 004_add_dedup_index.sql - Phase 9 LOG-10 dedup covering index (target user_version = 4).
-- The migrations.go runner sets PRAGMA user_version inside the same transaction;
-- do NOT set it from this file.
--
-- Authority + consumer: this index is the load-bearing optimization for
-- the LOG-07 dedup query (internal/store/queries.go::Queries.DedupRows,
-- ships in plan 09-03) and the LOG-08 drill-down query (Queries.EventsForPair,
-- same plan). The dedup query GROUP BYs (source_ip, user) and projects
-- per-tier mini-counters via SUM(CASE WHEN tier = '...' THEN 1 ELSE 0 END);
-- the drill-down query filters WHERE source_ip = ? AND user = ? ORDER BY
-- ts_unix_ns DESC. Both queries' WHERE/GROUP BY/ORDER BY shape matches
-- the leading 3 columns of this index; the trailing `tier` column is
-- present so the dedup query's outer GROUP BY scan reads as a COVERING
-- index (per the EQP regression test in queries_test.go).
--
-- D-16 typo correction: ROADMAP.md and REQUIREMENTS.md LOG-10 both say
-- `observation_runs(source_ip, username, ts_unix_ns DESC)`. The actual
-- table is `observations` (NOT `observation_runs`), and the column is
-- `user` (NOT `username`). Verified against 001_init.sql lines 36-65.
--
-- D-16 + D-18 column-set resolution (per 09-RESEARCH.md RQ-9 option B):
-- D-16 originally specified 3 columns (source_ip, user, ts_unix_ns DESC).
-- D-18 locked the assertion `USING COVERING INDEX idx_observations_dedup`
-- on the dedup query. The dedup query's outer GROUP BY scan projects
-- `tier`, which is NOT in a 3-column index, forcing SQLite to emit
-- `USING INDEX` (not COVERING). Adding `tier` as a 4th column resolves
-- the conflict: the dedup query becomes covering; the drill-down query
-- still benefits from the 3-column prefix-match (its `raw_message` /
-- `raw_json` projections preclude any covering form regardless of tier).
--
-- Index size impact: ~5-10% per entry (tier is short TEXT, max 9 bytes
-- for 'unmatched'). Acceptable for the regression-test invariant.
--
-- ANALYZE rationale (first migration to use ANALYZE; load-bearing not
-- merely tuning): without sqlite_stat1, SQLite's planner choice between
-- this 4-column index and the existing 2-column idx_observations_ip
-- (002_add_indexes.sql line 10) is "arbitrary" per
-- https://www.sqlite.org/queryplanner.html. The EQP regression test in
-- plan 09-03 (TestQueries_DedupRows_uses_covering_index) becomes flaky
-- without deterministic stats. ANALYZE populates sqlite_stat1 so the
-- planner reliably picks idx_observations_dedup. Cost is small relative
-- to the index build itself (~50-200ms on 100k rows; ~200-800ms on 1M
-- rows tier-1 lab) and runs inside the same transaction so failure
-- rolls back atomically.

CREATE INDEX idx_observations_dedup
    ON observations (source_ip, user, ts_unix_ns DESC, tier);

ANALYZE observations;
