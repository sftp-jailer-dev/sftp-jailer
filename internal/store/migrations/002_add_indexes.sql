-- 002_add_indexes.sql — Phase 2 indexes for LOG-01 filters and D-08 status.
--
-- LOG-01 + LOG-04 + LOG-06: most common access pattern is "filter by user
-- and/or source_ip and/or tier, ordered by ts DESC". Composite indexes
-- that cover the common combinations.

CREATE INDEX idx_observations_ts_desc ON observations(ts_unix_ns DESC);
CREATE INDEX idx_observations_user    ON observations(user, ts_unix_ns DESC);
CREATE INDEX idx_observations_tier    ON observations(tier, ts_unix_ns DESC);
CREATE INDEX idx_observations_ip      ON observations(source_ip, ts_unix_ns DESC);
CREATE INDEX idx_observations_event   ON observations(event_type, ts_unix_ns DESC);
-- run_id index is FK-induced; SQLite does NOT auto-create it. Add it.
CREATE INDEX idx_observations_run     ON observations(run_id);

-- D-08 status row: "last run" → SELECT max(finished_at_unix_ns) FROM
-- observation_runs WHERE result='success'. Composite for this and for
-- the "list of recent runs in audit panel" if we ever ship that.
CREATE INDEX idx_observation_runs_finished
    ON observation_runs(result, finished_at_unix_ns DESC);

-- noise_counters: D-08 "<C> daily counters" is just a COUNT(*) — full-table
-- scan is fine for a small table. No index needed there; the PRIMARY KEY
-- already covers UPSERT lookups during compaction.
