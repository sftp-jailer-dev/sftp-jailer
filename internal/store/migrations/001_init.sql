-- 001_init.sql — Phase 2 initial schema (target user_version = 1).
-- The migrations.go runner sets PRAGMA user_version inside the same
-- transaction; do NOT set it from this file.
--
-- Three tables:
--   observations      — one row per parsed sshd event (detail tier).
--   observation_runs  — one row per `observe-run` invocation (audit + cursor).
--   noise_counters    — compaction sink keyed by (date, tier, user, ip, event).
--
-- Indexes are created in 002_add_indexes.sql so they can be added or
-- recomputed without re-running the table-creation DDL.

-- observation_runs MUST be created BEFORE observations because observations
-- has a FOREIGN KEY (run_id) REFERENCES observation_runs(id).
CREATE TABLE observation_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at_unix_ns  INTEGER NOT NULL,
    finished_at_unix_ns INTEGER,
    -- result: 'success' | 'failure' | 'cancelled' (Esc on M-OBSERVE) | 'running'
    result              TEXT    NOT NULL DEFAULT 'running',
    -- counters emitted in the final summary line.
    events_read         INTEGER NOT NULL DEFAULT 0,
    events_classified   INTEGER NOT NULL DEFAULT 0,
    events_kept         INTEGER NOT NULL DEFAULT 0,  -- after compaction
    events_compacted    INTEGER NOT NULL DEFAULT 0,  -- detail rows folded into counters
    events_dropped      INTEGER NOT NULL DEFAULT 0,  -- counter rows pruned beyond MB cap
    counters_added      INTEGER NOT NULL DEFAULT 0,  -- new noise_counters rows
    -- error: human-readable message on result='failure'
    error               TEXT    NOT NULL DEFAULT '',
    -- cursor_before / cursor_after: the journalctl cursor strings (opaque).
    -- Useful for debugging cursor-file integrity bugs.
    cursor_before       TEXT    NOT NULL DEFAULT '',
    cursor_after        TEXT    NOT NULL DEFAULT ''
);

-- observations: one row per parsed sshd event.
CREATE TABLE observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- ts_unix_ns: nanoseconds since Unix epoch (UTC). journalctl gives us
    -- microseconds; we multiply by 1000 to keep ns precision for the future.
    -- INTEGER (8 bytes) covers years 1677..2262.
    ts_unix_ns      INTEGER NOT NULL,
    -- tier: one of 'success','targeted','noise','unmatched'. Stored as TEXT
    -- (SQLite has no enum) — short strings, table-scan-friendly.
    tier            TEXT    NOT NULL,
    -- user: parsed username (or empty for unmatched). Indexed for LOG-01 filters.
    user            TEXT    NOT NULL DEFAULT '',
    -- source_ip: parsed source IP (or empty for unmatched). Indexed.
    source_ip       TEXT    NOT NULL DEFAULT '',
    -- event_type: short tag derived from the regex that matched (e.g.
    -- 'auth_pubkey_ok','auth_pwd_ok','auth_pubkey_fail','invalid_user', or
    -- 'unmatched'). Indexed for LOG-01 filters.
    event_type      TEXT    NOT NULL DEFAULT 'unmatched',
    -- raw_message: the sshd MESSAGE field verbatim. Used by D-05 raw copy.
    raw_message     TEXT    NOT NULL,
    -- raw_json: the FULL journalctl JSON record verbatim, for D-05 raw copy
    -- (per the user-locked decision: copy the RAW journalctl JSON record,
    -- not just the MESSAGE). Stored as TEXT; SQLite has no JSON type, but
    -- TEXT is fine for our query shapes (we never filter on JSON fields).
    raw_json        TEXT    NOT NULL,
    -- pid: sshd worker PID (informational; not indexed).
    pid             INTEGER NOT NULL DEFAULT 0,
    -- run_id: which observation_run produced this row (FK).
    run_id          INTEGER NOT NULL REFERENCES observation_runs(id) ON DELETE CASCADE
);

-- noise_counters: one row per (date, tier, user, source_ip, event_type)
-- bucket. Fills as compaction folds older detail rows. Lets the admin see
-- "203.0.113.99 hit alice 4823 times on 2026-03-12" without keeping
-- every row.
CREATE TABLE noise_counters (
    -- bucket_date: ISO-8601 'YYYY-MM-DD' (UTC). One row per (date,…) tuple.
    bucket_date     TEXT    NOT NULL,
    tier            TEXT    NOT NULL,
    user            TEXT    NOT NULL DEFAULT '',
    source_ip       TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL DEFAULT '',
    count           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_date, tier, user, source_ip, event_type)
);
