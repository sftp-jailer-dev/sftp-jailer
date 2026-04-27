-- 003_user_ips.sql — Phase 4 FW-08 SQLite mirror of per-user firewall
-- rules (target user_version = 3). The migrations.go runner sets
-- PRAGMA user_version inside the same transaction; do NOT set it here.
--
-- Authority: this table is a DERIVED CACHE rebuilt from
-- `ufw status numbered` Enumerate output. Per D-FW-04 / pitfall C3 the
-- firewall comments (sftpj:v=1:user=<name>) are the authoritative
-- store; this table is a belt-and-suspenders recovery mirror only.
--
-- Rebuild contract (internal/store.Queries.RebuildUserIPs):
--   BeginTx → DELETE FROM user_ips → INSERT … FROM rules → Commit.
--   Pragmas (WAL/busy_timeout=5000/synchronous=NORMAL/foreign_keys=ON)
--   are pre-paid by store.go:67 — no per-migration PRAGMA needed.
--
-- Composite primary key prevents duplicate (user, source, proto, port)
-- entries — a single rebuild produces one row per rule even if the
-- caller's input contains duplicates (later rows ON CONFLICT update
-- the last_seen_unix_ns column).

CREATE TABLE user_ips (
    user              TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    proto             TEXT    NOT NULL,            -- 'v4' | 'v6'
    port              TEXT    NOT NULL,            -- string (supports '22/tcp' etc)
    last_seen_unix_ns INTEGER NOT NULL,            -- last successful Enumerate
    PRIMARY KEY (user, source, proto, port)
);

CREATE INDEX idx_user_ips_user ON user_ips (user);
