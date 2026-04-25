// Package store_test exercises the SQLite reader-pool / single-writer
// handle pair and the embedded-migration framework.
//
// Tests use a temp-file DB (not :memory:) because WAL mode behavior
// differs between file-backed and in-memory databases — we specifically
// verify that journal_mode resolves to "wal" on disk.
package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

func TestOpen_creates_wal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var mode string
	err = s.R.QueryRow("PRAGMA journal_mode").Scan(&mode)
	require.NoError(t, err)
	require.Equal(t, "wal", mode)
}

func TestOpen_busy_timeout_set(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var ms int
	err = s.R.QueryRow("PRAGMA busy_timeout").Scan(&ms)
	require.NoError(t, err)
	require.Equal(t, 5000, ms)
}

func TestWriter_single_conn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	wStats := s.W.Stats()
	require.Equal(t, 1, wStats.MaxOpenConnections)
}

func TestReader_pool_sized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	rStats := s.R.Stats()
	require.Equal(t, 8, rStats.MaxOpenConnections)
}

// TestMigrate_advances_to_expected_version replaces the Phase-1
// "empty migrations" no-op test. With Phase 2's 001+002 migrations
// landed, a fresh DB MUST advance to ExpectedSchemaVersion (2) on Migrate.
// The detailed table+index assertions live in
// TestMigrate_applies_001_init_and_002_indexes.
func TestMigrate_advances_to_expected_version(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Migrate(context.Background()))

	var v int
	require.NoError(t, s.R.QueryRow("PRAGMA user_version").Scan(&v))
	require.Equal(t, store.ExpectedSchemaVersion, v,
		"Migrate must advance fresh DB to ExpectedSchemaVersion")
}

func TestClose_closes_both(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)

	err = s.Close()
	require.NoError(t, err)

	_, err = s.R.Exec("SELECT 1")
	require.Error(t, err, "reader handle should be closed")
	_, err = s.W.Exec("SELECT 1")
	require.Error(t, err, "writer handle should be closed")
}

// TestMigrate_applies_001_init_and_002_indexes verifies that the embedded
// 001 + 002 migrations bring a fresh DB to user_version=2, with all three
// tables and at least the seven expected indexes named per RESEARCH.md.
func TestMigrate_applies_001_init_and_002_indexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Migrate(context.Background()))

	var version int
	require.NoError(t, s.R.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, 2, version, "migrations 001+002 must advance user_version to 2")

	tables := map[string]bool{}
	rows, err := s.R.Query("SELECT name FROM sqlite_master WHERE type='table'")
	require.NoError(t, err)
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		tables[n] = true
	}
	require.NoError(t, rows.Close())
	require.True(t, tables["observations"], "observations table missing")
	require.True(t, tables["observation_runs"], "observation_runs table missing")
	require.True(t, tables["noise_counters"], "noise_counters table missing")

	want := []string{
		"idx_observations_ts_desc",
		"idx_observations_user",
		"idx_observations_tier",
		"idx_observations_ip",
		"idx_observations_event",
		"idx_observations_run",
		"idx_observation_runs_finished",
	}
	idx := map[string]bool{}
	rows2, err := s.R.Query("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
	require.NoError(t, err)
	for rows2.Next() {
		var n string
		require.NoError(t, rows2.Scan(&n))
		idx[n] = true
	}
	require.NoError(t, rows2.Close())
	for _, w := range want {
		require.True(t, idx[w], "missing expected index: %s", w)
	}
}

// TestMigrate_idempotent verifies that calling Migrate a second time after
// a successful run is a no-op (no error, version still 2).
func TestMigrate_idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))
	require.NoError(t, s.Migrate(ctx), "second Migrate must be a no-op")

	var version int
	require.NoError(t, s.R.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, 2, version)
}

// TestPeekUserVersion_freshDB verifies that PeekUserVersion of an
// just-opened-but-not-migrated DB returns 0.
func TestPeekUserVersion_freshDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	v, err := store.PeekUserVersion(context.Background(), path)
	require.NoError(t, err)
	require.Equal(t, 0, v, "fresh DB must report user_version=0")
}

// TestPeekUserVersion_postMigrate verifies that PeekUserVersion of a DB
// that has been Migrated returns the binary's expected schema version.
func TestPeekUserVersion_postMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	require.NoError(t, s.Migrate(context.Background()))
	require.NoError(t, s.Close())

	v, err := store.PeekUserVersion(context.Background(), path)
	require.NoError(t, err)
	require.Equal(t, 2, v, "post-migrate DB must report user_version=2")
}

// TestPeekUserVersion_nonexistent_path verifies that pointing PeekUserVersion
// at a non-existent file returns 0 (sqlite auto-creates an empty file at
// version 0; Migrate would later bring it forward). This is the OBS-04
// schema-drift gate behavior: read but don't apply.
func TestPeekUserVersion_nonexistent_path(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.db")
	v, err := store.PeekUserVersion(context.Background(), path)
	require.NoError(t, err)
	require.Equal(t, 0, v, "non-existent path must report user_version=0 with no error")
}

// TestExpectedSchemaVersion_constant verifies the exported constant matches
// the highest-numbered migration this binary ships (currently 2).
func TestExpectedSchemaVersion_constant(t *testing.T) {
	require.Equal(t, 2, store.ExpectedSchemaVersion, "ExpectedSchemaVersion must equal 2 (highest migration)")
}

// TestSchema_observations_columns verifies the observations table schema
// covers every column downstream consumers (Runner, Queries) depend on.
func TestSchema_observations_columns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))

	cols := tableColumns(t, s.R, "observations")
	for _, want := range []string{
		"id", "ts_unix_ns", "tier", "user", "source_ip",
		"event_type", "raw_message", "raw_json", "pid", "run_id",
	} {
		require.True(t, cols[want], "observations missing required column: %s", want)
	}
}

// TestSchema_observation_runs_columns verifies the audit-row schema covers
// every column the Runner needs (D-08 status row + cursor bookkeeping).
func TestSchema_observation_runs_columns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))

	cols := tableColumns(t, s.R, "observation_runs")
	for _, want := range []string{
		"id", "started_at_unix_ns", "finished_at_unix_ns", "result",
		"events_read", "events_classified", "events_kept", "events_compacted",
		"events_dropped", "counters_added", "error", "cursor_before", "cursor_after",
	} {
		require.True(t, cols[want], "observation_runs missing required column: %s", want)
	}
}

// TestSchema_noise_counters_pk verifies the composite primary key shape
// that compaction (D-09) UPSERTs rely on.
func TestSchema_noise_counters_pk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))

	// PRAGMA table_info: pk column (5th) is non-zero for PK members and
	// numbers them in the composite-key order.
	pkOrder := map[string]int{}
	rows, err := s.R.Query("PRAGMA table_info(noise_counters)")
	require.NoError(t, err)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		require.NoError(t, rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk))
		if pk > 0 {
			pkOrder[name] = pk
		}
	}
	require.NoError(t, rows.Close())
	for _, want := range []string{"bucket_date", "tier", "user", "source_ip", "event_type"} {
		require.NotZero(t, pkOrder[want], "noise_counters PK missing column: %s", want)
	}

	// Auto-generated PK index should appear in index_list.
	var hasPKIndex bool
	rows2, err := s.R.Query("PRAGMA index_list(noise_counters)")
	require.NoError(t, err)
	for rows2.Next() {
		var seq int
		var name, origin string
		var unique, partial int
		require.NoError(t, rows2.Scan(&seq, &name, &unique, &origin, &partial))
		if origin == "pk" {
			hasPKIndex = true
		}
	}
	require.NoError(t, rows2.Close())
	require.True(t, hasPKIndex, "noise_counters auto-generated PK index missing")
}

// tableColumns is a small helper that returns the set of column names for
// a given table, queried via PRAGMA table_info.
func tableColumns(t *testing.T, db interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		require.NoError(t, rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk))
		out[name] = true
	}
	return out
}

// Concurrent reader/writer test: exercise that the 5s busy_timeout keeps
// SQLITE_BUSY from surfacing when a reader tx overlaps with a writer.
// In WAL mode, readers don't block writers, so this is a sanity check
// that the DSN wiring didn't accidentally disable WAL.
func TestConcurrent_reader_and_writer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	_, err = s.W.ExecContext(ctx, "CREATE TABLE t (id INTEGER)")
	require.NoError(t, err)
	_, err = s.W.ExecContext(ctx, "INSERT INTO t (id) VALUES (1), (2), (3)")
	require.NoError(t, err)

	// Open a reader transaction.
	rtx, err := s.R.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rtx.Rollback() })

	var count int
	require.NoError(t, rtx.QueryRowContext(ctx, "SELECT COUNT(*) FROM t").Scan(&count))
	require.Equal(t, 3, count)

	// Writer proceeds (in WAL mode this does not block on an open read tx).
	_, err = s.W.ExecContext(ctx, "INSERT INTO t (id) VALUES (4)")
	require.NoError(t, err)
}
