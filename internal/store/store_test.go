// Package store_test exercises the SQLite reader-pool / single-writer
// handle pair and the embedded-migration framework.
//
// Tests use a temp-file DB (not :memory:) because WAL mode behavior
// differs between file-backed and in-memory databases — we specifically
// verify that journal_mode resolves to "wal" on disk.
package store_test

import (
	"context"
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

func TestMigrate_empty_is_noop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	err = s.Migrate(context.Background())
	require.NoError(t, err)

	var v int
	err = s.R.QueryRow("PRAGMA user_version").Scan(&v)
	require.NoError(t, err)
	require.Equal(t, 0, v, "empty migrations dir must leave user_version at 0")
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
