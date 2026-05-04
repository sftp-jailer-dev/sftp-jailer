// Package store_test - migrations_test.go covers the WithProgress
// functional-option API added in Phase 9 plan 09-02 (LOG-10) plus the
// D-26 row-count-preservation invariant for the v3 -> v4 transition.
//
// The original Migrate basics (fresh DB advances, idempotent re-run,
// schema correctness) live in store_test.go; this file is scoped to the
// callback hook + the migration-004 invariant the Phase 9 success criteria
// explicitly call out.
package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

// TestMigrate_progress_callback_fires verifies that WithProgress receives
// one callback per applied migration, in numeric order. On a fresh DB,
// 4 migrations apply and 4 labels are recorded.
func TestMigrate_progress_callback_fires(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db.sqlite"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var labels []string
	err = s.Migrate(context.Background(), store.WithProgress(func(label string) {
		labels = append(labels, label)
	}))
	require.NoError(t, err)

	expected := []string{
		"Creating observation tables...",  // 001
		"Creating observation indexes...", // 002
		"Creating user-IP cache table...", // 003
		"Upgrading observation index...",  // 004 (D-15 locked label)
	}
	require.Equal(t, expected, labels)
}

// TestMigrate_progress_callback_skips_already_migrated verifies that
// re-running Migrate on an already-migrated DB does NOT fire the callback.
func TestMigrate_progress_callback_skips_already_migrated(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db.sqlite"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Migrate(context.Background())) // initial migrate, no callback

	var labels []string
	err = s.Migrate(context.Background(), store.WithProgress(func(label string) {
		labels = append(labels, label)
	}))
	require.NoError(t, err)
	require.Empty(t, labels, "callback must not fire when no migrations are applied")
}

// TestMigrate_progress_nil_callback_is_safe verifies that passing
// WithProgress(nil) does not panic and behaves identically to omitting
// the option.
func TestMigrate_progress_nil_callback_is_safe(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db.sqlite"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NotPanics(t, func() {
		err := s.Migrate(context.Background(), store.WithProgress(nil))
		require.NoError(t, err)
	})
}

// TestMigrate_004_preserves_observations_row_count pins the D-26 invariant
// in its STRONG form: stand up a v3 DB (apply 001-003 manually by reading
// the embedded SQL files via os.ReadFile from the source tree), seed N
// rows, run Migrate (which applies 004 only), and assert the row count
// stayed at N. The previous weak form (run all migrations, then re-run
// Migrate as a no-op) tested idempotency, NOT the v3->v4 transition the
// invariant actually promises.
//
// Because the embed.FS in migrations.go is package-private, the test reads
// the migration files directly from the source path under the project root.
// `go test` sets the working directory to the package dir (internal/store),
// so the SQL files live at "migrations/00N_*.sql" relative to it. If a
// future contributor runs the test with a different working directory
// (e.g. via some `go test -C` flag combination), the relative path will
// fail and signal "fix me" rather than silently passing.
func TestMigrate_004_preserves_observations_row_count(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db.sqlite"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// Apply 001+002+003 manually to land at user_version=3 (one tx per file
	// mirrors what migrations.go does).
	for _, m := range []struct {
		version int
		name    string
	}{
		{1, "migrations/001_init.sql"},
		{2, "migrations/002_add_indexes.sql"},
		{3, "migrations/003_user_ips.sql"},
	} {
		sqlBytes, err := os.ReadFile(m.name)
		require.NoError(t, err, "read %s", m.name)
		tx, err := s.W.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, string(sqlBytes))
		require.NoError(t, err, "exec %s", m.name)
		_, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version))
		require.NoError(t, err)
		require.NoError(t, tx.Commit())
	}

	// Confirm we landed at v3 (NOT v4).
	var v int
	require.NoError(t, s.R.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, 3, v, "manual setup must land at user_version=3 before running Migrate")

	// Seed N rows on the v3 schema (no idx_observations_dedup yet).
	_, err = s.W.ExecContext(ctx, `INSERT INTO observation_runs (started_at_unix_ns) VALUES (1)`)
	require.NoError(t, err)
	const runID int64 = 1
	const N = 5
	for i := 0; i < N; i++ {
		_, err = s.W.ExecContext(ctx,
			`INSERT INTO observations (ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, run_id)
             VALUES (?, 'noise', 'alice', '203.0.113.7', 'auth_pwd_fail', 'msg', '{}', ?)`,
			int64(1_700_000_000_000_000_000+i), runID,
		)
		require.NoError(t, err)
	}
	var beforeCount int
	require.NoError(t, s.R.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&beforeCount))
	require.Equal(t, N, beforeCount, "seed must land N rows on v3")

	// Run Migrate: applies ONLY 004 (since user_version is already at 3).
	require.NoError(t, s.Migrate(ctx))

	// user_version must now be 4.
	require.NoError(t, s.R.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, 4, v, "Migrate must advance v3 -> v4")

	// D-26 invariant: row count UNCHANGED.
	var afterCount int
	require.NoError(t, s.R.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&afterCount))
	require.Equal(t, beforeCount, afterCount, "observations row count must be byte-identical across the v3 -> v4 transition (D-26)")

	// Sanity: idx_observations_dedup must now exist (proves 004 actually ran,
	// not just incremented user_version).
	var idxName string
	err = s.R.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_observations_dedup'`).Scan(&idxName)
	require.NoError(t, err, "migration 004 must have created idx_observations_dedup")
	require.Equal(t, "idx_observations_dedup", idxName)
}
