// Package lockdown_test exercises the LOCK-02 proposal generator. The
// Generator reads observations directly from the Phase 2 store via a
// parameterized SQL query (T-OBS-01 mitigation preserved). Tests drive
// the seeded-DB → generated-proposal round-trip end-to-end so the SQL
// grouping, tier-filtering, window-enforcement, and sort-order
// invariants are pinned at the package boundary.
//
// Test discipline:
//   - Use `newSeededDB` analogous to internal/store/queries_test.go.
//   - Use `time.Time`-frozen `nowFn` via `Generator.SetNowFnForTest`
//     for window-cutoff determinism.
//   - Empty user observations (the Phase 2 schema stores `user TEXT NOT
//     NULL DEFAULT ''`) MUST be excluded (LOCK-02 doesn't propose IPs
//     for "the empty user").
package lockdown_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

// newSeededDB opens + migrates a tmp DB and returns the Store + Queries
// wrapper. Mirrors internal/store/queries_test.go's helper of the same
// name so the seeding idioms are identical across packages.
func newSeededDB(t *testing.T) (*store.Store, *store.Queries) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s, store.NewQueries(s)
}

// insertRun inserts an observation_runs row and returns its rowid.
func insertRun(t *testing.T, w *sql.DB, finishedAtNs int64) int64 {
	t.Helper()
	res, err := w.ExecContext(context.Background(),
		`INSERT INTO observation_runs(started_at_unix_ns, finished_at_unix_ns, result)
		 VALUES (?, ?, 'success')`,
		finishedAtNs-1, finishedAtNs)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// insertObs is a thin wrapper around the observations INSERT — every
// test seeds via this helper for consistency.
func insertObs(t *testing.T, w *sql.DB, runID int64, ts int64, tier, user, ip string) {
	t.Helper()
	_, err := w.ExecContext(context.Background(),
		`INSERT INTO observations(ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, pid, run_id)
		 VALUES (?, ?, ?, ?, 'login_success', '', '{}', 0, ?)`,
		ts, tier, user, ip, runID)
	require.NoError(t, err)
}

// frozenNow returns a deterministic clock for window-cutoff tests. The
// Generator's nowFn defaults to time.Now; tests inject this via
// SetNowFnForTest so cutoff arithmetic is reproducible.
func frozenNow() time.Time {
	// 2026-04-27T12:00:00Z — well after every seeded ts in tests.
	return time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
}

// daysAgo returns ts_unix_ns at (frozenNow - n days). Encapsulates the
// arithmetic so tests read declaratively.
func daysAgo(n int) int64 {
	return frozenNow().Add(-time.Duration(n) * 24 * time.Hour).UnixNano()
}

// TestGenerate_groups_observations_by_user_and_source pins the core
// pivot: rows grouped by (user, source_ip) emit one ProposedIP per
// distinct source per user, with the connection count being the
// number of seeded rows. Two users → two proposals; alice has 2 IPs
// (3+1 conns), bob has 1 IP (5 conns).
func TestGenerate_groups_observations_by_user_and_source(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	for i := 0; i < 3; i++ {
		insertObs(t, s.W, runID, daysAgo(1)+int64(i), "success", "alice", "1.1.1.1")
	}
	insertObs(t, s.W, runID, daysAgo(1), "success", "alice", "2.2.2.2")
	for i := 0; i < 5; i++ {
		insertObs(t, s.W, runID, daysAgo(2)+int64(i), "success", "bob", "3.3.3.3")
	}

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Len(t, props, 2, "two distinct users → two proposals")

	require.Equal(t, "alice", props[0].User)
	require.Len(t, props[0].IPs, 2, "alice has two distinct source IPs")
	require.False(t, props[0].ZeroConn, "alice has observed connections")

	// alice's IPs should be ordered by ConnCount DESC — 3 then 1.
	require.Equal(t, "1.1.1.1", props[0].IPs[0].Source)
	require.Equal(t, 3, props[0].IPs[0].ConnCount)
	require.Equal(t, "2.2.2.2", props[0].IPs[1].Source)
	require.Equal(t, 1, props[0].IPs[1].ConnCount)

	require.Equal(t, "bob", props[1].User)
	require.Len(t, props[1].IPs, 1)
	require.Equal(t, "3.3.3.3", props[1].IPs[0].Source)
	require.Equal(t, 5, props[1].IPs[0].ConnCount)
	require.Equal(t, "success", props[1].IPs[0].Tier)
}

// TestGenerate_default_excludes_targeted_tier — D-L0204-02: tier=success
// only by default. Setting includeTargeted=true broadens to tier=targeted.
func TestGenerate_default_excludes_targeted_tier(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	insertObs(t, s.W, runID, daysAgo(1), "success", "alice", "1.1.1.1")
	insertObs(t, s.W, runID, daysAgo(1), "targeted", "alice", "2.2.2.2")

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Len(t, props, 1)
	require.Len(t, props[0].IPs, 1, "default excludes targeted")
	require.Equal(t, "1.1.1.1", props[0].IPs[0].Source)

	props, err = g.Generate(context.Background(), 90, true)
	require.NoError(t, err)
	require.Len(t, props, 1)
	require.Len(t, props[0].IPs, 2, "includeTargeted=true picks up tier=targeted")

	// Both IPs present; tiers must be preserved on each.
	tiers := map[string]string{}
	for _, ip := range props[0].IPs {
		tiers[ip.Source] = ip.Tier
	}
	require.Equal(t, "success", tiers["1.1.1.1"])
	require.Equal(t, "targeted", tiers["2.2.2.2"])
}

// TestGenerate_skips_observations_outside_window — window cutoff is
// strict: rows older than (now - windowDays * 24h) are excluded.
func TestGenerate_skips_observations_outside_window(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	// 100 days ago — outside a 90-day window.
	insertObs(t, s.W, runID, daysAgo(100), "success", "alice", "1.1.1.1")

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Empty(t, props, "alice's observation is outside the 90-day window → no proposal")
}

// TestGenerate_skips_null_user_observations — the Phase 2 schema stores
// `user TEXT NOT NULL DEFAULT ''`, so "no user" is empty-string, not
// NULL. The query must filter user != '' (and tolerate NULL defensively).
func TestGenerate_skips_null_user_observations(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	insertObs(t, s.W, runID, daysAgo(1), "success", "", "1.1.1.1")

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Empty(t, props, "empty-user observations are excluded")
}

// TestGenerate_window_days_validation — windowDays must be positive.
func TestGenerate_window_days_validation(t *testing.T) {
	_, q := newSeededDB(t)
	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	for _, bad := range []int{0, -1, -90} {
		_, err := g.Generate(context.Background(), bad, false)
		require.Error(t, err, "windowDays=%d must fail", bad)
		require.Contains(t, err.Error(), "windowDays must be > 0")
	}
}

// TestGenerate_sorts_by_user_ascending — proposal output is sorted by
// User ASC for deterministic UI rendering. Insert order is irrelevant.
func TestGenerate_sorts_by_user_ascending(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	// Insert in reverse alphabetical order to confirm sort works.
	insertObs(t, s.W, runID, daysAgo(1), "success", "charlie", "9.9.9.9")
	insertObs(t, s.W, runID, daysAgo(1), "success", "alice", "1.1.1.1")
	insertObs(t, s.W, runID, daysAgo(1), "success", "bob", "5.5.5.5")

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Len(t, props, 3)
	require.Equal(t, "alice", props[0].User)
	require.Equal(t, "bob", props[1].User)
	require.Equal(t, "charlie", props[2].User)
}

// TestGenerate_uses_parameterized_SQL_no_injection — preserves the
// T-OBS-01 mitigation pattern from FilterEvents. Even if a username
// were a SQL-injection payload, the parameterized binding would treat
// it as an opaque value. We can't directly attack the Generate API
// (windowDays is int, includeTargeted is bool — neither flows as a
// string), but we can pin that observation rows containing nasty
// usernames are returned verbatim (i.e. no row was injected and no
// table was dropped).
func TestGenerate_uses_parameterized_SQL_no_injection(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, daysAgo(0))
	// A username that, if naively concatenated into SQL, would close
	// the WHERE clause and DROP the table. We seed it via a `?`
	// placeholder, so the row is stored verbatim — and the Generator's
	// own SQL must not turn it back into executable text.
	const nasty = "alice'; DROP TABLE observations; --"
	insertObs(t, s.W, runID, daysAgo(1), "success", nasty, "1.1.1.1")

	g := lockdown.NewGenerator(q)
	g.SetNowFnForTest(frozenNow)

	props, err := g.Generate(context.Background(), 90, false)
	require.NoError(t, err)
	require.Len(t, props, 1, "the injection-payload row is returned verbatim")
	require.Equal(t, nasty, props[0].User, "username preserved byte-for-byte")

	// Confirm the table still exists by issuing a sanity query.
	var n int
	require.NoError(t, s.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&n))
	require.Equal(t, 1, n, "DROP TABLE attempt did not execute")
}
