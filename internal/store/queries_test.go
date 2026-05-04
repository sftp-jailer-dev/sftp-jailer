// Package store_test exercises the typed read query layer (queries.go)
// against a freshly-migrated tmp DB. Tests insert seed rows directly via
// the writer handle (s.W) - bypassing any future "Inserter" abstraction -
// so this file's failures unambiguously point at the read path.
package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// newSeededDB opens + migrates a tmp DB and returns the Store + a Queries
// wrapper. The cleanup hook closes the store. Callers seed via s.W
// directly using the helper insert functions below.
func newSeededDB(t *testing.T) (*store.Store, *store.Queries) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s, store.NewQueries(s)
}

// insertRun inserts an observation_runs row and returns its rowid. Callers
// pass result + finishedAt; everything else is zero-valued.
func insertRun(t *testing.T, w *sql.DB, result string, finishedAtNs int64) int64 {
	t.Helper()
	res, err := w.ExecContext(context.Background(),
		`INSERT INTO observation_runs(started_at_unix_ns, finished_at_unix_ns, result)
		 VALUES (?, ?, ?)`,
		finishedAtNs-1, finishedAtNs, result)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// insertObservation inserts one observations row. Returns the new rowid.
func insertObservation(t *testing.T, w *sql.DB, runID int64, ts int64, tier, user, ip, eventType string) int64 {
	t.Helper()
	res, err := w.ExecContext(context.Background(),
		`INSERT INTO observations(ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, pid, run_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, tier, user, ip, eventType, "raw msg", "{}", 0, runID)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// insertCounter inserts one noise_counters row.
func insertCounter(t *testing.T, w *sql.DB, date, tier, user, ip, eventType string, count int64) {
	t.Helper()
	_, err := w.ExecContext(context.Background(),
		`INSERT INTO noise_counters(bucket_date, tier, user, source_ip, event_type, count)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		date, tier, user, ip, eventType, count)
	require.NoError(t, err)
}

// ------ StatusRow ------

func TestQueries_StatusRow_emptyDB(t *testing.T) {
	_, q := newSeededDB(t)
	got, err := q.StatusRow(context.Background())
	require.NoError(t, err)
	require.Equal(t, store.ExpectedSchemaVersion, got.SchemaVersion)
	require.Equal(t, int64(0), got.DetailCount)
	require.Equal(t, int64(0), got.CounterCount)
	require.Equal(t, int64(0), got.LastSuccessNs)
}

func TestQueries_StatusRow_seeded(t *testing.T) {
	s, q := newSeededDB(t)
	const ts int64 = 1_700_000_000_000_000_000
	runID := insertRun(t, s.W, "success", ts)
	for i := int64(0); i < 5; i++ {
		insertObservation(t, s.W, runID, ts+i, "noise", "alice", "203.0.113.1", "auth_pwd_fail")
	}
	insertCounter(t, s.W, "2026-04-25", "noise", "alice", "203.0.113.1", "auth_pwd_fail", 100)
	insertCounter(t, s.W, "2026-04-24", "noise", "bob", "198.51.100.7", "invalid_user", 50)

	got, err := q.StatusRow(context.Background())
	require.NoError(t, err)
	// Phase 4 plan 04-03 bumped ExpectedSchemaVersion 2 -> 3 with 003_user_ips.sql.
	// Phase 9 plan 09-02 bumps 3 -> 4 with 004_add_dedup_index.sql.
	require.Equal(t, 4, got.SchemaVersion)
	require.Equal(t, int64(5), got.DetailCount)
	require.Equal(t, int64(2), got.CounterCount)
	require.Equal(t, ts, got.LastSuccessNs)
}

// ------ FilterEvents ------

// seedTwoUsers inserts 10 observations alternating between alice and bob,
// across mixed tiers/IPs, with monotonically-increasing ts. Returns the
// run_id.
func seedTwoUsers(t *testing.T, s *store.Store) int64 {
	t.Helper()
	const base int64 = 1_700_000_000_000_000_000
	runID := insertRun(t, s.W, "success", base+10)
	users := []string{"alice", "bob"}
	tiers := []string{"success", "noise", "targeted", "success", "noise"}
	ips := []string{"10.0.0.1", "203.0.113.7"}
	for i := 0; i < 10; i++ {
		insertObservation(t, s.W, runID, base+int64(i),
			tiers[i%len(tiers)], users[i%2], ips[i%2], "auth_pwd_ok")
	}
	return runID
}

func TestQueries_FilterEvents_noFilter(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	got, err := q.FilterEvents(context.Background(), store.FilterOpts{Limit: 100})
	require.NoError(t, err)
	require.Len(t, got, 10)
	// DESC order: largest ts first.
	for i := 1; i < len(got); i++ {
		require.True(t, got[i-1].TsUnixNs > got[i].TsUnixNs,
			"FilterEvents must return rows ordered by ts_unix_ns DESC")
	}
}

func TestQueries_FilterEvents_byUser(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	got, err := q.FilterEvents(context.Background(), store.FilterOpts{User: "alice", Limit: 100})
	require.NoError(t, err)
	require.NotEmpty(t, got)
	for _, e := range got {
		require.Equal(t, "alice", e.User)
	}
}

func TestQueries_FilterEvents_byTier(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	got, err := q.FilterEvents(context.Background(), store.FilterOpts{Tier: "noise", Limit: 100})
	require.NoError(t, err)
	require.NotEmpty(t, got)
	for _, e := range got {
		require.Equal(t, "noise", e.Tier)
	}
}

func TestQueries_FilterEvents_bySourceIP(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	got, err := q.FilterEvents(context.Background(), store.FilterOpts{SourceIP: "203.0.113.7", Limit: 100})
	require.NoError(t, err)
	require.NotEmpty(t, got)
	for _, e := range got {
		require.Equal(t, "203.0.113.7", e.SourceIP)
	}
}

func TestQueries_FilterEvents_byTimeRange(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)
	const base int64 = 1_700_000_000_000_000_000
	// Window [base+3, base+7) → events with ts 3,4,5,6 → 4 rows.
	got, err := q.FilterEvents(context.Background(), store.FilterOpts{
		SinceNs: base + 3,
		UntilNs: base + 7,
		Limit:   100,
	})
	require.NoError(t, err)
	require.Len(t, got, 4)
	for _, e := range got {
		require.GreaterOrEqual(t, e.TsUnixNs, base+3)
		require.Less(t, e.TsUnixNs, base+7)
	}
}

func TestQueries_FilterEvents_pagination(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	got, err := q.FilterEvents(context.Background(), store.FilterOpts{Limit: 3, Offset: 6})
	require.NoError(t, err)
	require.Len(t, got, 3, "Limit 3 Offset 6 must return 3 rows (the 7th, 8th, 9th most-recent)")
}

// ------ PerUserBreakdown ------

func TestQueries_PerUserBreakdown(t *testing.T) {
	s, q := newSeededDB(t)
	const base int64 = 1_700_000_000_000_000_000
	runID := insertRun(t, s.W, "success", base+1000)
	// alice: 3 success (newest IP 10.0.0.99 last), 2 targeted, 1 noise.
	insertObservation(t, s.W, runID, base+1, "success", "alice", "10.0.0.1", "auth_pwd_ok")
	insertObservation(t, s.W, runID, base+2, "success", "alice", "10.0.0.2", "auth_pwd_ok")
	insertObservation(t, s.W, runID, base+3, "success", "alice", "10.0.0.99", "auth_pwd_ok")
	insertObservation(t, s.W, runID, base+4, "targeted", "alice", "10.0.0.4", "auth_pwd_fail")
	insertObservation(t, s.W, runID, base+5, "targeted", "alice", "10.0.0.5", "auth_pwd_fail")
	insertObservation(t, s.W, runID, base+6, "noise", "alice", "10.0.0.6", "auth_pwd_fail")
	// bob: noise only, distractor.
	insertObservation(t, s.W, runID, base+7, "noise", "bob", "203.0.113.1", "auth_pwd_fail")

	// Plan 06-03 / TUI-10: PerUserBreakdown gained a sinceNs filter. The
	// pre-extension shape (lifetime counts) is preserved by passing 0 -
	// this regression guard ensures the new third arg doesn't drift the
	// existing semantics.
	ub, err := q.PerUserBreakdown(context.Background(), "alice", 0)
	require.NoError(t, err)
	tiers := map[string]int64{}
	for _, tb := range ub.Tiers {
		tiers[tb.Tier] = tb.Count
	}
	require.Equal(t, int64(3), tiers["success"])
	require.Equal(t, int64(2), tiers["targeted"])
	require.Equal(t, int64(1), tiers["noise"])
	// FirstSeenIP = first by ts ASC across alice's rows = 10.0.0.1
	require.Equal(t, "10.0.0.1", ub.FirstSeenIP)
	// LastSuccessNs = max ts where tier='success' for alice = base+3
	require.Equal(t, base+3, ub.LastSuccessNs)
}

// TestPerUserBreakdown_with_since_ns_filters pins the Plan 06-03 / TUI-10
// signature extension: PerUserBreakdown gains a sinceNs int64 argument that
// filters tier counts to observations with ts_unix_ns >= sinceNs. Mirrors
// the FilterEvents.SinceNs convention.
//
// Setup: insert observations spanning ~200 days. Query with a 90-day cutoff.
// Assert: tier counts reflect ONLY events within the last 90 days.
func TestPerUserBreakdown_with_since_ns_filters(t *testing.T) {
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())

	// Recent (within 90 days): 2 success, 1 noise.
	insertObservation(t, s.W, runID, now.Add(-1*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.1", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-30*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.2", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-60*24*time.Hour).UnixNano(), "noise", "alice", "10.0.0.3", "auth_pwd_fail")

	// Older than 90 days: 5 noise (must be filtered out).
	for i := int64(0); i < 5; i++ {
		insertObservation(t, s.W, runID, now.Add(-150*24*time.Hour).UnixNano()-i, "noise", "alice", "10.0.0.99", "auth_pwd_fail")
	}

	cutoff := now.Add(-90 * 24 * time.Hour).UnixNano()
	ub, err := q.PerUserBreakdown(context.Background(), "alice", cutoff)
	require.NoError(t, err)

	tiers := map[string]int64{}
	for _, tb := range ub.Tiers {
		tiers[tb.Tier] = tb.Count
	}
	require.Equal(t, int64(2), tiers["success"], "expect 2 recent success rows; got %v", tiers)
	require.Equal(t, int64(1), tiers["noise"], "expect 1 recent noise row (the 60-day-old one); got %v", tiers)
	require.Zero(t, tiers["targeted"], "no targeted rows seeded; got %v", tiers)
}

// TestPerUserBreakdown_since_ns_zero_disables_filter pins the regression
// guard: passing sinceNs=0 returns full lifetime counts (mirroring the
// FilterEvents convention "(? = 0 OR ts_unix_ns >= ?)"). Pre-existing
// callers that pass 0 must observe behaviour identical to the prior
// 2-arg signature.
func TestPerUserBreakdown_since_ns_zero_disables_filter(t *testing.T) {
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())

	// Spread observations across ~200 days.
	insertObservation(t, s.W, runID, now.Add(-1*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.1", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-30*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.2", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-60*24*time.Hour).UnixNano(), "noise", "alice", "10.0.0.3", "auth_pwd_fail")
	for i := int64(0); i < 5; i++ {
		insertObservation(t, s.W, runID, now.Add(-150*24*time.Hour).UnixNano()-i, "noise", "alice", "10.0.0.99", "auth_pwd_fail")
	}

	ub, err := q.PerUserBreakdown(context.Background(), "alice", 0)
	require.NoError(t, err)
	tiers := map[string]int64{}
	for _, tb := range ub.Tiers {
		tiers[tb.Tier] = tb.Count
	}
	require.Equal(t, int64(2), tiers["success"], "sinceNs=0 returns lifetime success count; got %v", tiers)
	require.Equal(t, int64(6), tiers["noise"], "sinceNs=0 returns lifetime noise count (1 recent + 5 old); got %v", tiers)
}

// ------ LastLoginPerUser ------

func TestQueries_LastLoginPerUser(t *testing.T) {
	s, q := newSeededDB(t)
	const base int64 = 1_700_000_000_000_000_000
	runID := insertRun(t, s.W, "success", base+1000)
	// alice success at 100; bob success at 200; charlie only noise.
	insertObservation(t, s.W, runID, base+100, "success", "alice", "10.0.0.1", "auth_pwd_ok")
	insertObservation(t, s.W, runID, base+50, "success", "alice", "10.0.0.1", "auth_pwd_ok") // older
	insertObservation(t, s.W, runID, base+200, "success", "bob", "10.0.0.2", "auth_pwd_ok")
	insertObservation(t, s.W, runID, base+300, "noise", "charlie", "203.0.113.99", "auth_pwd_fail")
	// Empty-username success row should be excluded.
	insertObservation(t, s.W, runID, base+400, "success", "", "10.0.0.99", "auth_pwd_ok")

	got, err := q.LastLoginPerUser(context.Background())
	require.NoError(t, err)

	users := map[string]int64{}
	for _, u := range got {
		users[u.User] = u.LastLoginNs
	}
	require.Equal(t, base+100, users["alice"], "alice last login should be max of her success rows")
	require.Equal(t, base+200, users["bob"])
	_, hasCharlie := users["charlie"]
	require.False(t, hasCharlie, "charlie has no success rows so must be absent")
	_, hasEmpty := users[""]
	require.False(t, hasEmpty, "empty-username rows must be filtered out")
}

// ------ SQL injection discipline ------

func TestQueries_FilterEvents_parameterized_no_injection(t *testing.T) {
	s, q := newSeededDB(t)
	seedTwoUsers(t, s)

	// Classic injection payload - should be matched literally as a username
	// (zero rows) and MUST NOT drop the table.
	payload := `'; DROP TABLE observations; --`
	got, err := q.FilterEvents(context.Background(), store.FilterOpts{User: payload, Limit: 100})
	require.NoError(t, err)
	require.Empty(t, got)

	// Sanity: observations table still exists, still has all 10 rows.
	var n int
	require.NoError(t, s.R.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&n))
	require.Equal(t, 10, n, "observations table must NOT have been dropped by injection payload")
}

// ------ FW-08 SQLite mirror (Phase 4 plan 04-03) ------

// TestExpectedSchemaVersion_is_4 pins the Phase 9 schema bump from 3 -> 4.
// Migration 004_add_dedup_index.sql lands the LOG-07/LOG-08 covering index;
// ExpectedSchemaVersion is bumped accordingly. If the migrations directory
// gains 005_*.sql but ExpectedSchemaVersion stays at 4, this test fails.
func TestExpectedSchemaVersion_is_4(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4, store.ExpectedSchemaVersion)
}

// TestRebuildUserIPs_replaces_table_in_single_tx pins the D-FW-04 contract:
// RebuildUserIPs is a derived-cache writer (TRUNCATE + bulk INSERT in a
// single transaction). Foreign rules (ParseErr != nil) are skipped per the
// forward-compat invariant from internal/ufwcomment.
func TestRebuildUserIPs_replaces_table_in_single_tx(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	_ = s

	rules := []firewall.Rule{
		{ID: 1, User: "alice", Source: "203.0.113.7/32", Proto: "v4", Port: "22"},
		{ID: 2, User: "alice", Source: "203.0.113.8/32", Proto: "v4", Port: "22"},
		{ID: 3, User: "bob", Source: "203.0.113.9/32", Proto: "v4", Port: "22"},
		// Foreign rule - ParseErr != nil → MUST be skipped.
		{ID: 4, RawComment: "foreign", ParseErr: ufwcomment.ErrNotOurs},
		// v=2 forward-compat rule - ParseErr=ErrBadVersion + User=="" → skipped.
		{ID: 5, RawComment: "sftpj:v=2:user=carol", ParseErr: ufwcomment.ErrBadVersion},
	}
	frozen := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return frozen }
	require.NoError(t, q.RebuildUserIPs(context.Background(), rules, nowFn))

	aliceIPs, err := q.UserIPs(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, aliceIPs, 2)
	require.Equal(t, frozen.UnixNano(), aliceIPs[0].LastSeenUnixNs)

	bobIPs, err := q.UserIPs(context.Background(), "bob")
	require.NoError(t, err)
	require.Len(t, bobIPs, 1)

	// Carol is the v=2 forward-compat rule's user - it MUST NOT have leaked
	// into the mirror because ParseErr was ErrBadVersion (and User was "").
	carolIPs, err := q.UserIPs(context.Background(), "carol")
	require.NoError(t, err)
	require.Empty(t, carolIPs)

	// Rebuild with empty input wipes the table (truncate semantics).
	require.NoError(t, q.RebuildUserIPs(context.Background(), nil, nowFn))
	aliceIPs2, err := q.UserIPs(context.Background(), "alice")
	require.NoError(t, err)
	require.Empty(t, aliceIPs2)
}

// TestRebuildUserIPs_skips_rules_with_empty_user pins that User=="" rules
// (legacy v=0 with no user, or any malformed decode) are excluded from
// the mirror.
func TestRebuildUserIPs_skips_rules_with_empty_user(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	_ = s

	rules := []firewall.Rule{
		{ID: 1, User: "", Source: "203.0.113.7/32", Proto: "v4", Port: "22"}, // skipped
	}
	require.NoError(t, q.RebuildUserIPs(context.Background(), rules, nil))

	// nil-user query: just confirm no leakage occurred under any name.
	got, err := q.UserIPs(context.Background(), "")
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestRebuildUserIPs_default_now_when_nil pins that nowFn=nil falls back
// to time.Now() - production callers don't have to thread a clock through.
func TestRebuildUserIPs_default_now_when_nil(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	_ = s

	before := time.Now().UnixNano()
	rules := []firewall.Rule{
		{ID: 1, User: "alice", Source: "203.0.113.7/32", Proto: "v4", Port: "22"},
	}
	require.NoError(t, q.RebuildUserIPs(context.Background(), rules, nil))
	after := time.Now().UnixNano()

	ips, err := q.UserIPs(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	require.GreaterOrEqual(t, ips[0].LastSeenUnixNs, before)
	require.LessOrEqual(t, ips[0].LastSeenUnixNs, after)
}

// TestUserIPs_returns_empty_slice_not_nil_on_no_match pins the contract
// that callers can range over the result without nil-checking.
func TestUserIPs_returns_empty_slice_not_nil_on_no_match(t *testing.T) {
	t.Parallel()
	_, q := newSeededDB(t)
	got, err := q.UserIPs(context.Background(), "nobody")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Len(t, got, 0)
}

// TestRebuildUserIPs_idempotent_repeat_call pins that calling RebuildUserIPs
// twice in a row with identical input yields identical output (no PRIMARY
// KEY collision crashes; the ON CONFLICT clause covers a same-rebuild race).
func TestRebuildUserIPs_idempotent_repeat_call(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	_ = s

	rules := []firewall.Rule{
		{ID: 1, User: "alice", Source: "203.0.113.7/32", Proto: "v4", Port: "22"},
	}
	frozen := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return frozen }
	require.NoError(t, q.RebuildUserIPs(context.Background(), rules, nowFn))
	require.NoError(t, q.RebuildUserIPs(context.Background(), rules, nowFn))

	ips, err := q.UserIPs(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, ips, 1)
}

// ------ Phase 9 plan 09-03: DedupRows + EventsForPair (LOG-07/LOG-08/LOG-09) ------

// seedDedupCorpus seeds 3 (ip, user) buckets with deterministic ts increments.
// Returns the runID for the inserted rows.
//
// Signature is widened to testing.TB in Task 4 (helper-widening commit) so
// the benchmark's seeder can reuse it; for now it takes *testing.T because
// the existing helper signatures in this file (insertRun / insertObservation)
// haven't been widened yet.
func seedDedupCorpus(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	runID := insertRun(t, db, "success", int64(1_700_000_000_000_000_000))
	base := int64(1_700_000_000_000_000_000)
	// bucket A: (alice, 203.0.113.7) - 3x noise
	insertObservation(t, db, runID, base+1, "noise", "alice", "203.0.113.7", "auth_pwd_fail")
	insertObservation(t, db, runID, base+2, "noise", "alice", "203.0.113.7", "auth_pwd_fail")
	insertObservation(t, db, runID, base+3, "noise", "alice", "203.0.113.7", "auth_pwd_fail")
	// bucket B: (alice, 203.0.113.8) - 1x success (most recent overall)
	insertObservation(t, db, runID, base+10, "success", "alice", "203.0.113.8", "auth_pubkey_ok")
	// bucket C: (bob, 203.0.113.7) - 2x targeted
	insertObservation(t, db, runID, base+5, "targeted", "bob", "203.0.113.7", "invalid_user")
	insertObservation(t, db, runID, base+6, "targeted", "bob", "203.0.113.7", "invalid_user")
	return runID
}

// getQueryPlan runs `EXPLAIN QUERY PLAN <sql>` and returns the joined
// `detail` rows. First occurrence of EQP testing in this repo (ADR-3 in
// 09-03 plan).
//
// EQP returns a 4-column result: (id INT, parent INT, notused INT, detail TEXT).
// We only care about `detail` for substring matching; the join with newlines
// preserves the multi-row plan structure for assert error messages.
func getQueryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notused, &detail))
		lines = append(lines, detail)
	}
	require.NoError(t, rows.Err())
	return strings.Join(lines, "\n")
}

func TestQueries_DedupRows_three_buckets(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)
	// ANALYZE so the planner deterministically prefers idx_observations_dedup
	// over the older idx_observations_ip in case both are candidates.
	_, err := s.W.Exec(`ANALYZE observations`)
	require.NoError(t, err)

	rows, err := q.DedupRows(context.Background(), store.DedupOpts{SinceNs: 0})
	require.NoError(t, err)
	require.Len(t, rows, 3)

	// Sort: last_seen DESC, total_count DESC, source_ip ASC.
	// bucket B last_seen = base+10 -> first.
	require.Equal(t, "alice", rows[0].User)
	require.Equal(t, "203.0.113.8", rows[0].SourceIP)
	require.Equal(t, int64(1), rows[0].TotalCount)
	require.Equal(t, int64(1), rows[0].SuccessCount)
	require.Equal(t, "success", rows[0].MostRecentTier)
	// bucket C last_seen = base+6, total=2 -> second.
	require.Equal(t, "bob", rows[1].User)
	require.Equal(t, int64(2), rows[1].TotalCount)
	require.Equal(t, int64(2), rows[1].TargetedCount)
	require.Equal(t, "targeted", rows[1].MostRecentTier)
	// bucket A last_seen = base+3, total=3 -> third.
	require.Equal(t, "alice", rows[2].User)
	require.Equal(t, "203.0.113.7", rows[2].SourceIP)
	require.Equal(t, int64(3), rows[2].TotalCount)
	require.Equal(t, int64(3), rows[2].NoiseCount)
	require.Equal(t, "noise", rows[2].MostRecentTier)
}

func TestQueries_DedupRows_window_filter_excludes_old_rows(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)
	_, _ = s.W.Exec(`ANALYZE observations`)

	// SinceNs above bucket-A latest ts; bucket A (last=base+3) is excluded.
	rows, err := q.DedupRows(context.Background(), store.DedupOpts{
		SinceNs: int64(1_700_000_000_000_000_000) + 4,
	})
	require.NoError(t, err)
	// Buckets remaining: B (alice, 203.0.113.8 - last=base+10) and C
	// (bob, 203.0.113.7 - last=base+6). Bucket A (alice, 203.0.113.7 -
	// last=base+3) is filtered out by the SinceNs bound.
	require.Len(t, rows, 2)
	for _, r := range rows {
		// The filtered-out bucket is (alice, 203.0.113.7); bucket C also
		// uses 203.0.113.7 but with user='bob', so we must not naively
		// assert on SourceIP alone. Assert that no row matches the (ip, user)
		// pair of bucket A.
		isBucketA := r.SourceIP == "203.0.113.7" && r.User == "alice"
		require.False(t, isBucketA, "bucket A (alice@203.0.113.7) must be filtered out by window")
	}
}

// TestQueries_DedupRows_tiebreak_highest_id_wins pins D-10: when two rows
// for the same (source_ip, user) share ts_unix_ns, the higher id row's
// tier wins for MostRecentTier.
func TestQueries_DedupRows_tiebreak_highest_id_wins(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, "success", int64(1_700_000_000_000_000_000))
	sameTs := int64(1_700_000_000_000_000_500)
	// insertObservation returns the inserted id; SQLite AUTOINCREMENT gives monotonic ids.
	idLow := insertObservation(t, s.W, runID, sameTs, "noise", "alice", "203.0.113.7", "auth_pwd_fail")
	idHigh := insertObservation(t, s.W, runID, sameTs, "success", "alice", "203.0.113.7", "auth_pubkey_ok")
	require.Greater(t, idHigh, idLow, "monotonic ids expected")
	_, _ = s.W.Exec(`ANALYZE observations`)

	rows, err := q.DedupRows(context.Background(), store.DedupOpts{SinceNs: 0})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "success", rows[0].MostRecentTier,
		"higher-id row's tier (success) must win on shared ts_unix_ns (D-10)")
}

// TestQueries_DedupRows_includes_empty_username_bucket pins ADR-5 for
// 09-03: rows with user='' surface as a (source_ip, '') bucket whose
// most-recent-tier is typically 'unmatched' (yellow per LOG-09).
func TestQueries_DedupRows_includes_empty_username_bucket(t *testing.T) {
	s, q := newSeededDB(t)
	runID := insertRun(t, s.W, "success", int64(1_700_000_000_000_000_000))
	base := int64(1_700_000_000_000_000_000)
	insertObservation(t, s.W, runID, base+1, "unmatched", "", "203.0.113.99", "unmatched")
	insertObservation(t, s.W, runID, base+2, "unmatched", "", "203.0.113.99", "unmatched")
	_, _ = s.W.Exec(`ANALYZE observations`)

	rows, err := q.DedupRows(context.Background(), store.DedupOpts{SinceNs: 0})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "203.0.113.99", rows[0].SourceIP)
	require.Equal(t, "", rows[0].User, "empty-username bucket must be included (ADR-5)")
	require.Equal(t, int64(2), rows[0].TotalCount)
	require.Equal(t, int64(2), rows[0].UnmatchedCount)
	require.Equal(t, "unmatched", rows[0].MostRecentTier)
}

func TestQueries_DedupRows_default_limit_is_500(t *testing.T) {
	// Only check that opts.Limit==0 is normalized to 500. With seedDedupCorpus
	// we have 3 buckets which is well below the 500 default, so the assertion
	// is that no error fires and len(rows) <= 500.
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)
	rows, err := q.DedupRows(context.Background(), store.DedupOpts{}) // Limit=0
	require.NoError(t, err)
	require.LessOrEqual(t, len(rows), 500)
	require.Len(t, rows, 3, "seedDedupCorpus has 3 distinct (ip, user) buckets")
}

// TestQueries_DedupRows_uses_covering_index pins D-18: the dedup query's
// EQP plan contains "USING COVERING INDEX idx_observations_dedup". This
// is a first-occurrence test idiom in the repo (ADR-3).
//
// Substring match (NOT full-line equality) per sqlite.org/eqp.html: the
// EQP format is documented as "subject to change between releases".
func TestQueries_DedupRows_uses_covering_index(t *testing.T) {
	s, _ := newSeededDB(t)
	seedDedupCorpus(t, s.W)
	_, _ = s.W.Exec(`ANALYZE observations`)

	// Use a non-zero SinceNs so the WHERE clause exercises the index.
	plan := getQueryPlan(t, s.R, store.DedupRowsSQL,
		int64(1), int64(1), // subquery SinceNs pair
		int64(1), int64(1), // outer SinceNs pair
		500, 0, // limit, offset
	)
	require.Contains(t, plan, "USING COVERING INDEX idx_observations_dedup",
		"dedup query must use the new covering index per D-18; got plan:\n%s", plan)
}

// ------ EventsForPair (LOG-08 drill-down) ------

func TestQueries_EventsForPair_returns_only_matching_pair(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	rows, err := q.EventsForPair(context.Background(), store.EventsForPairOpts{
		SourceIP: "203.0.113.7",
		User:     "alice",
		SinceNs:  0,
	})
	require.NoError(t, err)
	require.Len(t, rows, 3, "alice@203.0.113.7 has 3 events in seedDedupCorpus")
	for _, r := range rows {
		require.Equal(t, "alice", r.User)
		require.Equal(t, "203.0.113.7", r.SourceIP)
		require.Equal(t, "noise", r.Tier)
	}
	// Sort: ts_unix_ns DESC.
	require.Greater(t, rows[0].TsUnixNs, rows[1].TsUnixNs)
	require.Greater(t, rows[1].TsUnixNs, rows[2].TsUnixNs)
}

func TestQueries_EventsForPair_empty_pair_returns_empty(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	rows, err := q.EventsForPair(context.Background(), store.EventsForPairOpts{
		SourceIP: "10.0.0.99",
		User:     "ghost",
	})
	require.NoError(t, err)
	require.Empty(t, rows)
}

// TestQueries_EventsForPair_swapped_args_returns_empty pins that the WHERE
// clause is column-correct: a user value passed as SourceIP (and vice versa)
// must NOT match any rows. Cheap regression guard for accidental column
// swaps in eventsForPairSQL.
func TestQueries_EventsForPair_swapped_args_returns_empty(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	rows, err := q.EventsForPair(context.Background(), store.EventsForPairOpts{
		SourceIP: "alice",       // intentional swap
		User:     "203.0.113.7", // intentional swap
	})
	require.NoError(t, err)
	require.Empty(t, rows, "swapped args must not match anything")
}

// TestQueries_EventsForPair_since_ns_excludes_old_rows pins the SinceNs
// window filter: rows older than the bound are excluded.
func TestQueries_EventsForPair_since_ns_excludes_old_rows(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	rows, err := q.EventsForPair(context.Background(), store.EventsForPairOpts{
		SourceIP: "203.0.113.7",
		User:     "alice",
		SinceNs:  int64(1_700_000_000_000_000_000) + 2, // excludes base+1
	})
	require.NoError(t, err)
	require.Len(t, rows, 2, "should exclude the oldest of the 3 alice@203.0.113.7 events")
}

// TestQueries_EventsForPair_uses_index pins ADR-4: drill-down query uses
// idx_observations_dedup but COVERING is NOT achievable due to raw_message
// + raw_json projections.
func TestQueries_EventsForPair_uses_index(t *testing.T) {
	s, _ := newSeededDB(t)
	seedDedupCorpus(t, s.W)
	_, _ = s.W.Exec(`ANALYZE observations`)

	plan := getQueryPlan(t, s.R, store.EventsForPairSQL,
		"203.0.113.7", "alice",
		int64(1), int64(1),
		500, 0,
	)
	require.Contains(t, plan, "USING INDEX idx_observations_dedup",
		"drill-down query must use idx_observations_dedup (covering NOT expected per ADR-4); got plan:\n%s", plan)
}

// TestQueries_DedupRows_parameterized_no_injection mirrors the existing
// FilterEvents injection regression (T-OBS-01 threat model). DedupOpts has
// no string fields so injection isn't possible by shape; the test
// documents the discipline AND confirms the observations row count is
// unchanged after a query against a numeric-only payload.
func TestQueries_DedupRows_parameterized_no_injection(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	// SinceNs has no string injection vector; numeric-only opts. The
	// regression's job is to confirm the observations table is
	// untouched after the query runs.
	rows, err := q.DedupRows(context.Background(), store.DedupOpts{SinceNs: 0})
	require.NoError(t, err)
	require.NotEmpty(t, rows)

	var n int
	require.NoError(t, s.R.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&n))
	require.Equal(t, 6, n, "observations table must NOT have been dropped")
}

// TestQueries_EventsForPair_parameterized_no_injection pins T-OBS-01 for
// EventsForPair: a malicious User string MUST be parameterized, NOT
// formatted into the SQL.
func TestQueries_EventsForPair_parameterized_no_injection(t *testing.T) {
	s, q := newSeededDB(t)
	seedDedupCorpus(t, s.W)

	payload := `'; DROP TABLE observations; --`
	rows, err := q.EventsForPair(context.Background(), store.EventsForPairOpts{
		SourceIP: payload,
		User:     payload,
	})
	require.NoError(t, err)
	require.Empty(t, rows)

	var n int
	require.NoError(t, s.R.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&n))
	require.Equal(t, 6, n, "observations table must NOT have been dropped")
}
