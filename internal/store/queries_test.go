// Package store_test exercises the typed read query layer (queries.go)
// against a freshly-migrated tmp DB. Tests insert seed rows directly via
// the writer handle (s.W) — bypassing any future "Inserter" abstraction —
// so this file's failures unambiguously point at the read path.
package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
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
	// Phase 4 plan 04-03 bumps ExpectedSchemaVersion 2 → 3 with 003_user_ips.sql.
	require.Equal(t, 3, got.SchemaVersion)
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

	ub, err := q.PerUserBreakdown(context.Background(), "alice")
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

	// Classic injection payload — should be matched literally as a username
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

// TestExpectedSchemaVersion_is_3 pins the Phase 4 schema bump from 2 → 3.
// Migration 003_user_ips.sql lands the user_ips table; ExpectedSchemaVersion
// must equal the highest migration prefix.
func TestExpectedSchemaVersion_is_3(t *testing.T) {
	t.Parallel()
	require.Equal(t, 3, store.ExpectedSchemaVersion)
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
		// Foreign rule — ParseErr != nil → MUST be skipped.
		{ID: 4, RawComment: "foreign", ParseErr: ufwcomment.ErrNotOurs},
		// v=2 forward-compat rule — ParseErr=ErrBadVersion + User=="" → skipped.
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

	// Carol is the v=2 forward-compat rule's user — it MUST NOT have leaked
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
// to time.Now() — production callers don't have to thread a clock through.
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
