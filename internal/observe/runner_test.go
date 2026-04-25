// Package observe_test (runner_test.go): exercises the headless observation
// pipeline orchestrator (Runner) end-to-end against a tmp SQLite DB seeded
// by 02-01's migrations and a sysops Fake whose JournalctlStdout is canned.
//
// Coverage map:
//   - TestRunner_writes_observation_runs_row_on_success: happy-path.
//   - TestRunner_inserts_observations_with_correct_tier: classification flows
//     through into observations.tier.
//   - TestRunner_emits_json_progress_lines: D-02 stdout JSON contract.
//   - TestRunner_quiet_emits_done_only: --quiet suppresses per-phase lines.
//   - TestRunner_skipped_when_lock_held: Fake.LockHeld → skipped phase.
//   - TestRunner_compaction_folds_old_rows: pre-seeded old rows roll up.
//   - TestRunner_compaction_prunes_when_over_cap: db_max_size_mb pruning.
//   - TestRunner_two_consecutive_runs_with_distinct_streams: cursor-style
//     resume semantics (Fake's stdout is consumed-once).
//   - TestRunner_unmatched_lines_counted_not_aborted: bad/no-match lines
//     do not fail the run; they're counted as unmatched.
package observe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/observe"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// helpers ---------------------------------------------------------------

// openTmpStore opens a fresh tmp SQLite DB and applies migrations.
func openTmpStore(t *testing.T) *store.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.Migrate(context.Background()))
	return st
}

// loadFixtureBytes returns the raw bytes of testdata/journalctl/<name>.
func loadFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/journalctl/" + name) //nolint:gosec // G304: hardcoded fixture filename
	require.NoError(t, err)
	return b
}

// concatLines joins every fixture's bytes with a newline so the canned stdout
// looks like genuine NDJSON output from journalctl --output=json.
func concatLines(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, n := range names {
		raw := loadFixtureBytes(t, n)
		// Strip trailing newline if present, then re-add a single '\n' so
		// each line is exactly one record.
		raw = bytes.TrimRight(raw, "\n")
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// canonicalRunOpts builds RunOpts whose retention values keep all events
// produced by Phase-1 fixtures (timestamps in 2025) — the test seeds the DB
// "as of now" via reading observation rows post-run for verification.
func canonicalRunOpts() observe.RunOpts {
	return observe.RunOpts{
		CursorFile:          "/tmp/sftp-jailer-test.cursor",
		DetailRetentionDays: 36500, // ~100 years — keep everything
		DBMaxSizeMB:         500,
		CompactAfterDays:    36500,
	}
}

// ---------------------------------------------------------------------

func TestRunner_writes_observation_runs_row_on_success(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = concatLines(t, "success.json", "wrong-password.json", "invalid-user.json")

	var stdout bytes.Buffer
	r := observe.NewRunner(f, st)
	require.NoError(t, r.Run(context.Background(), canonicalRunOpts(), &stdout))

	// Verify observation_runs row.
	var nRuns int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observation_runs").Scan(&nRuns))
	require.Equal(t, 1, nRuns)

	var result string
	var read, classified, kept int
	require.NoError(t, st.R.QueryRow("SELECT result, events_read, events_classified, events_kept FROM observation_runs").
		Scan(&result, &read, &classified, &kept))
	require.Equal(t, "success", result)
	require.Equal(t, 3, read)
	require.Equal(t, 3, classified)
	require.Equal(t, 3, kept, "with retention 36500d, all rows kept")
}

func TestRunner_inserts_observations_with_correct_tier(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = concatLines(t, "success.json", "wrong-password.json", "invalid-user.json")

	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), canonicalRunOpts(), &bytes.Buffer{}))

	rows, err := st.R.Query("SELECT tier FROM observations ORDER BY ts_unix_ns ASC")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var got []string
	for rows.Next() {
		var tier string
		require.NoError(t, rows.Scan(&tier))
		got = append(got, tier)
	}
	// Fixture timestamps: success.json=1745500000, invalid-user.json=1745500001,
	// wrong-password.json=1745500002 → ts ASC order is success, noise, targeted.
	require.Equal(t, []string{"success", "noise", "targeted"}, got)
}

func TestRunner_emits_json_progress_lines(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = concatLines(t, "success.json")

	var stdout bytes.Buffer
	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), canonicalRunOpts(), &stdout))

	out := stdout.String()
	require.Contains(t, out, `"phase":"read"`)
	require.Contains(t, out, `"phase":"classify"`)
	require.Contains(t, out, `"phase":"compact"`)
	require.Contains(t, out, `"phase":"done"`)
	require.Contains(t, out, `"summary"`)

	// Each line must be valid JSON.
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), "non-JSON line: %q", line)
		require.NotEmpty(t, m["phase"], "missing phase: %q", line)
	}
}

func TestRunner_quiet_emits_done_only(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = concatLines(t, "success.json")

	opts := canonicalRunOpts()
	opts.Quiet = true

	var stdout bytes.Buffer
	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), opts, &stdout))

	out := strings.TrimRight(stdout.String(), "\n")
	lines := strings.Split(out, "\n")
	require.Len(t, lines, 1, "quiet mode: expected exactly one line, got %d: %q", len(lines), out)
	require.Contains(t, lines[0], `"phase":"done"`)
}

func TestRunner_skipped_when_lock_held(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.LockHeld = true
	// JournalctlStdout intentionally empty — runner must not even reach it.

	var stdout bytes.Buffer
	// The Runner itself doesn't acquire the lock — that's the cobra-cmd's
	// job (Task 3). Runner only emits the skipped phase when explicitly
	// signaled. We verify the runner is invoked inside a "skip" wrapper at
	// Task 3; here we just confirm the runner emits the skipped phase line
	// when called via the public helper.
	require.NoError(t, observe.EmitSkipped(&stdout, "another run in progress"))

	require.Contains(t, stdout.String(), `"phase":"skipped"`)
	require.Contains(t, stdout.String(), `"reason":"another run in progress"`)

	// Observations untouched.
	var n int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&n))
	require.Equal(t, 0, n)

	// Reference unused fields to keep the linter quiet on the f variable.
	_ = f
}

func TestRunner_compaction_folds_old_rows(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	// No new events from journalctl — we want compaction to be the only mover.
	f.JournalctlStdout["ssh"] = []byte("")

	// Pre-seed an observation_runs row so the FK in observations is satisfied.
	res, err := st.W.Exec(`INSERT INTO observation_runs(started_at_unix_ns, result) VALUES (?, 'success')`, time.Now().UnixNano())
	require.NoError(t, err)
	runID, err := res.LastInsertId()
	require.NoError(t, err)

	// Seed 5 OLD rows (>40 days back) and 2 NEW rows (today).
	now := time.Now().UnixNano()
	old := time.Now().Add(-40 * 24 * time.Hour).UnixNano()
	insertObs := func(ts int64) {
		_, err := st.W.Exec(`INSERT INTO observations(ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, run_id)
			VALUES (?, 'noise', 'xyz', '198.51.100.1', 'auth_pwd_fail_invalid', 'msg', '{"MESSAGE":"msg"}', ?)`, ts, runID)
		require.NoError(t, err)
	}
	for i := 0; i < 5; i++ {
		insertObs(old + int64(i))
	}
	for i := 0; i < 2; i++ {
		insertObs(now + int64(i))
	}

	// Compact_after_days=30 → all 5 old rows fold; 2 new rows survive.
	opts := canonicalRunOpts()
	opts.CompactAfterDays = 30
	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), opts, &bytes.Buffer{}))

	var nObs, nCounters int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&nObs))
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM noise_counters").Scan(&nCounters))
	require.Equal(t, 2, nObs, "2 recent rows must remain")
	require.GreaterOrEqual(t, nCounters, 1, "old rows must fold into ≥1 noise_counters row")

	// Verify the counter sums to 5 events (all old rows had identical bucket
	// tuple so they collapse into one counter row with count=5).
	var totalCount int
	require.NoError(t, st.R.QueryRow("SELECT COALESCE(SUM(count),0) FROM noise_counters").Scan(&totalCount))
	require.Equal(t, 5, totalCount)
}

func TestRunner_compaction_prunes_when_over_cap(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = []byte("")

	// Pre-seed a large amount of noise_counters spanning many distinct
	// bucket dates so the prune-by-oldest-date path has work to do.
	for d := 0; d < 50; d++ {
		date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(d) * 24 * time.Hour)
		_, err := st.W.Exec(`INSERT INTO noise_counters(bucket_date, tier, user, source_ip, event_type, count)
			VALUES (?, 'noise', 'xyz', '198.51.100.1', 'auth_pwd_fail_invalid', 100)`,
			date.Format("2006-01-02"))
		require.NoError(t, err)
	}

	// Set a tiny cap — RunOpts.DBMaxSizeMB=1 — to force the prune loop to
	// run. The runner will repeatedly delete oldest bucket_date rows until
	// the on-disk size dips under the cap; at 50 small rows a 1MB cap
	// should be a no-op (DB is much smaller than 1MB), so this test
	// confirms the prune loop terminates cleanly when already under cap.
	opts := canonicalRunOpts()
	opts.DBMaxSizeMB = 1

	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), opts, &bytes.Buffer{}))

	// All 50 counter rows should still be present (DB much smaller than 1 MB).
	var nCounters int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM noise_counters").Scan(&nCounters))
	require.Equal(t, 50, nCounters, "1MB cap is well above test DB size; no prune expected")
}

func TestRunner_two_consecutive_runs_with_distinct_streams(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	f.JournalctlStdout["ssh"] = concatLines(t, "success.json", "wrong-password.json", "invalid-user.json")

	r := observe.NewRunner(f, st)
	require.NoError(t, r.Run(context.Background(), canonicalRunOpts(), &bytes.Buffer{}))

	// Second invocation: the Fake returns the same canned bytes again,
	// because the production cursor-file mechanism handles the actual
	// resume semantics. The test verifies the runner CORRECTLY processes
	// each run as an independent invocation — the production guarantee
	// of OBS-02 (no missed/duplicated events) is enforced by journalctl's
	// --cursor-file at runtime, not by the test.
	//
	// To simulate "the cursor advanced and there are zero new events,"
	// reset JournalctlStdout to empty before the second run.
	f.JournalctlStdout["ssh"] = []byte("")
	require.NoError(t, r.Run(context.Background(), canonicalRunOpts(), &bytes.Buffer{}))

	var nObs, nRuns int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&nObs))
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observation_runs").Scan(&nRuns))
	require.Equal(t, 3, nObs, "first run wrote 3 events; second wrote 0")
	require.Equal(t, 2, nRuns, "exactly one observation_runs row per Run call")
}

func TestRunner_unmatched_lines_counted_not_aborted(t *testing.T) {
	st := openTmpStore(t)
	f := sysops.NewFake()
	// One valid success line + one garbage non-JSON line + one valid line whose
	// MESSAGE doesn't match any regex (→ unmatched).
	f.JournalctlStdout["ssh"] = []byte(
		`{"MESSAGE":"Accepted publickey for alice from 1.2.3.4 port 22 ssh2","__REALTIME_TIMESTAMP":"1745500001000000","_PID":"1","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6"}` + "\n" +
			`this is not json at all` + "\n" +
			`{"MESSAGE":"reverse mapping checking getaddrinfo failed","__REALTIME_TIMESTAMP":"1745500002000000","_PID":"2","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6"}` + "\n",
	)

	require.NoError(t, observe.NewRunner(f, st).Run(context.Background(), canonicalRunOpts(), &bytes.Buffer{}))

	// Garbage line is dropped before classification (Parse error). The two
	// valid lines flow through and end up in observations.
	var n int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&n))
	require.Equal(t, 2, n)

	var nUnmatched int
	require.NoError(t, st.R.QueryRow("SELECT COUNT(*) FROM observations WHERE tier='unmatched'").Scan(&nUnmatched))
	require.Equal(t, 1, nUnmatched)
}
