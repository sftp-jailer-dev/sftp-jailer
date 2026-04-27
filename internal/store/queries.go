// Package store — queries.go is the typed read layer over the reader pool
// (Store.R). Every method takes a context and returns typed structs (no
// *sql.Rows leakage). All SQL uses parameterized placeholders — never
// string-formatting of user input.
//
// Phase 2 read shape:
//   - StatusRow            — D-08 status row (S-LOGS header).
//   - FilterEvents         — LOG-01 filtered + paginated event list.
//   - PerUserBreakdown     — LOG-06 per-user tier counts + last login.
//   - LastLoginPerUser     — USER-01 last-login column for the user list.
//
// Phase 4 plan 04-03 adds the FW-08 derived-cache writer surface:
//   - RebuildUserIPs       — TRUNCATE + bulk INSERT per Enumerate output.
//   - UserIPs              — read-back per username for S-USERS allowlist.
//
// Threat model (PLAN.md §threat_model T-OBS-01 + T-04-03-04):
//
//	All filter-string fields flow through `?` placeholders. The
//	queries_test.go injection test asserts that a payload of
//	"'; DROP TABLE observations; --" matches zero rows and leaves the
//	table intact. New query methods MUST follow the same discipline —
//	any `fmt.Sprintf` of user input into a SQL string is a security bug.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
)

// Queries holds the reader pool + single-conn writer references.
// Construct via NewQueries(*Store). Treat Queries as long-lived: the TUI
// should share a single instance across screens so the connection pool
// is reused.
//
// The writer field (w) is unexported and only used by RebuildUserIPs
// (the FW-08 derived-cache writer) — every other method routes
// reads through r per the reader-pool/single-writer split documented
// in store.go.
type Queries struct {
	r *sql.DB
	w *sql.DB
}

// NewQueries wraps the Store's reader + writer halves. The writer is
// only consumed by RebuildUserIPs (D-FW-04 derived-cache rebuild);
// every read path goes through r as before.
func NewQueries(s *Store) *Queries { return &Queries{r: s.R, w: s.W} }

// StatusRow drives the D-08 status display in S-LOGS:
//
//	Schema: vN  ·  Detail rows: D  ·  Counters: C  ·  Last run: <ts>
//
// LastSuccessNs is 0 when no successful observation_runs row exists yet.
type StatusRow struct {
	SchemaVersion int
	DetailCount   int64
	CounterCount  int64
	LastSuccessNs int64
}

// statusRowSQL is one round-trip per call. The four scalar subqueries
// each touch a small index (PRAGMA + COUNT(*)+ a single MAX over the
// idx_observation_runs_finished index), so total cost is O(few ms) even
// at the 100k-row Phase 2 cap.
const statusRowSQL = `
SELECT
  (SELECT user_version FROM pragma_user_version) AS schema_version,
  (SELECT COUNT(*) FROM observations) AS detail_count,
  (SELECT COUNT(*) FROM noise_counters) AS counter_count,
  COALESCE(
    (SELECT MAX(finished_at_unix_ns) FROM observation_runs WHERE result='success'),
    0
  ) AS last_success_ns;
`

// StatusRow returns the D-08 status row in a single round-trip.
func (q *Queries) StatusRow(ctx context.Context) (StatusRow, error) {
	var s StatusRow
	err := q.r.QueryRowContext(ctx, statusRowSQL).Scan(
		&s.SchemaVersion, &s.DetailCount, &s.CounterCount, &s.LastSuccessNs)
	if err != nil {
		return StatusRow{}, fmt.Errorf("queries.StatusRow: %w", err)
	}
	return s, nil
}

// Event is one row from the observations table — the typed shape that
// LOG-01 (filtered list) renders into the S-LOGS table viewport.
type Event struct {
	ID         int64
	TsUnixNs   int64
	Tier       string
	User       string
	SourceIP   string
	EventType  string
	RawMessage string
	RawJSON    string
}

// FilterOpts is the LOG-01 filter set. Empty-string fields disable that
// filter (interpreted as "match all"); zero ts disables that bound.
//
// Discipline: every field maps to a `?` placeholder in filterEventsSQL.
// New filters MUST follow the same shape — never format directly into
// the SQL string.
type FilterOpts struct {
	User      string
	Tier      string
	SourceIP  string
	EventType string
	SinceNs   int64
	UntilNs   int64
	Limit     int // default 500 if zero
	Offset    int
}

// filterEventsSQL uses the "placeholder-equals-empty OR col-equals-placeholder"
// idiom so the same prepared statement covers every combination of filters
// (an empty-string filter disables itself). Each placeholder appears
// twice — once for the empty-string check (disables the filter) and once
// for the equality check. SQLite's query planner handles this idiomatic
// shape efficiently when the matching index exists (002_add_indexes.sql).
const filterEventsSQL = `
SELECT id, ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json
FROM observations
WHERE
  (? = '' OR user       = ?)
  AND (? = '' OR tier       = ?)
  AND (? = '' OR source_ip  = ?)
  AND (? = '' OR event_type = ?)
  AND (? = 0  OR ts_unix_ns >= ?)
  AND (? = 0  OR ts_unix_ns <  ?)
ORDER BY ts_unix_ns DESC
LIMIT ? OFFSET ?;
`

// FilterEvents returns observations matching opts, ordered by ts DESC.
//
// Default Limit is 500 (matches RESEARCH.md §Open-Questions #3 v1 cap).
// V1.1 will switch to cursor-based paging; the current Offset-based shape
// is fine up to ~10k rows then degrades — documented as T-OBS-03 (accept).
func (q *Queries) FilterEvents(ctx context.Context, opts FilterOpts) ([]Event, error) {
	if opts.Limit == 0 {
		opts.Limit = 500
	}
	rows, err := q.r.QueryContext(ctx, filterEventsSQL,
		opts.User, opts.User,
		opts.Tier, opts.Tier,
		opts.SourceIP, opts.SourceIP,
		opts.EventType, opts.EventType,
		opts.SinceNs, opts.SinceNs,
		opts.UntilNs, opts.UntilNs,
		opts.Limit, opts.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("queries.FilterEvents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.TsUnixNs, &e.Tier, &e.User,
			&e.SourceIP, &e.EventType, &e.RawMessage, &e.RawJSON,
		); err != nil {
			return nil, fmt.Errorf("queries.FilterEvents scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queries.FilterEvents rows.Err: %w", err)
	}
	return out, nil
}

// TierBreakdown is one tier-bucket row of the LOG-06 per-user breakdown.
type TierBreakdown struct {
	Tier  string
	Count int64
}

// UserBreakdown aggregates a single user's activity for LOG-06:
//   - Tiers: success/targeted/noise/unmatched counts.
//   - FirstSeenIP: source_ip of the user's earliest observation (any tier).
//   - LastSuccessNs: ns timestamp of the user's most recent successful
//     login (0 if none).
//
// Three round-trips by design (counts vs first-seen vs last-success use
// different index shapes). Cheap enough at Phase 2 row counts that we
// prefer the readability over a single grand UNION.
type UserBreakdown struct {
	Tiers         []TierBreakdown
	FirstSeenIP   string
	LastSuccessNs int64
}

const (
	perUserTiersSQL       = `SELECT tier, COUNT(*) FROM observations WHERE user = ? GROUP BY tier`
	perUserFirstSeenIPSQL = `SELECT source_ip FROM observations WHERE user = ? ORDER BY ts_unix_ns ASC LIMIT 1`
	perUserLastSuccessSQL = `SELECT MAX(ts_unix_ns) FROM observations WHERE user = ? AND tier = 'success'`
)

// PerUserBreakdown returns the LOG-06 aggregation for a single user.
//
// FirstSeenIP and LastSuccessNs scans tolerate sql.ErrNoRows (the user
// may have zero rows, or zero successful logins) — they leave the field
// at its zero value and return no error. Only the tier-count query
// surfaces errors, since an empty result there is a valid outcome.
func (q *Queries) PerUserBreakdown(ctx context.Context, user string) (UserBreakdown, error) {
	var ub UserBreakdown

	rows, err := q.r.QueryContext(ctx, perUserTiersSQL, user)
	if err != nil {
		return ub, fmt.Errorf("queries.PerUserBreakdown tiers: %w", err)
	}
	for rows.Next() {
		var tb TierBreakdown
		if err := rows.Scan(&tb.Tier, &tb.Count); err != nil {
			_ = rows.Close()
			return ub, fmt.Errorf("queries.PerUserBreakdown tiers scan: %w", err)
		}
		ub.Tiers = append(ub.Tiers, tb)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return ub, fmt.Errorf("queries.PerUserBreakdown tiers rows.Err: %w", err)
	}

	// First-seen IP: NULL/no-row tolerated.
	if err := q.r.QueryRowContext(ctx, perUserFirstSeenIPSQL, user).Scan(&ub.FirstSeenIP); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ub, fmt.Errorf("queries.PerUserBreakdown first-seen-ip: %w", err)
	}

	// Last successful login: NULL/no-row tolerated. MAX() over zero rows
	// returns NULL → use a nullable scan target so we don't error on a
	// user with no successful logins.
	var lastSuccess sql.NullInt64
	if err := q.r.QueryRowContext(ctx, perUserLastSuccessSQL, user).Scan(&lastSuccess); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ub, fmt.Errorf("queries.PerUserBreakdown last-success: %w", err)
	}
	if lastSuccess.Valid {
		ub.LastSuccessNs = lastSuccess.Int64
	}

	return ub, nil
}

// UserLastLogin pairs a username with the ns timestamp of their most
// recent successful login. Used by USER-01 to populate the "last login"
// column in S-USERS.
type UserLastLogin struct {
	User        string
	LastLoginNs int64
}

const lastLoginPerUserSQL = `
SELECT user, MAX(ts_unix_ns)
FROM observations
WHERE tier = 'success' AND user != ''
GROUP BY user
`

// LastLoginPerUser returns one row per username that has at least one
// successful login. Empty-username success rows (which can occur for
// pre-auth events) are excluded by the SQL filter.
func (q *Queries) LastLoginPerUser(ctx context.Context) ([]UserLastLogin, error) {
	rows, err := q.r.QueryContext(ctx, lastLoginPerUserSQL)
	if err != nil {
		return nil, fmt.Errorf("queries.LastLoginPerUser: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []UserLastLogin
	for rows.Next() {
		var u UserLastLogin
		if err := rows.Scan(&u.User, &u.LastLoginNs); err != nil {
			return nil, fmt.Errorf("queries.LastLoginPerUser scan: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queries.LastLoginPerUser rows.Err: %w", err)
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// Phase 4 plan 04-03 — FW-08 derived-cache mirror (D-FW-04).
//
// The user_ips table is a DERIVED CACHE rebuilt from `ufw status numbered`
// Enumerate output. The firewall comments (sftpj:v=1:user=<name>) are the
// AUTHORITATIVE store; this mirror is a belt-and-suspenders recovery path
// only. Pitfall C3 (dual-source-of-truth) is retired by treating the
// firewall as the source-of-truth and rebuilding this table from it on
// every relevant event (see 04-CONTEXT.md D-FW-04 for the rebuild surfaces).
// ----------------------------------------------------------------------------

// UserIP is the typed shape of one row in the user_ips mirror table.
type UserIP struct {
	User           string
	Source         string
	Proto          string // "v4" | "v6"
	Port           string
	LastSeenUnixNs int64
}

// rebuildUserIPsInsertSQL is the insert statement template for RebuildUserIPs.
// The ON CONFLICT clause covers the case where the caller's input contains
// duplicate (user, source, proto, port) tuples in a single rebuild — later
// rows update the timestamp rather than crashing the transaction. This
// preserves the "single rebuild = idempotent" contract.
const rebuildUserIPsInsertSQL = `
INSERT INTO user_ips (user, source, proto, port, last_seen_unix_ns)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(user, source, proto, port)
DO UPDATE SET last_seen_unix_ns = excluded.last_seen_unix_ns
`

// RebuildUserIPs replaces the user_ips table with one row per
// sftpj-decoded rule. Per D-FW-04 the table is a derived cache —
// never authority. Single transaction (DELETE + bulk INSERT) so a
// mid-rebuild crash leaves the prior contents intact; SQLite's
// implicit rollback on tx.Rollback() handles partial failures.
//
// Inputs:
//   - rules: from firewall.Enumerate. We filter to those with
//     User != "" AND ParseErr == nil (sftpj v=1 rules). Foreign rules
//     (ErrNotOurs), forward-compat (ErrBadVersion), and any rule with
//     an empty User are skipped per the forward-compat invariant
//     documented in internal/ufwcomment.
//   - nowFn: supplies the timestamp for last_seen_unix_ns. Pass nil
//     to use time.Now() (production callers don't have to thread a
//     clock through; tests inject a frozen clock for determinism).
//
// Performance: BeginTx pre-paid pragmas (WAL/synchronous=NORMAL).
// PROJECT.md targets 20-100 users — even 1000 rows fits in a single
// tx in <100ms on dev hardware. T-04-03-03 (DoS at 10k rows) accepted.
//
// Threat model (T-04-03-04): every value is parameterized via `?`
// placeholders. No fmt.Sprintf into SQL.
func (q *Queries) RebuildUserIPs(ctx context.Context, rules []firewall.Rule, nowFn func() time.Time) error {
	if nowFn == nil {
		nowFn = time.Now
	}
	nowNs := nowFn().UnixNano()

	tx, err := q.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("queries.RebuildUserIPs BeginTx: %w", err)
	}
	defer func() {
		// If Commit succeeded, Rollback returns sql.ErrTxDone — ignored.
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, "DELETE FROM user_ips"); err != nil {
		return fmt.Errorf("queries.RebuildUserIPs DELETE: %w", err)
	}

	for _, r := range rules {
		if r.User == "" || r.ParseErr != nil {
			continue // skip foreign rules + ErrBadVersion forward-compat
		}
		if _, err := tx.ExecContext(ctx, rebuildUserIPsInsertSQL,
			r.User, r.Source, r.Proto, r.Port, nowNs); err != nil {
			return fmt.Errorf("queries.RebuildUserIPs INSERT user=%s source=%s: %w", r.User, r.Source, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("queries.RebuildUserIPs Commit: %w", err)
	}
	return nil
}

const userIPsSelectSQL = `
SELECT user, source, proto, port, last_seen_unix_ns
FROM user_ips
WHERE user = ?
ORDER BY source ASC
`

// UserIPs returns all rows in the user_ips mirror for a given username.
// Returns an empty slice (NOT nil) on no match — callers can range
// over the result without nil-checking. Read-only — uses the pooled
// reader.
//
// Threat model (T-04-03-04): username flows through a `?` placeholder.
// No fmt.Sprintf into SQL.
func (q *Queries) UserIPs(ctx context.Context, username string) ([]UserIP, error) {
	rows, err := q.r.QueryContext(ctx, userIPsSelectSQL, username)
	if err != nil {
		return nil, fmt.Errorf("queries.UserIPs query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []UserIP{}
	for rows.Next() {
		var u UserIP
		if err := rows.Scan(&u.User, &u.Source, &u.Proto, &u.Port, &u.LastSeenUnixNs); err != nil {
			return nil, fmt.Errorf("queries.UserIPs scan: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queries.UserIPs rows.Err: %w", err)
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// Phase 4 plan 04-07 — LOCK-02 proposal generator read surface.
//
// LockdownObservation is one (user, source_ip, tier) bucket within the
// proposal-window cutoff, with the per-bucket observation count and
// most-recent timestamp. The internal/lockdown.Generator pivots these
// rows into per-user Proposal structs.
//
// Threat model (T-04-07-01 / T-OBS-01): all values flow through `?`
// placeholders. No fmt.Sprintf into SQL.
// ----------------------------------------------------------------------------

// LockdownObservation is the typed result of one row from the
// LockdownObservations query — a (user, source_ip, tier) aggregate within
// the proposal window.
type LockdownObservation struct {
	User       string
	SourceIP   string
	ConnCount  int
	LastSeenNs int64
	Tier       string
}

// lockdownObservationsSQL groups observations by (user, source_ip, tier)
// within the cutoff window. Per D-L0204-02 the default inclusion is
// tier='success' only; the includeTargeted flag broadens to
// tier='targeted' (1) or excludes it (0).
//
// NULL-vs-empty: the Phase 2 schema declares `user TEXT NOT NULL DEFAULT ''`
// so user is never NULL in production. We still guard against IS NOT NULL
// defensively in case a future migration relaxes the constraint — costs
// nothing on a NOT NULL column. The user != '' filter is the load-bearing
// guard; LOCK-02 doesn't propose IPs for "the empty user" (unmatched events).
//
// ORDER BY user ASC, conn_count DESC: stable ordering for deterministic
// pivot output downstream (Generator does an in-memory sort by user ASC
// after the pivot, so this ORDER BY is mainly for the per-user IP
// ordering — most-active IP first).
const lockdownObservationsSQL = `
SELECT user, source_ip, COUNT(*) AS conn_count, MAX(ts_unix_ns) AS last_seen, tier
FROM observations
WHERE user IS NOT NULL AND user != ''
  AND ts_unix_ns > ?
  AND (tier = 'success' OR (? = 1 AND tier = 'targeted'))
GROUP BY user, source_ip, tier
ORDER BY user ASC, conn_count DESC
`

// LockdownObservations returns one row per (user, source_ip, tier) bucket
// for observations newer than cutoffUnixNs. When includeTargeted is true,
// tier='targeted' rows are included alongside tier='success'; otherwise
// only tier='success' rows are returned (D-L0204-02).
//
// Used by internal/lockdown.Generator to build per-user IP-allowlist
// proposals (LOCK-02). Read-only — uses the pooled reader.
func (q *Queries) LockdownObservations(ctx context.Context, cutoffUnixNs int64, includeTargeted bool) ([]LockdownObservation, error) {
	includeFlag := 0
	if includeTargeted {
		includeFlag = 1
	}
	rows, err := q.r.QueryContext(ctx, lockdownObservationsSQL, cutoffUnixNs, includeFlag)
	if err != nil {
		return nil, fmt.Errorf("queries.LockdownObservations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []LockdownObservation{}
	for rows.Next() {
		var o LockdownObservation
		if err := rows.Scan(&o.User, &o.SourceIP, &o.ConnCount, &o.LastSeenNs, &o.Tier); err != nil {
			return nil, fmt.Errorf("queries.LockdownObservations scan: %w", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queries.LockdownObservations rows.Err: %w", err)
	}
	return out, nil
}
