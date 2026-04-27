// Package lockdown contains the progressive-lockdown flow's data layer:
// the LOCK-02 proposal generator (this file), the LOCK-03 admin-IP
// detector (admin_ip.go), and the SAFE-04 reverse-command renderer
// re-export (render_reverse.go, Plan 04-04).
//
// The proposal generator reads the observation DB and produces a
// per-user IP allowlist proposal (LOCK-02). Per D-L0204-02, the
// default inclusion criterion is `tier=success` only; the
// includeTargeted flag broadens to `tier=targeted` per-user (rare;
// admin opt-in via the editor).
//
// Architectural invariants:
//   - All SQL goes through internal/store.Queries.LockdownObservations,
//     which uses `?`-bound placeholders only (T-04-07-01 / T-OBS-01
//     SQL-injection mitigation preserved).
//   - This package never imports os or os/exec.
//   - The Generator is treated as long-lived: S-LOCKDOWN constructs one
//     and re-uses it across "regenerate" key presses.
package lockdown

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

// Proposal is the per-user lockdown proposal — the IPs the editor seeds
// the right pane with (D-L0204-04). ZeroConn is true when IPs is empty
// after Generate; the S-LOCKDOWN screen surfaces this with the
// "no observations in the last N days" warning row (D-L0204-03).
//
// Note that Generate itself does NOT emit ZeroConn proposals — it only
// returns users with ≥1 observation in the window. The S-LOCKDOWN
// caller (Plan 04-08) augments by enumerating sftp-jailer-managed users
// via internal/users.Enumerate and synthesising empty-IPs Proposal
// entries for users absent from the Generator output. The ZeroConn
// flag exists on the struct so both paths produce a uniform shape.
type Proposal struct {
	User     string
	IPs      []ProposedIP
	ZeroConn bool
}

// ProposedIP is one row in the right pane of S-LOCKDOWN: a source IP
// that observed at least one connection of the right tier within the
// proposal window.
//
// Tier values:
//   - "success" — observation tier=success (always included by default)
//   - "targeted" — observation tier=targeted (only when includeTargeted=true)
//   - "manual" — never produced by Generate; reserved for the editor's
//     "I added this IP by hand" flow (Plan 04-08).
type ProposedIP struct {
	Source     string // CIDR or single IP from observations.source_ip
	ConnCount  int    // number of observations within window
	LastSeenNs int64  // most recent ts_unix_ns
	Tier       string
}

// Generator owns the reader pool reference (via *store.Queries) and the
// time-source seam. Construct via NewGenerator; treat as long-lived
// (the S-LOCKDOWN screen builds one at construction and re-uses it for
// every "regenerate" key).
type Generator struct {
	q     *store.Queries
	nowFn func() time.Time
}

// NewGenerator constructs a Generator using the given Queries handle.
// The default nowFn is time.Now; override via SetNowFnForTest in tests.
func NewGenerator(q *store.Queries) *Generator {
	return &Generator{q: q, nowFn: time.Now}
}

// SetNowFnForTest overrides the time source for deterministic
// window-cutoff arithmetic in tests. Production callers must NEVER use
// this — the production seam is `time.Now`.
func (g *Generator) SetNowFnForTest(fn func() time.Time) {
	if fn == nil {
		g.nowFn = time.Now
		return
	}
	g.nowFn = fn
}

// Generate produces the per-user Proposal slice. windowDays is the
// observation lookback (D-L0204-01); includeTargeted broadens to
// tier='targeted' (D-L0204-02).
//
// Returns []Proposal sorted by user ascending (deterministic UI
// rendering). Per-user IPs are ordered by ConnCount DESC (most-active
// first), inherited from the underlying SQL ORDER BY.
//
// Validation: windowDays MUST be > 0. The S-SETTINGS screen clamps the
// koanf knob to [1, 3650] (Validate in internal/config); this method's
// guard is a defensive backstop for direct callers.
func (g *Generator) Generate(ctx context.Context, windowDays int, includeTargeted bool) ([]Proposal, error) {
	if windowDays <= 0 {
		return nil, fmt.Errorf("lockdown.Generate: windowDays must be > 0, got %d", windowDays)
	}
	cutoffNs := g.nowFn().Add(-time.Duration(windowDays) * 24 * time.Hour).UnixNano()

	rows, err := g.q.LockdownObservations(ctx, cutoffNs, includeTargeted)
	if err != nil {
		return nil, fmt.Errorf("lockdown.Generate: %w", err)
	}

	// Pivot rows into a per-user IP slice. The SQL emits rows ordered by
	// (user ASC, conn_count DESC), so as we iterate, IPs append in the
	// correct per-user order automatically.
	byUser := map[string][]ProposedIP{}
	order := []string{} // first-seen order (matches user ASC from SQL)
	for _, r := range rows {
		if _, ok := byUser[r.User]; !ok {
			order = append(order, r.User)
		}
		byUser[r.User] = append(byUser[r.User], ProposedIP{
			Source:     r.SourceIP,
			ConnCount:  r.ConnCount,
			LastSeenNs: r.LastSeenNs,
			Tier:       r.Tier,
		})
	}

	// Materialise the proposal slice. The map iteration above is
	// non-deterministic, but we use the `order` slice (built from the
	// SQL's user-ASC stream) to preserve a stable order. We then re-sort
	// with sort.Slice for belt-and-suspenders (cheap; ≤100 users).
	proposals := make([]Proposal, 0, len(order))
	for _, u := range order {
		ips := byUser[u]
		proposals = append(proposals, Proposal{
			User:     u,
			IPs:      ips,
			ZeroConn: len(ips) == 0,
		})
	}
	sort.Slice(proposals, func(i, j int) bool {
		return proposals[i].User < proposals[j].User
	})

	return proposals, nil
}
