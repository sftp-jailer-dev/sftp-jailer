// mutate.go is the single firewall WRITER per D-FW-01. AddRule and
// DeleteRule are the only two entry points; ResolveRuleIDByCommentSource
// is the helper used both by NewUfwInsertStep's compensator-ID lookup
// (Plan 04-02 + 04-05) and by Plan 04-06's M-DELETE-RULE by-source mode.
//
// Architectural invariants (mirror enumerate.go's preamble):
//   - All ufw subprocess execution goes through sysops; this file
//     never imports os/exec.
//   - The sftp-jailer comment grammar literal must NOT appear in this
//     file — only internal/ufwcomment owns the grammar string
//     constants. We CALL ufwcomment.Encode for the comment value but
//     NEVER hand-construct the grammar string. CI grep gate enforces.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// ErrRuleNotFound is returned by DeleteRule when ufw reports the rule
// ID does not exist. Callers treat this as success at the application
// layer (idempotent delete) — but it's surfaced here for tests + the
// SAFE-04 Compensate paths.
var ErrRuleNotFound = errors.New("firewall: rule not found")

// AddRule inserts a per-user allow rule at position 1 (D-FW-02).
// Returns the assigned rule ID by post-insert Enumerate diff.
//
// Validation contract (caller's responsibility — Plan 04-05's M-ADD-RULE):
//   - user MUST match `^[a-z_][a-z0-9_-]{0,31}$` (UI-SPEC §M-ADD-RULE).
//     The ufwcomment.Encode regex re-validates as a defense-in-depth gate
//     (T-04-03-01 mitigation): if the caller forgot, Encode rejects the
//     bad input and we return a wrapped error WITHOUT invoking UfwInsert.
//   - source MUST be a CIDR or single IP that net.ParseCIDR has accepted.
//     Bare IPs are pre-promoted to /32 (v4) or /128 (v6) at the caller.
//   - port MUST be a non-empty string from the parsed sshd_config.
//
// Failures:
//   - Returns wrapped ufwcomment error if Encode rejects the user.
//   - Returns wrapped sysops error if ops.UfwInsert fails.
//   - Returns wrapped sysops error if the post-insert Enumerate fails.
//   - Returns ErrRuleNotFound if the rule was inserted but not found in
//     the post-Enumerate output (this should never happen in production;
//     surface as a wrapped sentinel for the caller to log).
func AddRule(ctx context.Context, ops sysops.SystemOps, user, source, port string) (assignedID int, err error) {
	comment, err := ufwcomment.Encode(user)
	if err != nil {
		return -1, fmt.Errorf("firewall.AddRule encode: %w", err)
	}
	opts := sysops.UfwAllowOpts{
		Proto:   "tcp",
		Source:  source,
		Port:    port,
		Comment: comment,
	}
	if err := ops.UfwInsert(ctx, 1, opts); err != nil {
		return -1, fmt.Errorf("firewall.AddRule: %w", err)
	}
	// Post-insert Enumerate to discover the assigned ID. The new rule
	// is the one matching (User=user, Source=source, Port matches port);
	// D-FW-02 always inserts at position 1, so the freshest match is at
	// the lowest ID — same logic as ResolveRuleIDByCommentSource below.
	rules, err := Enumerate(ctx, ops)
	if err != nil {
		return -1, fmt.Errorf("firewall.AddRule post-insert enumerate: %w", err)
	}
	bestID := -1
	for _, r := range rules {
		if r.User == user && r.Source == source && portMatches(r.Port, port) {
			if bestID == -1 || r.ID < bestID {
				bestID = r.ID
			}
		}
	}
	if bestID == -1 {
		return -1, fmt.Errorf("firewall.AddRule: %w (user=%s source=%s port=%s)",
			ErrRuleNotFound, user, source, port)
	}
	return bestID, nil
}

// DeleteRule wraps ops.UfwDelete. Treats "Could not delete" /
// "rule not found" / "No matching rule" exit-message variants as
// ErrRuleNotFound (idempotent at the call-site level — SAFE-04
// Compensate paths can retry without spurious errors).
//
// T-04-03-02 (accepted): the ufw "rule not found" message is fragile
// across ufw versions. Tests pin the canonical phrases; if a future
// ufw rewords, the worst case is a DeleteRule that returns a wrapped
// error instead of ErrRuleNotFound — caller still treats both as
// success at the application layer.
func DeleteRule(ctx context.Context, ops sysops.SystemOps, ruleID int) error {
	if err := ops.UfwDelete(ctx, ruleID); err != nil {
		es := err.Error()
		if strings.Contains(es, "Could not delete") ||
			strings.Contains(es, "not found") ||
			strings.Contains(es, "No matching") {
			return ErrRuleNotFound
		}
		return fmt.Errorf("firewall.DeleteRule id=%d: %w", ruleID, err)
	}
	return nil
}

// ResolveRuleIDByCommentSource finds the rule whose (User, Source) pair
// matches the given values, returning the ID (or -1, nil if no match).
// Used by:
//   - txn.NewUfwInsertStep's compensator-ID lookup (Plan 04-02 calls
//     SetAssignedID with the result post-Apply via firewall.AddRule).
//   - Plan 04-06's M-DELETE-RULE by-source mode resolver.
//
// If multiple rules match (rare — duplicate rules for the same user +
// source), returns the LOWEST-numbered rule. D-FW-02's always-position-1
// insertion means the most-recently-inserted is at ID 1; older
// duplicates have higher IDs.
//
// Enumerate failure propagates as a wrapped error. A "no match" outcome
// is NOT an error — callers use the -1 sentinel to distinguish.
func ResolveRuleIDByCommentSource(ctx context.Context, ops sysops.SystemOps, user, source string) (int, error) {
	rules, err := Enumerate(ctx, ops)
	if err != nil {
		return -1, fmt.Errorf("firewall.ResolveRuleIDByCommentSource: %w", err)
	}
	bestID := -1
	for _, r := range rules {
		if r.User == user && r.Source == source {
			if bestID == -1 || r.ID < bestID {
				bestID = r.ID
			}
		}
	}
	return bestID, nil
}
