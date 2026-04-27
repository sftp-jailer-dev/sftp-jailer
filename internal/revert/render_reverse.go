package revert

import (
	"fmt"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
)

// MutationOp is the kind of pending firewall mutation. RenderReverseCommands
// produces the inverse `ufw` command for each.
type MutationOp int

const (
	// OpAdd forward = `ufw insert 1 allow …`; reverse = `ufw --force delete <AssignedID>`.
	OpAdd MutationOp = iota
	// OpDelete forward = `ufw delete <id>`; reverse = `ufw insert <originalID> allow …`.
	OpDelete
)

// PendingMutation describes one mutation in the batch about to be
// applied. The reverse command depends on the Op + the surrounding
// Rule fields:
//
//	OpAdd:    Rule.User + Rule.Source + Rule.Port are the values for the
//	          forward `ufw insert`. AssignedID is populated POST-APPLY by
//	          AddRule's re-Enumerate-and-diff (Plan 04-03). Reverse =
//	          `ufw --force delete <AssignedID>`.
//	OpDelete: Rule must be the FULL pre-delete rule (ID, source, port,
//	          raw comment) so the reverse `ufw insert` reconstructs it
//	          byte-for-byte.
//
// Per D-S04-08 the inline /bin/sh -c shell-quoting safety relies on
// (a) ufwcomment.Encode rejecting all shell metacharacters via its regex
// AND (b) net.ParseCIDR pre-validation of every Source value. NEVER pass
// unsanitized strings here. T-04-04-04 mitigation lives in the doc-comment
// caller-contract; tests pin the exact rendered output.
type PendingMutation struct {
	Op         MutationOp
	Rule       firewall.Rule
	AssignedID int // OpAdd: populated post-Apply; OpDelete: ignored.
}

// RenderReverseCommands produces the per-mutation reverse-`ufw` script
// lines (D-S04-09 step 2). The output is suitable for
// strings.Join(out, "; ") into the systemd-run ExecStart shell body
// (D-S04-08 inline /bin/sh -c shape).
//
// The trailing `ufw reload` is appended automatically — it ensures the
// kernel picks up the rolled-back ruleset cleanly. (Per smoke-ufw.sh
// in Phase 1, comments survive across reload.)
//
// Returns nil for an empty input or one consisting entirely of
// defensive-skipped Adds (AssignedID == 0). Callers should treat nil
// as "no reverse needed" rather than as an error.
//
// Preconditions:
//   - Every Source value in mutations[i].Rule.Source has been validated
//     via net.ParseCIDR (caller's responsibility — D-FW-CIDR).
//   - Every RawComment value is the output of ufwcomment.Encode (or a
//     literal "" for the catch-all path).
func RenderReverseCommands(mutations []PendingMutation) []string {
	out := make([]string, 0, len(mutations)+1)
	for _, m := range mutations {
		switch m.Op {
		case OpAdd:
			if m.AssignedID <= 0 {
				// Defensive: caller must populate AssignedID post-AddRule.
				// Skip rather than emit a malformed reverse.
				continue
			}
			out = append(out, fmt.Sprintf("ufw --force delete %d", m.AssignedID))
		case OpDelete:
			out = append(out, renderInsert(m.Rule))
		}
	}
	if len(out) == 0 {
		return nil
	}
	out = append(out, "ufw reload")
	return out
}

// renderInsert reconstructs `ufw insert <id> allow proto <p> from <src>
// to any port <port> [comment '<c>']`.
//
// Note (I2): Phase 4 SFTP rules are always tcp (D-FW-05 — SFTP port
// source is parsed from sshd_config Port directives, which are TCP-only
// by protocol). The Rule struct's Proto field carries the address-family
// ("v4"/"v6"), not the L4 protocol; the L4 protocol is implicit "tcp".
// Future protocols (e.g. UDP-based file transfer) would need a
// Rule.L4Proto field.
//
// Empty RawComment → omit the `comment` clause entirely. ufw rejects
// `comment ''` (empty string), so this is required for catch-all
// rollback (LOCK-08). RawComment for sftpj rules is always non-empty
// (ufwcomment.Encode never returns an empty string for a valid user).
func renderInsert(r firewall.Rule) string {
	var b strings.Builder
	// Literal "ufw insert %d allow proto tcp" pinned by acceptance grep —
	// keep contiguous so future refactors don't accidentally split the
	// canonical argv shape across two Fprintf calls.
	fmt.Fprintf(&b, "ufw insert %d allow proto tcp", r.ID)
	fmt.Fprintf(&b, " from %s to any port %s", r.Source, r.Port)
	if r.RawComment != "" {
		// Wrap in single-quotes; ufwcomment.Encode never emits a
		// single-quote (the regex rejects it) — load-bearing per
		// D-S04-08 / T-04-04-04.
		fmt.Fprintf(&b, " comment '%s'", r.RawComment)
	}
	return b.String()
}
