// Package firewall is the read-only typed reader over `ufw status numbered`.
//
// Phase 2 surface: Enumerate parses ufw output into []Rule for the S-FIREWALL
// screen (FW-01/FW-04) and for the per-user IP-allowlist count column on
// S-USERS. The sftp-jailer ufw rule comment grammar is owned end-to-end by
// internal/ufwcomment — this package never re-implements that parser; it
// forwards the raw comment to ufwcomment.Decode and surfaces the returned
// sentinels (ErrNotOurs / ErrBadVersion) so the UI can render `?` for
// forward-compat or foreign rules per UI-SPEC line 419.
//
// Phase 4 will add the writer (FW-02/FW-08) under the same package — the
// reader stays untouched.
//
// Architectural invariants:
//   - All ufw subprocess execution goes through sysops.Exec (the binary is
//     allowlisted in sysops.Real by plan 02-02; this package never imports
//     os/exec).
//   - The sftp-jailer comment grammar literal must NOT appear in this file —
//     only internal/ufwcomment owns the grammar string constants. This
//     package decodes via ufwcomment.Decode and re-exports nothing.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// ErrUFWInactive is returned when `ufw status numbered` reports the firewall
// is disabled. The S-FIREWALL screen translates this into the actionable
// empty state ("ufw is inactive — run `ufw enable` to start filtering").
var ErrUFWInactive = errors.New("firewall: ufw status reports inactive")

// Rule is the typed shape of a single numbered ufw allow/deny rule.
//
// Field semantics:
//   - ID: the numbered rule ID, parsed from the leading "[N]" token.
//   - Proto: "v4" or "v6"; detected by the literal "(v6)" substring in
//     either the To or From field. UFW emits IPv4 and IPv6 as separate
//     numbered rules — we do not coalesce them.
//   - Port: the To column (port spec like "22", "22/tcp", "22 (v6)" with
//     the (v6) suffix stripped).
//   - Source: the From column (IP / CIDR / "Anywhere", with the (v6)
//     suffix stripped — protocol is carried separately in Proto).
//   - Action: the Action column ("ALLOW IN", "DENY IN", "LIMIT IN", etc.).
//   - RawComment: the comment text after `#`, trimmed of surrounding space.
//     Empty if the rule has no comment.
//   - User: the decoded sftp-jailer user from RawComment, or "" if the
//     comment is foreign (ErrNotOurs), forward-compat (ErrBadVersion), or
//     missing.
//   - ParseErr: the error returned by ufwcomment.Decode (or nil for a
//     successful v=1 decode). Consumers test with errors.Is — see
//     UI-SPEC line 419 for the `?` rendering rule on ErrBadVersion.
type Rule struct {
	ID         int
	Proto      string
	Port       string
	Source     string
	Action     string
	RawComment string
	User       string
	ParseErr   error
}

// ruleLineRE matches the "[N]" prefix and captures the rest of the line.
// Lines without this prefix (header rows, blank lines, the "Status:" line)
// are silently skipped.
var ruleLineRE = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*)$`)

// multiSpaceRE splits a rule body into columns by 2-or-more whitespace runs.
// We use this AFTER stripping the trailing "# <comment>" — see the
// commentary in splitComment for why we cannot rely on column widths
// directly (RESEARCH Pitfall 5 — long comments break fixed-width columns).
var multiSpaceRE = regexp.MustCompile(`\s{2,}`)

// Enumerate runs `ufw status numbered` via sysops.Exec, parses the output
// into []Rule, and decodes any sftpj comments. Returns:
//   - ErrUFWInactive if the firewall is disabled.
//   - A wrapped exec error if the subprocess fails (e.g. ufw not installed).
//   - A wrapped ufw-exit error if ufw exits non-zero.
//   - Otherwise the parsed slice (possibly empty if the firewall has no rules)
//     and a nil error.
//
// The function is read-only — it never invokes mutation flags like
// `ufw allow` / `ufw delete`.
func Enumerate(ctx context.Context, ops sysops.SystemOps) ([]Rule, error) {
	res, err := ops.Exec(ctx, "ufw", "status", "numbered")
	if err != nil {
		// Wrap with the binary name so callers can render
		// "ufw not installed or not allowlisted" without sniffing the
		// underlying syscall error string.
		return nil, fmt.Errorf("firewall.Enumerate ufw exec: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("firewall.Enumerate ufw exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	text := string(res.Stdout)
	// Status: inactive is detected before line scan — short-circuit so the
	// caller renders the actionable empty state instead of an empty slice
	// (which would imply "active firewall, no rules").
	if strings.Contains(text, "Status: inactive") {
		return nil, ErrUFWInactive
	}

	var rules []Rule
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t\r")
		m := ruleLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, err := strconv.Atoi(m[1])
		if err != nil {
			// Defensive: regex matched \d+ so this is unreachable in practice,
			// but if Atoi ever fails we drop the line rather than poison the
			// whole result.
			continue
		}

		// RESEARCH Pitfall 5: split on " # " FIRST so a long comment cannot
		// shift the column widths and break the field-split heuristic.
		body, comment := splitComment(m[2])
		fields := multiSpaceRE.Split(strings.TrimSpace(body), -1)

		r := Rule{ID: id, RawComment: comment}

		// IPv4/v6 detection: the literal "(v6)" appears in either the To
		// (port) or From (source) field. UFW emits IPv6 as separate rules.
		r.Proto = "v4"
		for _, f := range fields {
			if strings.Contains(f, "(v6)") {
				r.Proto = "v6"
				break
			}
		}

		// Field positions are loose; defensively handle short slices.
		// Layout: fields[0] = port, fields[1..n-2] = action tokens, fields[n-1] = source.
		if len(fields) >= 1 {
			r.Port = stripV6Suffix(fields[0])
		}
		if len(fields) >= 3 {
			// Action is the middle slot. The action column itself contains
			// a single 2+-space-separated token like "ALLOW IN" — but
			// 2+-space splitting collapses it to one field, so we emit it
			// verbatim.
			r.Action = fields[1]
			r.Source = stripV6Suffix(fields[len(fields)-1])
		} else if len(fields) == 2 {
			// Edge case: only port + source columns, no Action (shouldn't
			// happen in real ufw output but keeps us robust).
			r.Source = stripV6Suffix(fields[1])
		}

		// Decode the comment. ufwcomment.Decode handles all four cases:
		//   - empty       → ErrNotOurs
		//   - non-sftpj   → ErrNotOurs
		//   - v=1         → Parsed{User: …}, nil
		//   - v>=2        → Parsed{User: ""}, ErrBadVersion
		if comment == "" {
			r.ParseErr = ufwcomment.ErrNotOurs
		} else {
			p, derr := ufwcomment.Decode(comment)
			r.ParseErr = derr
			if derr == nil {
				r.User = p.User
			}
		}

		rules = append(rules, r)
	}
	return rules, nil
}

// splitComment isolates the trailing "# <comment>" from the rule body.
// We require " # " (space-hash-space) by default because ufw renders the
// comment with that separator; we fall back to a tab-or-space-then-hash
// scan for resilience against future ufw formatting tweaks. Returns
// (body, comment) with both ends trimmed.
func splitComment(s string) (body, comment string) {
	if idx := strings.Index(s, " # "); idx >= 0 {
		return strings.TrimRight(s[:idx], " \t"), strings.TrimSpace(s[idx+3:])
	}
	// Fallback: a "#" with whitespace immediately before it.
	if i := strings.LastIndex(s, "#"); i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		return strings.TrimRight(s[:i], " \t"), strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// stripV6Suffix removes the literal "(v6)" suffix and surrounding whitespace
// from a port or source column. Protocol is carried separately in Rule.Proto.
func stripV6Suffix(f string) string {
	return strings.TrimSpace(strings.ReplaceAll(f, "(v6)", ""))
}
