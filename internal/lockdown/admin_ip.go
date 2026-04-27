package lockdown

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// whoAmIParenRE captures the trailing "(source)" suffix from `who am i`
// output. Format: `alice  pts/0  2026-04-27 10:23 (203.0.113.7)` —
// the IP (or hostname; rejected post-capture) is in the parens at end
// of line. Single capture group; the regex anchors with $ so output
// containing parens earlier in the line (e.g. timestamps with TZ) does
// not false-match.
var whoAmIParenRE = regexp.MustCompile(`\(([^)]+)\)\s*$`)

// whoAmITimeout bounds the `who am i` subprocess. Bubble Tea's input
// loop must not stall on a hung utmp parse — 2s is generous (typical
// `who` runtime is sub-millisecond).
const whoAmITimeout = 2 * time.Second

// DetectAdminIP returns the admin's SSH source IP, using SSH_CONNECTION
// first and falling back to `who am i` parsing per D-L0204-05.
//
// Returns "" in these cases (treat as console session — LOCK-03 guard
// is skipped, banner reads "Console session detected"):
//
//   - SSH_CONNECTION unset/empty AND `who am i` fails or has no
//     parenthesised source
//   - SSH_CONNECTION's first token is not a parseable IP AND `who am i`
//     yields no usable source (defensive against forged env)
//   - `who am i` output contains a hostname instead of an IP — LOCK-03
//     compares against allowlist IPs, so a hostname is unusable
//
// Precedence rationale:
//
//   - SSH_CONNECTION first because it's set verbatim by sshd and survives
//     `sudo -E` (env preservation).
//   - `who am i` fallback handles `sudo -i` (env wiped) by reading the
//     utmp source field.
//
// Threat model:
//
//   - T-04-07-02 (forged SSH_CONNECTION): if the env is tampered with,
//     the worst case is a wrong IP in the LOCK-03 banner. The fail-closed
//     default in S-LOCKDOWN (commit blocked when admin IP not in
//     proposal) protects against this — admin must manually verify and
//     add their actual IP via the editor.
//   - T-04-07-03 (hostname injection via `who am i`): post-capture
//     net.ParseIP rejects hostnames; we return "" rather than smuggling
//     a hostname through.
//   - T-04-07-04 (`who am i` hangs): wrapped in a 2s context.WithTimeout.
func DetectAdminIP(ctx context.Context, ops sysops.SystemOps) string {
	// Strategy 1: SSH_CONNECTION env. Format:
	//   "<client-ip> <client-port> <server-ip> <server-port>"
	// First whitespace-separated token is the client IP. Validate via
	// net.ParseIP and fall through to strategy 2 on failure.
	if conn := os.Getenv("SSH_CONNECTION"); conn != "" {
		fields := strings.Fields(conn)
		if len(fields) > 0 {
			if ip := net.ParseIP(fields[0]); ip != nil {
				return ip.String()
			}
			// Fall through — invalid IP in env is treated as "no env",
			// not as "forge the IP we got". T-04-07-02 mitigation.
		}
	}

	// Strategy 2: `who am i` parser. Bound the subprocess time tightly
	// (T-04-07-04). The "who" binary is allowlisted in sysops.Real.Exec
	// (Phase 4 plan 04-07).
	cctx, cancel := context.WithTimeout(ctx, whoAmITimeout)
	defer cancel()
	res, err := ops.Exec(cctx, "who", "am", "i")
	if err != nil || res.ExitCode != 0 {
		return ""
	}

	// Take the first non-empty output line. Multi-line output is rare;
	// `who am i` should emit a single line for the invoking session.
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := whoAmIParenRE.FindStringSubmatch(line)
		if len(match) < 2 {
			// No parens → console session (`tty1`) or X11-session-style
			// `:0`. Return "" — caller skips guard.
			return ""
		}
		candidate := strings.TrimSpace(match[1])
		// Defensive: `who` may emit a hostname (`(myhost.example.com)`)
		// when reverse-DNS is configured. LOCK-03 needs an IP to compare
		// against allowlist entries — return "" if the candidate isn't
		// a valid IP. T-04-07-03 mitigation.
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
		return ""
	}
	return ""
}
