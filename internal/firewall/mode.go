package firewall

import "strings"

// Mode is the OPEN / STAGING / LOCKED / UNKNOWN classification of the
// firewall's posture toward the SFTP port (D-L0809-02). It's a derived
// value — recomputed from `ufw status numbered` output. There is NO
// persistent flag; admin tampering between sessions never causes drift
// (pitfall C3 retired by avoiding dual sources of truth).
type Mode int

const (
	// ModeOpen = catch-all `allow port <p> from any` AND no sftpj rules.
	// SFTP port accepts all IPv4+IPv6.
	ModeOpen Mode = iota

	// ModeStaging = catch-all coexists with ≥1 sftpj rule. The sftpj
	// rules are present but enforcement is the catch-all's. This is
	// the "staged promotion" state per D-L0809-01.
	ModeStaging

	// ModeLocked = no catch-all, ≥1 sftpj rule. Per-user IP allowlist
	// is enforced; non-listed IPs are rejected at the firewall layer.
	ModeLocked

	// ModeUnknown = no rules on the SFTP port at all. The doctor
	// screen surfaces this with [WARN].
	ModeUnknown
)

// String returns the lowercase name for logs/UI; the TUI banner styles
// come from theme.Critical/Warn/Info/Success at the call site.
func (m Mode) String() string {
	switch m {
	case ModeOpen:
		return "open"
	case ModeStaging:
		return "staging"
	case ModeLocked:
		return "locked"
	default:
		return "unknown"
	}
}

// DetectMode classifies the firewall posture from the Enumerate output.
// sftpPort is the canonical SFTP port string from the parsed
// sshd_config (Plan 04-07 supplies this; Plan 04-03 pure-function tests
// pass "22" by default).
//
// Detection rules (D-L0809-02):
//   - "catch-all" = Action contains "ALLOW" AND Source matches
//     "Anywhere" (case-insensitive — ufw emits "Anywhere" for both
//     v4 and v6) AND Port matches sftpPort (literal or "<p>/tcp" /
//     "<p>/udp" variant) AND RawComment == "" (catch-all rules carry
//     no sftpj comment).
//   - "sftpj rule" = ParseErr == nil AND User != "" AND Port matches
//     sftpPort. ParseErr != nil rules (forward-compat ErrBadVersion
//     from a v=2-writing newer binary, or ErrNotOurs from foreign
//     comments) are treated as opaque — they do NOT count toward the
//     sftpj predicate per the v>=2 forward-compat contract from
//     internal/ufwcomment.
//   - The two predicates are evaluated independently; both can be
//     true simultaneously (ModeStaging).
//
// Pure: zero side effects; safe to call from any package.
func DetectMode(rules []Rule, sftpPort string) Mode {
	var hasCatchAll, hasSftpjRule bool
	for _, r := range rules {
		if !portMatches(r.Port, sftpPort) {
			continue
		}
		if !strings.Contains(strings.ToUpper(r.Action), "ALLOW") {
			continue
		}
		// sftpj-rule predicate: a v=1-decoded comment with a non-empty
		// User field. ParseErr != nil rules drop through to the catch-all
		// predicate, which then rejects them via the RawComment != ""
		// guard (a foreign / v=2 rule still has a non-empty RawComment).
		if r.User != "" && r.ParseErr == nil {
			hasSftpjRule = true
			continue
		}
		// Catch-all predicate: empty comment AND Anywhere source.
		if r.RawComment == "" && strings.EqualFold(r.Source, "Anywhere") {
			hasCatchAll = true
		}
	}
	switch {
	case hasCatchAll && !hasSftpjRule:
		return ModeOpen
	case hasCatchAll && hasSftpjRule:
		return ModeStaging
	case !hasCatchAll && hasSftpjRule:
		return ModeLocked
	default:
		return ModeUnknown
	}
}

// portMatches reports whether the ufw-parsed Port string matches sftpPort.
// Accepts: "22", "22/tcp", "22/udp" against sftpPort="22"; rejects all
// other ports. The /tcp and /udp suffixes are how ufw renders rules
// scoped by `proto tcp` / `proto udp`.
func portMatches(rulePort, sftpPort string) bool {
	if rulePort == sftpPort {
		return true
	}
	for _, suffix := range []string{"/tcp", "/udp"} {
		if rulePort == sftpPort+suffix {
			return true
		}
	}
	return false
}
