package observe

import "regexp"

// Tier is the classification assigned to a single sshd event. The four
// tiers are specified in REQUIREMENTS.md LOG-05.
type Tier string

// Tier values per REQUIREMENTS.md LOG-05.
const (
	TierSuccess   Tier = "success"
	TierTargeted  Tier = "targeted"
	TierNoise     Tier = "noise"
	TierUnmatched Tier = "unmatched"
)

// Classification is the output of Classify. User and SourceIP are empty for
// TierUnmatched and may be empty for other tiers if the regex couldn't
// recover them.
//
// EventType is a short tag (snake_case) identifying the regex that matched —
// used by the runner to populate observations.event_type for LOG-01 filters.
// The string set is deliberately small and stable; new event types must
// land alongside their fixture and a TestClassify_… case.
type Classification struct {
	Tier      Tier
	User      string
	SourceIP  string
	EventType string
}

// Event-type tags. Keep these stable — they're stored in the observations
// table and consumed by LOG-01 filters in S-LOGS.
//
// gosec G101 false positives: a few of these contain the substring "pwd"
// or "fail" which trip the hardcoded-credentials heuristic. The values are
// non-secret event-type tags, not credentials.
//
//nolint:gosec // G101: event-type identifiers, not secrets
const (
	EventAuthPubkeyOK        = "auth_pubkey_ok"
	EventAuthPasswordOK      = "auth_pwd_ok"
	EventAuthPubkeyFail      = "auth_pubkey_fail"
	EventAuthPasswordFail    = "auth_pwd_fail"
	EventAuthPubkeyFailInv   = "auth_pubkey_fail_invalid"
	EventAuthPasswordFailInv = "auth_pwd_fail_invalid"
	EventInvalidUser         = "invalid_user"
	EventSftpSubsystem       = "sftp_subsystem"
	EventUnmatched           = "unmatched"
)

// Regex ordering is load-bearing. The "Failed password for invalid user xyz
// from ..." line matches BOTH the invalid-user shape and the generic-failed
// shape; the invalid-user match must win (pitfall D2). Accepted-* and
// Invalid-user-alt-shape come next, and the generic reFailedValid is the
// fall-through for valid-user auth failures.
//
// Phase 2 additions (PUBLIC_KEY_AUTH_FAIL, SFTP_TRANSFER) preserve the same
// invalid-before-generic priority. The split-by-method (publickey vs
// password) lets us record a richer event_type on each row without changing
// the four-tier mapping.
var (
	reAcceptedPubkey   = regexp.MustCompile(`Accepted publickey for (\S+) from (\S+) port \d+ ssh2`)
	reAcceptedPassword = regexp.MustCompile(`Accepted password for (\S+) from (\S+) port \d+ ssh2`)

	// Invalid-user variants per auth method MUST precede the generic
	// "Failed (password|publickey) for valid user" patterns (D2).
	reFailedPubkeyInvalid   = regexp.MustCompile(`Failed publickey for invalid user (\S+) from (\S+) port \d+`)
	reFailedPasswordInvalid = regexp.MustCompile(`Failed password for invalid user (\S+) from (\S+) port \d+`)
	reInvalidUser           = regexp.MustCompile(`Invalid user (\S+) from (\S+) port \d+`)

	// Generic "Failed (password|publickey) for <user>" — reached only when
	// the invalid-user variants above did not match, so <user> here is a
	// (structurally) valid system user.
	reFailedPubkey   = regexp.MustCompile(`Failed publickey for (\S+) from (\S+) port \d+`)
	reFailedPassword = regexp.MustCompile(`Failed password for (\S+) from (\S+) port \d+`)

	// SFTP subsystem negotiation: "subsystem request for sftp by user
	// <name>". Recorded as a success tier event because (a) the user
	// authenticated and (b) requested sftp specifically — useful signal
	// for LOG-01's "SFTP-only logins" filter.
	reSftpSubsystem = regexp.MustCompile(`subsystem request for sftp by user (\S+)`)
)

// Classify applies the four-tier ruleset to an SshdEvent's raw message.
//
// Phase 1 scope: classification is purely structural (based on the log line
// shape). Phase 2 will extend this with external lookups — is the user in
// /etc/passwd? is the source IP in the firewall allowlist? — to refine the
// "targeted" vs "noise" split beyond the single-word sshd distinction.
//
// Regex match order is critical: the *invalid* variants of failed auth
// MUST precede the generic-failed patterns because an "invalid user" line
// also matches the generic shape. Likewise reInvalidUser precedes the
// generic-failed patterns for the alt-shape log line.
func Classify(e SshdEvent) Classification {
	msg := e.Raw

	// Invalid-user fail variants (per method) — D2 priority.
	if m := reFailedPubkeyInvalid.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierNoise, User: m[1], SourceIP: m[2], EventType: EventAuthPubkeyFailInv}
	}
	if m := reFailedPasswordInvalid.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierNoise, User: m[1], SourceIP: m[2], EventType: EventAuthPasswordFailInv}
	}
	if m := reInvalidUser.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierNoise, User: m[1], SourceIP: m[2], EventType: EventInvalidUser}
	}

	// Successful auth.
	if m := reAcceptedPubkey.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierSuccess, User: m[1], SourceIP: m[2], EventType: EventAuthPubkeyOK}
	}
	if m := reAcceptedPassword.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierSuccess, User: m[1], SourceIP: m[2], EventType: EventAuthPasswordOK}
	}

	// Generic-failed (valid user) — must come AFTER invalid-user variants.
	if m := reFailedPubkey.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierTargeted, User: m[1], SourceIP: m[2], EventType: EventAuthPubkeyFail}
	}
	if m := reFailedPassword.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierTargeted, User: m[1], SourceIP: m[2], EventType: EventAuthPasswordFail}
	}

	// SFTP subsystem negotiation (success-tier; no source IP in this line).
	if m := reSftpSubsystem.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierSuccess, User: m[1], EventType: EventSftpSubsystem}
	}

	return Classification{Tier: TierUnmatched, EventType: EventUnmatched}
}
