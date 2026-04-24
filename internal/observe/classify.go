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
type Classification struct {
	Tier     Tier
	User     string
	SourceIP string
}

// Regex ordering is load-bearing. The "Failed password for invalid user xyz
// from ..." line matches BOTH the invalid-user shape and the generic-failed
// shape; the invalid-user match must win (pitfall D2). Accepted-* and
// Invalid-user-alt-shape come next, and the generic reFailedValid is the
// fall-through for valid-user auth failures.
var (
	reAcceptedPubkey   = regexp.MustCompile(`Accepted publickey for (\S+) from (\S+) port \d+ ssh2`)
	reAcceptedPassword = regexp.MustCompile(`Accepted password for (\S+) from (\S+) port \d+ ssh2`)
	reFailedInvalid    = regexp.MustCompile(`Failed (?:password|publickey) for invalid user (\S+) from (\S+) port \d+`)
	reInvalidUser      = regexp.MustCompile(`Invalid user (\S+) from (\S+) port \d+`)
	reFailedValid      = regexp.MustCompile(`Failed (?:password|publickey) for (\S+) from (\S+) port \d+`)
)

// Classify applies the four-tier ruleset to an SshdEvent's raw message.
//
// Phase 1 scope: classification is purely structural (based on the log line
// shape). Phase 2 will extend this with external lookups — is the user in
// /etc/passwd? is the source IP in the firewall allowlist? — to refine the
// "targeted" vs "noise" split beyond the single-word sshd distinction.
//
// Regex match order is critical: reFailedInvalid must precede reFailedValid
// because an "invalid user" line also matches the generic failed shape.
// Likewise reInvalidUser precedes reFailedValid for the alt-shape log line.
func Classify(e SshdEvent) Classification {
	msg := e.Raw

	if m := reFailedInvalid.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierNoise, User: m[1], SourceIP: m[2]}
	}
	if m := reInvalidUser.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierNoise, User: m[1], SourceIP: m[2]}
	}
	if m := reAcceptedPubkey.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierSuccess, User: m[1], SourceIP: m[2]}
	}
	if m := reAcceptedPassword.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierSuccess, User: m[1], SourceIP: m[2]}
	}
	if m := reFailedValid.FindStringSubmatch(msg); m != nil {
		return Classification{Tier: TierTargeted, User: m[1], SourceIP: m[2]}
	}
	return Classification{Tier: TierUnmatched}
}
