// Package ufwcomment encodes and decodes the structured sftp-jailer ufw
// rule comment used as the single source of truth for the user↔IP mapping.
//
// Grammar (versioned from day one per REQUIREMENTS.md line 10):
//
//	comment  := prefix version ":user=" username
//	prefix   := "sftpj"
//	version  := ":v=1"                       // current; v=0 legacy accepted on decode
//	username := [a-z_][a-z0-9_-]{0,31}       // Debian adduser policy; 32 bytes max
//	MaxComment = 64 bytes                    // well under iptables/nft 256-char cap
//
// The regex rejects every shell metacharacter, space, quote, and backslash
// by construction, so the comment can be passed unquoted to `ufw ...
// comment "<c>"` without injection risk (T-05-01). The smoke test
// scripts/smoke-ufw.sh verifies `ufw reload` preserves the comment
// byte-for-byte on Ubuntu 24.04's ufw 0.36.2 - that preservation is
// architecturally load-bearing for Phase 4's FW-08.
package ufwcomment

import (
	"errors"
	"fmt"
	"regexp"
)

// Grammar constants. Exported so callers (and CI grep guards in later phases)
// can reference a single source of truth.
const (
	Prefix     = "sftpj"
	Version    = 1
	MaxUser    = 32
	MaxComment = 64
)

// userRE enforces the Debian adduser username policy. The {0,31} quantifier
// bounds the total length at 32 bytes (1-char lead + 31 body chars).
// Shared with decode.go for symmetric validation on both paths.
var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Error sentinels. Use errors.Is() to test.
var (
	ErrInvalidUser = errors.New("ufwcomment: invalid username")
	ErrTooLong     = errors.New("ufwcomment: comment exceeds 64 bytes")
	ErrNotOurs     = errors.New("ufwcomment: not an sftp-jailer comment")
	ErrBadVersion  = errors.New("ufwcomment: unknown schema version")
)

// Encode formats a user into a versioned sftp-jailer ufw comment.
// Returns ErrInvalidUser for any username that doesn't match
// ^[a-z_][a-z0-9_-]{0,31}$; returns ErrTooLong if the rendered comment
// exceeds MaxComment bytes (defensive - with a 32-byte username the
// rendered comment is 20 bytes, so this is unreachable in practice and
// only fires if grammar constants are changed).
func Encode(user string) (string, error) {
	if !userRE.MatchString(user) {
		return "", ErrInvalidUser
	}
	c := fmt.Sprintf("%s:v=%d:user=%s", Prefix, Version, user)
	if len(c) > MaxComment {
		return "", ErrTooLong
	}
	return c, nil
}

// Kind discriminates which payload shape Decode classified for a v=1
// comment. Defaults to KindUnknown (zero value) so a Parsed returned
// alongside an error reads as "unclassified". Legacy v=0 sets Kind=KindUser
// explicitly (NOT KindUnknown) so downstream switches on Kind work for
// legacy rules. See 09-CONTEXT.md D-02.
type Kind int

// Kind enumeration values. KindUnknown is the zero value and is what
// callers will see in any Parsed returned alongside a non-nil error.
const (
	KindUnknown Kind = iota // zero value: no successful classification (error path)
	KindUser                // user-rule: sftpj:v=1:user=<name> (or legacy sftpj:user=<name>)
	KindSubnet              // subnet-rule: sftpj:v=1:scope=subnet:reason=<r>
)

// Subnet-rule reason constants. Closed enum per D-03; unknown reason
// strings on Decode return ErrBadVersion (single forward-compat sentinel),
// on Encode return ErrInvalidReason (precise caller surface for Phase 11
// M-DRY-RUN preview per D-04).
const (
	ReasonRFC1918   = "rfc1918"
	ReasonRFC4193   = "rfc4193"
	ReasonLinkLocal = "link-local"
	ReasonOperator  = "operator"
)

// ErrInvalidReason is returned by EncodeSubnet for any reason string not
// in the closed enum. Decode-side rejects unknown reasons with the broader
// ErrBadVersion (forward-compat: future v1.4 may add a fifth reason; older
// binaries should treat it as opaque, not "invalid").
var ErrInvalidReason = errors.New("ufwcomment: invalid subnet reason")

// EncodeSubnet renders a subnet-rule comment in the form
//
//	sftpj:v=1:scope=subnet:reason=<r>
//
// where <r> is one of ReasonRFC1918, ReasonRFC4193, ReasonLinkLocal,
// ReasonOperator. Returns ErrInvalidReason for any other input.
//
// Longest output is `sftpj:v=1:scope=subnet:reason=link-local` at 40 bytes
// (well under MaxComment=64). The defensive cap check is preserved for
// the same reason Encode keeps it: future grammar changes that push past
// the cap surface here, not silently in the firewall.
func EncodeSubnet(reason string) (string, error) {
	switch reason {
	case ReasonRFC1918, ReasonRFC4193, ReasonLinkLocal, ReasonOperator:
		// valid; fall through
	default:
		return "", ErrInvalidReason
	}
	c := fmt.Sprintf("%s:v=%d:scope=subnet:reason=%s", Prefix, Version, reason)
	if len(c) > MaxComment {
		return "", ErrTooLong
	}
	return c, nil
}
