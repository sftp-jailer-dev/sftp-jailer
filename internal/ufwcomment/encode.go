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
// byte-for-byte on Ubuntu 24.04's ufw 0.36.2 — that preservation is
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
// exceeds MaxComment bytes (defensive — with a 32-byte username the
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
