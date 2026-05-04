package ufwcomment

import (
	"fmt"
	"strings"
)

// Parsed is the structured form of a decoded sftp-jailer ufw comment.
//
// Version is 0 for the legacy v=0-implicit format, 1 for the current
// format, and the raw integer for any v>=2 input (paired with ErrBadVersion).
//
// Kind discriminates the payload shape inside v=1: KindUser for user-rules
// (`sftpj:v=1:user=<name>` and legacy `sftpj:user=<name>`), KindSubnet for
// subnet-rules (`sftpj:v=1:scope=subnet:reason=<r>`). Error returns leave
// Kind at its zero value (KindUnknown) - callers should pattern-match on
// Kind only after checking err == nil. Legacy v=0 successful decode sets
// Kind=KindUser explicitly so downstream Kind-based switches work
// uniformly across both grammar versions (per 09-CONTEXT.md D-02).
//
// User is populated when Kind==KindUser; empty otherwise. SubnetReason is
// populated when Kind==KindSubnet (one of ReasonRFC1918, ReasonRFC4193,
// ReasonLinkLocal, ReasonOperator); empty otherwise.
type Parsed struct {
	Version      int
	Kind         Kind
	User         string
	SubnetReason string
}

// Decode accepts both the current format (sftpj:v=1:user=<name>) and the
// legacy v=0-implicit format (sftpj:user=<name>) for forward compatibility.
// As of FW-10 (Phase 9) it also classifies the v=1 subnet-rule shape
// (sftpj:v=1:scope=subnet:reason=<rfc1918|rfc4193|link-local|operator>).
//
// Return-value contract:
//   - Empty string or no "sftpj:" prefix → ErrNotOurs.
//   - v>=2 → Parsed{Version: v} + ErrBadVersion. Caller knows the comment
//     IS ours but a newer binary wrote it; safest response is to leave the
//     rule alone and surface a warning in the TUI.
//   - Malformed v= field (non-numeric) → ErrBadVersion.
//   - v=1 with unknown payload shape → ErrBadVersion (forward-compat sink
//     for future Phase-N payload variants).
//   - v=1 scope=subnet with reason outside the closed enum → ErrBadVersion.
//   - Username that fails the Encode regex → ErrInvalidUser.
//   - Successful classification: Kind populated; User OR SubnetReason
//     populated depending on Kind. Legacy v=0 sets Kind=KindUser per D-02.
//
// Decode is fuzz-tested to never panic on arbitrary input (FuzzDecodeNeverPanics).
func Decode(c string) (Parsed, error) {
	if !strings.HasPrefix(c, Prefix+":") {
		return Parsed{}, ErrNotOurs
	}
	rest := strings.TrimPrefix(c, Prefix+":")

	// Legacy shape: sftpj:user=<name> (implicit v=0). Must be checked BEFORE
	// the v=N shape because "user=" starting immediately after "sftpj:" is
	// unambiguous - the current grammar requires "v=" next. Kind=KindUser
	// is set explicitly per D-02 so downstream Kind-based switches work
	// uniformly across legacy and current grammar versions.
	if strings.HasPrefix(rest, "user=") {
		u := strings.TrimPrefix(rest, "user=")
		if !userRE.MatchString(u) {
			return Parsed{}, ErrInvalidUser
		}
		return Parsed{Version: 0, Kind: KindUser, User: u}, nil
	}

	// Current shape: sftpj:v=N:<payload>.
	if !strings.HasPrefix(rest, "v=") {
		return Parsed{}, ErrBadVersion
	}
	rest = strings.TrimPrefix(rest, "v=")
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return Parsed{}, ErrBadVersion
	}
	var v int
	if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
		return Parsed{}, ErrBadVersion
	}
	// Forward-compat: v>=2 preserves the integer so the caller can report
	// "written by a newer binary" rather than "corrupt".
	if v != Version {
		return Parsed{Version: v}, ErrBadVersion
	}

	// v=1 payload: three-way classifier (D-01..D-03).
	payload := parts[1]
	switch {
	case strings.HasPrefix(payload, "user="):
		u := strings.TrimPrefix(payload, "user=")
		if !userRE.MatchString(u) {
			return Parsed{}, ErrInvalidUser
		}
		return Parsed{Version: v, Kind: KindUser, User: u}, nil

	case strings.HasPrefix(payload, "scope=subnet:reason="):
		r := strings.TrimPrefix(payload, "scope=subnet:reason=")
		switch r {
		case ReasonRFC1918, ReasonRFC4193, ReasonLinkLocal, ReasonOperator:
			return Parsed{Version: v, Kind: KindSubnet, SubnetReason: r}, nil
		default:
			// Unknown reason inside a recognized scope: forward-compat per D-03.
			return Parsed{Version: v}, ErrBadVersion
		}

	default:
		// Unknown payload shape inside v=1: same forward-compat semantics.
		return Parsed{Version: v}, ErrBadVersion
	}
}
