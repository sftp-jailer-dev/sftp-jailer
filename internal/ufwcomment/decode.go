package ufwcomment

import (
	"fmt"
	"strings"
)

// Parsed is the structured form of a decoded sftp-jailer ufw comment.
// Version is 0 for the legacy v=0-implicit format, 1 for the current
// format, and the raw integer for any v>=2 input (paired with ErrBadVersion).
type Parsed struct {
	Version int
	User    string
}

// Decode accepts both the current format (sftpj:v=1:user=<name>) and the
// legacy v=0-implicit format (sftpj:user=<name>) for forward compatibility.
//
// Return-value contract:
//   - Empty string or no "sftpj:" prefix → ErrNotOurs.
//   - v>=2 → Parsed{Version: v, User: ""} + ErrBadVersion. Caller knows the
//     comment IS ours but a newer binary wrote it; safest response is to
//     leave the rule alone and surface a warning in the TUI.
//   - Malformed v= field (non-numeric, missing trailing :user=) → ErrBadVersion.
//   - Username that fails the Encode regex → ErrInvalidUser.
//
// Decode is fuzz-tested to never panic on arbitrary input (FuzzDecodeNeverPanics).
func Decode(c string) (Parsed, error) {
	if !strings.HasPrefix(c, Prefix+":") {
		return Parsed{}, ErrNotOurs
	}
	rest := strings.TrimPrefix(c, Prefix+":")

	// Legacy shape: sftpj:user=<name> (implicit v=0). Must be checked BEFORE
	// the v=N shape because "user=" starting immediately after "sftpj:" is
	// unambiguous — the current grammar requires "v=" next.
	if strings.HasPrefix(rest, "user=") {
		u := strings.TrimPrefix(rest, "user=")
		if !userRE.MatchString(u) {
			return Parsed{}, ErrInvalidUser
		}
		return Parsed{Version: 0, User: u}, nil
	}

	// Current shape: sftpj:v=N:user=<name>.
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
		return Parsed{Version: v, User: ""}, ErrBadVersion
	}
	if !strings.HasPrefix(parts[1], "user=") {
		return Parsed{}, ErrBadVersion
	}
	u := strings.TrimPrefix(parts[1], "user=")
	if !userRE.MatchString(u) {
		return Parsed{}, ErrInvalidUser
	}
	return Parsed{Version: v, User: u}, nil
}
