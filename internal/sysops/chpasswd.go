package sysops

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Chpasswd runs `chpasswd` with "<user>:<password>\n" piped to stdin.
//
// Pitfall E3: password NEVER appears on argv (which would leak it via ps,
// /proc/<pid>/cmdline, and audit logs). The stdin pipe is the documented
// chpasswd(8) interface for password updates.
//
// Format per chpasswd(8): each line is "user_name:password" with no
// surrounding whitespace. Trailing newline appended for portability across
// chpasswd builds.
//
// Non-zero exit (typically a pam_pwquality rejection) returns *ChpasswdError
// containing stderr bytes verbatim — surface to admin via theme.Critical
// inline error per D-13 / B5.
//
// Threat model T-03-01-01 / T-03-01-02 / T-03-01-06:
//   - Password is in stdin only, never argv.
//   - ChpasswdError.Stderr is pam_pwquality output only — chpasswd writes
//     nothing else to stderr on a rejection.
//   - Caller MUST apply a context deadline (recommended 30s) — chpasswd
//     can in principle hang on stdin pipe if the child misbehaves.
//
// chpasswd is INTENTIONALLY excluded from real.go's Exec allowlist: this
// is the sole exec callsite for chpasswd in the project (the architectural
// invariant `scripts/check-no-exec-outside-sysops.sh` is satisfied because
// this file lives in internal/sysops).
func (r *Real) Chpasswd(ctx context.Context, username, password string) error {
	if r.binChpasswd == "" {
		return fmt.Errorf("sysops: chpasswd not installed")
	}
	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.binChpasswd) //nolint:gosec // G204: typed wrapper, password via stdin per pitfall E3
	cmd.Stdin = strings.NewReader(username + ":" + password + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil // chpasswd writes nothing to stdout on success
	if err := cmd.Run(); err != nil {
		return &ChpasswdError{
			Username: username,
			Stderr:   stderr.Bytes(),
			ExitErr:  err,
		}
	}
	return nil
}

// ChpasswdError is returned when chpasswd exits non-zero. The Stderr field
// carries pam_pwquality (or other PAM module) rejection text verbatim —
// surface to admin via theme.Critical inline error per D-13 / B5. Callers
// extract the typed error via errors.As(err, &cerr).
type ChpasswdError struct {
	Username string
	Stderr   []byte
	ExitErr  error
}

func (e *ChpasswdError) Error() string {
	return fmt.Sprintf("chpasswd %s: %s (%v)", e.Username,
		strings.TrimSpace(string(e.Stderr)), e.ExitErr)
}

// Unwrap returns the underlying exec error so errors.Is(err, exec.ExitError)
// continues to work for callers that need to dispatch on the wrapped exec
// failure.
func (e *ChpasswdError) Unwrap() error { return e.ExitErr }
