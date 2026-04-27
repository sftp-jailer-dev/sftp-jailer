// Package lockdown_test admin-IP detector tests.
//
// LOCK-03 detection chain (D-L0204-05):
//
//  1. SSH_CONNECTION env (set by sshd; survives sudo -E)
//  2. `who am i` parse (covers sudo -i which wipes env)
//  3. otherwise "" (console session — guard skipped by caller)
//
// Each strategy is exercised independently; the precedence is pinned so
// a regression that swaps the order surfaces in TestDetectAdminIP_*.
package lockdown_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// TestDetectAdminIP_SSH_CONNECTION_first_token — when SSH_CONNECTION is
// set to the canonical sshd format, the first whitespace-separated token
// is the admin's source IP.
func TestDetectAdminIP_SSH_CONNECTION_first_token(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "203.0.113.7 54321 192.168.1.1 22")
	f := sysops.NewFake()
	require.Equal(t, "203.0.113.7", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_falls_back_to_who_when_env_empty — sudo -i wipes
// SSH_CONNECTION; the detector must fall back to `who am i` and parse
// the parenthesised source.
func TestDetectAdminIP_falls_back_to_who_when_env_empty(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	f := sysops.NewFake()
	f.ExecResponses["who am i"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("alice  pts/0  2026-04-27 10:23 (203.0.113.7)\n"),
	}
	require.Equal(t, "203.0.113.7", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_console_session_returns_empty — `who am i` on a
// physical console emits no parenthesised source; detector returns ""
// and the caller skips the LOCK-03 guard ("Console session detected").
func TestDetectAdminIP_console_session_returns_empty(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	f := sysops.NewFake()
	f.ExecResponses["who am i"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("alice  tty1  2026-04-27 10:23\n"),
	}
	require.Equal(t, "", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_who_failure_returns_empty — exec failure on `who am i`
// (binary missing, ENOENT, ctx-cancel) collapses to "" so the caller
// treats the whole detection as inconclusive.
func TestDetectAdminIP_who_failure_returns_empty(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	f := sysops.NewFake()
	f.ExecError = errors.New("who not found")
	require.Equal(t, "", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_invalid_ip_in_env_falls_back_to_who — if
// SSH_CONNECTION's first token isn't a parseable IP (corruption /
// hostile environment), the detector falls back to `who am i` rather
// than returning the malformed value verbatim. T-04-07-02 mitigation.
func TestDetectAdminIP_invalid_ip_in_env_falls_back_to_who(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "not-an-ip 22 server 22")
	f := sysops.NewFake()
	f.ExecResponses["who am i"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("alice  pts/0  (1.2.3.4)\n"),
	}
	require.Equal(t, "1.2.3.4", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_ipv6_in_env — IPv6 admin connections must yield the
// canonical IPv6 source. net.ParseIP normalises (e.g. zero-suppression);
// the result is the canonical form returned by ip.String().
func TestDetectAdminIP_ipv6_in_env(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "2001:db8::1 54321 ::1 22")
	f := sysops.NewFake()
	require.Equal(t, "2001:db8::1", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_who_returns_hostname_returns_empty — `who am i` can
// emit a hostname instead of an IP (DNS reverse-lookup happy path on
// some configs, e.g. `(myhost.example.com)`). LOCK-03 needs an IP to
// compare against allowlist entries — return "" rather than smuggling
// a hostname through. T-04-07-03 mitigation.
func TestDetectAdminIP_who_returns_hostname_returns_empty(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	f := sysops.NewFake()
	f.ExecResponses["who am i"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("alice  pts/0  2026-04-27 10:23 (myhost.example.com)\n"),
	}
	require.Equal(t, "", lockdown.DetectAdminIP(context.Background(), f))
}

// TestDetectAdminIP_who_returns_no_parens_returns_empty — defensive:
// some `who am i` shapes (e.g. `:0` for X11 desktop sessions) emit a
// source token without parens. The regex doesn't match → return "".
func TestDetectAdminIP_who_returns_no_parens_returns_empty(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	f := sysops.NewFake()
	f.ExecResponses["who am i"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("alice  :0  2026-04-27 10:23\n"),
	}
	require.Equal(t, "", lockdown.DetectAdminIP(context.Background(), f))
}
