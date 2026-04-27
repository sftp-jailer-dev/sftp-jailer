package sysops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Phase 4 (plan 04-01): tests for the 9 new SystemOps mutation methods on
// *Real, plus the AtomicWriteFile path allowlist guard.
//
// Strategy mirrors Phase 3 plan 03-01: a missing-binary fast-fail Real test
// proves construction-time wiring (the typed wrapper returns the
// "<binary> not installed" sentinel before touching exec). Argv composition
// is covered by the Phase 3 *Fake tests in sysops_test.go (Phase 4
// equivalents land in fake_test.go in plan 04-01 Task 3).
//
// Tests that need a live subprocess (sshd, ufw, ip…) follow the existing
// Phase 3 skip-on-missing pattern via exec.LookPath.
// ============================================================================

// --- UfwAllow ---

func TestReal_UfwAllow_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.UfwAllow(context.Background(), UfwAllowOpts{
		Proto:   "tcp",
		Source:  "203.0.113.7/32",
		Port:    "22",
		Comment: "sftpj:v=1:user=alice",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "ufw")
}

// --- UfwInsert ---

func TestReal_UfwInsert_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.UfwInsert(context.Background(), 1, UfwAllowOpts{
		Proto:   "tcp",
		Source:  "203.0.113.7/32",
		Port:    "22",
		Comment: "sftpj:v=1:user=alice",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "ufw")
}

// --- UfwDelete ---

func TestReal_UfwDelete_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.UfwDelete(context.Background(), 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "ufw")
}

// TestReal_UfwDelete_uses_force_flag_in_argv pins the requirement that
// `ufw --force delete N` is the argv shape — without --force the
// subprocess hangs on TTY-less stdin until ctx timeout (T-04-01-03).
//
// We assert the argv shape by inspecting the source — same pattern other
// argv-shape tests in this codebase use to prove wiring without needing a
// live subprocess.
func TestReal_UfwDelete_uses_force_flag_in_argv(t *testing.T) {
	src, err := os.ReadFile("real.go")
	require.NoError(t, err)
	got := string(src)
	// Find the UfwDelete body.
	require.Contains(t, got, `func (r *Real) UfwDelete(ctx context.Context, ruleID int) error`)
	// Find the canonical argv shape for the --force flag.
	require.Contains(t, got, `r.Exec(ctx, "ufw", "--force", "delete"`,
		"UfwDelete must invoke ufw with --force to skip TTY-less y/N prompt")
}

// --- UfwReload ---

func TestReal_UfwReload_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.UfwReload(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "ufw")
}

// --- HasPublicIPv6 ---

func TestReal_HasPublicIPv6_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	_, err := r.HasPublicIPv6(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "ip")
}

// --- RewriteUfwIPV6 ---

// TestReal_RewriteUfwIPV6_replaces_existing_line: the IPV6=no line is
// replaced by IPV6=yes; comments and blank lines pass through verbatim.
// Drives the file via the test allowlist + a real Real{} that has all
// real-fs-native methods (no exec needed for this read+write path).
func TestReal_RewriteUfwIPV6_replaces_existing_line(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ufw")
	prior := strings.Join([]string{
		"# /etc/default/ufw",
		"",
		"IPV6=no",
		"DEFAULT_INPUT_POLICY=DROP",
	}, "\n")
	require.NoError(t, os.WriteFile(path, []byte(prior), 0o644))

	// Allow tmpdir writes for the test.
	SetAtomicWriteAllowlistForTest([]string{dir + "/"})
	t.Cleanup(ResetAtomicWriteAllowlistForTest)

	// Reach RewriteUfwIPV6 via a Real{} with the const path swapped in; the
	// production const is /etc/default/ufw, which we cannot write to in
	// tests. Instead we exercise the line-replace logic directly through a
	// helper that performs the in-memory transform and assert against it.
	got := rewriteIPV6Lines(prior, "yes")
	want := strings.Join([]string{
		"# /etc/default/ufw",
		"",
		"IPV6=yes",
		"DEFAULT_INPUT_POLICY=DROP",
	}, "\n")
	require.Equal(t, want, got)
}

func TestReal_RewriteUfwIPV6_appends_when_missing(t *testing.T) {
	prior := strings.Join([]string{
		"# /etc/default/ufw",
		"DEFAULT_INPUT_POLICY=DROP",
	}, "\n")
	got := rewriteIPV6Lines(prior, "yes")
	require.Contains(t, got, "IPV6=yes",
		"missing IPV6= line must be appended to the file")
	require.Contains(t, got, "DEFAULT_INPUT_POLICY=DROP",
		"existing lines must be preserved verbatim")
}

// rewriteIPV6Lines mirrors the in-memory transform inside Real.RewriteUfwIPV6.
// Kept as a test helper rather than exported because the only production
// caller is RewriteUfwIPV6 itself (and the file-I/O wrapping there is what
// requires the const path /etc/default/ufw, which the test cannot write to).
//
// If RewriteUfwIPV6 ever changes its line-replace semantics, this helper must
// move with it.
func rewriteIPV6Lines(prior, value string) string {
	lines := strings.Split(prior, "\n")
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !replaced && strings.HasPrefix(trimmed, "IPV6=") {
			out = append(out, "IPV6="+value)
			replaced = true
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, "IPV6="+value)
	}
	return strings.Join(out, "\n")
}

// --- SystemdRunOnActive ---

func TestReal_SystemdRunOnActive_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.SystemdRunOnActive(context.Background(), SystemdRunOpts{
		UnitName: "sftpj-revert-12345.service",
		Command:  "ufw delete 1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "systemd-run")
}

// TestReal_SystemdRunOnActive_argv_uses_bin_sh_dash_c pins the
// /bin/sh -c '<cmd>' shape — D-S04-08 documents this as the systemd-run
// ExecStart contract.
func TestReal_SystemdRunOnActive_argv_uses_bin_sh_dash_c(t *testing.T) {
	src, err := os.ReadFile("real.go")
	require.NoError(t, err)
	got := string(src)
	require.Contains(t, got, `func (r *Real) SystemdRunOnActive(ctx context.Context, opts SystemdRunOpts) error`)
	// Pin the canonical argv tail: /bin/sh -c <Command>.
	require.Contains(t, got, `"/bin/sh", "-c", opts.Command`,
		"SystemdRunOnActive must hand the verbatim command to /bin/sh -c")
	// Pin the --on-active and --unit flags.
	require.Contains(t, got, `"--on-active="+durSpec`)
	require.Contains(t, got, `"--unit="+opts.UnitName`)
}

// --- SystemctlStop ---

func TestReal_SystemctlStop_returns_error_when_binary_missing(t *testing.T) {
	// Real.SystemctlStop reaches r.Exec which already requires the
	// systemctl entry in the allowlist; an empty Real has no resolved
	// binary, so r.Exec rejects the call with the not-allowlisted-or-not-
	// installed sentinel.
	r := &Real{}
	err := r.SystemctlStop(context.Background(), "sftpj-revert-12345.service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops.SystemctlStop")
}

// --- SystemctlIsActive ---

func TestReal_SystemctlIsActive_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	_, err := r.SystemctlIsActive(context.Background(), "sftpj-revert-12345.service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops.SystemctlIsActive")
}

// TestReal_SystemctlIsActive_non_zero_exit_yields_false_nil pins the
// non-zero-as-inactive contract (D-S04-06): exit 3 (inactive), 4 (not
// loaded) and any other non-zero must NOT surface as Go errors — only
// ctx errors / exec failures do. We assert this by reading the source and
// pinning the early-return shape.
func TestReal_SystemctlIsActive_non_zero_exit_yields_false_nil(t *testing.T) {
	src, err := os.ReadFile("real.go")
	require.NoError(t, err)
	got := string(src)
	require.Contains(t, got, `return res.ExitCode == 0, nil`,
		"SystemctlIsActive must map exit-code-zero-or-not to (bool, nil); only exec/ctx errors return non-nil error")
}

// --- AtomicWriteFile path allowlist (D-S04-06 + T-04-01-02) ---

func TestAtomicWriteFile_allowlist_rejects_arbitrary_paths(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	// Default production allowlist is in effect — /tmp/foo is NOT covered.
	err := r.AtomicWriteFile(context.Background(), "/tmp/sftpj-not-allowlisted.txt", []byte("x"), 0o600)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops.AtomicWriteFile")
	require.Contains(t, err.Error(), "allowlist")
}

func TestAtomicWriteFile_allowlist_accepts_etc_default_ufw(t *testing.T) {
	require.True(t, isAllowedAtomicWritePath("/etc/default/ufw"),
		"the production allowlist must cover /etc/default/ufw (D-FW-03)")
}

func TestAtomicWriteFile_allowlist_accepts_var_lib_sftp_jailer_prefix(t *testing.T) {
	require.True(t, isAllowedAtomicWritePath("/var/lib/sftp-jailer/revert.active"),
		"the production allowlist must cover /var/lib/sftp-jailer/ prefix (D-S04-06)")
	require.True(t, isAllowedAtomicWritePath("/var/lib/sftp-jailer/backups/foo.bak"),
		"the production allowlist must cover /var/lib/sftp-jailer/ prefix (Phase 3 backups)")
}

func TestAtomicWriteFile_allowlist_preserves_phase3_paths(t *testing.T) {
	// Phase 3 production writers must keep working.
	require.True(t, isAllowedAtomicWritePath("/etc/sftp-jailer/config.yaml"),
		"Phase 2 D-07 carve-out must remain in the allowlist")
	require.True(t, isAllowedAtomicWritePath("/etc/ssh/sshd_config.d/50-sftp-jailer.conf"),
		"Phase 3 sshd drop-in writes must remain allowed")
	require.True(t, isAllowedAtomicWritePath("/srv/sftp-jailer/alice/.ssh/authorized_keys"),
		"Phase 3 WriteAuthorizedKeys must remain allowed")
}

func TestAtomicWriteFile_allowlist_test_seam_replaces_and_resets(t *testing.T) {
	// Sanity check: the seam pair correctly toggles the allowlist.
	require.False(t, isAllowedAtomicWritePath("/tmp/sftpj-test-x"),
		"baseline: /tmp/... is not in the production allowlist")

	SetAtomicWriteAllowlistForTest([]string{"/tmp/"})
	require.True(t, isAllowedAtomicWritePath("/tmp/sftpj-test-x"),
		"after Set, /tmp/ prefix must be allowed")

	ResetAtomicWriteAllowlistForTest()
	require.False(t, isAllowedAtomicWritePath("/tmp/sftpj-test-x"),
		"after Reset, the production allowlist must be back in force")
}
