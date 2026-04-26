package sysops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- Fake tests ---

func TestFake_Geteuid_default_is_root(t *testing.T) {
	f := NewFake()
	require.Equal(t, 0, f.Geteuid())
	require.Equal(t, 1, len(f.Calls))
	require.Equal(t, "Geteuid", f.Calls[0].Method)
}

func TestFake_Geteuid_scripted_non_root(t *testing.T) {
	f := NewFake()
	f.EUID = 1000
	require.Equal(t, 1000, f.Geteuid())
	require.Equal(t, "Geteuid", f.Calls[0].Method)
}

func TestFake_ReadFile_scripted_returns_content(t *testing.T) {
	f := NewFake()
	f.Files["/x"] = []byte("hi")
	b, err := f.ReadFile(context.Background(), "/x")
	require.NoError(t, err)
	require.Equal(t, []byte("hi"), b)
	require.Len(t, f.Calls, 1)
	require.Equal(t, FakeCall{Method: "ReadFile", Args: []string{"/x"}}, f.Calls[0])
}

func TestFake_ReadFile_missing_returns_fs_ErrNotExist(t *testing.T) {
	f := NewFake()
	_, err := f.ReadFile(context.Background(), "/nope")
	require.Error(t, err)
	require.True(t, errors.Is(err, fs.ErrNotExist), "expected fs.ErrNotExist, got %v", err)
}

// TestFake_ReadShadow_returns_both_fields: seeded ShadowEntry returns BOTH
// the lstchg (field 3) and max (field 5) values verbatim.
func TestFake_ReadShadow_returns_both_fields(t *testing.T) {
	f := NewFake()
	f.Shadow["alice"] = ShadowEntry{LastChangeDay: 19500, MaxDays: 90}
	lstchg, maxDays, err := f.ReadShadow(context.Background(), "alice")
	require.NoError(t, err)
	require.Equal(t, 19500, lstchg)
	require.Equal(t, 90, maxDays)
	// Call recorded with the username.
	require.GreaterOrEqual(t, len(f.Calls), 1)
	last := f.Calls[len(f.Calls)-1]
	require.Equal(t, "ReadShadow", last.Method)
	require.Equal(t, []string{"alice"}, last.Args)
}

// TestFake_ReadShadow_returns_indefinite_max: a seeded entry with MaxDays
// >= 99999 is round-tripped without normalization — the caller decides how
// to interpret "no expiry policy."
func TestFake_ReadShadow_returns_indefinite_max(t *testing.T) {
	f := NewFake()
	f.Shadow["bob"] = ShadowEntry{LastChangeDay: 19000, MaxDays: 99999}
	_, maxDays, err := f.ReadShadow(context.Background(), "bob")
	require.NoError(t, err)
	require.Equal(t, 99999, maxDays)
}

// TestFake_ReadShadow_unknown_user_returns_fs_ErrNotExist: an unseeded
// username surfaces fs.ErrNotExist so callers can errors.Is and silently
// degrade (leave PasswordAgeDays / PasswordMaxDays at -1).
func TestFake_ReadShadow_unknown_user_returns_fs_ErrNotExist(t *testing.T) {
	f := NewFake()
	_, _, err := f.ReadShadow(context.Background(), "ghost")
	require.Error(t, err)
	require.True(t, errors.Is(err, fs.ErrNotExist), "expected fs.ErrNotExist, got %v", err)
}

func TestFake_Exec_exact_match_wins(t *testing.T) {
	f := NewFake()
	f.ExecResponses["sshd -T"] = ExecResult{Stdout: []byte("port 22\n"), ExitCode: 0}
	res, err := f.Exec(context.Background(), "sshd", "-T")
	require.NoError(t, err)
	require.Equal(t, []byte("port 22\n"), res.Stdout)
	require.Equal(t, 0, res.ExitCode)
}

func TestFake_Exec_prefix_match_longest_wins(t *testing.T) {
	f := NewFake()
	f.ExecResponsesByPrefix["nft"] = ExecResult{Stdout: []byte("short")}
	f.ExecResponsesByPrefix["nft -j list"] = ExecResult{Stdout: []byte("long")}
	res, err := f.Exec(context.Background(), "nft", "-j", "list", "ruleset")
	require.NoError(t, err)
	require.Equal(t, []byte("long"), res.Stdout,
		"longest-prefix should win ('nft -j list' over 'nft')")
}

func TestFake_Exec_no_script_returns_error(t *testing.T) {
	f := NewFake()
	_, err := f.Exec(context.Background(), "whatever")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no scripted response")
}

func TestFake_Stat_scripted_returns_FileInfo(t *testing.T) {
	f := NewFake()
	want := FileInfo{Path: "/etc", UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/etc"] = want
	got, err := f.Stat(context.Background(), "/etc")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// --- Real tests ---

func TestReal_Exec_rejects_unlisted_binary(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)
	_, err := r.Exec(context.Background(), "rm", "-rf", "/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowlisted")
}

func TestReal_Exec_honors_context_deadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	r, ok := NewReal().(*Real)
	require.True(t, ok, "NewReal must return *Real so tests can exercise it directly")

	_, err := r.Exec(ctx, "/bin/sleep", "10")
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled),
		"expected context.Canceled, got %v", err)
}

// --- Bonus smoke: timeout constant is what we claim (plan 03 will grep for this in source). ---

func TestReal_default_timeout_is_10_seconds(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)
	require.Equal(t, 10*time.Second, r.defaultTimeout)
}

// ============================================================================
// Phase 3 (plan 03-01): RED tests for new sysops mutation methods.
//
// Each new method gets BOTH a Fake test (asserting record() entries appear
// with the right argv shape) AND a Real test confirming a missing-binary
// fast-fail returns a wrapped error containing the package name. The Fake is
// the production test surface for downstream callers; the Real test only
// proves construction-time binary lookup wires correctly.
// ============================================================================

// --- Useradd ---

func TestFake_Useradd_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Useradd(context.Background(), UseraddOpts{
		Username:           "alice",
		UID:                2000,
		Home:               "/srv/sftp-jailer/alice",
		Shell:              "/usr/sbin/nologin",
		CreateHome:         true,
		MemberOfSftpJailer: true,
	})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Useradd", f.Calls[0].Method)
	require.Equal(t, []string{
		"alice",
		"uid=2000",
		"home=/srv/sftp-jailer/alice",
		"shell=/usr/sbin/nologin",
		"createHome=true",
		"memberOfSftpJailer=true",
	}, f.Calls[0].Args)
}

func TestFake_Useradd_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("uid in use")
	f.UseraddError = scripted
	err := f.Useradd(context.Background(), UseraddOpts{Username: "alice", UID: 2000})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Useradd", f.Calls[0].Method)
}

func TestReal_Useradd_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Useradd(context.Background(), UseraddOpts{Username: "alice"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "useradd")
}

// --- Userdel ---

func TestFake_Userdel_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Userdel(context.Background(), "alice", true)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Userdel", f.Calls[0].Method)
	require.Equal(t, []string{"alice", "removeHome=true"}, f.Calls[0].Args)
}

func TestFake_Userdel_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("user not found")
	f.UserdelError = scripted
	err := f.Userdel(context.Background(), "ghost", false)
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
	require.Equal(t, []string{"ghost", "removeHome=false"}, f.Calls[0].Args)
}

func TestReal_Userdel_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Userdel(context.Background(), "alice", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "userdel")
}

// --- Gpasswd ---

func TestFake_Gpasswd_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Gpasswd(context.Background(), GpasswdAdd, "alice", "sftp-jailer")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Gpasswd", f.Calls[0].Method)
	require.Equal(t, []string{"op=add", "alice", "sftp-jailer"}, f.Calls[0].Args)

	require.NoError(t, f.Gpasswd(context.Background(), GpasswdDel, "alice", "sftp-jailer"))
	require.Len(t, f.Calls, 2)
	require.Equal(t, []string{"op=del", "alice", "sftp-jailer"}, f.Calls[1].Args)
}

func TestFake_Gpasswd_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("group missing")
	f.GpasswdError = scripted
	err := f.Gpasswd(context.Background(), GpasswdAdd, "alice", "sftp-jailer")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_Gpasswd_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Gpasswd(context.Background(), GpasswdAdd, "alice", "sftp-jailer")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "gpasswd")
}

// --- Chpasswd ---

func TestFake_Chpasswd_records_call_without_password_literal(t *testing.T) {
	f := NewFake()
	err := f.Chpasswd(context.Background(), "alice", "secret123!")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Chpasswd", f.Calls[0].Method)
	// Security invariant (D-13 / pitfall E3): NEVER record password literal.
	// Length-only marker is recorded.
	require.Equal(t, []string{"alice", "len=10"}, f.Calls[0].Args)
}

func TestFake_Chpasswd_returns_typed_ChpasswdError_with_pam_stderr(t *testing.T) {
	f := NewFake()
	f.ChpasswdStderr = []byte("BAD PASSWORD: too short")
	f.ChpasswdError = errors.New("exit 1")
	err := f.Chpasswd(context.Background(), "alice", "x")
	require.Error(t, err)

	var cerr *ChpasswdError
	require.True(t, errors.As(err, &cerr), "expected *ChpasswdError, got %T", err)
	require.Equal(t, "alice", cerr.Username)
	require.True(t, bytes.Contains(cerr.Stderr, []byte("BAD PASSWORD")),
		"stderr should carry pam_pwquality message; got %q", cerr.Stderr)
	// Call still recorded.
	require.Len(t, f.Calls, 1)
	require.Equal(t, []string{"alice", "len=1"}, f.Calls[0].Args)
}

func TestReal_Chpasswd_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Chpasswd(context.Background(), "alice", "secret")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "chpasswd")
}

// --- Chage ---

func TestFake_Chage_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Chage(context.Background(), "alice", ChageOpts{LastDay: 0})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Chage", f.Calls[0].Method)
	require.Equal(t, []string{"alice", "lastDay=0"}, f.Calls[0].Args)
}

func TestFake_Chage_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("chage exit 1")
	f.ChageError = scripted
	err := f.Chage(context.Background(), "alice", ChageOpts{LastDay: 0})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_Chage_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Chage(context.Background(), "alice", ChageOpts{LastDay: 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "chage")
}

// --- Chmod ---

func TestFake_Chmod_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Chmod(context.Background(), "/srv/sftp-jailer/alice", 0o750)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Chmod", f.Calls[0].Method)
	require.Equal(t, []string{"/srv/sftp-jailer/alice", "mode=750"}, f.Calls[0].Args)
}

func TestFake_Chmod_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("EACCES")
	f.ChmodError = scripted
	err := f.Chmod(context.Background(), "/x", 0o700)
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// Real test: Chmod wraps os.Chmod directly (no binary lookup). A non-existent
// path returns the underlying os.PathError; this serves the "Real wires up"
// smoke check without needing root.
func TestReal_Chmod_returns_error_when_path_missing(t *testing.T) {
	r := &Real{}
	err := r.Chmod(context.Background(), "/nonexistent/path/sftp-jailer-test", 0o700)
	require.Error(t, err)
}

// --- Chown ---

func TestFake_Chown_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Chown(context.Background(), "/srv/sftp-jailer/alice", 2000, 2000)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Chown", f.Calls[0].Method)
	require.Equal(t, []string{"/srv/sftp-jailer/alice", "uid=2000", "gid=2000"}, f.Calls[0].Args)
}

func TestFake_Chown_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("EPERM")
	f.ChownError = scripted
	err := f.Chown(context.Background(), "/x", 2000, 2000)
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_Chown_returns_error_when_path_missing(t *testing.T) {
	r := &Real{}
	err := r.Chown(context.Background(), "/nonexistent/path/sftp-jailer-test", 2000, 2000)
	require.Error(t, err)
}

// --- WriteAuthorizedKeys ---

func TestFake_WriteAuthorizedKeys_records_call_and_materializes_file(t *testing.T) {
	f := NewFake()
	keys := []byte("ssh-ed25519 AAAA...")
	err := f.WriteAuthorizedKeys(context.Background(), "alice", "/srv/sftp-jailer", keys)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "WriteAuthorizedKeys", f.Calls[0].Method)
	require.Equal(t, []string{
		"alice",
		"/srv/sftp-jailer",
		fmt.Sprintf("len=%d", len(keys)),
		"mode=600",
	}, f.Calls[0].Args)

	// Materialized in f.Files at the conventional path.
	got, ok := f.Files["/srv/sftp-jailer/alice/.ssh/authorized_keys"]
	require.True(t, ok, "authorized_keys should be materialized in f.Files")
	require.Equal(t, keys, got)
}

func TestFake_WriteAuthorizedKeys_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("write blew up")
	f.WriteAuthorizedKeysError = scripted
	err := f.WriteAuthorizedKeys(context.Background(), "alice", "/srv/sftp-jailer", []byte("k"))
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
	// Error-path: do NOT materialize state.
	_, ok := f.Files["/srv/sftp-jailer/alice/.ssh/authorized_keys"]
	require.False(t, ok, "error path must not write to Files")
}

func TestReal_WriteAuthorizedKeys_returns_error_when_user_missing(t *testing.T) {
	r := &Real{}
	// No such user → os/user.Lookup fails before any binary work.
	err := r.WriteAuthorizedKeys(context.Background(),
		"sftp-jailer-doesnotexist-xyz", t.TempDir(), []byte("ssh-ed25519 AAAA"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops.WriteAuthorizedKeys")
}

// --- SshdT ---

func TestFake_SshdT_returns_scripted_stderr_and_error(t *testing.T) {
	f := NewFake()
	f.SshdTStderr = []byte("Bad configuration option: foo")
	scripted := errors.New("exit 255")
	f.SshdTError = scripted
	stderr, err := f.SshdT(context.Background())
	require.ErrorIs(t, err, scripted)
	require.Equal(t, []byte("Bad configuration option: foo"), stderr)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SshdT", f.Calls[0].Method)
	require.Empty(t, f.Calls[0].Args)
}

func TestFake_SshdT_default_returns_nil(t *testing.T) {
	f := NewFake()
	stderr, err := f.SshdT(context.Background())
	require.NoError(t, err)
	require.Nil(t, stderr)
	require.Len(t, f.Calls, 1)
}

func TestReal_SshdT_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	_, err := r.SshdT(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "sshd")
}

// --- SshdTWithContext (B-04) ---

func TestFake_SshdTWithContext_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	stderr, err := f.SshdTWithContext(context.Background(), SshdTContextOpts{
		User: "alice", Host: "localhost", Addr: "127.0.0.1",
	})
	require.NoError(t, err)
	require.Nil(t, stderr)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SshdTWithContext", f.Calls[0].Method)
	require.Equal(t, []string{"user=alice", "host=localhost", "addr=127.0.0.1"}, f.Calls[0].Args)
}

func TestFake_SshdTWithContext_returns_scripted_stderr_and_error(t *testing.T) {
	f := NewFake()
	f.SshdTWithContextStderr = []byte("Match user alice: chroot resolves to non-existent path")
	scripted := errors.New("exit 255")
	f.SshdTWithContextError = scripted
	stderr, err := f.SshdTWithContext(context.Background(), SshdTContextOpts{User: "alice"})
	require.ErrorIs(t, err, scripted)
	require.True(t, bytes.Contains(stderr, []byte("Match user alice")))
}

func TestReal_SshdTWithContext_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	_, err := r.SshdTWithContext(context.Background(), SshdTContextOpts{User: "alice"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "sshd")
}

// --- SystemctlReload ---

func TestFake_SystemctlReload_records_call(t *testing.T) {
	f := NewFake()
	err := f.SystemctlReload(context.Background(), "ssh.service")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemctlReload", f.Calls[0].Method)
	require.Equal(t, []string{"ssh.service"}, f.Calls[0].Args)
}

func TestFake_SystemctlReload_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("unit not found")
	f.SystemctlReloadError = scripted
	err := f.SystemctlReload(context.Background(), "ssh.service")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_SystemctlReload_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.SystemctlReload(context.Background(), "ssh.service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "systemctl")
}

// --- SystemctlRestartSocket ---

func TestFake_SystemctlRestartSocket_records_call(t *testing.T) {
	f := NewFake()
	err := f.SystemctlRestartSocket(context.Background(), "ssh.socket")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemctlRestartSocket", f.Calls[0].Method)
	require.Equal(t, []string{"ssh.socket"}, f.Calls[0].Args)
}

func TestFake_SystemctlRestartSocket_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("unit not found")
	f.SystemctlRestartSocketError = scripted
	err := f.SystemctlRestartSocket(context.Background(), "ssh.socket")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_SystemctlRestartSocket_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.SystemctlRestartSocket(context.Background(), "ssh.socket")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "systemctl")
}

// --- SystemctlDaemonReload ---

func TestFake_SystemctlDaemonReload_records_call(t *testing.T) {
	f := NewFake()
	err := f.SystemctlDaemonReload(context.Background())
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemctlDaemonReload", f.Calls[0].Method)
	require.Empty(t, f.Calls[0].Args)
}

func TestFake_SystemctlDaemonReload_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("dbus error")
	f.SystemctlDaemonReloadError = scripted
	err := f.SystemctlDaemonReload(context.Background())
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_SystemctlDaemonReload_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.SystemctlDaemonReload(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "systemctl")
}

// --- Tar ---

func TestFake_Tar_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.Tar(context.Background(), TarOpts{
		Mode:        TarCreateGzip,
		ArchivePath: "/var/lib/sftp-jailer/archive/alice-2026-04-26T10-00-00Z.tar.gz",
		SourceDir:   "/srv/sftp-jailer/alice",
	})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "Tar", f.Calls[0].Method)
	require.Equal(t, []string{
		"mode=czf",
		"archive=/var/lib/sftp-jailer/archive/alice-2026-04-26T10-00-00Z.tar.gz",
		"source=/srv/sftp-jailer/alice",
	}, f.Calls[0].Args)
}

func TestFake_Tar_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("tar exit 2")
	f.TarError = scripted
	err := f.Tar(context.Background(), TarOpts{Mode: TarCreateGzip, ArchivePath: "/a", SourceDir: "/b"})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

func TestReal_Tar_returns_error_when_binary_missing(t *testing.T) {
	r := &Real{}
	err := r.Tar(context.Background(), TarOpts{Mode: TarCreateGzip, ArchivePath: "/a", SourceDir: "/b"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sysops")
	require.Contains(t, err.Error(), "tar")
}

// --- MkdirAll (W-02) ---

func TestFake_MkdirAll_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.MkdirAll(context.Background(), "/var/lib/sftp-jailer/archive", 0o700)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "MkdirAll", f.Calls[0].Method)
	require.Equal(t, []string{"/var/lib/sftp-jailer/archive", "mode=700"}, f.Calls[0].Args)
}

func TestFake_MkdirAll_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("EACCES")
	f.MkdirAllError = scripted
	err := f.MkdirAll(context.Background(), "/x", 0o700)
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- RemoveAll (W-02) ---

func TestFake_RemoveAll_records_call(t *testing.T) {
	f := NewFake()
	err := f.RemoveAll(context.Background(), "/tmp/test-dir")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "RemoveAll", f.Calls[0].Method)
	require.Equal(t, []string{"/tmp/test-dir"}, f.Calls[0].Args)
}

func TestFake_RemoveAll_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("EPERM")
	f.RemoveAllError = scripted
	err := f.RemoveAll(context.Background(), "/x")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- SshdDumpConfig fakeable (W-04) ---

func TestFake_SshdDumpConfig_returns_scripted_response(t *testing.T) {
	f := NewFake()
	f.SshdConfigResponse = map[string][]string{
		"passwordauthentication": {"no"},
		"chrootdirectory":        {"/srv/sftp-jailer/%u"},
	}
	got, err := f.SshdDumpConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"no"}, got["passwordauthentication"])
	require.Equal(t, []string{"/srv/sftp-jailer/%u"}, got["chrootdirectory"])
	// Recorded.
	require.GreaterOrEqual(t, len(f.Calls), 1)
	last := f.Calls[len(f.Calls)-1]
	require.Equal(t, "SshdDumpConfig", last.Method)
	require.Empty(t, last.Args)
}

func TestFake_SshdDumpConfig_default_returns_empty_map_not_nil(t *testing.T) {
	f := NewFake()
	got, err := f.SshdDumpConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, got, "default response must be empty map, not nil")
	require.Empty(t, got)
}

// --- Lstat / Stat ModTime population (B-06) ---

func TestReal_Lstat_populates_ModTime_from_filesystem(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/testfile"
	require.NoError(t, os.WriteFile(path, []byte("hi"), 0o600))
	// Set a deterministic mtime so we can compare exactly.
	want := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(path, want, want))

	r, ok := NewReal().(*Real)
	require.True(t, ok)

	li, err := r.Lstat(context.Background(), path)
	require.NoError(t, err)
	require.False(t, li.ModTime.IsZero(), "Lstat must populate ModTime from filesystem")
	require.WithinDuration(t, want, li.ModTime, time.Second,
		"Lstat ModTime should match os.Chtimes value")

	si, err := r.Stat(context.Background(), path)
	require.NoError(t, err)
	require.False(t, si.ModTime.IsZero(), "Stat must populate ModTime from filesystem")
	require.WithinDuration(t, want, si.ModTime, time.Second,
		"Stat ModTime should match os.Chtimes value")
}

// --- Interface conformance ---

func TestSysops_PhaseInterfaceSurface(t *testing.T) {
	// Compile-time check via runtime assertion: both Real and Fake satisfy
	// the post-Phase-3 SystemOps interface (with the 16 new methods).
	var _ SystemOps = (*Real)(nil)
	var _ SystemOps = (*Fake)(nil)
	// Touch t so the test isn't flagged as unused.
	t.Log("Real and Fake satisfy SystemOps")
}
