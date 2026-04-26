package sysops

import (
	"context"
	"errors"
	"io/fs"
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
