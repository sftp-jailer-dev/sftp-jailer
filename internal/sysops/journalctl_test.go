package sysops

import (
	"context"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJournalctlFollowCmd_returns_unstarted_cmd: factory returns an *exec.Cmd
// suitable for tea.ExecProcess — Process must be nil (not started); Args must
// include the unit + -f + --no-pager flags.
func TestJournalctlFollowCmd_returns_unstarted_cmd(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	cmd := r.JournalctlFollowCmd("ssh")
	require.NotNil(t, cmd)
	require.Nil(t, cmd.Process, "ExecProcess hand-off requires an unstarted *exec.Cmd")

	// Path is whatever LookPath resolved to (or the bare name on systems
	// where journalctl isn't installed); Args[0] mirrors that, then args.
	require.NotEmpty(t, cmd.Args)

	// Args slice must contain every expected flag in order.
	joined := ""
	for _, a := range cmd.Args {
		joined += a + " "
	}
	require.Contains(t, joined, "-u")
	require.Contains(t, joined, "ssh")
	require.Contains(t, joined, "-f")
	require.Contains(t, joined, "--no-pager")

	// On any platform, the program name (whether resolved by LookPath or
	// fallback) ends in "journalctl".
	require.Equal(t, "journalctl", filepath.Base(cmd.Args[0]))
}

// TestJournalctlStream_returns_pipe: on Linux with journalctl installed the
// stream returns successfully; on non-Linux (or no journalctl) the call wraps
// a LookPath/exec error and returns it. Either way, no panics.
func TestJournalctlStream_returns_pipe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires linux journalctl; CI on ubuntu-latest exercises this branch")
	}
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	if r.binJournalctl == "" {
		// journalctl not installed in this Linux environment — confirm
		// JournalctlStream surfaces an unambiguous error.
		_, _, err := r.JournalctlStream(context.Background(), JournalctlStreamOpts{
			CursorFile: "/tmp/sftp-jailer-test.cursor",
			Unit:       "ssh",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "journalctl")
		return
	}

	// Real journalctl present — pass --since with a far-future date so the
	// stream finishes immediately (zero events) instead of tailing forever.
	proc, stdout, err := r.JournalctlStream(context.Background(), JournalctlStreamOpts{
		CursorFile: filepath.Join(t.TempDir(), "test.cursor"),
		Unit:       "ssh",
		Since:      "9999-01-01",
	})
	require.NoError(t, err)
	require.NotNil(t, proc)
	require.NotNil(t, stdout)
	_, _ = io.Copy(io.Discard, stdout)
	_ = stdout.Close()
	_, _ = proc.Wait()
}

// TestJournalctlStream_fake_canned_stdout: Fake.JournalctlStream returns
// scripted bytes via JournalctlStdout; two calls return distinct streams.
func TestJournalctlStream_fake_canned_stdout(t *testing.T) {
	f := NewFake()
	f.JournalctlStdout = map[string][]byte{
		"ssh": []byte(`{"MESSAGE":"hi","__REALTIME_TIMESTAMP":"1"}` + "\n"),
	}

	proc, rc, err := f.JournalctlStream(context.Background(), JournalctlStreamOpts{
		CursorFile: "/tmp/c",
		Unit:       "ssh",
	})
	require.NoError(t, err)
	require.NotNil(t, rc)
	// proc may be nil for the fake — sentinel — that's fine.
	_ = proc

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, f.JournalctlStdout["ssh"], got)
	require.NoError(t, rc.Close())

	// Second call returns a fresh stream (independent ReadCloser).
	_, rc2, err := f.JournalctlStream(context.Background(), JournalctlStreamOpts{
		CursorFile: "/tmp/c",
		Unit:       "ssh",
	})
	require.NoError(t, err)
	got2, err := io.ReadAll(rc2)
	require.NoError(t, err)
	require.Equal(t, f.JournalctlStdout["ssh"], got2)
	_ = rc2.Close()

	// Both invocations recorded.
	count := 0
	for _, c := range f.Calls {
		if c.Method == "JournalctlStream" {
			count++
		}
	}
	require.Equal(t, 2, count)
}

// TestObserveRunStream_fake_canned_stdout: Fake.ObserveRunStream returns
// scripted bytes via ObserveRunStdout.
func TestObserveRunStream_fake_canned_stdout(t *testing.T) {
	f := NewFake()
	f.ObserveRunStdout = []byte(`{"phase":"done"}` + "\n")

	proc, rc, err := f.ObserveRunStream(context.Background(), ObserveRunSubprocessOpts{
		CursorFile: "/tmp/c",
		DBPath:     "/tmp/db",
	})
	require.NoError(t, err)
	require.NotNil(t, rc)
	_ = proc

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, f.ObserveRunStdout, got)
	require.NoError(t, rc.Close())

	// Call recorded.
	count := 0
	for _, c := range f.Calls {
		if c.Method == "ObserveRunStream" {
			count++
		}
	}
	require.Equal(t, 1, count)
}

// TestJournalctlFollowCmd_fake_returns_noop_cmd: the Fake mirror returns a
// no-op *exec.Cmd whose program name is the literal "journalctl"; it is never
// Run by the unit tests.
func TestJournalctlFollowCmd_fake_returns_noop_cmd(t *testing.T) {
	f := NewFake()
	cmd := f.JournalctlFollowCmd("ssh")
	require.NotNil(t, cmd)
	require.Equal(t, "journalctl", filepath.Base(cmd.Args[0]))

	// And it was recorded.
	require.Len(t, f.Calls, 1)
	require.Equal(t, "JournalctlFollowCmd", f.Calls[0].Method)
}

