package revert

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// setUp wires a fresh Fake + temp-redirected PointerPath for each test.
// The atomic-write-path allowlist is also retargeted so the Real path
// would also accept the temp dir if a future test routes through it
// (Fake currently ignores the allowlist; harmless to set).
func setUp(t *testing.T) (*sysops.Fake, *Watcher) {
	t.Helper()
	tmp := t.TempDir()
	sysops.SetAtomicWriteAllowlistForTest([]string{tmp + "/"})
	SetPointerPathForTest(filepath.Join(tmp, "revert.active"))
	t.Cleanup(func() {
		sysops.ResetAtomicWriteAllowlistForTest()
		ResetPointerPathForTest()
	})
	f := sysops.NewFake()
	return f, New(f)
}

func TestWatcher_Set_writes_pointer_and_records_state(t *testing.T) {
	f, w := setUp(t)
	deadline := time.Date(2026, 4, 27, 12, 5, 0, 0, time.UTC)
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", deadline, []string{"ufw delete 1"}))

	st := w.Get()
	require.NotNil(t, st)
	require.Equal(t, "sftpj-revert-1.service", st.UnitName)
	require.Equal(t, deadline.UnixNano(), st.DeadlineUnixNs)

	// Reverse cmds defensive-copy
	require.Equal(t, []string{"ufw delete 1"}, w.ReverseCommands())

	// Pointer file exists with the expected JSON
	body, err := f.ReadFile(context.Background(), PointerPath())
	require.NoError(t, err)
	var raw State
	require.NoError(t, json.Unmarshal(body, &raw))
	require.Equal(t, "sftpj-revert-1.service", raw.UnitName)
	require.Equal(t, deadline.UnixNano(), raw.DeadlineUnixNs)
}

func TestWatcher_Clear_removes_pointer_and_state(t *testing.T) {
	f, w := setUp(t)
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", time.Now().Add(3*time.Minute), nil))
	require.NotNil(t, w.Get())
	require.NoError(t, w.Clear(context.Background()))
	require.Nil(t, w.Get())
	// Pointer file is gone — Fake.RemoveAll deletes from f.Files.
	_, err := f.ReadFile(context.Background(), PointerPath())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestWatcher_Clear_idempotent_when_nothing_armed(t *testing.T) {
	_, w := setUp(t)
	require.NoError(t, w.Clear(context.Background()))
	require.NoError(t, w.Clear(context.Background()))
	require.Nil(t, w.Get())
}

func TestWatcher_Restore_no_pointer_returns_clean(t *testing.T) {
	_, w := setUp(t)
	fired, err := w.Restore(context.Background())
	require.NoError(t, err)
	require.False(t, fired)
	require.Nil(t, w.Get())
}

func TestWatcher_Restore_pointer_active_unit_restores_state(t *testing.T) {
	f, w := setUp(t)
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", time.Now().Add(3*time.Minute), nil))
	// Drop in-process state to simulate a TUI restart.
	w.state = nil

	f.SystemctlIsActiveResult = true
	fired, err := w.Restore(context.Background())
	require.NoError(t, err)
	require.False(t, fired)
	require.NotNil(t, w.Get())
	require.Equal(t, "sftpj-revert-1.service", w.Get().UnitName)
}

func TestWatcher_Restore_pointer_inactive_unit_fired_clears_pointer(t *testing.T) {
	f, w := setUp(t)
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", time.Now().Add(3*time.Minute), nil))
	// Simulate TUI restart + unit fired
	w.state = nil
	f.SystemctlIsActiveResult = false

	fired, err := w.Restore(context.Background())
	require.NoError(t, err)
	require.True(t, fired)
	require.Nil(t, w.Get())

	// Pointer file is gone
	_, err = f.ReadFile(context.Background(), PointerPath())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestWatcher_Restore_corrupt_pointer_returns_fired_true(t *testing.T) {
	f, w := setUp(t)
	// Write garbage directly to the pointer.
	require.NoError(t, f.AtomicWriteFile(context.Background(), PointerPath(), []byte("not-json"), 0o600))
	fired, err := w.Restore(context.Background())
	require.True(t, fired)
	require.Error(t, err)
	// Pointer should be cleaned up.
	_, e := f.ReadFile(context.Background(), PointerPath())
	require.ErrorIs(t, e, fs.ErrNotExist)
}

func TestWatcher_Get_returns_defensive_copy(t *testing.T) {
	_, w := setUp(t)
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", time.Now().Add(3*time.Minute), nil))
	s1 := w.Get()
	s1.UnitName = "mutated"
	s2 := w.Get()
	require.Equal(t, "sftpj-revert-1.service", s2.UnitName)
}

func TestWatcher_ReverseCommands_returns_defensive_copy(t *testing.T) {
	_, w := setUp(t)
	original := []string{"ufw --force delete 1", "ufw reload"}
	require.NoError(t, w.Set(context.Background(), "sftpj-revert-1.service", time.Now().Add(3*time.Minute), original))

	got := w.ReverseCommands()
	require.Equal(t, original, got)
	// Mutate the returned slice; the watcher's internal slice should be unaffected.
	got[0] = "MUTATED"
	got2 := w.ReverseCommands()
	require.Equal(t, "ufw --force delete 1", got2[0])
}

func TestWatcher_satisfies_txn_RevertWatcher_interface(t *testing.T) {
	// Compile-time check: *Watcher implements the txn.RevertWatcher adapter
	// shape (Plan 04-02). We don't import internal/txn here (to avoid the
	// cycle the adapter interface exists to prevent), so we re-state the
	// shape inline and assert *Watcher satisfies it.
	var _ interface {
		Set(ctx context.Context, unitName string, deadline time.Time, reverseCmds []string) error
		Clear(ctx context.Context) error
	} = (*Watcher)(nil)
	_ = errors.New // silence unused if errors not referenced elsewhere
}
