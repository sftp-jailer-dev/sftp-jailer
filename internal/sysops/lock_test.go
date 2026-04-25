package sysops

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAcquireRunLock_first_succeeds: lockfile in tmpdir; first call returns
// release+nil; release unlocks (verified by being able to re-acquire after).
func TestAcquireRunLock_first_succeeds(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	lockPath := filepath.Join(t.TempDir(), "observe-run.lock")
	release, err := r.AcquireRunLock(context.Background(), lockPath)
	require.NoError(t, err)
	require.NotNil(t, release)
	release()
}

// TestAcquireRunLock_second_returns_ErrLockHeld: first call holds lock; second
// call against the same path returns sentinel ErrLockHeld.
func TestAcquireRunLock_second_returns_ErrLockHeld(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	lockPath := filepath.Join(t.TempDir(), "observe-run.lock")
	release, err := r.AcquireRunLock(context.Background(), lockPath)
	require.NoError(t, err)
	defer release()

	_, err2 := r.AcquireRunLock(context.Background(), lockPath)
	require.Error(t, err2)
	require.True(t, errors.Is(err2, ErrLockHeld),
		"expected ErrLockHeld, got %v", err2)
}

// TestAcquireRunLock_release_on_second_succeeds: first acquire → release →
// second acquire succeeds.
func TestAcquireRunLock_release_on_second_succeeds(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	lockPath := filepath.Join(t.TempDir(), "observe-run.lock")
	release1, err := r.AcquireRunLock(context.Background(), lockPath)
	require.NoError(t, err)
	release1()

	release2, err := r.AcquireRunLock(context.Background(), lockPath)
	require.NoError(t, err)
	defer release2()
}

// TestFakeAcquireRunLock_scripted_held: with f.LockHeld=true, AcquireRunLock
// returns ErrLockHeld; with f.LockHeld=false, it returns a release closure
// and flips f.LockHeld=true.
func TestFakeAcquireRunLock_scripted_held(t *testing.T) {
	f := NewFake()
	f.LockHeld = true
	_, err := f.AcquireRunLock(context.Background(), "/tmp/x.lock")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrLockHeld))
}

func TestFakeAcquireRunLock_scripted_unheld_acquires(t *testing.T) {
	f := NewFake()
	f.LockHeld = false
	release, err := f.AcquireRunLock(context.Background(), "/tmp/x.lock")
	require.NoError(t, err)
	require.NotNil(t, release)
	require.True(t, f.LockHeld, "Fake should flip LockHeld=true after acquire")
	release()

	// Method recorded.
	count := 0
	for _, c := range f.Calls {
		if c.Method == "AcquireRunLock" {
			count++
		}
	}
	require.Equal(t, 1, count)
}
