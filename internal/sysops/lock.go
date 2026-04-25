package sysops

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// AcquireRunLock takes an exclusive, non-blocking flock(2) on path. Returns a
// release func and nil on success, or the sentinel ErrLockHeld when another
// process already holds the lock.
//
// flock semantics:
//   - The lock is advisory — only processes that also call flock() see it.
//   - The lock is bound to the file *description*; closing the fd releases it.
//   - The lock is auto-released when the process dies (kernel clean-up).
//
// We deliberately keep the *os.File alive inside the release closure so the
// lock persists for the lifetime of the caller's "critical section." When
// release() runs we explicitly LOCK_UN then Close; LOCK_UN is technically
// redundant after Close but is the polite signal to any concurrent
// flock-waiters and matches the man-page recommendation.
//
// gosec G304: path is caller-supplied per the SystemOps contract; the caller
// (cmd/sftp-jailer/observe.go) hardcodes /var/lib/sftp-jailer/observe-run.lock.
func (r *Real) AcquireRunLock(_ context.Context, path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // G304: caller-supplied path per sysops contract
	if err != nil {
		return nil, fmt.Errorf("sysops.AcquireRunLock open %q: %w", path, err)
	}

	// gosec G115: f.Fd() returns uintptr (the OS file descriptor); on every
	// platform Go supports an FD fits in int. The conversion is safe.
	fd := int(f.Fd()) //nolint:gosec // G115: OS fd always fits in int
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		// EWOULDBLOCK is the "another process holds it" case.
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLockHeld
		}
		return nil, fmt.Errorf("sysops.AcquireRunLock flock %q: %w", path, err)
	}

	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
