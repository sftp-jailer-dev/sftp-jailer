package sysops

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to path with the standard tmp+fsync+rename
// dance. The temp file is created in the SAME directory as path so the
// final os.Rename is atomic on POSIX filesystems (cross-filesystem rename
// is non-atomic — RESEARCH §"Anti-Patterns" line 616).
//
// On any failure path the temp file is removed (best effort) so partial
// writes never leave .tmp orphans on disk.
//
// The mode argument is applied via os.Chmod after Write+Close — necessary
// because os.CreateTemp creates the file with mode 0600, which is too
// restrictive for /etc/sftp-jailer/config.yaml (D-07 wants 0644).
//
// ctx is currently unused (the os.Write/Sync/Rename calls are not
// context-aware) but is accepted for interface symmetry with slow-I/O
// methods. A future revision could honor ctx by checking after each step.
//
// gosec G304 / G302 / G306: write paths and modes flow from caller-supplied
// values per the SystemOps contract. Validation is the caller's job.
func (r *Real) AtomicWriteFile(_ context.Context, path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".sftp-jailer-config-*.tmp")
	if err != nil {
		return fmt.Errorf("sysops.AtomicWriteFile create tmp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()

	// On any error before the final rename, remove the tmp file. cleanup
	// flips to false only on the success path.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sysops.AtomicWriteFile write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sysops.AtomicWriteFile fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sysops.AtomicWriteFile close: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil { //nolint:gosec // G302: mode supplied by caller per sysops contract
		return fmt.Errorf("sysops.AtomicWriteFile chmod %v: %w", mode, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("sysops.AtomicWriteFile rename %q → %q: %w", tmpName, path, err)
	}
	cleanup = false
	return nil
}
