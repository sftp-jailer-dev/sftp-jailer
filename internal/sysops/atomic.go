package sysops

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// atomicWritePathAllowlist is the canonical write-allowlist for AtomicWriteFile.
// Consumers MUST land in one of these prefixes / exact-paths:
//
//   - /etc/sftp-jailer/config.yaml         — Phase 2 (D-07 carve-out).
//   - /etc/ssh/sshd_config.d/              — Phase 3 (D-09 drop-in writes via
//     NewWriteSshdDropInStep; the tool owns this directory end-to-end).
//   - /etc/default/ufw                     — Phase 4 (D-FW-03 IPV6 rewrite).
//   - /srv/sftp-jailer/                    — Phase 3 (chrootRoot default;
//     WriteAuthorizedKeys writes <root>/<user>/.ssh/authorized_keys).
//   - /srv/sftp/                           — Phase 3 (alt default chrootRoot).
//   - /var/lib/sftp-jailer/                — Phase 4 (D-S04-06 revert pointer
//   - Phase 3 backup directory + future writers).
//
// Entries ending in `/` are prefix matches; bare paths are exact matches.
// Tests can replace the list via SetAtomicWriteAllowlistForTest (paired with
// ResetAtomicWriteAllowlistForTest in t.Cleanup).
//
// Note (Rule 2 deviation from plan 04-01): the plan only enumerated
// /etc/default/ufw + /var/lib/sftp-jailer/ as new entries, but enabling the
// allowlist guard without preserving the Phase 3 production paths would
// break WriteAuthorizedKeys (USER-09/10/14) and NewWriteSshdDropInStep
// (SETUP-02/03 + USER-13). The list is the union of every shipped
// production writer.
var (
	atomicWritePathAllowlistMu sync.Mutex
	atomicWritePathAllowlist   = defaultAtomicWriteAllowlist()
)

func defaultAtomicWriteAllowlist() []string {
	return []string{
		"/etc/sftp-jailer/config.yaml",
		"/etc/default/ufw",
		"/etc/ssh/sshd_config.d/", // prefix — sshd drop-in writes
		"/srv/sftp-jailer/",       // prefix — chrootRoot default
		"/srv/sftp/",              // prefix — alt chrootRoot default
		"/var/lib/sftp-jailer/",   // prefix — backups + revert pointer
	}
}

// isAllowedAtomicWritePath reports whether path is permitted by the current
// allowlist. Prefix entries (those ending with `/`) match by HasPrefix;
// non-prefix entries match by exact equality.
func isAllowedAtomicWritePath(path string) bool {
	atomicWritePathAllowlistMu.Lock()
	defer atomicWritePathAllowlistMu.Unlock()
	for _, allowed := range atomicWritePathAllowlist {
		if strings.HasSuffix(allowed, "/") {
			if strings.HasPrefix(path, allowed) {
				return true
			}
			continue
		}
		if path == allowed {
			return true
		}
	}
	return false
}

// SetAtomicWriteAllowlistForTest replaces the allowlist for the duration of
// a test. Pair with t.Cleanup(ResetAtomicWriteAllowlistForTest).
func SetAtomicWriteAllowlistForTest(paths []string) {
	atomicWritePathAllowlistMu.Lock()
	defer atomicWritePathAllowlistMu.Unlock()
	atomicWritePathAllowlist = append([]string(nil), paths...)
}

// ResetAtomicWriteAllowlistForTest restores the production allowlist.
func ResetAtomicWriteAllowlistForTest() {
	atomicWritePathAllowlistMu.Lock()
	defer atomicWritePathAllowlistMu.Unlock()
	atomicWritePathAllowlist = defaultAtomicWriteAllowlist()
}

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
//
// Path allowlist: Phase 2 carved out /etc/sftp-jailer/config.yaml; Phase 4
// adds /etc/default/ufw (D-FW-03) and /var/lib/sftp-jailer/ (D-S04-06).
// Writes outside the allowlist are rejected — see atomicWritePathAllowlist.
// Tests can extend via SetAtomicWriteAllowlistForTest.
func (r *Real) AtomicWriteFile(_ context.Context, path string, data []byte, mode fs.FileMode) error {
	if !isAllowedAtomicWritePath(path) {
		return fmt.Errorf("sysops.AtomicWriteFile: path not in allowlist: %q", path)
	}
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
