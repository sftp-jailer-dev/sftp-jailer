package chrootcheck

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// CheckAuthKeysFile verifies sshd's StrictModes prerequisites for a per-
// user authorized_keys file (D-21 steps 1 and 2):
//
//  1. Path-walk from / down to <chrootRoot> — every component must be
//     root-owned, no group/other-write, no symlinks (delegates to
//     WalkRoot). This is the chroot-chain part that sshd's chroot check
//     enforces.
//  2. Per-user dir <chrootRoot>/<user> mode 0750 owner <user>:<user>
//     (matches D-12 / SETUP-05 — the chroot writable subdir per user).
//  3. .ssh/ dir mode 0700 owner <user>:<user>.
//  4. authorized_keys file mode 0600 owner <user>:<user>.
//
// Steps 3 (re-parse the file content) and 4 (sshd -T -C user=...) of the
// D-21 suite are out of scope for this package — they belong in the
// M-ADD-KEY caller (plan 03-08) because they involve reading file content
// and invoking sshd directly via SshdTWithContext.
//
// The user's UID and GID are looked up via the package-level userLookup
// seam (overridable in tests via SetUserLookupForTest). The function is
// fully read-only: it uses ops.Lstat for all metadata reads and never
// modifies any filesystem state.
func CheckAuthKeysFile(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]Violation, error) {
	u, err := userLookup(username)
	if err != nil {
		return nil, fmt.Errorf("chrootcheck.CheckAuthKeysFile: lookup %s: %w", username, err)
	}

	// 1. Path-walk from / down to <chrootRoot>. NOT including the per-user
	// subdir below — that subdir is intentionally user-owned (mode 0750)
	// and would be flagged as a violation by WalkRoot's root:root rule.
	walkVio, err := WalkRoot(ctx, ops, chrootRoot)
	if err != nil {
		return nil, err
	}
	violations := append([]Violation(nil), walkVio...)

	// 2-4. Per-user dir, .ssh dir, authorized_keys file.
	userDir := filepath.Join(chrootRoot, username)
	sshDir := filepath.Join(userDir, ".ssh")
	keysPath := filepath.Join(sshDir, "authorized_keys")

	if v, ok := checkPerUserDir(ctx, ops, userDir, u, 0o750); !ok {
		violations = append(violations, v)
	}
	if v, ok := checkPerUserDir(ctx, ops, sshDir, u, 0o700); !ok {
		violations = append(violations, v)
	}
	if v, ok := checkPerUserFile(ctx, ops, keysPath, u, 0o600); !ok {
		violations = append(violations, v)
	}
	return violations, nil
}

// checkPerUserDir verifies a directory has the expected mode + owner.
// Returns (Violation, false) on missing/wrong, (zero, true) on clean.
func checkPerUserDir(ctx context.Context, ops sysops.SystemOps, path string, u *userInfo, expectedMode fs.FileMode) (Violation, bool) {
	fi, err := ops.Lstat(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Violation{
				Path:   path,
				Reason: fmt.Sprintf("%s does not exist (run M-NEW-USER's mkdir step before adding keys)", path),
			}, false
		}
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s lstat error: %v", path, err),
		}, false
	}
	if fi.IsLink {
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s is a symlink — sshd's StrictModes refuses .ssh symlinks", path),
		}, false
	}
	if fi.Mode&fs.ModePerm != expectedMode {
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s has mode %#o, required %#o; fix with: sudo chmod %o %s", path, fi.Mode&fs.ModePerm, expectedMode, expectedMode, path),
		}, false
	}
	if fi.UID != u.UID || fi.GID != u.GID {
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s is owned uid=%d gid=%d, required %s:%s (uid=%d gid=%d); fix with: sudo chown %s:%s %s", path, fi.UID, fi.GID, u.Name, u.Name, u.UID, u.GID, u.Name, u.Name, path),
		}, false
	}
	return Violation{}, true
}

// checkPerUserFile is the file-mode variant. Same shape as checkPerUserDir
// but the missing-file message + lstat semantics differ slightly.
func checkPerUserFile(ctx context.Context, ops sysops.SystemOps, path string, u *userInfo, expectedMode fs.FileMode) (Violation, bool) {
	fi, err := ops.Lstat(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Violation{
				Path:   path,
				Reason: fmt.Sprintf("%s does not exist (no keys yet for %s)", path, u.Name),
			}, false
		}
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s lstat error: %v", path, err),
		}, false
	}
	if fi.Mode&fs.ModePerm != expectedMode {
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s has mode %#o, required %#o; fix with: sudo chmod %o %s", path, fi.Mode&fs.ModePerm, expectedMode, expectedMode, path),
		}, false
	}
	if fi.UID != u.UID || fi.GID != u.GID {
		return Violation{
			Path:   path,
			Reason: fmt.Sprintf("%s is owned uid=%d gid=%d, required %s (uid=%d gid=%d)", path, fi.UID, fi.GID, u.Name, u.UID, u.GID),
		}, false
	}
	return Violation{}, true
}

// userInfo is the minimal user-record shape this package needs. Indirection
// exists so tests can stub userLookup without involving the real os/user
// (which would require a real account on the test box).
type userInfo struct {
	Name string
	UID  uint32
	GID  uint32
}

// userLookup is a package-level variable so tests can override it. The
// production implementation calls os/user.Lookup via lookupOSUser (in
// oslookup.go). Tests use SetUserLookupForTest / ResetUserLookupForTest
// to inject a deterministic stub.
var userLookup = lookupOSUser
