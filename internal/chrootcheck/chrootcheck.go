// Package chrootcheck verifies that a chroot directory chain satisfies
// sshd's StrictModes-equivalent rules: every component from / down to
// <chrootRoot> must be owned root:root, must NOT be group/other-writable,
// and must NOT be a symlink (sshd refuses symlinked chroot components per
// RESEARCH pitfall 6 / pitfall A6).
//
// The package is read-only by contract (D-10) — it never modifies file
// system state, only inspects. Callers translate Violations into UX
// (modal blocking, doctor warnings) and may invoke separate sysops
// mutations to remediate.
//
// Two public entry points:
//   - WalkRoot: D-10 path-walk validator from / to <chrootRoot>. Used by
//     M-APPLY-SETUP pre-flight (plan 03-06), M-NEW-USER pre-flight
//     (plan 03-07 via internal/txn), and CheckAuthKeysFile below.
//   - CheckAuthKeysFile (in strictmodes.go): D-21 steps 1+2 — file/dir
//     mode+owner verification PLUS path-walk down to authorized_keys.
//     Used by M-ADD-KEY post-write verifier (plan 03-08 via internal/txn).
//
// Steps 3 (re-parse the file) and 4 (sshd -T -C user=...) of D-21 are NOT
// in this package — they belong in the M-ADD-KEY caller because they
// involve reading file content / invoking sshd directly.
package chrootcheck

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// Violation describes a single chroot-chain component that fails sshd's
// chroot requirements. Reason is a complete admin-readable sentence
// including a remediation command the admin can copy-paste.
type Violation struct {
	Path   string // absolute path of the offending component
	Reason string // human sentence with remediation hint
}

// ErrTargetNotAbsolute is returned by WalkRoot when target is not an
// absolute path. Callers compare via errors.Is.
var ErrTargetNotAbsolute = errors.New("chrootcheck: target must be absolute path")

// WalkRoot walks every path component from / down to target, returning a
// Violation for each component that is NOT root-owned OR has group/other-
// write OR is a symlink. Empty slice = chain is clean.
//
// Uses Lstat (not Stat) so symlinks at any level are flagged rather than
// silently followed — matches sshd's chroot-component check semantics
// (pitfall 6).
//
// The walk is purely diagnostic: this function NEVER calls Chmod, Chown,
// AtomicWriteFile, or any other mutating sysops method (D-10 contract).
// The TestWalkRoot_read_only_invariant test pins this by asserting
// f.Calls contains only Lstat entries.
func WalkRoot(ctx context.Context, ops sysops.SystemOps, target string) ([]Violation, error) {
	if !filepath.IsAbs(target) {
		return nil, fmt.Errorf("%w: %q", ErrTargetNotAbsolute, target)
	}
	target = filepath.Clean(target)

	// Build ascending list of paths from / down to target.
	// For "/srv/sftp-jailer": ["/", "/srv", "/srv/sftp-jailer"].
	paths := []string{"/"}
	if target != "/" {
		parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
		acc := ""
		for _, p := range parts {
			if p == "" {
				continue
			}
			acc = acc + "/" + p
			paths = append(paths, acc)
		}
	}

	var violations []Violation
	for _, p := range paths {
		fi, err := ops.Lstat(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("chrootcheck: lstat %q: %w", p, err)
		}
		if fi.IsLink {
			violations = append(violations, Violation{
				Path:   p,
				Reason: fmt.Sprintf("%s is a symlink — sshd's chroot requires real directories at every component", p),
			})
			// Don't pile on more diagnostics for a symlink — the symlink
			// itself is the blocker; the admin will resolve it before the
			// other checks become meaningful.
			continue
		}
		if fi.UID != 0 || fi.GID != 0 {
			violations = append(violations, Violation{
				Path:   p,
				Reason: fmt.Sprintf("%s is owned uid=%d gid=%d (sshd requires root:root); fix with: sudo chown root:root %s", p, fi.UID, fi.GID, p),
			})
		}
		if fi.Mode&0o022 != 0 {
			violations = append(violations, Violation{
				Path:   p,
				Reason: fmt.Sprintf("%s has mode %#o (group/other-write); fix with: sudo chmod go-w %s", p, fi.Mode&fs.ModePerm, p),
			})
		}
	}
	return violations, nil
}
