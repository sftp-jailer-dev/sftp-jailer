// Package chrootcheck_test exercises the D-10 path-walk validator that
// promotes Phase 1's internal/service/doctor.detectChrootChain pattern into
// a dedicated package. WalkRoot is read-only by contract — the
// read_only_invariant test asserts the validator never calls any mutating
// sysops method (no Chmod, no Chown, no AtomicWriteFile, etc.).
package chrootcheck_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// makeFake constructs a *sysops.Fake with the supplied path -> FileInfo
// fixtures pre-loaded into FileStats. Missing keys are surfaced by the
// fake's Lstat as fs.ErrNotExist (chrootcheck wraps that into a reason).
func makeFake(stats map[string]sysops.FileInfo) *sysops.Fake {
	f := sysops.NewFake()
	f.FileStats = stats
	return f
}

// fileInfo is a small constructor that hides the FileInfo struct shape from
// the test cases so they read as path/mode/uid/gid/isLink tuples.
func fileInfo(path string, mode fs.FileMode, uid, gid uint32, isLink bool) sysops.FileInfo {
	return sysops.FileInfo{
		Path:   path,
		Mode:   mode,
		UID:    uid,
		GID:    gid,
		IsDir:  !isLink,
		IsLink: isLink,
	}
}

// rootClean is the canonical "clean" / fixture (mode 0755 root:root) used
// by every WalkRoot test that doesn't deliberately break /.
func rootClean() sysops.FileInfo {
	return fileInfo("/", 0o755, 0, 0, false)
}

func TestWalkRoot(t *testing.T) {
	ctx := context.Background()
	target := "/srv/sftp-jailer"

	tests := []struct {
		name           string
		stats          map[string]sysops.FileInfo
		walkTarget     string // override target if non-empty
		expectErr      bool
		expectErrSub   string // substring match on err.Error()
		expectVioCount int
		expectVio      []struct {
			path      string
			reasonSub []string // substrings that MUST appear in Reason
		}
	}{
		{
			name: "clean_chain_no_violations",
			stats: map[string]sysops.FileInfo{
				"/":                rootClean(),
				"/srv":             fileInfo("/srv", 0o755, 0, 0, false),
				"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, false),
			},
			expectVioCount: 0,
		},
		{
			name: "group_write_at_srv",
			stats: map[string]sysops.FileInfo{
				"/":                rootClean(),
				"/srv":             fileInfo("/srv", 0o775, 0, 0, false),
				"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, false),
			},
			expectVioCount: 1,
			expectVio: []struct {
				path      string
				reasonSub []string
			}{
				{path: "/srv", reasonSub: []string{"group/other-write", "chmod go-w /srv"}},
			},
		},
		{
			name: "owned_by_non_root",
			stats: map[string]sysops.FileInfo{
				"/":                rootClean(),
				"/srv":             fileInfo("/srv", 0o755, 1000, 1000, false),
				"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, false),
			},
			expectVioCount: 1,
			expectVio: []struct {
				path      string
				reasonSub []string
			}{
				{path: "/srv", reasonSub: []string{"chown root:root /srv"}},
			},
		},
		{
			name: "symlink_at_chrootRoot",
			stats: map[string]sysops.FileInfo{
				"/":                rootClean(),
				"/srv":             fileInfo("/srv", 0o755, 0, 0, false),
				"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, true),
			},
			expectVioCount: 1,
			expectVio: []struct {
				path      string
				reasonSub []string
			}{
				{path: "/srv/sftp-jailer", reasonSub: []string{"symlink", "requires real directories"}},
			},
		},
		{
			name: "multiple_violations_in_chain",
			stats: map[string]sysops.FileInfo{
				"/":                rootClean(),
				"/srv":             fileInfo("/srv", 0o775, 0, 0, false), // group-write
				"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 1000, 1000, false),
			},
			expectVioCount: 2,
			expectVio: []struct {
				path      string
				reasonSub []string
			}{
				{path: "/srv", reasonSub: []string{"group/other-write"}},
				{path: "/srv/sftp-jailer", reasonSub: []string{"chown root:root /srv/sftp-jailer"}},
			},
		},
		{
			name: "missing_component_returns_error",
			stats: map[string]sysops.FileInfo{
				"/":    rootClean(),
				"/srv": fileInfo("/srv", 0o755, 0, 0, false),
				// "/srv/sftp-jailer" deliberately missing → Lstat returns fs.ErrNotExist
			},
			expectErr:    true,
			expectErrSub: "lstat",
		},
		{
			name:         "non_absolute_target_rejected",
			stats:        map[string]sysops.FileInfo{},
			walkTarget:   "relative/path",
			expectErr:    true,
			expectErrSub: "must be absolute",
		},
		{
			name: "root_only_target",
			stats: map[string]sysops.FileInfo{
				"/": rootClean(),
			},
			walkTarget:     "/",
			expectVioCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := makeFake(tt.stats)
			tgt := target
			if tt.walkTarget != "" {
				tgt = tt.walkTarget
			}
			vios, err := chrootcheck.WalkRoot(ctx, f, tgt)
			if tt.expectErr {
				require.Error(t, err)
				if tt.expectErrSub != "" {
					require.Contains(t, err.Error(), tt.expectErrSub)
				}
				require.Nil(t, vios)
				return
			}
			require.NoError(t, err)
			require.Len(t, vios, tt.expectVioCount, "violations: %+v", vios)
			for i, exp := range tt.expectVio {
				require.Equal(t, exp.path, vios[i].Path, "violation[%d].Path", i)
				for _, sub := range exp.reasonSub {
					require.Contains(t, vios[i].Reason, sub, "violation[%d].Reason missing %q", i, sub)
				}
			}
		})
	}
}

// TestWalkRoot_read_only_invariant locks down the D-10 contract: WalkRoot
// MUST NOT call any mutating sysops method. We assert by inspecting the
// recorded f.Calls and verifying every entry is Method=="Lstat".
func TestWalkRoot_read_only_invariant(t *testing.T) {
	ctx := context.Background()
	f := makeFake(map[string]sysops.FileInfo{
		"/":                rootClean(),
		"/srv":             fileInfo("/srv", 0o755, 0, 0, false),
		"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, false),
	})

	_, err := chrootcheck.WalkRoot(ctx, f, "/srv/sftp-jailer")
	require.NoError(t, err)

	require.NotEmpty(t, f.Calls, "WalkRoot should have called Lstat at least once")
	for _, c := range f.Calls {
		require.Equal(t, "Lstat", c.Method, "WalkRoot must only call Lstat — found %s call: %+v", c.Method, c.Args)
	}
}

// TestWalkRoot_ErrTargetNotAbsolute_isErrSentinel verifies callers can use
// errors.Is to branch on the well-known sentinel rather than string-matching.
func TestWalkRoot_ErrTargetNotAbsolute_isErrSentinel(t *testing.T) {
	ctx := context.Background()
	f := makeFake(map[string]sysops.FileInfo{})

	_, err := chrootcheck.WalkRoot(ctx, f, "not-absolute")
	require.Error(t, err)
	require.True(t, errors.Is(err, chrootcheck.ErrTargetNotAbsolute), "expected errors.Is(err, ErrTargetNotAbsolute) — got: %v", err)
}
