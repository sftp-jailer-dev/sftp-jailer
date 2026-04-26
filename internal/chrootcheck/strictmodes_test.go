// Package chrootcheck_test (strictmodes) exercises CheckAuthKeysFile —
// D-21 steps 1 (file/dir mode + owner) and 2 (path-walk down to
// authorized_keys). Steps 3 (re-parse) and 4 (sshd -T -C) are the
// M-ADD-KEY caller's concern (plan 03-08) and are NOT in this package.
package chrootcheck_test

import (
	"context"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// withFakeUserLookup swaps chrootcheck's userLookup seam for a deterministic
// stub that returns the supplied uid/gid for the named user. Restored on
// test cleanup so parallel runs across this file don't leak.
func withFakeUserLookup(t *testing.T, name string, uid, gid uint32) {
	t.Helper()
	chrootcheck.SetUserLookupForTest(func(n string) (chrootcheck.UserInfoForTest, error) {
		return chrootcheck.UserInfoForTest{Name: n, UID: uid, GID: gid}, nil
	})
	t.Cleanup(chrootcheck.ResetUserLookupForTest)
}

// cleanUserChain returns the path-walk fixtures for a clean
// /, /srv, /srv/sftp-jailer, /srv/sftp-jailer/<user> chain.
// All path-walk components are root:root mode 0755 except <user> which is
// owned by the user uid/gid at mode 0750 (matches D-12 / SETUP-05).
func cleanUserChain(user string, uid, gid uint32) map[string]sysops.FileInfo {
	return map[string]sysops.FileInfo{
		"/":                fileInfo("/", 0o755, 0, 0, false),
		"/srv":             fileInfo("/srv", 0o755, 0, 0, false),
		"/srv/sftp-jailer": fileInfo("/srv/sftp-jailer", 0o755, 0, 0, false),
		"/srv/sftp-jailer/" + user: fileInfo("/srv/sftp-jailer/"+user, 0o750, uid, gid, false),
	}
}

// addSSH appends a clean .ssh directory + authorized_keys to the supplied
// chain at <chrootRoot>/<user>/.ssh/authorized_keys with mode 0700/0600.
func addSSH(stats map[string]sysops.FileInfo, user string, uid, gid uint32) {
	sshPath := "/srv/sftp-jailer/" + user + "/.ssh"
	keysPath := sshPath + "/authorized_keys"
	stats[sshPath] = fileInfo(sshPath, 0o700, uid, gid, false)
	stats[keysPath] = fileInfo(keysPath, 0o600, uid, gid, false)
}

func TestCheckAuthKeysFile(t *testing.T) {
	ctx := context.Background()
	user := "alice"
	chrootRoot := "/srv/sftp-jailer"
	uid, gid := uint32(2000), uint32(2000)

	tests := []struct {
		name           string
		setupStats     func() map[string]sysops.FileInfo
		expectErr      bool
		expectVioCount int
		// expectVio[i] = (pathSuffix, reasonSubstrings)
		expectVio []struct {
			pathSuffix string
			reasonSub  []string
		}
	}{
		{
			name: "all_perms_correct",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				addSSH(s, user, uid, gid)
				return s
			},
			expectVioCount: 0,
		},
		{
			name: "authkeys_file_mode_too_loose",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				addSSH(s, user, uid, gid)
				keysPath := "/srv/sftp-jailer/" + user + "/.ssh/authorized_keys"
				s[keysPath] = fileInfo(keysPath, 0o644, uid, gid, false)
				return s
			},
			expectVioCount: 1,
			expectVio: []struct {
				pathSuffix string
				reasonSub  []string
			}{
				{pathSuffix: "authorized_keys", reasonSub: []string{"mode", "600"}},
			},
		},
		{
			name: "authkeys_file_owned_by_root",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				addSSH(s, user, uid, gid)
				keysPath := "/srv/sftp-jailer/" + user + "/.ssh/authorized_keys"
				s[keysPath] = fileInfo(keysPath, 0o600, 0, 0, false)
				return s
			},
			expectVioCount: 1,
			expectVio: []struct {
				pathSuffix string
				reasonSub  []string
			}{
				{pathSuffix: "authorized_keys", reasonSub: []string{"owned", "alice"}},
			},
		},
		{
			name: "ssh_dir_mode_too_loose",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				addSSH(s, user, uid, gid)
				sshPath := "/srv/sftp-jailer/" + user + "/.ssh"
				s[sshPath] = fileInfo(sshPath, 0o750, uid, gid, false)
				return s
			},
			expectVioCount: 1,
			expectVio: []struct {
				pathSuffix string
				reasonSub  []string
			}{
				{pathSuffix: ".ssh", reasonSub: []string{"700"}},
			},
		},
		{
			name: "path_walk_violation_in_user_chain",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				addSSH(s, user, uid, gid)
				// Break /srv with group-write — path-walk should flag /srv
				s["/srv"] = fileInfo("/srv", 0o775, 0, 0, false)
				return s
			},
			// At least one violation from path-walk; per-file checks remain clean.
			expectVioCount: 1,
			expectVio: []struct {
				pathSuffix string
				reasonSub  []string
			}{
				{pathSuffix: "/srv", reasonSub: []string{"group/other-write"}},
			},
		},
		{
			name: "authkeys_missing",
			setupStats: func() map[string]sysops.FileInfo {
				s := cleanUserChain(user, uid, gid)
				// .ssh exists with correct perms; authorized_keys is missing.
				sshPath := "/srv/sftp-jailer/" + user + "/.ssh"
				s[sshPath] = fileInfo(sshPath, 0o700, uid, gid, false)
				return s
			},
			expectVioCount: 1,
			expectVio: []struct {
				pathSuffix string
				reasonSub  []string
			}{
				{pathSuffix: "authorized_keys", reasonSub: []string{"does not exist"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeUserLookup(t, user, uid, gid)

			f := makeFake(tt.setupStats())
			vios, err := chrootcheck.CheckAuthKeysFile(ctx, f, user, chrootRoot)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, vios, tt.expectVioCount, "violations: %+v", vios)
			for i, exp := range tt.expectVio {
				require.True(t, hasSuffix(vios[i].Path, exp.pathSuffix),
					"violation[%d].Path %q does not end with %q", i, vios[i].Path, exp.pathSuffix)
				for _, sub := range exp.reasonSub {
					require.Contains(t, vios[i].Reason, sub,
						"violation[%d].Reason missing %q", i, sub)
				}
			}
		})
	}
}

// TestCheckAuthKeysFile_lookup_failure verifies that a userLookup error
// surfaces as a non-nil error from the function (graceful early-return,
// no panic).
func TestCheckAuthKeysFile_lookup_failure(t *testing.T) {
	ctx := context.Background()
	chrootcheck.SetUserLookupForTest(func(name string) (chrootcheck.UserInfoForTest, error) {
		return chrootcheck.UserInfoForTest{}, fs.ErrNotExist
	})
	t.Cleanup(chrootcheck.ResetUserLookupForTest)

	f := makeFake(map[string]sysops.FileInfo{})
	_, err := chrootcheck.CheckAuthKeysFile(ctx, f, "ghost", "/srv/sftp-jailer")
	require.Error(t, err)
	require.Contains(t, err.Error(), "ghost")
}

// hasSuffix is a tiny helper kept local to avoid importing strings in test
// fixtures (golangci-lint flagged unused-import in earlier scaffolding).
func hasSuffix(s, suf string) bool {
	if len(s) < len(suf) {
		return false
	}
	return s[len(s)-len(suf):] == suf
}
