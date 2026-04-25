// Package users_test exercises the D-10 union enumeration (sftp* group ∪
// ChrootDirectory home users) plus the D-12 INFO pseudo-rows for
// orphan / missing-match / missing-chroot detection. All filesystem reads
// flow through sysops.Fake so the seam discipline is preserved end-to-end.
package users_test

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// fakeDirEntry is a minimal fs.DirEntry implementation used to seed
// sysops.Fake.DirEntries for orphan-row detection. Only Name() and IsDir()
// are exercised by users.Enumerate.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (e fakeDirEntry) Name() string               { return e.name }
func (e fakeDirEntry) IsDir() bool                { return e.isDir }
func (e fakeDirEntry) Type() fs.FileMode          { return 0 }
func (e fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// loadFixture reads testdata/<name>.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err, "fixture %s", name)
	return b
}

// newDB opens a tmp store + Queries wrapper for enrichment tests that need
// real LastLoginPerUser / FilterEvents results.
func newDB(t *testing.T) (*store.Store, *store.Queries) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s, store.NewQueries(s)
}

// insertObservation seeds one observations row via the writer handle. Used
// by the last-login enrichment test.
func insertObservation(t *testing.T, w *sql.DB, ts int64, tier, user, ip string) {
	t.Helper()
	_, err := w.ExecContext(context.Background(),
		`INSERT INTO observation_runs(started_at_unix_ns, finished_at_unix_ns, result)
		 VALUES (?, ?, 'success')`, ts-1, ts)
	require.NoError(t, err)
	_, err = w.ExecContext(context.Background(),
		`INSERT INTO observations(ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, pid, run_id)
		 VALUES (?, ?, ?, ?, 'login', 'msg', '{}', 0, last_insert_rowid())`,
		ts, tier, user, ip)
	require.NoError(t, err)
}

// seedBaseFakeFS plants /etc/group + /etc/passwd + the typical sshd drop-in
// in f.Files / f.GlobResults so the helpers below only need to override the
// pieces they care about.
func seedBaseFakeFS(t *testing.T, f *sysops.Fake) {
	t.Helper()
	f.Files["/etc/group"] = loadFixture(t, "etc-group-typical.txt")
	f.Files["/etc/passwd"] = loadFixture(t, "etc-passwd-typical.txt")
	f.GlobResults["/etc/ssh/sshd_config.d/*.conf"] = []string{
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
	}
	f.Files["/etc/ssh/sshd_config.d/50-sftp-jailer.conf"] = loadFixture(t, "sshd-config-with-chroot.txt")
}

// rowFor returns the row whose Username matches name, or fails the test.
func rowFor(t *testing.T, rows []users.Row, name string) users.Row {
	t.Helper()
	for _, r := range rows {
		if r.Username == name {
			return r
		}
	}
	t.Fatalf("no row for user %q in %#v", name, rows)
	return users.Row{}
}

// hasInfo reports whether infos contains a row with the given Kind.
func hasInfo(infos []users.InfoRow, kind users.InfoKind) bool {
	for _, i := range infos {
		if i.Kind == kind {
			return true
		}
	}
	return false
}

// TestEnumerate_returns_sftp_group_members: alice + bob (sftp-jailer) and
// carol (sftponly) appear; dave (other group) does NOT.
func TestEnumerate_returns_sftp_group_members(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	// Pre-script ufw so the per-user allowlist enrichment doesn't error out.
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}

	_, q := newDB(t)
	e := users.New(f, q)
	rows, infos, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	usernames := map[string]bool{}
	for _, r := range rows {
		usernames[r.Username] = true
	}
	require.True(t, usernames["alice"], "alice in sftp-jailer group must appear")
	require.True(t, usernames["bob"], "bob in sftp-jailer group must appear")
	require.True(t, usernames["carol"], "carol in sftponly group (sftp* prefix) must appear")
	require.False(t, usernames["dave"], "dave is in 'other' group only — must NOT appear")
	// Match Group sftp-jailer block IS present in the fixture; ChrootDirectory IS present.
	require.False(t, hasInfo(infos, users.InfoMissingMatch))
	require.False(t, hasInfo(infos, users.InfoMissingChroot))
}

// TestEnumerate_includes_chroot_home_users_via_sshdcfg: wendy is NOT in
// any sftp* group, but her home /srv/sftp/wendy sits under the
// ChrootDirectory /srv/sftp/%u — she must appear in the union.
func TestEnumerate_includes_chroot_home_users_via_sshdcfg(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}

	_, q := newDB(t)
	e := users.New(f, q)
	rows, _, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	wendy := rowFor(t, rows, "wendy")
	require.Equal(t, "/srv/sftp/wendy", wendy.HomePath)
}

// TestEnumerate_emits_orphan_info_rows: the chroot root contains "ghost"
// which has no /etc/passwd entry — emit an orphan InfoRow with the
// "[fix in Phase 3]" hint.
func TestEnumerate_emits_orphan_info_rows(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}
	// Chroot root is /srv/sftp (matches ChrootDirectory /srv/sftp/%u).
	f.DirEntries["/srv/sftp"] = []fs.DirEntry{
		fakeDirEntry{name: "alice", isDir: true},
		fakeDirEntry{name: "wendy", isDir: true},
		fakeDirEntry{name: "ghost", isDir: true},
	}

	_, q := newDB(t)
	e := users.New(f, q)
	_, infos, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	var orphan *users.InfoRow
	for i := range infos {
		if infos[i].Kind == users.InfoOrphan {
			orphan = &infos[i]
			break
		}
	}
	require.NotNil(t, orphan, "expected at least one orphan row, got infos=%#v", infos)
	require.Contains(t, orphan.Detail, "ghost")
	require.Equal(t, "[fix in Phase 3]", orphan.Hint)
}

// TestEnumerate_missing_match_group_info_row: drop-in has no Match Group
// sftp* block → InfoMissingMatch row emitted.
func TestEnumerate_missing_match_group_info_row(t *testing.T) {
	f := sysops.NewFake()
	f.Files["/etc/group"] = loadFixture(t, "etc-group-typical.txt")
	f.Files["/etc/passwd"] = loadFixture(t, "etc-passwd-typical.txt")
	f.GlobResults["/etc/ssh/sshd_config.d/*.conf"] = []string{
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
	}
	f.Files["/etc/ssh/sshd_config.d/50-sftp-jailer.conf"] = loadFixture(t, "sshd-config-no-match.txt")
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}

	_, q := newDB(t)
	e := users.New(f, q)
	_, infos, err := e.Enumerate(context.Background())
	require.NoError(t, err)
	require.True(t, hasInfo(infos, users.InfoMissingMatch),
		"no Match Group sftp* block → InfoMissingMatch expected, got %#v", infos)
}

// TestEnumerate_missing_chrootdir_info_row: a drop-in with no ChrootDirectory
// directive (anywhere) → InfoMissingChroot row emitted.
func TestEnumerate_missing_chrootdir_info_row(t *testing.T) {
	f := sysops.NewFake()
	f.Files["/etc/group"] = loadFixture(t, "etc-group-typical.txt")
	f.Files["/etc/passwd"] = loadFixture(t, "etc-passwd-typical.txt")
	f.GlobResults["/etc/ssh/sshd_config.d/*.conf"] = []string{
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
	}
	f.Files["/etc/ssh/sshd_config.d/50-sftp-jailer.conf"] = loadFixture(t, "sshd-config-no-match.txt")
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}

	_, q := newDB(t)
	e := users.New(f, q)
	_, infos, err := e.Enumerate(context.Background())
	require.NoError(t, err)
	require.True(t, hasInfo(infos, users.InfoMissingChroot),
		"no ChrootDirectory directive → InfoMissingChroot expected, got %#v", infos)
}

// TestEnumerate_enriches_with_last_login_from_queries: alice has a successful
// observation row at ts=1700; her enriched row carries LastLoginNs == 1700.
func TestEnumerate_enriches_with_last_login_from_queries(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}

	s, q := newDB(t)
	insertObservation(t, s.W, 1700, "success", "alice", "203.0.113.7")

	e := users.New(f, q)
	rows, _, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	alice := rowFor(t, rows, "alice")
	require.Equal(t, int64(1700), alice.LastLoginNs)
}

// TestEnumerate_enriches_with_allowlist_count_from_firewall: ufw fixture has
// 2 rules tagged user=alice; alice's row reports IPAllowlistCount == 2.
func TestEnumerate_enriches_with_allowlist_count_from_firewall(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    203.0.113.7                # sftpj:v=1:user=alice
[ 2] 22/tcp                     ALLOW IN    198.51.100.42              # sftpj:v=1:user=alice
[ 3] 22/tcp                     ALLOW IN    192.0.2.99                 # sftpj:v=1:user=bob
`),
		ExitCode: 0,
	}

	_, q := newDB(t)
	e := users.New(f, q)
	rows, _, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	alice := rowFor(t, rows, "alice")
	require.Equal(t, 2, alice.IPAllowlistCount)
	bob := rowFor(t, rows, "bob")
	require.Equal(t, 1, bob.IPAllowlistCount)
}

// TestEnumerate_authorized_keys_count_via_sysops_ReadFile: alice's
// authorized_keys file has 3 non-empty non-comment lines → KeysCount == 3.
// Carol's file is missing → KeysCount == 0.
func TestEnumerate_authorized_keys_count_via_sysops_ReadFile(t *testing.T) {
	f := sysops.NewFake()
	seedBaseFakeFS(t, f)
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout: []byte("Status: active\n"), ExitCode: 0,
	}
	f.Files["/srv/sftp/alice/.ssh/authorized_keys"] = []byte(
		"# my keys\n" +
			"ssh-ed25519 AAAA1 alice@laptop\n" +
			"\n" +
			"ssh-ed25519 AAAA2 alice@phone\n" +
			"# another comment\n" +
			"ssh-rsa AAAA3 alice@server\n",
	)
	// carol's file deliberately not seeded → ReadFile returns ErrNotExist.

	_, q := newDB(t)
	e := users.New(f, q)
	rows, _, err := e.Enumerate(context.Background())
	require.NoError(t, err)

	alice := rowFor(t, rows, "alice")
	require.Equal(t, 3, alice.KeysCount)
	carol := rowFor(t, rows, "carol")
	require.Equal(t, 0, carol.KeysCount, "missing authorized_keys → 0, not error")
}
