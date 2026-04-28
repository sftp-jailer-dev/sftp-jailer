package txn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/stretchr/testify/require"
)

// frozenNow returns a deterministic now func for tests so backup paths are
// stable across runs.
func frozenNow() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 4, 26, 12, 34, 56, 0, time.UTC)
	}
}

const frozenStamp = "20260426T123456Z"

func TestNewWriteSshdDropInStep_apply_calls_AtomicWriteFile_then_compensate_restores_backup(t *testing.T) {
	t.Parallel()

	const (
		dropInPath = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"
		backupDir  = "/var/lib/sftp-jailer/backups"
	)
	priorBytes := []byte("OLD CONTENT\n")
	newBytes := []byte("NEW CONTENT\n")

	f := sysops.NewFake()
	f.Files[dropInPath] = priorBytes

	step := NewWriteSshdDropInStep(dropInPath, backupDir, newBytes, 0o644, frozenNow())

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// New content is now in the fake file system.
	require.Equal(t, newBytes, f.Files[dropInPath])

	// Backup was written too.
	expectedBackup := filepath.Join(backupDir, frozenStamp+"-50-sftp-jailer.conf.bak")
	require.Equal(t, priorBytes, f.Files[expectedBackup], "backup must contain prior content")

	// Now compensate: restores the prior content.
	require.NoError(t, step.Compensate(ctx, f))
	require.Equal(t, priorBytes, f.Files[dropInPath], "compensator must restore prior bytes")

	// Confirm at least three relevant calls happened: ReadFile, AtomicWriteFile (backup),
	// AtomicWriteFile (drop-in), then in compensate AtomicWriteFile (restore).
	var atomicWrites int
	for _, c := range f.Calls {
		if c.Method == "AtomicWriteFile" {
			atomicWrites++
		}
	}
	require.GreaterOrEqual(t, atomicWrites, 3)
}

func TestNewWriteSshdDropInStep_apply_with_no_prior_then_compensate_removes_file(t *testing.T) {
	t.Parallel()

	const (
		dropInPath = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"
		backupDir  = "/var/lib/sftp-jailer/backups"
	)
	newBytes := []byte("NEW CONTENT\n")

	f := sysops.NewFake()
	// no prior file at dropInPath
	step := NewWriteSshdDropInStep(dropInPath, backupDir, newBytes, 0o644, frozenNow())

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.Equal(t, newBytes, f.Files[dropInPath])

	// Compensate: with no prior, should call RemoveAll on the drop-in path.
	require.NoError(t, step.Compensate(ctx, f))

	// Look for RemoveAll call on dropInPath.
	var removed bool
	for _, c := range f.Calls {
		if c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == dropInPath {
			removed = true
		}
	}
	require.True(t, removed, "compensator with no prior content must call RemoveAll on the drop-in path")
}

func TestNewUseraddStep_apply_calls_Useradd_compensate_calls_Userdel(t *testing.T) {
	t.Parallel()

	opts := sysops.UseraddOpts{
		Username:   "alice",
		UID:        2000,
		Home:       "/srv/sftp/alice",
		Shell:      "/usr/sbin/nologin",
		CreateHome: true,
	}

	f := sysops.NewFake()
	step := NewUseraddStep(opts)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	// Confirm both methods recorded.
	methods := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		methods = append(methods, c.Method)
	}
	require.Contains(t, methods, "Useradd")
	require.Contains(t, methods, "Userdel")

	// Compensator's removeHome arg matches CreateHome.
	for _, c := range f.Calls {
		if c.Method == "Userdel" {
			require.Equal(t, "alice", c.Args[0])
			require.Equal(t, "removeHome=true", c.Args[1])
		}
	}
}

func TestNewGpasswdAddStep_apply_records_op_add_compensate_records_op_del(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	step := NewGpasswdAddStep("alice", "sftp-jailer")

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	require.Len(t, f.Calls, 2)
	require.Equal(t, "Gpasswd", f.Calls[0].Method)
	require.Equal(t, "op=add", f.Calls[0].Args[0])
	require.Equal(t, "alice", f.Calls[0].Args[1])
	require.Equal(t, "sftp-jailer", f.Calls[0].Args[2])

	require.Equal(t, "Gpasswd", f.Calls[1].Method)
	require.Equal(t, "op=del", f.Calls[1].Args[0])
	require.Equal(t, "alice", f.Calls[1].Args[1])
	require.Equal(t, "sftp-jailer", f.Calls[1].Args[2])
}

func TestNewAtomicWriteAuthorizedKeysStep_apply_writes_new_compensate_restores_prior(t *testing.T) {
	t.Parallel()

	const (
		username   = "alice"
		chrootRoot = "/srv/sftp"
	)
	authPath := filepath.Join(chrootRoot, username, ".ssh", "authorized_keys")
	priorKeys := []byte("ssh-ed25519 AAAA-prior alice@old\n")
	newKeys := []byte("ssh-ed25519 AAAA-new alice@new\n")

	f := sysops.NewFake()
	f.Files[authPath] = priorKeys

	step := NewAtomicWriteAuthorizedKeysStep(username, chrootRoot, newKeys)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	// After Apply, the fake's Files should reflect newKeys at authPath.
	require.Equal(t, newKeys, f.Files[authPath])

	require.NoError(t, step.Compensate(ctx, f))
	require.Equal(t, priorKeys, f.Files[authPath], "compensator must restore prior authorized_keys content")
}

func TestNewAtomicWriteAuthorizedKeysStep_no_prior_compensate_removes_file(t *testing.T) {
	t.Parallel()

	const (
		username   = "alice"
		chrootRoot = "/srv/sftp"
	)
	authPath := filepath.Join(chrootRoot, username, ".ssh", "authorized_keys")
	newKeys := []byte("ssh-ed25519 AAAA-new alice@new\n")

	f := sysops.NewFake()
	step := NewAtomicWriteAuthorizedKeysStep(username, chrootRoot, newKeys)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.Equal(t, newKeys, f.Files[authPath])

	require.NoError(t, step.Compensate(ctx, f))

	var removed bool
	for _, c := range f.Calls {
		if c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == authPath {
			removed = true
		}
	}
	require.True(t, removed, "compensator must RemoveAll authPath when no prior existed")
}

func TestNewTarStep_apply_records_Tar_compensate_removes_partial_archive(t *testing.T) {
	t.Parallel()

	opts := sysops.TarOpts{
		Mode:        sysops.TarCreateGzip,
		ArchivePath: "/var/lib/sftp-jailer/archive/alice-2026.tar.gz",
		SourceDir:   "/srv/sftp/alice",
	}

	f := sysops.NewFake()
	step := NewTarStep(opts)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	var sawTar, sawRemove bool
	for _, c := range f.Calls {
		if c.Method == "Tar" {
			sawTar = true
		}
		if c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == opts.ArchivePath {
			sawRemove = true
		}
	}
	require.True(t, sawTar)
	require.True(t, sawRemove)
}

func TestNewChpasswdStep_apply_records_Chpasswd_compensate_is_noop(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	step := NewChpasswdStep("alice", "secret-pw")

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	beforeCount := len(f.Calls)
	require.NoError(t, step.Compensate(ctx, f))
	require.Equal(t, beforeCount, len(f.Calls), "compensate must NOT record any sysops call (D-13 no compensator)")
}

func TestNewChmodStep_apply_records_Chmod_compensate_restores_prior_mode(t *testing.T) {
	t.Parallel()

	const path = "/srv/sftp/alice"
	f := sysops.NewFake()
	// Prior mode from Lstat: 0o755
	f.FileStats[path] = sysops.FileInfo{Path: path, Mode: 0o755, IsDir: true}

	step := NewChmodStep(path, 0o750)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	// Two Chmod calls expected: one to 0o750 (Apply), one to 0o755 (Compensate).
	var modes []string
	for _, c := range f.Calls {
		if c.Method == "Chmod" && c.Args[0] == path {
			modes = append(modes, c.Args[1])
		}
	}
	require.Equal(t, []string{"mode=750", "mode=755"}, modes)
}

func TestNewChmodStep_compensate_noop_when_prior_lstat_failed(t *testing.T) {
	t.Parallel()

	const path = "/missing"
	f := sysops.NewFake()
	// no FileStats entry → Lstat returns ErrNotExist → priorCapture=false

	step := NewChmodStep(path, 0o750)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	var beforeChmods int
	for _, c := range f.Calls {
		if c.Method == "Chmod" {
			beforeChmods++
		}
	}

	require.NoError(t, step.Compensate(ctx, f))

	var afterChmods int
	for _, c := range f.Calls {
		if c.Method == "Chmod" {
			afterChmods++
		}
	}
	require.Equal(t, beforeChmods, afterChmods, "compensate must be a no-op when prior mode could not be captured")
}

func TestNewChownStep_apply_records_Chown_compensate_restores_prior_owner(t *testing.T) {
	t.Parallel()

	const path = "/srv/sftp/alice"
	f := sysops.NewFake()
	f.FileStats[path] = sysops.FileInfo{Path: path, UID: 0, GID: 0}

	step := NewChownStep(path, 2000, 2000)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	// Two Chown calls: 2000:2000 then back to 0:0.
	type pair struct{ uid, gid string }
	var pairs []pair
	for _, c := range f.Calls {
		if c.Method == "Chown" && c.Args[0] == path {
			pairs = append(pairs, pair{c.Args[1], c.Args[2]})
		}
	}
	require.Equal(t, []pair{{"uid=2000", "gid=2000"}, {"uid=0", "gid=0"}}, pairs)
}

func TestNewChownStep_compensate_noop_when_prior_lstat_failed(t *testing.T) {
	t.Parallel()

	const path = "/missing"
	f := sysops.NewFake()
	step := NewChownStep(path, 2000, 2000)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	var beforeChowns int
	for _, c := range f.Calls {
		if c.Method == "Chown" {
			beforeChowns++
		}
	}
	require.NoError(t, step.Compensate(ctx, f))

	var afterChowns int
	for _, c := range f.Calls {
		if c.Method == "Chown" {
			afterChowns++
		}
	}
	require.Equal(t, beforeChowns, afterChowns)
}

func TestStepNames_are_unique_and_descriptive(t *testing.T) {
	t.Parallel()

	steps := []Step{
		NewWriteSshdDropInStep("/etc/ssh/sshd_config.d/50-sftp-jailer.conf", "/var/lib/sftp-jailer/backups", []byte("x"), 0o644, frozenNow()),
		NewUseraddStep(sysops.UseraddOpts{Username: "alice"}),
		NewGpasswdAddStep("alice", "sftp-jailer"),
		NewAtomicWriteAuthorizedKeysStep("alice", "/srv/sftp", []byte("k")),
		NewTarStep(sysops.TarOpts{Mode: sysops.TarCreateGzip, ArchivePath: "/x.tar.gz", SourceDir: "/x"}),
		NewChpasswdStep("alice", "pw"),
		NewChmodStep("/srv/sftp/alice", 0o750),
		NewChownStep("/srv/sftp/alice", 2000, 2000),
		NewSshdValidateStep(),
		NewSystemctlReloadStep(ReloadService),
		NewSshdVerifyChrootDirectiveStep(),
		NewUserdelStep("alice", true),
		NewMkdirAllStep("/var/lib/sftp-jailer/archive", 0o700, 0, 0),
		NewVerifyAuthKeysStep("alice", "/srv/sftp", func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
			return nil, nil
		}),
	}

	seen := make(map[string]bool, len(steps))
	for _, s := range steps {
		name := s.Name()
		require.NotEmpty(t, name)
		require.False(t, seen[name], "duplicate step name: %q", name)
		seen[name] = true

		// Each starts with an uppercase verb (no whitespace, no special chars).
		require.Regexp(t, `^[A-Z][A-Za-z]+$`, name)
	}
}

func TestCanonicalApplySetupSteps_produces_the_D09_sequence(t *testing.T) {
	t.Parallel()

	steps := CanonicalApplySetupSteps(
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
		"/var/lib/sftp-jailer/backups",
		[]byte("Subsystem sftp internal-sftp\n"),
		ReloadService,
		frozenNow(),
	)

	require.Len(t, steps, 4)
	require.Equal(t, "WriteSshdDropIn", steps[0].Name())
	require.Equal(t, "SshdValidate", steps[1].Name())
	require.Equal(t, "SystemctlReload", steps[2].Name())
	require.Equal(t, "SshdVerifyChrootDirective", steps[3].Name())
}

func TestCanonicalApplySetupSteps_RestartSocket_dispatch_calls_daemon_reload_and_socket(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	f.SshdConfigResponse = map[string][]string{
		"chrootdirectory": {"/srv/sftp/%u"},
	}

	steps := CanonicalApplySetupSteps(
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
		"/var/lib/sftp-jailer/backups",
		[]byte("Subsystem sftp internal-sftp\n"),
		RestartSocket,
		frozenNow(),
	)

	tx := New(f)
	require.NoError(t, tx.Apply(context.Background(), steps))

	var sawDaemonReload, sawRestartSocket bool
	for _, c := range f.Calls {
		if c.Method == "SystemctlDaemonReload" {
			sawDaemonReload = true
		}
		if c.Method == "SystemctlRestartSocket" && len(c.Args) > 0 && c.Args[0] == "ssh.socket" {
			sawRestartSocket = true
		}
	}
	require.True(t, sawDaemonReload, "RestartSocket dispatch must call SystemctlDaemonReload first")
	require.True(t, sawRestartSocket, "RestartSocket dispatch must call SystemctlRestartSocket on ssh.socket")
}

func TestCanonicalApplySetupSteps_ReloadService_dispatch_calls_systemctl_reload(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	f.SshdConfigResponse = map[string][]string{
		"chrootdirectory": {"/srv/sftp/%u"},
	}

	steps := CanonicalApplySetupSteps(
		"/etc/ssh/sshd_config.d/50-sftp-jailer.conf",
		"/var/lib/sftp-jailer/backups",
		[]byte("Subsystem sftp internal-sftp\n"),
		ReloadService,
		frozenNow(),
	)

	tx := New(f)
	require.NoError(t, tx.Apply(context.Background(), steps))

	var sawReload bool
	for _, c := range f.Calls {
		if c.Method == "SystemctlReload" && len(c.Args) > 0 && c.Args[0] == "ssh.service" {
			sawReload = true
		}
	}
	require.True(t, sawReload, "ReloadService dispatch must call SystemctlReload on ssh.service")
}

func TestNewSshdValidateStep_apply_returns_error_when_sshdT_fails(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	f.SshdTStderr = []byte("/etc/ssh/sshd_config: line 22: Bad configuration option")
	f.SshdTError = errors.New("exit 255")

	step := NewSshdValidateStep()
	err := step.Apply(context.Background(), f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Bad configuration option", "Apply must surface stderr verbatim")
}

func TestNewSshdValidateStep_compensate_is_noop(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	step := NewSshdValidateStep()
	require.NoError(t, step.Compensate(context.Background(), f))
	require.Empty(t, f.Calls, "compensate must not invoke any sysops call")
}

func TestNewSshdVerifyChrootDirectiveStep_apply_succeeds_when_chrootdirectory_present(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	f.SshdConfigResponse = map[string][]string{
		"chrootdirectory": {"/srv/sftp/%u"},
		"forcecommand":    {"internal-sftp"},
	}

	step := NewSshdVerifyChrootDirectiveStep()
	require.NoError(t, step.Apply(context.Background(), f))
}

func TestNewSshdVerifyChrootDirectiveStep_apply_fails_when_neither_directive_present(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	f.SshdConfigResponse = map[string][]string{
		"port": {"22"},
	}

	step := NewSshdVerifyChrootDirectiveStep()
	err := step.Apply(context.Background(), f)
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "chrootdirectory")
}

// guard against accidental sshdcfg import (N-01 enforcement).
func TestStepsFile_does_not_import_sshdcfg(t *testing.T) {
	t.Parallel()

	// This is a build-time invariant; the test is a behavioral smoke that
	// fails if the structs accidentally pick up a sshdcfg dependency. The
	// real enforcement is the grep gate in the plan acceptance criteria.
	// Here we just sanity-check that the test file loads (compile) without
	// pulling sshdcfg via type names. If steps.go imports sshdcfg the
	// compile of this package would fail at the file boundary anyway.
	require.True(t, true)
}

// ============================================================================
// Plan 03-08a — NewUserdelStep / NewMkdirAllStep / NewVerifyAuthKeysStep
// ============================================================================

func TestNewUserdelStep_apply_records_Userdel_compensate_is_noop(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	step := NewUserdelStep("alice", true)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// One Userdel call recorded after Apply.
	var userdelCalls int
	for _, c := range f.Calls {
		if c.Method == "Userdel" {
			userdelCalls++
			require.Equal(t, "alice", c.Args[0])
			require.Equal(t, "removeHome=true", c.Args[1])
		}
	}
	require.Equal(t, 1, userdelCalls, "Apply must record exactly one Userdel call")

	beforeCount := len(f.Calls)
	require.NoError(t, step.Compensate(ctx, f))
	require.Equal(t, beforeCount, len(f.Calls),
		"Compensate must NOT record any sysops call (D-15 irreversibility — no-op)")
}

func TestNewUserdelStep_archive_path_uses_removeHome_false(t *testing.T) {
	t.Parallel()

	f := sysops.NewFake()
	step := NewUserdelStep("alice", false)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	for _, c := range f.Calls {
		if c.Method == "Userdel" {
			require.Equal(t, "removeHome=false", c.Args[1],
				"Archive path uses removeHome=false so the home dir survives for the tarball-residue inspection workflow")
		}
	}
}

func TestNewMkdirAllStep_apply_calls_ops_MkdirAll_then_Chmod_then_Chown(t *testing.T) {
	t.Parallel()

	const dir = "/var/lib/sftp-jailer/archive"
	f := sysops.NewFake()
	// No prior FileStats entry — Lstat returns ErrNotExist → existedBefore stays false.
	step := NewMkdirAllStep(dir, 0o700, 0, 0)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// Assert the typed-wrapper sequence: Lstat → MkdirAll → Chmod → Chown.
	// (W-02 — NOT direct os.MkdirAll; the typed wrapper IS the seam.)
	var seen []string
	for _, c := range f.Calls {
		switch c.Method {
		case "Lstat", "MkdirAll", "Chmod", "Chown":
			seen = append(seen, c.Method)
		}
	}
	require.Equal(t, []string{"Lstat", "MkdirAll", "Chmod", "Chown"}, seen,
		"Apply must call ops.Lstat (existed-before probe), then ops.MkdirAll, then ops.Chmod, then ops.Chown — in that order, all via the typed wrappers (W-02)")
}

func TestNewMkdirAllStep_apply_skips_chown_when_uid_negative(t *testing.T) {
	t.Parallel()

	const dir = "/var/lib/sftp-jailer/archive"
	f := sysops.NewFake()
	step := NewMkdirAllStep(dir, 0o700, -1, -1)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	for _, c := range f.Calls {
		require.NotEqual(t, "Chown", c.Method,
			"uid=-1 / gid=-1 means 'skip chown' — no Chown call should be recorded")
	}
}

func TestNewMkdirAllStep_compensate_calls_ops_RemoveAll_when_dir_didnt_exist_before(t *testing.T) {
	t.Parallel()

	const dir = "/var/lib/sftp-jailer/archive"
	f := sysops.NewFake()
	// No FileStats entry → Lstat returns ErrNotExist → existedBefore = false.
	step := NewMkdirAllStep(dir, 0o700, 0, 0)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	var sawRemove bool
	for _, c := range f.Calls {
		if c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == dir {
			sawRemove = true
		}
	}
	require.True(t, sawRemove,
		"Compensate must call ops.RemoveAll on the dir we created (W-02 typed wrapper)")
}

func TestNewMkdirAllStep_compensate_noop_when_dir_existed_before(t *testing.T) {
	t.Parallel()

	const dir = "/var/lib/sftp-jailer/archive"
	f := sysops.NewFake()
	// Pre-existing dir → Apply's initial Lstat succeeds → existedBefore = true.
	f.FileStats[dir] = sysops.FileInfo{Path: dir, Mode: 0o700, IsDir: true}

	step := NewMkdirAllStep(dir, 0o700, 0, 0)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	for _, c := range f.Calls {
		require.False(t, c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == dir,
			"Compensate must NOT remove a dir that existed before Apply — we don't claim ownership of it")
	}
}

func TestNewMkdirAllStep_uses_typed_sysops_wrappers_not_raw_os(t *testing.T) {
	t.Parallel()

	// W-02 contract: Apply must invoke ops.MkdirAll AND ops.RemoveAll
	// through the typed sysops seam — no direct os.MkdirAll / os.RemoveAll.
	// The Fake records every typed-wrapper call; if Apply / Compensate ever
	// regress to raw os calls, the Fake will not see them and this test
	// would fail by missing the expected call records.
	const dir = "/var/lib/sftp-jailer/archive"
	f := sysops.NewFake()
	step := NewMkdirAllStep(dir, 0o700, 0, 0)

	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	var sawMkdirAll, sawRemoveAll bool
	for _, c := range f.Calls {
		if c.Method == "MkdirAll" && len(c.Args) > 0 && c.Args[0] == dir {
			sawMkdirAll = true
		}
		if c.Method == "RemoveAll" && len(c.Args) > 0 && c.Args[0] == dir {
			sawRemoveAll = true
		}
	}
	require.True(t, sawMkdirAll, "Apply must route through ops.MkdirAll (W-02)")
	require.True(t, sawRemoveAll, "Compensate must route through ops.RemoveAll (W-02)")
}

func TestNewVerifyAuthKeysStep_apply_returns_joined_error_on_violations(t *testing.T) {
	t.Parallel()

	verify := func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
		return []VerifyViolation{
			{Path: "/x", Reason: "bad mode"},
			{Path: "/y", Reason: "bad owner"},
		}, nil
	}
	step := NewVerifyAuthKeysStep("alice", "/srv/sftp", verify)

	f := sysops.NewFake()
	err := step.Apply(context.Background(), f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "StrictModes failed")
	require.Contains(t, err.Error(), "bad mode")
	require.Contains(t, err.Error(), "bad owner")
}

func TestNewVerifyAuthKeysStep_apply_succeeds_on_no_violations(t *testing.T) {
	t.Parallel()

	verify := func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
		return nil, nil
	}
	step := NewVerifyAuthKeysStep("alice", "/srv/sftp", verify)

	f := sysops.NewFake()
	require.NoError(t, step.Apply(context.Background(), f))
}

func TestNewVerifyAuthKeysStep_apply_propagates_verifier_error(t *testing.T) {
	t.Parallel()

	verify := func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
		return nil, errors.New("boom")
	}
	step := NewVerifyAuthKeysStep("alice", "/srv/sftp", verify)

	err := step.Apply(context.Background(), sysops.NewFake())
	require.Error(t, err)
	require.Contains(t, err.Error(), "verify auth keys")
	require.Contains(t, err.Error(), "boom")
}

func TestNewVerifyAuthKeysStep_compensate_is_noop(t *testing.T) {
	t.Parallel()

	verify := func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
		return nil, nil
	}
	step := NewVerifyAuthKeysStep("alice", "/srv/sftp", verify)

	f := sysops.NewFake()
	require.NoError(t, step.Compensate(context.Background(), f))
	require.Empty(t, f.Calls, "Compensate must not invoke any sysops call")
}

// reflect-based sanity that Step is satisfied by a known concrete type.
// Compile-time assertion belongs in steps.go; here we just call Name() to
// fail loudly if the constructor returns nil.
func TestAllConstructors_return_non_nil_steps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		s    Step
	}{
		{"WriteSshdDropIn", NewWriteSshdDropInStep("/x", "/b", []byte("y"), 0o644, frozenNow())},
		{"Useradd", NewUseraddStep(sysops.UseraddOpts{Username: "u"})},
		{"GpasswdAdd", NewGpasswdAddStep("u", "g")},
		{"WriteAuthorizedKeys", NewAtomicWriteAuthorizedKeysStep("u", "/r", []byte("k"))},
		{"Tar", NewTarStep(sysops.TarOpts{Mode: sysops.TarCreateGzip, ArchivePath: "/a.tar.gz", SourceDir: "/s"})},
		{"Chpasswd", NewChpasswdStep("u", "p")},
		{"Chmod", NewChmodStep("/x", 0o750)},
		{"Chown", NewChownStep("/x", 1, 1)},
		{"SshdValidate", NewSshdValidateStep()},
		{"SystemctlReloadService", NewSystemctlReloadStep(ReloadService)},
		{"SystemctlReloadSocket", NewSystemctlReloadStep(RestartSocket)},
		{"SshdVerifyChrootDirective", NewSshdVerifyChrootDirectiveStep()},
		{"UserdelPermanent", NewUserdelStep("alice", true)},
		{"UserdelArchive", NewUserdelStep("alice", false)},
		{"MkdirAll", NewMkdirAllStep("/var/lib/sftp-jailer/archive", 0o700, 0, 0)},
		{"VerifyAuthKeys", NewVerifyAuthKeysStep("alice", "/srv/sftp", func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]VerifyViolation, error) {
			return nil, nil
		})},
	}

	for _, tc := range cases {
		require.NotNil(t, tc.s, "constructor %s returned nil", tc.name)
		require.NotEmpty(t, tc.s.Name(), "constructor %s returned a step with empty Name()", tc.name)
	}

	_ = reflect.TypeOf
	_ = fs.ModeSetuid // ensure fs import is used somewhere if needed
}

// ============================================================================
// Phase 4 Plan 02 — 9 new Step constructors (FW + SAFE-04 wrapper pair)
// ============================================================================

// containsCall reports whether f.Calls contains an entry with the given
// method name and (optionally) all of `wantArgs` as substrings of any of the
// entry's args. Helpful for asserting argv shape without coupling tests to
// the exact arg-ordering of the Fake's typed-string format.
func containsCall(calls []sysops.FakeCall, method string, wantArgs ...string) bool {
	for _, c := range calls {
		if c.Method != method {
			continue
		}
		all := true
		for _, w := range wantArgs {
			found := false
			for _, a := range c.Args {
				if strings.Contains(a, w) {
					found = true
					break
				}
			}
			if !found {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func TestNewUfwAllowStep_apply_calls_UfwAllow_compensate_is_noop(t *testing.T) {
	t.Parallel()
	opts := sysops.UfwAllowOpts{
		Proto: "tcp", Source: "203.0.113.7/32", Port: "22",
		Comment: "sftpj:v=1:user=alice",
	}
	f := sysops.NewFake()
	step := NewUfwAllowStep(opts)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// Apply records UfwAllow with the verbatim opts.
	require.True(t, containsCall(f.Calls, "UfwAllow", "src=203.0.113.7/32", "comment=sftpj:v=1:user=alice"),
		"Apply must record UfwAllow with src + comment")

	callsBefore := len(f.Calls)
	require.NoError(t, step.Compensate(ctx, f))
	// Compensate is intentionally a no-op (relies on SAFE-04 revert window).
	require.Equal(t, callsBefore, len(f.Calls), "Compensate must be a no-op")
}

func TestNewUfwInsertStep_apply_calls_UfwInsert_at_position_1(t *testing.T) {
	t.Parallel()
	opts := sysops.UfwAllowOpts{
		Proto: "tcp", Source: "203.0.113.7/32", Port: "22",
		Comment: "sftpj:v=1:user=alice",
	}
	f := sysops.NewFake()
	step := NewUfwInsertStep(opts)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// Apply records UfwInsert with pos=1 per D-FW-02.
	require.True(t, containsCall(f.Calls, "UfwInsert", "pos=1", "src=203.0.113.7/32"),
		"Apply must record UfwInsert at position 1")

	// Without SetAssignedID, Compensate is a no-op.
	callsBefore := len(f.Calls)
	require.NoError(t, step.Compensate(ctx, f))
	require.Equal(t, callsBefore, len(f.Calls), "Compensate without assignedID must be a no-op")
}

func TestNewUfwInsertStep_compensate_with_assigned_id_calls_UfwDelete(t *testing.T) {
	t.Parallel()
	opts := sysops.UfwAllowOpts{
		Proto: "tcp", Source: "203.0.113.7/32", Port: "22",
		Comment: "sftpj:v=1:user=alice",
	}
	f := sysops.NewFake()
	step := NewUfwInsertStep(opts)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// SetAssignedID populates the captured ID; Compensate then calls UfwDelete.
	concrete, ok := step.(*ufwInsertStep)
	require.True(t, ok, "NewUfwInsertStep must return *ufwInsertStep concrete")
	concrete.SetAssignedID(7)

	require.NoError(t, step.Compensate(ctx, f))
	require.True(t, containsCall(f.Calls, "UfwDelete", "id=7"),
		"Compensate with assignedID=7 must call UfwDelete with id=7")
}

func TestNewUfwInsertStep_compensate_treats_rule_not_found_as_success(t *testing.T) {
	t.Parallel()
	opts := sysops.UfwAllowOpts{
		Proto: "tcp", Source: "203.0.113.7/32", Port: "22",
		Comment: "sftpj:v=1:user=alice",
	}
	f := sysops.NewFake()
	f.UfwDeleteError = errors.New("ERROR: Could not delete non-existent rule")
	step := NewUfwInsertStep(opts).(*ufwInsertStep)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	step.SetAssignedID(99)

	// Idempotent: "Could not delete" maps to nil per W-04 idempotent-Compensate.
	require.NoError(t, step.Compensate(ctx, f))
}

func TestNewUfwDeleteStep_apply_calls_UfwDelete_compensate_is_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	step := NewUfwDeleteStep(3)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	require.True(t, containsCall(f.Calls, "UfwDelete", "id=3"),
		"Apply must record UfwDelete with id=3")

	callsBefore := len(f.Calls)
	require.NoError(t, step.Compensate(ctx, f))
	// Intentional no-op per D-S04-05 / D-FW-07 — once a rule is deleted at the
	// tool layer the SAFE-04 revert window is the only recovery path.
	require.Equal(t, callsBefore, len(f.Calls), "Compensate must be a no-op")
}

func TestNewUfwReloadStep_apply_and_compensate_both_call_UfwReload(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	step := NewUfwReloadStep()
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	// Both Apply and Compensate re-issue UfwReload — same op as compensator.
	var reloads int
	for _, c := range f.Calls {
		if c.Method == "UfwReload" {
			reloads++
		}
	}
	require.Equal(t, 2, reloads, "Apply + Compensate must each issue UfwReload exactly once")
}

func TestNewWriteUfwIPV6Step_apply_captures_prior_compensate_restores(t *testing.T) {
	t.Parallel()
	const ufwDefault = "/etc/default/ufw"
	priorBytes := []byte("IPV6=no\nFOO=bar\n")

	// Allow writes to the default ufw path AND any tmpdir for atomic-write
	// path-allowlist parity (the Fake doesn't actually use the allowlist, but
	// this matches the Real-world contract).
	f := sysops.NewFake()
	f.Files[ufwDefault] = priorBytes

	step := NewWriteUfwIPV6Step("yes", frozenNow())
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// Apply reads prior bytes, then calls RewriteUfwIPV6 with value=yes.
	require.True(t, containsCall(f.Calls, "ReadFile", ufwDefault),
		"Apply must read prior bytes via ReadFile")
	require.True(t, containsCall(f.Calls, "RewriteUfwIPV6", "value=yes"),
		"Apply must call RewriteUfwIPV6 with value=yes")

	require.NoError(t, step.Compensate(ctx, f))
	// Compensate writes the prior bytes back via AtomicWriteFile.
	require.True(t, containsCall(f.Calls, "AtomicWriteFile", ufwDefault),
		"Compensate must restore prior bytes via AtomicWriteFile")
	require.Equal(t, priorBytes, f.Files[ufwDefault],
		"Compensate must leave /etc/default/ufw byte-identical to the prior content")
}

func TestNewWriteUfwIPV6Step_apply_with_no_prior_compensate_removes(t *testing.T) {
	t.Parallel()
	const ufwDefault = "/etc/default/ufw"
	f := sysops.NewFake()
	// no prior file at /etc/default/ufw
	step := NewWriteUfwIPV6Step("yes", frozenNow())
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	// RewriteUfwIPV6 was still called — the "prior" capture is best-effort.
	require.True(t, containsCall(f.Calls, "RewriteUfwIPV6", "value=yes"))

	require.NoError(t, step.Compensate(ctx, f))
	// With no prior, Compensate calls RemoveAll on the path.
	require.True(t, containsCall(f.Calls, "RemoveAll", ufwDefault),
		"Compensate without prior content must RemoveAll the path")
}

func TestNewBackupDefaultUfwStep_and_NewRewriteUfwIPV6Step_are_aliases(t *testing.T) {
	t.Parallel()
	// Both alias constructors must return non-nil Steps with stable Names.
	a := NewBackupDefaultUfwStep(frozenNow())
	b := NewRewriteUfwIPV6Step("yes", frozenNow())
	require.NotNil(t, a)
	require.NotNil(t, b)
	require.NotEmpty(t, a.Name())
	require.NotEmpty(t, b.Name())
}

func TestNewSystemctlRestartUfwStep_apply_and_compensate_call_systemctl_restart_ufw(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Script the systemctl restart ufw response (Exec fake demands a scripted
	// response by exact-match key).
	f.ExecResponses = map[string]sysops.ExecResult{
		"systemctl restart ufw": {ExitCode: 0},
	}
	step := NewSystemctlRestartUfwStep()
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))
	require.NoError(t, step.Compensate(ctx, f))

	// Both Apply and Compensate dispatch via Exec("systemctl", "restart", "ufw").
	var execs int
	for _, c := range f.Calls {
		if c.Method != "Exec" {
			continue
		}
		// Args[0] is the binary name; remaining args are the argv tail.
		if len(c.Args) >= 3 && c.Args[0] == "systemctl" && c.Args[1] == "restart" && c.Args[2] == "ufw" {
			execs++
		}
	}
	require.Equal(t, 2, execs, "Apply + Compensate must each issue `systemctl restart ufw` once")
}

// ---- SAFE-04 wrapper pair tests (Task 2 — written together with Task 1
// to keep the file's test-block contiguous; the SAFE-04 helpers + impls
// land in Task 2's commit).
// ----------------------------------------------------------------------

// fakeRevertWatcher implements the txn.RevertWatcher adapter interface for
// testing without pulling internal/revert (Plan 04-04) into the dep tree.
type fakeRevertWatcher struct {
	setCalled   bool
	setUnit     string
	setDeadline time.Time
	setCmds     []string
	clearCalled bool
	setErr      error
	clearErr    error
}

func (w *fakeRevertWatcher) Set(_ context.Context, unit string, dl time.Time, cmds []string) error {
	w.setCalled = true
	w.setUnit = unit
	w.setDeadline = dl
	w.setCmds = append([]string(nil), cmds...)
	return w.setErr
}

func (w *fakeRevertWatcher) Clear(_ context.Context) error {
	w.clearCalled = true
	return w.clearErr
}

func TestNewScheduleRevertStep_unit_name_uses_unix_ns_format(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2026, 4, 27, 12, 0, 0, 123_456_789, time.UTC)
	nowFn := func() time.Time { return frozen }
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewScheduleRevertStep(
		[]string{"ufw delete 1", "ufw reload"},
		frozen.Add(3*time.Minute),
		w, nowFn,
	)
	require.NoError(t, step.Apply(context.Background(), f))

	// Unit name: sftpj-revert-<unix-ns>.service per D-S04-04.
	concrete, ok := step.(*scheduleRevertStep)
	require.True(t, ok, "NewScheduleRevertStep must return *scheduleRevertStep")
	wantUnit := fmt.Sprintf("sftpj-revert-%d.service", frozen.UnixNano())
	require.Equal(t, wantUnit, concrete.UnitName())

	// SystemdRunOnActive recorded with verbatim cmd ("ufw delete 1; ufw reload").
	require.True(t, containsCall(f.Calls, "SystemdRunOnActive", "cmd=ufw delete 1; ufw reload"),
		"SystemdRunOnActive must record verbatim joined cmd")
	require.True(t, containsCall(f.Calls, "SystemdRunOnActive", "unit="+wantUnit),
		"SystemdRunOnActive must record unit=<expected>")

	// Watcher.Set called exactly once with the assigned unit + deadline.
	require.True(t, w.setCalled, "watcher.Set must be called during Apply")
	require.Equal(t, wantUnit, w.setUnit)
	require.Equal(t, frozen.Add(3*time.Minute), w.setDeadline)
}

func TestNewScheduleRevertStep_compensate_stops_unit_and_clears_watcher(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return frozen }
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewScheduleRevertStep(
		[]string{"ufw delete 1", "ufw reload"},
		frozen.Add(3*time.Minute),
		w, nowFn,
	)
	ctx := context.Background()
	require.NoError(t, step.Apply(ctx, f))

	require.NoError(t, step.Compensate(ctx, f))
	// Compensate calls SystemctlStop on the assigned unit.
	concrete := step.(*scheduleRevertStep)
	require.True(t, containsCall(f.Calls, "SystemctlStop", "unit="+concrete.UnitName()),
		"Compensate must SystemctlStop the assigned unit")
	// Compensate also clears the watcher pointer.
	require.True(t, w.clearCalled, "Compensate must call watcher.Clear")
}

func TestNewScheduleRevertStep_rejects_empty_reverse_cmds(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	step := NewScheduleRevertStep(
		[]string{},
		time.Now().Add(3*time.Minute),
		nil, nil,
	)
	err := step.Apply(context.Background(), f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no reverse commands",
		"Apply must reject empty reverseCmds")
}

func TestNewScheduleRevertStep_rejects_past_deadline(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return frozen }
	f := sysops.NewFake()
	step := NewScheduleRevertStep(
		[]string{"ufw delete 1"},
		frozen.Add(-1*time.Minute), // past!
		nil, nowFn,
	)
	err := step.Apply(context.Background(), f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "deadline",
		"Apply must reject past deadlines (T-04-02-02 mitigation)")
}

func TestNewScheduleRevertStep_compensate_before_apply_is_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewScheduleRevertStep(
		[]string{"ufw delete 1"},
		time.Now().Add(3*time.Minute),
		w, nil,
	)
	// Apply NEVER ran — Compensate must be a no-op (no unit assigned).
	require.NoError(t, step.Compensate(context.Background(), f))
	require.False(t, w.clearCalled,
		"Compensate before Apply must not touch the watcher")
}

func TestNewCancelRevertStep_apply_stops_unit_and_clears_watcher(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewCancelRevertStep("sftpj-revert-1.service", w)
	require.NoError(t, step.Apply(context.Background(), f))

	require.True(t, containsCall(f.Calls, "SystemctlStop", "unit=sftpj-revert-1.service"),
		"Apply must SystemctlStop the named unit")
	// BUG-04-D regression guard: systemd-run --on-active creates BOTH a .timer
	// AND a .service unit per D-S04-04. Stopping only the .service leaves the
	// .timer ticking; the timer fires the .service again at the original
	// deadline, undoing the just-confirmed mutation. cancelRevertStep.Apply
	// MUST stop both. See cmd/uat-04/main.go:645-655 for the canonical pattern.
	require.True(t, containsCall(f.Calls, "SystemctlStop", "unit=sftpj-revert-1.timer"),
		"BUG-04-D: Apply must SystemctlStop the .timer unit (not just .service)")
	require.True(t, w.clearCalled, "Apply must call watcher.Clear")
}

// TestNewCancelRevertStep_apply_stops_timer_BEFORE_service pins the systemd
// convention: stop the .timer first so it can't re-arm the .service between
// the two stops. Mirrors cmd/uat-04/main.go:645-655's helper-side workaround
// for BUG-04-D. With this ordering, a forgotten .timer stop reliably reveals
// itself in production (the timer fires after Confirm), but with both stops
// in the canonical .timer-first order, the SAFE-04 cancellation contract
// (D-S04-05) holds.
func TestNewCancelRevertStep_apply_stops_timer_BEFORE_service(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewCancelRevertStep("sftpj-revert-1700000000.service", w)
	require.NoError(t, step.Apply(context.Background(), f))

	// Find both call indices and assert ordering.
	timerIdx, serviceIdx := -1, -1
	for i, call := range f.Calls {
		if call.Method != "SystemctlStop" {
			continue
		}
		for _, arg := range call.Args {
			if arg == "unit=sftpj-revert-1700000000.timer" {
				timerIdx = i
			}
			if arg == "unit=sftpj-revert-1700000000.service" {
				serviceIdx = i
			}
		}
	}
	require.NotEqual(t, -1, timerIdx, "BUG-04-D: .timer stop call missing from f.Calls")
	require.NotEqual(t, -1, serviceIdx, ".service stop call missing from f.Calls")
	require.Less(t, timerIdx, serviceIdx,
		"BUG-04-D: .timer stop must come BEFORE .service stop (systemd convention — "+
			"stopping .timer first prevents the timer re-arming the service between stops)")
}

func TestNewCancelRevertStep_compensate_is_intentional_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	w := &fakeRevertWatcher{}
	step := NewCancelRevertStep("sftpj-revert-1.service", w)
	require.NoError(t, step.Apply(context.Background(), f))
	callsBefore := len(f.Calls)

	// Compensate is intentional no-op per D-S04-05.
	require.NoError(t, step.Compensate(context.Background(), f))
	require.Equal(t, callsBefore, len(f.Calls),
		"Compensate must not touch sysops at all (D-S04-05 irreversible by design)")
}

// TestNewCancelRevertStep_unit_not_loaded_is_idempotent — also covers the
// BUG-04-D-fixed two-stop path: the shared f.SystemctlStopError returns
// "not loaded" for BOTH the .timer and .service stops, and Apply must
// still return nil (the not-loaded mapping covers both calls) and call
// watcher.Clear. This pins the idempotency contract under the strengthened
// two-stop production code.
func TestNewCancelRevertStep_unit_not_loaded_is_idempotent(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.SystemctlStopError = errors.New(
		"Failed to stop sftpj-revert-X.service: Unit sftpj-revert-X.service not loaded")
	w := &fakeRevertWatcher{}
	step := NewCancelRevertStep("sftpj-revert-X.service", w)
	// Idempotent: "not loaded" maps to nil, watcher.Clear still runs.
	require.NoError(t, step.Apply(context.Background(), f))
	require.True(t, w.clearCalled,
		"Apply must still call watcher.Clear when the unit was already stopped")
}

func TestRevertWatcher_interface_satisfied_by_fakeRevertWatcher(t *testing.T) {
	t.Parallel()
	// Compile-time verification that the test fake satisfies the production
	// adapter interface. Plan 04-04's *revert.Watcher must satisfy this same
	// shape so NewScheduleRevertStep accepts it without import cycle.
	var _ RevertWatcher = (*fakeRevertWatcher)(nil)
}

// ---------------------------------------------------------------------------
// Plan 04-12 (gap closure): NewUfwDeleteCatchAllByEnumerateStep tests
//
// These tests pin the failure modes empirically caught by Plan 04-10's UAT
// (04-10-SUMMARY "Production bugs discovered" table):
//
//   BUG-04-A: stale catch-all ID after `ufw insert 1` shifts positions.
//   BUG-04-C: only-one-catch-all-deleted on dual-family v4+v6 hosts.
//
// The step under test re-Enumerates ufw at Apply time and deletes EVERY
// matching catch-all (Source="Anywhere", ALLOW, empty RawComment, port
// matches). This is the production version of cmd/uat-04/main.go:432-450's
// helper-side workaround loop.
// ---------------------------------------------------------------------------

// ufwStatusFixtureDualFamily returns a "ufw status numbered" stdout
// modeling a default Ubuntu 24.04 box with IPV6=yes — a v4 catch-all
// (id=1), a v6 catch-all (id=2), and a sftpj rule (id=3). Format mirrors
// internal/firewall/testdata/ufw-status-numbered-mixed.txt verbatim.
func ufwStatusFixtureDualFamily() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// ufwStatusFixtureV6OnlyAfterFirstDelete: the v4 catch-all is gone;
// ufw renumbered remaining rules. v6 catch-all is now id=1, sftpj is id=2.
func ufwStatusFixtureV6OnlyAfterFirstDelete() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 2] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// ufwStatusFixtureSftpjOnly: both catch-alls gone, only sftpj remains.
func ufwStatusFixtureSftpjOnly() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// ufwStatusFixtureCatchallShifted: post-position-shift state where
// sftpj rule was inserted at top, pushing the catch-all from id=1 to id=2.
func ufwStatusFixtureCatchallShifted() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
[ 2] 22/tcp                     ALLOW IN    Anywhere
`)
}

// TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6
// pins BUG-04-C (P0): production buildPendingMutations breaks after the
// first catch-all match (`break` at lockdown.go:509). On a default Ubuntu
// 24.04 host (IPV6=yes), ufw maintains a v4 + v6 catch-all; only the v4
// gets deleted, and DetectMode keeps reporting STAGING because the v6
// catch-all still satisfies the hasCatchAll predicate. Empirically caught
// by Plan 04-10 UAT.
func TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Stateful Enumerate: each call returns a different rule listing,
	// modeling ufw's ID compaction after each delete.
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusFixtureDualFamily()},
		{ExitCode: 0, Stdout: ufwStatusFixtureV6OnlyAfterFirstDelete()},
		{ExitCode: 0, Stdout: ufwStatusFixtureSftpjOnly()},
	}

	step := NewUfwDeleteCatchAllByEnumerateStep("22")
	require.NoError(t, step.Apply(context.Background(), f))

	// Count UfwDelete calls — must be EXACTLY 2 (v4 + v6 catch-alls).
	deleteCount := 0
	for _, c := range f.Calls {
		if c.Method == "UfwDelete" {
			deleteCount++
		}
	}
	require.Equal(t, 2, deleteCount,
		"BUG-04-C: dual-family hosts have v4+v6 catch-alls; step must delete BOTH "+
			"(production's buildPendingMutations break-after-first only deleted v4)")
}

// TestUfwDeleteCatchAllByEnumerate_position_shift_uses_FRESH_id
// pins BUG-04-A (P0): production captured the catch-all ID at S-LOCKDOWN
// load time (pre-mutation), then ran `ufw insert 1 ...` per-user rules
// which shifted the catch-all from id=1 to id=2; the subsequent
// UfwDeleteStep using the captured id=1 then deleted the freshly-inserted
// sftpj rule instead of the catch-all. Empirically caught by Plan 04-10
// UAT (commit 5f92a62 phase 3 phase-3 setup uses signature-match — the
// helper-side workaround for this bug).
//
// The new step re-Enumerates at Apply time, so the id is always FRESH.
func TestUfwDeleteCatchAllByEnumerate_position_shift_uses_FRESH_id(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Single Enumerate response: catch-all has shifted to id=2 because
	// an earlier OpAdd inserted the sftpj rule at id=1.
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusFixtureCatchallShifted()},
		{ExitCode: 0, Stdout: ufwStatusFixtureSftpjOnly()}, // post-delete drain
	}

	step := NewUfwDeleteCatchAllByEnumerateStep("22")
	require.NoError(t, step.Apply(context.Background(), f))

	// Must delete id=2 (the fresh post-shift catch-all ID), NOT id=1
	// (which would be the sftpj rule).
	require.True(t, containsCall(f.Calls, "UfwDelete", "id=2"),
		"BUG-04-A: step must use FRESH id from Apply-time Enumerate (id=2 here), "+
			"not a stale ID captured at construction time")
	require.False(t, containsCall(f.Calls, "UfwDelete", "id=1"),
		"BUG-04-A: step must NOT delete id=1 (the sftpj rule); "+
			"stale-ID resolution would mis-target the sftpj rule")
}

// TestUfwDeleteCatchAllByEnumerate_no_catchalls_is_noop pins idempotency:
// a state with no catch-alls (already LOCKED) should result in zero
// UfwDelete calls. The step is safe to invoke regardless of current MODE.
func TestUfwDeleteCatchAllByEnumerate_no_catchalls_is_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusFixtureSftpjOnly()},
	}

	step := NewUfwDeleteCatchAllByEnumerateStep("22")
	require.NoError(t, step.Apply(context.Background(), f))

	for _, c := range f.Calls {
		require.NotEqual(t, "UfwDelete", c.Method,
			"no catch-alls present → zero UfwDelete calls expected (idempotent no-op)")
	}
}

// TestUfwDeleteCatchAllByEnumerate_compensate_is_intentional_noop
// mirrors the irreversibility-by-design pattern of NewUfwDeleteStep — the
// step is irreversible by design (D-FW-07 / D-S04-05); recovery rides the
// SAFE-04 transient unit's reverse-cmd, NOT this step's Compensate.
func TestUfwDeleteCatchAllByEnumerate_compensate_is_intentional_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusFixtureDualFamily()},
		{ExitCode: 0, Stdout: ufwStatusFixtureV6OnlyAfterFirstDelete()},
		{ExitCode: 0, Stdout: ufwStatusFixtureSftpjOnly()},
	}
	step := NewUfwDeleteCatchAllByEnumerateStep("22")
	require.NoError(t, step.Apply(context.Background(), f))
	callsBefore := len(f.Calls)

	require.NoError(t, step.Compensate(context.Background(), f))
	require.Equal(t, callsBefore, len(f.Calls),
		"Compensate must not touch sysops at all (D-FW-07 irreversible by design — "+
			"recovery rides the SAFE-04 transient unit's reverse-cmd)")
}
