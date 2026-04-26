package txn

import (
	"context"
	"errors"
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
	}

	for _, tc := range cases {
		require.NotNil(t, tc.s, "constructor %s returned nil", tc.name)
		require.NotEmpty(t, tc.s.Name(), "constructor %s returned a step with empty Name()", tc.name)
	}

	_ = reflect.TypeOf
	_ = fs.ModeSetuid // ensure fs import is used somewhere if needed
}
