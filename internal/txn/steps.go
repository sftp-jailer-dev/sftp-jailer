package txn

// NOTE (N-01): the canonical drop-in bytes are rendered by the CALLER
// (plan 03-06 M-APPLY-SETUP) and passed as the `content []byte` arg to
// NewWriteSshdDropInStep. This package stays config-renderer-agnostic so
// the framework is reusable for non-sshd writes (Phase 4 firewall flows).
// Do NOT add an import on the config-render package from this file.
//
// Compensator filesystem cleanup uses ops.RemoveAll (the typed sysops
// wrapper from plan 03-01) — never raw os.Remove. This preserves the
// W-02 typed-wrapper discipline and keeps every Step testable through
// sysops.Fake.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// ---- WriteSshdDropIn ↔ RestoreSshdDropInBackup (D-09 step 2-3) -------------

// NewWriteSshdDropInStep returns a Step that backs up the current drop-in
// (if it exists) and writes the new content via sysops.AtomicWriteFile.
// Compensate restores the backup on rollback. If no prior drop-in existed,
// Compensate calls ops.RemoveAll to delete the file we wrote.
//
// Backup path format: <backupDir>/<UTC-RFC3339-compact>-<basename>.bak
// (one rolling copy per session per SAFE-03; the call site rotates the
// backup directory per session).
//
// Idempotency: Compensate is safe to run twice — restoring the same bytes
// is a no-op AtomicWriteFile, and ops.RemoveAll treats ErrNotExist as
// success.
func NewWriteSshdDropInStep(dropInPath, backupDir string, newContent []byte, mode fs.FileMode, now func() time.Time) Step {
	if now == nil {
		now = time.Now
	}
	return &writeSshdDropInStep{
		dropInPath: dropInPath,
		backupDir:  backupDir,
		newContent: newContent,
		mode:       mode,
		now:        now,
	}
}

type writeSshdDropInStep struct {
	dropInPath string
	backupDir  string
	newContent []byte
	mode       fs.FileMode
	now        func() time.Time

	// populated by Apply for use in Compensate:
	backupPath  string
	priorBytes  []byte
	priorExists bool
}

func (s *writeSshdDropInStep) Name() string { return "WriteSshdDropIn" }

func (s *writeSshdDropInStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	prior, err := ops.ReadFile(ctx, s.dropInPath)
	if err == nil {
		s.priorBytes = prior
		s.priorExists = true
		ts := s.now().UTC().Format("20060102T150405Z")
		s.backupPath = filepath.Join(s.backupDir, ts+"-"+filepath.Base(s.dropInPath)+".bak")
		if werr := ops.AtomicWriteFile(ctx, s.backupPath, prior, 0o600); werr != nil {
			return fmt.Errorf("backup write %s: %w", s.backupPath, werr)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read prior drop-in %s: %w", s.dropInPath, err)
	}
	if werr := ops.AtomicWriteFile(ctx, s.dropInPath, s.newContent, s.mode); werr != nil {
		return fmt.Errorf("write drop-in %s: %w", s.dropInPath, werr)
	}
	return nil
}

func (s *writeSshdDropInStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if !s.priorExists {
		return ops.RemoveAll(ctx, s.dropInPath)
	}
	return ops.AtomicWriteFile(ctx, s.dropInPath, s.priorBytes, s.mode)
}

// ---- Useradd ↔ Userdel (D-12 step 4) ---------------------------------------

// NewUseraddStep wraps sysops.Useradd. Compensate calls Userdel with
// removeHome matching the step's CreateHome flag (D-15: the inverse of
// what Apply created).
//
// Idempotency: Userdel is idempotent — running it after success returns an
// "unknown user" error from the underlying tool which the call site treats
// as success when needed.
func NewUseraddStep(opts sysops.UseraddOpts) Step {
	return &useraddStep{opts: opts}
}

type useraddStep struct{ opts sysops.UseraddOpts }

func (s *useraddStep) Name() string { return "Useradd" }
func (s *useraddStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Useradd(ctx, s.opts)
}
func (s *useraddStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Userdel(ctx, s.opts.Username, s.opts.CreateHome)
}

// ---- GpasswdAdd ↔ GpasswdDel (D-12 step 5) ---------------------------------

// NewGpasswdAddStep adds username to group on Apply, removes it on
// Compensate. Idempotent on both sides.
func NewGpasswdAddStep(username, group string) Step {
	return &gpasswdAddStep{username: username, group: group}
}

type gpasswdAddStep struct{ username, group string }

func (s *gpasswdAddStep) Name() string { return "GpasswdAdd" }
func (s *gpasswdAddStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Gpasswd(ctx, sysops.GpasswdAdd, s.username, s.group)
}
func (s *gpasswdAddStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Gpasswd(ctx, sysops.GpasswdDel, s.username, s.group)
}

// ---- AtomicWriteAuthorizedKeys ↔ RestorePriorAuthorizedKeys (D-20) ---------

// NewAtomicWriteAuthorizedKeysStep captures the prior authorized_keys
// content (if any) during Apply, then writes the new keys via
// sysops.WriteAuthorizedKeys. Compensate restores the prior bytes via
// the same composite wrapper, or removes the file if nothing existed.
//
// Idempotency: rewriting the same prior bytes is a deterministic no-op;
// RemoveAll treats ErrNotExist as success.
func NewAtomicWriteAuthorizedKeysStep(username, chrootRoot string, newKeys []byte) Step {
	return &writeAuthKeysStep{username: username, chrootRoot: chrootRoot, newKeys: newKeys}
}

type writeAuthKeysStep struct {
	username, chrootRoot string
	newKeys              []byte

	priorBytes  []byte
	priorExists bool
	authPath    string
}

func (s *writeAuthKeysStep) Name() string { return "WriteAuthorizedKeys" }

func (s *writeAuthKeysStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	s.authPath = filepath.Join(s.chrootRoot, s.username, ".ssh", "authorized_keys")
	prior, err := ops.ReadFile(ctx, s.authPath)
	if err == nil {
		s.priorBytes = prior
		s.priorExists = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read prior authorized_keys %s: %w", s.authPath, err)
	}
	return ops.WriteAuthorizedKeys(ctx, s.username, s.chrootRoot, s.newKeys)
}

func (s *writeAuthKeysStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if !s.priorExists {
		return ops.RemoveAll(ctx, s.authPath)
	}
	return ops.WriteAuthorizedKeys(ctx, s.username, s.chrootRoot, s.priorBytes)
}

// ---- Tar ↔ RemovePartialTarball (D-15 Archive path) ------------------------

// NewTarStep wraps sysops.Tar. Compensate is a best-effort cleanup of a
// partial / completed tarball via ops.RemoveAll (W-02 typed wrapper —
// not raw os.Remove). RemoveAll treats ErrNotExist as success, so a
// clean-exit Apply followed by Compensate is a no-op.
func NewTarStep(opts sysops.TarOpts) Step {
	return &tarStep{opts: opts}
}

type tarStep struct{ opts sysops.TarOpts }

func (s *tarStep) Name() string { return "Tar" }
func (s *tarStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Tar(ctx, s.opts)
}
func (s *tarStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	return ops.RemoveAll(ctx, s.opts.ArchivePath)
}

// ---- Chpasswd (no compensator per D-13) ------------------------------------

// NewChpasswdStep wraps sysops.Chpasswd. Compensate is intentionally a
// no-op — chpasswd is irreversible by design (no prior-password recovery).
//
// Per T-03-05-02: Step.Name() is "Chpasswd" — never the password itself.
// The wrapping error format `txn.Apply step %s: %w` includes only Name(),
// not the password literal. The underlying *ChpasswdError from sysops
// carries pam_pwquality stderr and the username — never the password.
func NewChpasswdStep(username, password string) Step {
	return &chpasswdStep{username: username, password: password}
}

type chpasswdStep struct{ username, password string }

func (s *chpasswdStep) Name() string { return "Chpasswd" }
func (s *chpasswdStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Chpasswd(ctx, s.username, s.password)
}
func (s *chpasswdStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	return nil
}

// ---- Chmod (optional prior-mode capture) -----------------------------------

// NewChmodStep wraps ops.Chmod. Apply captures the prior mode via
// ops.Lstat so Compensate can restore it. If Lstat fails (e.g. the file
// did not exist before), Compensate is a no-op — there is nothing to
// restore.
func NewChmodStep(path string, mode fs.FileMode) Step {
	return &chmodStep{path: path, mode: mode}
}

type chmodStep struct {
	path string
	mode fs.FileMode

	priorMode    fs.FileMode
	priorCapture bool
}

func (s *chmodStep) Name() string { return "Chmod" }
func (s *chmodStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	if fi, err := ops.Lstat(ctx, s.path); err == nil {
		s.priorMode = fi.Mode & fs.ModePerm
		s.priorCapture = true
	}
	return ops.Chmod(ctx, s.path, s.mode)
}
func (s *chmodStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if !s.priorCapture {
		return nil
	}
	return ops.Chmod(ctx, s.path, s.priorMode)
}

// ---- Chown (optional prior-owner capture) ----------------------------------

// NewChownStep wraps ops.Chown. Apply captures prior UID/GID via
// ops.Lstat so Compensate can restore them. If Lstat fails, Compensate
// is a no-op.
func NewChownStep(path string, uid, gid int) Step {
	return &chownStep{path: path, uid: uid, gid: gid}
}

type chownStep struct {
	path     string
	uid, gid int

	priorUID, priorGID int
	priorCapture       bool
}

func (s *chownStep) Name() string { return "Chown" }
func (s *chownStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	if fi, err := ops.Lstat(ctx, s.path); err == nil {
		s.priorUID = int(fi.UID)
		s.priorGID = int(fi.GID)
		s.priorCapture = true
	}
	return ops.Chown(ctx, s.path, s.uid, s.gid)
}
func (s *chownStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if !s.priorCapture {
		return nil
	}
	return ops.Chown(ctx, s.path, s.priorUID, s.priorGID)
}

// ---- D-09 batch composer for plan 03-06 M-APPLY-SETUP ----------------------

// ReloadDispatch is the SAFE-06 dispatcher decision (plan 03-06 picks
// based on whether the change touches socket-affecting directives).
type ReloadDispatch int

// ReloadDispatch values map to the SAFE-06 dispatcher decision.
const (
	// ReloadService reloads ssh.service via `systemctl reload ssh.service`.
	// Use for changes that do NOT touch Port/ListenAddress/AddressFamily.
	ReloadService ReloadDispatch = iota
	// RestartSocket runs `systemctl daemon-reload && systemctl restart
	// ssh.socket`. Use for socket-affecting directive changes (Port,
	// ListenAddress, AddressFamily) per Launchpad #2069041.
	RestartSocket
)

// CanonicalApplySetupSteps composes the D-09 apply-canonical-config batch:
//  1. WriteSshdDropIn (with backup + restore-on-rollback)
//  2. SshdValidate (`sshd -t`; Compensate is a no-op)
//  3. SystemctlReload or RestartSocket per dispatcher (SAFE-06)
//  4. SshdVerifyChrootDirective (`sshd -T` post-reload sanity check)
//
// Returns the slice; caller passes to Tx.Apply. The compensator chain
// restores the prior drop-in then re-issues the reload, returning the
// running sshd to its prior config.
func CanonicalApplySetupSteps(dropInPath, backupDir string, content []byte, dispatch ReloadDispatch, now func() time.Time) []Step {
	return []Step{
		NewWriteSshdDropInStep(dropInPath, backupDir, content, 0o644, now),
		NewSshdValidateStep(),
		NewSystemctlReloadStep(dispatch),
		NewSshdVerifyChrootDirectiveStep(),
	}
}

// ---- SshdValidate (sshd -t gate, no compensator) ---------------------------

// NewSshdValidateStep wraps `sshd -t`. Apply calls SshdT and returns an
// error if non-zero; the wrapped error includes the captured stderr
// verbatim so the M-APPLY-SETUP modal can surface the line+offset
// diagnostic directly to the admin (SAFE-02 reload gate). Compensate is
// a no-op — the validator has no side effect to undo.
func NewSshdValidateStep() Step { return &sshdValidateStep{} }

type sshdValidateStep struct{}

func (s *sshdValidateStep) Name() string { return "SshdValidate" }
func (s *sshdValidateStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	stderr, err := ops.SshdT(ctx)
	if err != nil {
		return fmt.Errorf("sshd -t failed: %s: %w", string(stderr), err)
	}
	return nil
}
func (s *sshdValidateStep) Compensate(_ context.Context, _ sysops.SystemOps) error { return nil }

// ---- SystemctlReload / RestartSocket (SAFE-06 dispatcher) ------------------

// NewSystemctlReloadStep dispatches by SAFE-06 rule. The compensator
// re-issues the same reload — the prior step's WriteSshdDropIn
// compensator already restored the original file, so re-issuing the
// reload returns the running sshd to its prior config.
func NewSystemctlReloadStep(d ReloadDispatch) Step { return &systemctlReloadStep{disp: d} }

type systemctlReloadStep struct{ disp ReloadDispatch }

func (s *systemctlReloadStep) Name() string { return "SystemctlReload" }
func (s *systemctlReloadStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	switch s.disp {
	case RestartSocket:
		if err := ops.SystemctlDaemonReload(ctx); err != nil {
			return fmt.Errorf("daemon-reload: %w", err)
		}
		return ops.SystemctlRestartSocket(ctx, "ssh.socket")
	default:
		return ops.SystemctlReload(ctx, "ssh.service")
	}
}
func (s *systemctlReloadStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	switch s.disp {
	case RestartSocket:
		_ = ops.SystemctlDaemonReload(ctx)
		return ops.SystemctlRestartSocket(ctx, "ssh.socket")
	default:
		return ops.SystemctlReload(ctx, "ssh.service")
	}
}

// ---- SshdVerifyChrootDirective (post-reload sanity, no compensator) --------

// NewSshdVerifyChrootDirectiveStep runs `sshd -T` and confirms the active
// config reports either a `chrootdirectory` or `forcecommand` directive
// — coarse evidence that the just-applied drop-in is in effect (D-09
// step 6).
//
// Note: `sshd -T` (no -C) only reports global directives; Match-block
// directives only appear when invoked with `-C user=...`. Plan 03-08b
// uses sysops.SshdTWithContext for that user-context tightening (D-21
// step 4). For the generic post-reload verification path, presence of
// either directive is accepted as success.
func NewSshdVerifyChrootDirectiveStep() Step { return &sshdVerifyStep{} }

type sshdVerifyStep struct{}

func (s *sshdVerifyStep) Name() string { return "SshdVerifyChrootDirective" }
func (s *sshdVerifyStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	cfg, err := ops.SshdDumpConfig(ctx)
	if err != nil {
		return fmt.Errorf("sshd -T: %w", err)
	}
	if _, ok := cfg["chrootdirectory"]; ok {
		return nil
	}
	if _, ok := cfg["forcecommand"]; ok {
		return nil
	}
	return errors.New("sshd -T did not report chrootdirectory or forcecommand — drop-in not applied?")
}
func (s *sshdVerifyStep) Compensate(_ context.Context, _ sysops.SystemOps) error { return nil }

// ---- Userdel (no compensator — D-15 irreversibility) -----------------------

// NewUserdelStep is the standalone Userdel constructor for the D-15
// Permanent and Archive paths in M-DELETE-USER (plan 03-08a). Unlike the
// Useradd-paired Userdel inside [NewUseraddStep]'s compensator, this Step
// is a top-level Apply that intentionally has NO compensator: once a system
// user is gone there is no Go-level reverse operation — recreating from
// scratch is the admin's call (and would belong inside a separate
// M-NEW-USER batch, not a Userdel compensator).
//
//   - removeHome=true → adds `-r` to userdel (D-15 Permanent path —
//     irreversibly deletes the home directory).
//   - removeHome=false → leaves the home dir on disk (D-15 Archive path
//     — caller's NewTarStep wrote a backup tarball before this Step ran).
//
// Idempotency: re-running userdel on an already-deleted user returns an
// "unknown user" error from the underlying tool. The call site decides
// whether to treat that as success on retry; the Step itself returns the
// error verbatim from sysops.
func NewUserdelStep(username string, removeHome bool) Step {
	return &userdelStep{username: username, removeHome: removeHome}
}

type userdelStep struct {
	username   string
	removeHome bool
}

func (s *userdelStep) Name() string { return "Userdel" }
func (s *userdelStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.Userdel(ctx, s.username, s.removeHome)
}
func (s *userdelStep) Compensate(_ context.Context, _ sysops.SystemOps) error { return nil }

// ---- MkdirAll (W-02 — uses typed ops wrappers, fully Fake-testable) -------

// NewMkdirAllStep ensures dir exists with mode (mkdir + chmod, since the
// stdlib mkdir-all primitive respects umask). uid/gid passed: -1 means
// "skip chown".
//
// Compensate: best-effort ops.RemoveAll iff the dir did NOT exist before
// Apply (captured at Apply time via ops.Lstat). When the dir already
// existed, Compensate is a no-op — we don't claim ownership of a dir we
// did not create.
//
// W-02: this Step uses the sysops typed wrappers (sysops.MkdirAll +
// sysops.RemoveAll added to SystemOps in plan 03-01). It MUST NOT bypass
// them with raw stdlib FS calls — the typed wrappers are the seam that
// keeps the Step Fake-testable.
//
// Idempotency: ops.MkdirAll is idempotent on existing paths; ops.Chmod
// re-applies the same mode harmlessly; ops.RemoveAll treats ErrNotExist
// as success. Re-running Apply or Compensate is safe.
func NewMkdirAllStep(dir string, mode fs.FileMode, uid, gid int) Step {
	return &mkdirAllStep{dir: dir, mode: mode, uid: uid, gid: gid}
}

type mkdirAllStep struct {
	dir           string
	mode          fs.FileMode
	uid, gid      int
	existedBefore bool
}

func (s *mkdirAllStep) Name() string { return "MkdirAll" }
func (s *mkdirAllStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	if _, err := ops.Lstat(ctx, s.dir); err == nil {
		s.existedBefore = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("lstat %s: %w", s.dir, err)
	}
	if err := ops.MkdirAll(ctx, s.dir, s.mode); err != nil {
		return fmt.Errorf("mkdir %s: %w", s.dir, err)
	}
	if err := ops.Chmod(ctx, s.dir, s.mode); err != nil {
		return fmt.Errorf("chmod %s: %w", s.dir, err)
	}
	if s.uid >= 0 && s.gid >= 0 {
		if err := ops.Chown(ctx, s.dir, s.uid, s.gid); err != nil {
			return fmt.Errorf("chown %s: %w", s.dir, err)
		}
	}
	return nil
}
func (s *mkdirAllStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if s.existedBefore {
		return nil
	}
	return ops.RemoveAll(ctx, s.dir)
}

// ---- VerifyAuthKeys (D-21 steps 1+2 wrapper, callable from Apply) ---------

// VerifyViolation is the txn-level shape used by NewVerifyAuthKeysStep.
// Caller adapts internal/chrootcheck.Violation into this shape to avoid
// an import cycle (txn → chrootcheck would pull the FS-walking package
// into the framework). Fields mirror chrootcheck.Violation 1:1.
type VerifyViolation struct {
	Path   string
	Reason string
}

// NewVerifyAuthKeysStep wraps a verifier function in a Step. The verifier
// is the caller's responsibility to inject (avoiding txn → chrootcheck
// import — see VerifyViolation godoc).
//
// Apply returns a non-nil error iff there are violations; the error
// message joins all violation reasons with `; ` and is prefixed with
// "StrictModes failed: " so the M-ADD-KEY / S-USER-DETAIL UI can surface
// it verbatim per pitfall B6.
//
// Compensate is a no-op — verification has no side effect to undo. The
// rollback ordering ensures that the prior NewAtomicWriteAuthorizedKeysStep's
// compensator restores the prior file content when this verifier fails.
func NewVerifyAuthKeysStep(username, chrootRoot string, verify func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]VerifyViolation, error)) Step {
	return &verifyAuthKeysStep{
		username:   username,
		chrootRoot: chrootRoot,
		verify:     verify,
	}
}

type verifyAuthKeysStep struct {
	username, chrootRoot string
	verify               func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]VerifyViolation, error)
}

func (s *verifyAuthKeysStep) Name() string { return "VerifyAuthKeys" }
func (s *verifyAuthKeysStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	vios, err := s.verify(ctx, ops, s.username, s.chrootRoot)
	if err != nil {
		return fmt.Errorf("verify auth keys: %w", err)
	}
	if len(vios) > 0 {
		var buf strings.Builder
		for i, v := range vios {
			if i > 0 {
				buf.WriteString("; ")
			}
			buf.WriteString(v.Reason)
		}
		return fmt.Errorf("StrictModes failed: %s", buf.String())
	}
	return nil
}
func (s *verifyAuthKeysStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	return nil
}
