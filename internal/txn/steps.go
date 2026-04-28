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

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
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

// ============================================================================
// Phase 4 Plan 02 — 9 new Step constructors wrapping the Plan 04-01 sysops
// mutation surface. Composes into the standard apply+compensate framework.
// ============================================================================

// RevertWatcher is the txn-package-local view of the on-disk revert pointer
// manager. The full Watcher type lives in internal/revert (Plan 04-04) but
// this package cannot import revert (would force a circular package
// relationship via *revert.Watcher fields on Step structs). This minimal
// interface keeps the dep direction clean — internal/revert imports
// internal/txn for the Step contract, and *revert.Watcher will satisfy this
// interface implicitly.
//
// Set arms the on-disk pointer at /var/lib/sftp-jailer/revert.active with
// (unitName, deadline, reverseCmds) per D-S04-06. Clear removes the pointer
// + clears in-process state.
type RevertWatcher interface {
	Set(ctx context.Context, unitName string, deadline time.Time, reverseCmds []string) error
	Clear(ctx context.Context) error
}

// ufwDefaultPath is the path of the file written by NewWriteUfwIPV6Step.
// Pinned by the AtomicWriteFile path allowlist (Plan 04-01).
const ufwDefaultPath = "/etc/default/ufw"

// ---- UfwAllow ↔ (no-op compensator — relies on SAFE-04 revert window) -----

// NewUfwAllowStep wraps sysops.UfwAllow ("ufw allow" — no positional insert).
// Compensate is intentionally a no-op: identifying a freshly-allowed rule by
// (source, comment) requires a re-Enumerate diff that the bare Step layer
// does not own. Plan 04-03's firewall.AddRule writer wraps this with the
// re-Enumerate-and-diff helper for callers that need ID-tracking. Production
// callers prefer NewUfwInsertStep (deterministic position 1 per D-FW-02);
// NewUfwAllowStep exists for completeness / catch-all re-add in LOCK-08
// rollback.
//
// Idempotency: nil-Compensate is safe to call on any rollback path.
func NewUfwAllowStep(opts sysops.UfwAllowOpts) Step {
	return &ufwAllowStep{opts: opts}
}

type ufwAllowStep struct {
	opts sysops.UfwAllowOpts
}

func (s *ufwAllowStep) Name() string { return "UfwAllow" }
func (s *ufwAllowStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.UfwAllow(ctx, s.opts)
}
func (s *ufwAllowStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	// Best-effort: the SAFE-04 transient-unit revert is the recovery path for
	// a partially-applied batch that included this Step. Returning nil keeps
	// downstream compensators in a clean rollback chain.
	return nil
}

// ---- UfwInsert (always pos=1) ↔ UfwDelete by captured ID -------------------

// NewUfwInsertStep wraps sysops.UfwInsert at position 1 per D-FW-02 (newest
// rule lands at top — predictable for admins reading raw `ufw status
// numbered`). The bare Step does NOT capture the assigned rule ID — Plan
// 04-03's firewall.AddRule writer is expected to call SetAssignedID after
// re-Enumerate-and-diff so Compensate can issue UfwDelete on the correct ID.
//
// Idempotency: if the rule is already gone (e.g. SAFE-04 timer fired between
// Apply and Compensate), UfwDelete's "Could not delete" / "rule not found"
// non-zero exit is treated as success at the call site (W-04 idempotent-
// Compensate discipline from Phase 3).
func NewUfwInsertStep(opts sysops.UfwAllowOpts) Step {
	return &ufwInsertStep{opts: opts}
}

type ufwInsertStep struct {
	opts sysops.UfwAllowOpts
	// populated by SetAssignedID (Plan 04-03 firewall.AddRule writer):
	assignedID int
}

func (s *ufwInsertStep) Name() string { return "UfwInsert" }
func (s *ufwInsertStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.UfwInsert(ctx, 1, s.opts)
}
func (s *ufwInsertStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if s.assignedID <= 0 {
		// No ID populated — nothing to delete deterministically. The SAFE-04
		// revert window is the recovery path for this case.
		return nil
	}
	if err := ops.UfwDelete(ctx, s.assignedID); err != nil {
		// Idempotent: treat "rule not found" / "Could not delete" as success
		// (W-04 — see godoc for the discipline rationale).
		msg := err.Error()
		if strings.Contains(msg, "Could not delete") || strings.Contains(msg, "not found") {
			return nil
		}
		return err
	}
	return nil
}

// SetAssignedID lets the Plan 04-03 firewall.AddRule writer populate the
// captured rule ID after the post-insert re-Enumerate-and-diff. Internal —
// not exposed to TUI callers (the writer mediates).
func (s *ufwInsertStep) SetAssignedID(id int) { s.assignedID = id }

// ---- UfwDelete ↔ (irreversible — relies on SAFE-04 revert window) ---------

// NewUfwDeleteStep wraps sysops.UfwDelete. Compensate is intentionally a
// no-op (mirrors NewUserdelStep at steps.go:426-439) — once a rule is gone
// at the tool layer, the SAFE-04 transient-unit revert is the ONLY recovery
// path. Inside-txn rollback would race with the timer + cannot recover the
// original (user, source, comment) tuple from a deleted rule.
//
// Idempotency: nil-Compensate is safe to call on any path.
func NewUfwDeleteStep(ruleID int) Step {
	return &ufwDeleteStep{ruleID: ruleID}
}

type ufwDeleteStep struct{ ruleID int }

func (s *ufwDeleteStep) Name() string { return "UfwDelete" }
func (s *ufwDeleteStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.UfwDelete(ctx, s.ruleID)
}
func (s *ufwDeleteStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	// Intentional no-op — irreversible by design per D-S04-05 / D-FW-07.
	return nil
}

// ---- UfwReload ↔ UfwReload (re-issue) -------------------------------------

// NewUfwReloadStep is the standard reload-style wrapper (model after
// NewSystemctlReloadStep at steps.go:349-373). Compensate re-issues the same
// op so a prior file-restore step's compensator returns the running ufw to
// its prior config.
func NewUfwReloadStep() Step { return &ufwReloadStep{} }

type ufwReloadStep struct{}

func (s *ufwReloadStep) Name() string { return "UfwReload" }
func (s *ufwReloadStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	return ops.UfwReload(ctx)
}
func (s *ufwReloadStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	return ops.UfwReload(ctx)
}

// ---- UfwDeleteCatchAllByEnumerate ↔ (irreversible — relies on SAFE-04) ----

// maxCatchAllIterations bounds NewUfwDeleteCatchAllByEnumerateStep's
// re-Enumerate-and-delete loop. Real hosts have at most 2 catch-alls
// (v4 + v6); 4 leaves slack for unusual configs (e.g. admin manually
// added duplicate rules) without risking a runaway loop on a
// misbehaving Enumerate parser.
const maxCatchAllIterations = 4

// NewUfwDeleteCatchAllByEnumerateStep is the position-independent catch-all
// deletion step that fixes BUG-04-A (P0, stale catch-all ID after
// `ufw insert 1` shifts positions) and BUG-04-C (P0, only-one-catch-all
// deleted on dual-family v4+v6 hosts). Both bugs were caught by Plan 04-10's
// empirical UAT — see 04-10-SUMMARY's "Production bugs discovered" table.
//
// Apply's contract:
//  1. Re-Enumerate via firewall.Enumerate at Apply time (NOT at construction).
//     This guarantees fresh IDs even after intervening UfwInsert calls
//     shifted positions.
//  2. Loop up to maxCatchAllIterations times, deleting the first matching
//     catch-all (Source=Anywhere, ALLOW, RawComment=="", port matches).
//     ufw renumbers after each delete; the next Enumerate sees the
//     compacted state.
//  3. Terminate cleanly when no more catch-alls are found. Both v4 and v6
//     catch-alls are deleted in any order they appear (the predicate
//     doesn't distinguish — Rule.Source equals "Anywhere" for both after
//     enumerate.go's stripV6Suffix).
//
// Idempotency: zero catch-alls present → zero UfwDelete calls → return nil.
// A "rule not found" / "Could not delete" exit phrase from a UfwDelete call
// is treated as success (admin or race deleted concurrently); the loop
// continues to the next iteration.
//
// Compensate is intentional no-op per D-FW-07 — once a rule is gone at the
// tool layer, the SAFE-04 transient-unit revert is the ONLY recovery path.
// The wrapping NewScheduleRevertStep's reverseCmds includes the per-rule
// re-add commands; the SAFE-04 timer fires those if Apply errors mid-loop.
//
// Architectural note: this Step imports internal/firewall, breaking the
// Plan 04-04 constraint that txn imports only sysops. The break is
// deliberate and minimal — Enumerate is read-only, has no other dep on
// txn, and is the load-bearing primitive for the catch-all predicate that
// must match firewall.DetectMode's predicate exactly. Inline-duplicating
// the predicate would risk drift between detection and deletion. (If
// future refactoring extracts the predicate into a shared package — e.g.
// internal/firewall/predicates — this Step can switch to that import
// without behavior change.)
func NewUfwDeleteCatchAllByEnumerateStep(port string) Step {
	return &ufwDeleteCatchAllByEnumerateStep{port: port}
}

type ufwDeleteCatchAllByEnumerateStep struct {
	port string
}

func (s *ufwDeleteCatchAllByEnumerateStep) Name() string {
	return "UfwDeleteCatchAllByEnumerate"
}

func (s *ufwDeleteCatchAllByEnumerateStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	for i := 0; i < maxCatchAllIterations; i++ {
		rules, err := firewall.Enumerate(ctx, ops)
		if err != nil {
			return fmt.Errorf("UfwDeleteCatchAllByEnumerate iter=%d enumerate: %w", i, err)
		}
		id := s.findCatchAllID(rules)
		if id < 0 {
			// No catch-alls remain — clean termination.
			return nil
		}
		if dErr := ops.UfwDelete(ctx, id); dErr != nil {
			msg := dErr.Error()
			if strings.Contains(msg, "Could not delete") || strings.Contains(msg, "rule not found") {
				// Idempotent: admin or race deleted concurrently; continue.
				continue
			}
			return fmt.Errorf("UfwDeleteCatchAllByEnumerate iter=%d delete id=%d: %w", i, id, dErr)
		}
	}
	// Loop bound exceeded without clean termination. Defensive — should
	// never trigger on real hosts (max 2 catch-alls expected). Surface
	// as error so the SAFE-04 timer can take over.
	return fmt.Errorf("UfwDeleteCatchAllByEnumerate: exceeded %d iterations without clearing all catch-alls "+
		"(possible Enumerate parser bug or runaway state)", maxCatchAllIterations)
}

func (s *ufwDeleteCatchAllByEnumerateStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	// Intentional no-op per D-FW-07 / D-S04-05: catch-all deletion is
	// irreversible by design. Recovery rides the wrapping SAFE-04
	// NewScheduleRevertStep's reverseCmds.
	return nil
}

// findCatchAllID returns the ID of the first catch-all rule matching this
// step's port, or -1 if none. The predicate matches firewall.DetectMode's
// hasCatchAll predicate exactly (mode.go lines 67-99):
//   - Action contains "ALLOW" (case-insensitive)
//   - Source equals "Anywhere" (case-insensitive — both v4 and v6 catch-alls
//     after enumerate.go's stripV6Suffix)
//   - RawComment == "" (foreign / sftpj rules carry non-empty comments)
//   - portMatchesCatchAllPort(rule.Port, s.port) — accepts "22", "22/tcp",
//     "22/udp" against s.port="22"
func (s *ufwDeleteCatchAllByEnumerateStep) findCatchAllID(rules []firewall.Rule) int {
	for _, r := range rules {
		if !portMatchesCatchAllPort(r.Port, s.port) {
			continue
		}
		if !strings.Contains(strings.ToUpper(r.Action), "ALLOW") {
			continue
		}
		if r.RawComment != "" {
			continue
		}
		if !strings.EqualFold(r.Source, "Anywhere") {
			continue
		}
		return r.ID
	}
	return -1
}

// portMatchesCatchAllPort mirrors firewall.portMatches (mode.go:101-115)
// verbatim. Duplicated rather than imported because firewall.portMatches
// is unexported; the duplication is small (4 lines) and the predicate is
// load-bearing for the catch-all definition contract — keeping the two
// copies in lock-step is a small-enough hazard.
func portMatchesCatchAllPort(rulePort, sftpPort string) bool {
	if rulePort == sftpPort {
		return true
	}
	for _, suffix := range []string{"/tcp", "/udp"} {
		if rulePort == sftpPort+suffix {
			return true
		}
	}
	return false
}

// ---- WriteUfwIPV6 ↔ (restore prior /etc/default/ufw bytes) ----------------

// NewWriteUfwIPV6Step is the SAFE-03-style backup+rewrite of
// /etc/default/ufw to set IPV6=<value>. Apply captures the prior bytes via
// ops.ReadFile then calls ops.RewriteUfwIPV6 (which uses AtomicWriteFile
// internally per Plan 04-01). Compensate restores the prior bytes via
// AtomicWriteFile, or RemoveAll if the prior file did not exist.
//
// The single-step shape (subsuming "backup + rewrite") matches the Phase 3
// NewWriteSshdDropInStep precedent (steps.go:40-92). Aliased constructors
// NewBackupDefaultUfwStep and NewRewriteUfwIPV6Step are provided for plans
// that compose explicitly with the more-granular CONTEXT.md vocabulary.
//
// Idempotency: rewriting the same prior bytes is a deterministic
// AtomicWriteFile no-op; RemoveAll treats ErrNotExist as success.
//
// The `now` arg is the time-source seam for any future backup-path emission
// (currently unused — restoration is in-place from priorBytes captured in
// Apply, no on-disk backup file).
func NewWriteUfwIPV6Step(value string, now func() time.Time) Step {
	if now == nil {
		now = time.Now
	}
	return &writeUfwIPV6Step{value: value, now: now}
}

type writeUfwIPV6Step struct {
	value string
	now   func() time.Time
	// populated by Apply for use in Compensate:
	priorBytes  []byte
	priorExists bool
}

func (s *writeUfwIPV6Step) Name() string { return "WriteUfwIPV6" }
func (s *writeUfwIPV6Step) Apply(ctx context.Context, ops sysops.SystemOps) error {
	prior, err := ops.ReadFile(ctx, ufwDefaultPath)
	if err == nil {
		s.priorBytes = prior
		s.priorExists = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("WriteUfwIPV6 read prior: %w", err)
	}
	if werr := ops.RewriteUfwIPV6(ctx, s.value); werr != nil {
		return fmt.Errorf("WriteUfwIPV6 rewrite: %w", werr)
	}
	return nil
}
func (s *writeUfwIPV6Step) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if !s.priorExists {
		return ops.RemoveAll(ctx, ufwDefaultPath)
	}
	return ops.AtomicWriteFile(ctx, ufwDefaultPath, s.priorBytes, 0o644)
}

// NewBackupDefaultUfwStep is the CONTEXT.md alias for the backup-half of the
// /etc/default/ufw rewrite cycle. In practice it returns the same composite
// Step as NewWriteUfwIPV6Step("", now) — the backup capture happens inside
// Apply, atomically with the rewrite. Production callers should use
// NewWriteUfwIPV6Step directly for clarity.
func NewBackupDefaultUfwStep(now func() time.Time) Step {
	return NewWriteUfwIPV6Step("", now)
}

// NewRewriteUfwIPV6Step is the CONTEXT.md alias for NewWriteUfwIPV6Step.
// Same constructor, same semantics — distinct name for plans that compose
// the rewrite cycle in two named conceptual steps.
func NewRewriteUfwIPV6Step(value string, now func() time.Time) Step {
	return NewWriteUfwIPV6Step(value, now)
}

// ---- SystemctlRestartUfw ↔ SystemctlRestartUfw (re-issue) -----------------

// NewSystemctlRestartUfwStep wraps `systemctl restart ufw` after
// /etc/default/ufw is rewritten (the kernel must reload the IPV6 setting).
// Compensate re-issues so a prior file-restore returns the kernel to its
// prior config.
//
// Implementation note: this dispatches via ops.Exec("systemctl", "restart",
// "ufw") — no dedicated typed wrapper exists yet (would require extending
// sysops). For Phase 4 we accept the bare Exec call through the existing
// "Useradd uses Exec underneath" precedent — the binary is in the r.Exec
// allowlist (systemctl is allowlisted by Plan 03-01).
func NewSystemctlRestartUfwStep() Step {
	return &systemctlRestartUfwStep{}
}

type systemctlRestartUfwStep struct{}

func (s *systemctlRestartUfwStep) Name() string { return "SystemctlRestartUfw" }
func (s *systemctlRestartUfwStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	res, err := ops.Exec(ctx, "systemctl", "restart", "ufw")
	if err != nil {
		return fmt.Errorf("SystemctlRestartUfw: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("SystemctlRestartUfw exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
func (s *systemctlRestartUfwStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	res, err := ops.Exec(ctx, "systemctl", "restart", "ufw")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("SystemctlRestartUfw compensate exit %d", res.ExitCode)
	}
	return nil
}

// ---- ScheduleRevert (SAFE-04 phase gate) ----------------------------------

// NewScheduleRevertStep arms a 3-min systemd-run --on-active=<dur>
// --unit=sftpj-revert-<unix-ns>.service transient unit whose ExecStart is
// `/bin/sh -c '<reverseCmds joined by ;>'` per D-S04-08. Per D-S04-04 the
// unix-nanosecond unit name is monotonic, sortable in `systemctl
// list-units`, and conflict-free for human-paced operations.
//
// Apply: schedules the unit + writes the on-disk pointer via watcher.Set
// (D-S04-06).
//
// Compensate: stops the unit (idempotent — non-zero exit is mapped to nil at
// the call site) AND clears the watcher pointer so a downstream rollback
// doesn't leave the pointer file orphaned (T-04-02-05 mitigation).
//
// The SAFE-04 wrapper pair (this Step + NewCancelRevertStep) sandwiches the
// FW mutation steps in tx.Apply. Cancel is NOT in the txn batch — it runs
// only after admin Confirm in the countdown UI (see D-S04-09 step 5).
//
// Threat-model commitments (T-04-02-01 / T-04-02-02 / T-04-02-03):
//   - reverseCmds is constructed by Plan 04-08's RenderReverseCommands which
//     composes from already-validated CIDR (net.ParseCIDR) + already-encoded
//     comments (ufwcomment.Encode regex). This Step does NO string
//     concatenation of user-influenced values.
//   - Apply rejects deadlines < 1 second in the future with explicit error.
//   - Unit-name uses now().UnixNano() — monotonic; collisions impossible at
//     human pace.
func NewScheduleRevertStep(reverseCmds []string, deadline time.Time, watcher RevertWatcher, now func() time.Time) Step {
	if now == nil {
		now = time.Now
	}
	return &scheduleRevertStep{
		reverseCmds: reverseCmds,
		deadline:    deadline,
		watcher:     watcher,
		now:         now,
	}
}

type scheduleRevertStep struct {
	reverseCmds []string
	deadline    time.Time
	watcher     RevertWatcher
	now         func() time.Time
	// populated by Apply for use in Compensate + UnitName():
	unitName string
}

func (s *scheduleRevertStep) Name() string { return "ScheduleRevert" }

func (s *scheduleRevertStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	// Compose the verbatim ExecStart body. The trailing `ufw reload` (when
	// present) is appended by the caller in reverseCmds — this Step doesn't
	// add it implicitly.
	cmd := strings.Join(s.reverseCmds, "; ")
	if cmd == "" {
		return errors.New("ScheduleRevert: no reverse commands provided")
	}
	// OnActive duration = deadline - now (caller-injected time source).
	onActive := s.deadline.Sub(s.now())
	if onActive < time.Second {
		return fmt.Errorf("ScheduleRevert: deadline must be at least 1 second in the future, got %s", onActive)
	}
	s.unitName = fmt.Sprintf("sftpj-revert-%d.service", s.now().UnixNano())
	if err := ops.SystemdRunOnActive(ctx, sysops.SystemdRunOpts{
		OnActive: onActive,
		UnitName: s.unitName,
		Command:  cmd,
	}); err != nil {
		return fmt.Errorf("ScheduleRevert systemd-run: %w", err)
	}
	if s.watcher != nil {
		if err := s.watcher.Set(ctx, s.unitName, s.deadline, s.reverseCmds); err != nil {
			// Try to undo the systemd-run schedule so we don't leave a ghost
			// timer behind. Best-effort: ignore the stop error (idempotent).
			_ = ops.SystemctlStop(ctx, s.unitName)
			return fmt.Errorf("ScheduleRevert watcher.Set: %w", err)
		}
	}
	return nil
}

func (s *scheduleRevertStep) Compensate(ctx context.Context, ops sysops.SystemOps) error {
	if s.unitName == "" {
		return nil // Apply never ran or never assigned a unit
	}
	// Stop is idempotent: non-zero exit on already-stopped / never-loaded is
	// mapped to nil here. Surface ctx errors only.
	_ = ops.SystemctlStop(ctx, s.unitName)
	if s.watcher != nil {
		// T-04-02-05 mitigation: clearing is best-effort — a Clear failure
		// would otherwise cascade through the rollback. Plan 04-04's
		// Watcher.Restore detects orphan pointers via SystemctlIsActive and
		// self-cleans on next TUI startup.
		_ = s.watcher.Clear(ctx)
	}
	return nil
}

// UnitName exposes the assigned unit name for the post-Apply countdown UI.
// Returns "" before Apply runs.
func (s *scheduleRevertStep) UnitName() string { return s.unitName }

// ---- CancelRevert (no compensator — D-S04-05 cancellation irreversible) ---

// NewCancelRevertStep stops the named transient unit and clears the watcher
// pointer. Apply runs only after admin confirmation in the countdown UI
// (D-S04-09 step 5). Compensate is intentionally a no-op per D-S04-05: once
// Cancel runs, the rules are permanent. Downstream failures cannot
// un-permanent-ize them.
//
// Idempotency: ops.SystemctlStop on an already-stopped or never-loaded unit
// returns non-zero exit; we map that to success. Only ctx-level exec errors
// are surfaced.
func NewCancelRevertStep(unitName string, watcher RevertWatcher) Step {
	return &cancelRevertStep{unitName: unitName, watcher: watcher}
}

type cancelRevertStep struct {
	unitName string
	watcher  RevertWatcher
}

func (s *cancelRevertStep) Name() string { return "CancelRevert" }
func (s *cancelRevertStep) Apply(ctx context.Context, ops sysops.SystemOps) error {
	// BUG-04-D fix (P0, was empirically caught by Plan 04-10 UAT —
	// 04-10-SUMMARY "Production bugs discovered" table).
	//
	// systemd-run --on-active=<dur> --unit=<X>.service per D-S04-04 creates
	// BOTH a `.service` AND a `.timer` transient unit. The .timer is what
	// fires the .service at the deadline; stopping only the .service leaves
	// the .timer armed, which fires the .service AGAIN at the original
	// deadline — undoing the just-confirmed mutation.
	//
	// Stop order: .timer FIRST (so it can't re-arm the .service between
	// the two stops), then .service. Both stops are idempotent on
	// "not loaded" / "not found" — by the time admin presses Confirm,
	// either or both units may already be gone (timer fired self-cleaning,
	// admin re-pressed Confirm, etc.).
	//
	// s.unitName always carries the ".service" suffix per
	// scheduleRevertStep.Apply (fmt.Sprintf("sftpj-revert-%d.service", ...)).
	timerName := strings.TrimSuffix(s.unitName, ".service") + ".timer"
	if err := ops.SystemctlStop(ctx, timerName); err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "not loaded") && !strings.Contains(msg, "not found") {
			return fmt.Errorf("CancelRevert stop timer: %w", err)
		}
		// "not loaded" / "not found" → idempotent success; fall through
		// to .service stop (the .service may still be running).
	}
	if err := ops.SystemctlStop(ctx, s.unitName); err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "not loaded") && !strings.Contains(msg, "not found") {
			return fmt.Errorf("CancelRevert stop service: %w", err)
		}
		// fall through to watcher.Clear
	}
	if s.watcher != nil {
		if err := s.watcher.Clear(ctx); err != nil {
			return fmt.Errorf("CancelRevert watcher.Clear: %w", err)
		}
	}
	return nil
}
func (s *cancelRevertStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	// Intentional no-op per D-S04-05: cancellation is irreversible by
	// design. Once SystemctlStop succeeds, the SAFE-04 transient unit is
	// gone — the FW rules just applied are permanent.
	return nil
}
