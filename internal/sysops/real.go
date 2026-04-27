package sysops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// errEmptyLastChange signals that /etc/shadow has the user line but field
// 3 is empty (force-change-on-next-login). Caller should leave
// PasswordAgeDays at -1.
var errEmptyLastChange = errors.New("ReadShadow: empty last-change field")

// Real is the production SystemOps implementation. It is the ONLY type in
// the project that holds os/exec state or calls unix syscalls directly.
//
// Exported so tests in the same package (and plan-02/04 tests) can construct
// and inspect it, e.g. r, ok := sysops.NewReal().(*sysops.Real).
type Real struct {
	// Absolute paths resolved once at startup — defeats $PATH injection by a
	// compromised environment, and makes audit logging unambiguous.
	binSshd       string
	binAAStatus   string
	binNft        string
	binSystemctl  string
	binJournalctl string // Phase 2 — observe-run + S-LOGS live-tail
	binUfw        string // Phase 2 — internal/firewall reader (consumed by 02-03)

	// Phase 3 — user/group + password + aging + reload + archive binaries.
	binUseradd  string
	binUserdel  string
	binGpasswd  string
	binChpasswd string
	binChage    string
	binTar      string

	// Phase 4 — FW-06 IPv6 detection + SAFE-04 transient-unit revert.
	binIp         string // `ip -6 addr show scope global` (HasPublicIPv6)
	binSystemdRun string // `systemd-run --on-active=<dur> --unit=<n> /bin/sh -c '<cmd>'`

	// defaultTimeout applies to Exec() calls whose context has no deadline.
	// Bounds T-01-07 (unbounded subprocess hang).
	defaultTimeout time.Duration
}

// NewReal resolves binary paths and returns the production implementation.
// Missing binaries are non-fatal for Phase 1 — the doctor detector surfaces
// "not installed" as diagnostic state. The per-method "binary not installed"
// check returns the typed error at call time.
func NewReal() SystemOps {
	r := &Real{defaultTimeout: 10 * time.Second}
	r.binSshd, _ = exec.LookPath("sshd")
	r.binAAStatus, _ = exec.LookPath("aa-status")
	r.binNft, _ = exec.LookPath("nft")
	r.binSystemctl, _ = exec.LookPath("systemctl")
	r.binJournalctl, _ = exec.LookPath("journalctl")
	r.binUfw, _ = exec.LookPath("ufw")
	// Phase 3 binaries.
	r.binUseradd, _ = exec.LookPath("useradd")
	r.binUserdel, _ = exec.LookPath("userdel")
	r.binGpasswd, _ = exec.LookPath("gpasswd")
	r.binChpasswd, _ = exec.LookPath("chpasswd")
	r.binChage, _ = exec.LookPath("chage")
	r.binTar, _ = exec.LookPath("tar")
	// Phase 4 binaries.
	r.binIp, _ = exec.LookPath("ip")
	r.binSystemdRun, _ = exec.LookPath("systemd-run")
	return r
}

// Geteuid implements [SystemOps.Geteuid].
func (r *Real) Geteuid() int { return os.Geteuid() }

// ReadFile implements [SystemOps.ReadFile]. Synchronous; ctx is accepted for
// interface symmetry with slow-I/O methods.
//
// gosec G304: caller-supplied path is the documented SystemOps contract;
// only this package may shell out or touch /etc, so path validation is the
// caller's responsibility.
func (r *Real) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: deliberate — sysops contract
}

// ReadDir implements [SystemOps.ReadDir].
func (r *Real) ReadDir(_ context.Context, path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}

// Stat implements [SystemOps.Stat] (follows symlinks).
func (r *Real) Stat(_ context.Context, path string) (FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Path:    path,
		Mode:    fs.FileMode(st.Mode & 0o7777),
		UID:     st.Uid,
		GID:     st.Gid,
		IsDir:   (st.Mode & syscall.S_IFDIR) != 0,
		IsLink:  false, // Stat follows symlinks by definition
		ModTime: time.Unix(st.Mtim.Unix()),
	}, nil
}

// Lstat implements [SystemOps.Lstat] (does not follow symlinks).
func (r *Real) Lstat(_ context.Context, path string) (FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Path:    path,
		Mode:    fs.FileMode(st.Mode & 0o7777),
		UID:     st.Uid,
		GID:     st.Gid,
		IsDir:   (st.Mode & syscall.S_IFDIR) != 0,
		IsLink:  (st.Mode & syscall.S_IFLNK) != 0,
		ModTime: time.Unix(st.Mtim.Unix()),
	}, nil
}

// Glob implements [SystemOps.Glob].
func (r *Real) Glob(_ context.Context, pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

// Exec enforces: allowlist, absolute path, context timeout, no sh -c,
// no inherited stdin. Non-zero exit codes are reported via ExecResult.ExitCode
// rather than error — the caller interprets.
//
// Absolute-path names (starting with /) bypass the allowlist. This is used by
// tests (e.g. /bin/sleep) and must NEVER be used from production code paths —
// the CI grep guard (scripts/check-no-exec-outside-sysops.sh) plus code review
// keep this honest.
func (r *Real) Exec(ctx context.Context, name string, args ...string) (ExecResult, error) {
	var bin string
	if strings.HasPrefix(name, "/") {
		// Escape hatch for tests; production code must use allowlisted names.
		bin = name
	} else {
		allow := map[string]string{
			"sshd":       r.binSshd,
			"aa-status":  r.binAAStatus,
			"nft":        r.binNft,
			"systemctl":  r.binSystemctl,
			"journalctl": r.binJournalctl, // Phase 2 — observe-run + live-tail
			"ufw":        r.binUfw,        // Phase 2 — firewall reader (02-03)
			// Phase 3 — user/group/aging/archive mutations.
			"useradd": r.binUseradd,
			"userdel": r.binUserdel,
			"gpasswd": r.binGpasswd,
			"chage":   r.binChage,
			"tar":     r.binTar,
			// Phase 4 — FW-06 detection + SAFE-04 transient unit.
			"ip":          r.binIp,         // Phase 4 — HasPublicIPv6
			"systemd-run": r.binSystemdRun, // Phase 4 — SAFE-04 transient unit
			// chpasswd is INTENTIONALLY excluded from this allow map: it
			// has its own non-Exec wrapper (chpasswd.go) for the stdin
			// pipe per pitfall E3 (password never on argv).
		}
		b, ok := allow[name]
		if !ok || b == "" {
			return ExecResult{}, fmt.Errorf("sysops: binary %q not allowlisted or not installed", name)
		}
		bin = b
	}

	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	// E3: Phase 1 has zero interactive subprocesses. Never inherit stdin;
	// would steal bytes from Bubble Tea's input reader in later phases.
	cmd.Stdin = nil

	start := time.Now()
	out, err := cmd.CombinedOutput()
	res := ExecResult{
		Stdout:   out,
		Duration: time.Since(start),
	}

	// Context errors take precedence — surface them so callers can retry or abort.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		res.Stderr = exitErr.Stderr
		return res, nil // non-zero exit is not a Go error
	}
	return res, err
}

// ReadShadow implements [SystemOps.ReadShadow]. Reads /etc/shadow and
// returns BOTH field 3 (last-password-change-day, days since 1970-01-01
// UTC) AND field 5 (password-max-days; >= 99999 conventionally means
// "no expiry policy"; an empty field is reported as 0) for the matching
// user.
//
// /etc/shadow format (per shadow(5)):
//
//	user:hash:lstchg:min:max:warn:inactive:expire:reserved
//
// Returns fs.ErrNotExist if the user is not present in the file.
// Returns the underlying ReadFile error for permission/missing-file paths.
// An empty lstchg field (force-change-on-next-login) is reported as
// (0, 0, errEmptyLastChange) — callers SHOULD treat this as "unknown" and
// leave PasswordAgeDays / PasswordMaxDays at -1 (graceful degradation).
//
// gosec G304: deliberate — sysops contract; root-only access controlled
// by ownership/mode (0640 root:shadow on Ubuntu 24.04).
func (r *Real) ReadShadow(_ context.Context, username string) (int, int, error) {
	raw, err := os.ReadFile("/etc/shadow") //nolint:gosec // G304: deliberate — sysops contract
	if err != nil {
		return 0, 0, fmt.Errorf("ReadShadow read /etc/shadow: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 9)
		if len(fields) < 5 {
			// Malformed shadow line — skip rather than crash.
			continue
		}
		if fields[0] != username {
			continue
		}
		if fields[2] == "" {
			return 0, 0, errEmptyLastChange
		}
		lstchg, perr := strconv.Atoi(fields[2])
		if perr != nil {
			return 0, 0, fmt.Errorf("ReadShadow parse field 3 for %q: %w", username, perr)
		}
		// Field 5 (max). Empty string is conventionally "not set" → 0; we
		// surface 0 rather than an error so the caller can render ∞ via
		// the FormatPasswordAge contract (max==0 → indefinite policy).
		var maxDays int
		if fields[4] != "" {
			maxDays, perr = strconv.Atoi(fields[4])
			if perr != nil {
				return 0, 0, fmt.Errorf("ReadShadow parse field 5 for %q: %w", username, perr)
			}
		}
		return lstchg, maxDays, nil
	}
	return 0, 0, fs.ErrNotExist
}

// ----------------------------------------------------------------------------
// Phase 3 mutation methods. Each method follows the existing wrapper
// shape: binary-missing fast-fail, build args, exec via r.Exec (which
// owns the allowlist + timeout), interpret ExitCode → typed error.
//
// Chmod / Chown / MkdirAll / RemoveAll wrap os.* directly (no exec) and
// accept ctx for interface symmetry; cancellation has no leverage on
// these synchronous syscalls. SshdT / SshdTWithContext use exec directly
// (not r.Exec) because they need stderr split from stdout.
// ----------------------------------------------------------------------------

// Useradd implements [SystemOps.Useradd] — `useradd` typed wrapper. See man8/useradd.
func (r *Real) Useradd(ctx context.Context, opts UseraddOpts) error {
	if r.binUseradd == "" {
		return fmt.Errorf("sysops: useradd not installed")
	}
	args := []string{}
	if opts.UID > 0 {
		args = append(args, "-u", strconv.Itoa(opts.UID))
	}
	if opts.GID > 0 {
		args = append(args, "-g", strconv.Itoa(opts.GID))
	}
	if opts.Home != "" {
		args = append(args, "-d", opts.Home)
	}
	if opts.Shell != "" {
		args = append(args, "-s", opts.Shell)
	}
	if opts.CreateHome {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	args = append(args, opts.Username)

	res, err := r.Exec(ctx, "useradd", args...)
	if err != nil {
		return fmt.Errorf("sysops.Useradd %s: %w", opts.Username, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.Useradd %s: exit %d: %s",
			opts.Username, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Userdel implements [SystemOps.Userdel] — `userdel [-r] <user>`.
func (r *Real) Userdel(ctx context.Context, username string, removeHome bool) error {
	if r.binUserdel == "" {
		return fmt.Errorf("sysops: userdel not installed")
	}
	args := []string{}
	if removeHome {
		args = append(args, "-r")
	}
	args = append(args, username)
	res, err := r.Exec(ctx, "userdel", args...)
	if err != nil {
		return fmt.Errorf("sysops.Userdel %s: %w", username, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.Userdel %s: exit %d: %s",
			username, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Gpasswd implements [SystemOps.Gpasswd] — `gpasswd -a|-d <user> <group>`.
func (r *Real) Gpasswd(ctx context.Context, op GpasswdOp, username, group string) error {
	if r.binGpasswd == "" {
		return fmt.Errorf("sysops: gpasswd not installed")
	}
	var flag string
	switch op {
	case GpasswdAdd:
		flag = "-a"
	case GpasswdDel:
		flag = "-d"
	default:
		return fmt.Errorf("sysops.Gpasswd: unknown op %d", op)
	}
	res, err := r.Exec(ctx, "gpasswd", flag, username, group)
	if err != nil {
		return fmt.Errorf("sysops.Gpasswd %s %s %s: %w", flag, username, group, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.Gpasswd %s %s %s: exit %d: %s",
			flag, username, group, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Chage implements [SystemOps.Chage] — `chage -d <days> <user>`.
func (r *Real) Chage(ctx context.Context, username string, opts ChageOpts) error {
	if r.binChage == "" {
		return fmt.Errorf("sysops: chage not installed")
	}
	res, err := r.Exec(ctx, "chage", "-d", strconv.Itoa(opts.LastDay), username)
	if err != nil {
		return fmt.Errorf("sysops.Chage %s: %w", username, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.Chage %s: exit %d: %s",
			username, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Chmod implements [SystemOps.Chmod]. Wraps os.Chmod directly (no exec).
// gosec G302: mode supplied by caller per the SystemOps contract.
func (r *Real) Chmod(_ context.Context, path string, mode fs.FileMode) error {
	if err := os.Chmod(path, mode); err != nil { //nolint:gosec // G302: mode from caller per sysops contract
		return fmt.Errorf("sysops.Chmod %s mode=%o: %w", path, mode, err)
	}
	return nil
}

// Chown implements [SystemOps.Chown]. Wraps os.Chown directly (no exec).
func (r *Real) Chown(_ context.Context, path string, uid, gid int) error {
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("sysops.Chown %s uid=%d gid=%d: %w", path, uid, gid, err)
	}
	return nil
}

// MkdirAll implements [SystemOps.MkdirAll]. Wraps os.MkdirAll. ctx accepted
// for interface symmetry but unused — synchronous syscall, no cancellation
// leverage.
func (r *Real) MkdirAll(_ context.Context, path string, mode fs.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil { //nolint:gosec // G301: mode from caller per sysops contract
		return fmt.Errorf("sysops.MkdirAll %s mode=%o: %w", path, mode, err)
	}
	return nil
}

// RemoveAll implements [SystemOps.RemoveAll]. Wraps os.RemoveAll; ErrNotExist
// is treated as success per os.RemoveAll convention.
func (r *Real) RemoveAll(_ context.Context, path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("sysops.RemoveAll %s: %w", path, err)
	}
	return nil
}

// WriteAuthorizedKeys implements [SystemOps.WriteAuthorizedKeys]. Composite
// wrapper per D-18: ensures <chrootRoot>/<username>/.ssh exists with mode
// 0700 owned <user>:<user>, then atomically writes authorized_keys with
// mode 0600 owned <user>:<user>.
//
// Threat model T-03-01-04 / T-03-01-08:
//   - Username is resolved through os/user.Lookup, which rejects non-existent
//     users. Caller MUST also reject usernames containing `..` before calling
//     (validator lives in plan 03-08b).
//   - The MkdirAll(0700) + Chmod(0700) pair closes the umask-determined-mode
//     window (mirror pitfall 1 useradd-mkdir race). sshd's StrictModes
//     verifier catches any persistent mode mismatch.
func (r *Real) WriteAuthorizedKeys(ctx context.Context, username, chrootRoot string, keys []byte) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys lookup %s: %w", username, err)
	}
	uid, perr := strconv.Atoi(u.Uid)
	if perr != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys parse uid %q: %w", u.Uid, perr)
	}
	gid, perr := strconv.Atoi(u.Gid)
	if perr != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys parse gid %q: %w", u.Gid, perr)
	}

	sshDir := filepath.Join(chrootRoot, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys mkdir %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys chown ssh dir %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil { //nolint:gosec // G302: explicit mode is the documented contract
		return fmt.Errorf("sysops.WriteAuthorizedKeys chmod ssh dir %s: %w", sshDir, err)
	}

	authPath := filepath.Join(sshDir, "authorized_keys")
	if err := r.AtomicWriteFile(ctx, authPath, keys, 0o600); err != nil {
		return err
	}
	if err := os.Chown(authPath, uid, gid); err != nil {
		return fmt.Errorf("sysops.WriteAuthorizedKeys chown %s: %w", authPath, err)
	}
	return nil
}

// SshdT implements [SystemOps.SshdT] — `sshd -t` (config validator) WITHOUT
// -C user-context. Returns stderr verbatim and a non-nil error on non-zero
// exit. exec.CombinedOutput is wrong here: we need stderr split from stdout
// because sshd -t writes diagnostics ONLY to stderr.
func (r *Real) SshdT(ctx context.Context) ([]byte, error) {
	if r.binSshd == "" {
		return nil, fmt.Errorf("sysops: sshd not installed")
	}
	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.binSshd, "-t") //nolint:gosec // G204: typed wrapper, fixed argv shape
	cmd.Stdin = nil
	var serr bytes.Buffer
	cmd.Stderr = &serr
	err := cmd.Run()
	return serr.Bytes(), err
}

// SshdTWithContext implements [SystemOps.SshdTWithContext]. Per D-21 step 4
// the M-ADD-KEY verifier needs `-C user=<u>,host=<h>,addr=<a>` so the
// validator evaluates Match-block-scoped directives for THIS user.
//
// T-03-01-09: the fmt.Sprintf builds `user=%s,host=%s,addr=%s` — caller
// MUST pre-validate opts.User (no commas / `=` characters); host/addr are
// tool-set literals.
func (r *Real) SshdTWithContext(ctx context.Context, opts SshdTContextOpts) ([]byte, error) {
	if r.binSshd == "" {
		return nil, fmt.Errorf("sysops: sshd not installed")
	}
	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
		defer cancel()
	}
	connSpec := fmt.Sprintf("user=%s,host=%s,addr=%s", opts.User, opts.Host, opts.Addr)
	// OpenSSH requires -T (extended test mode that prints effective config) when
	// -C is supplied; -t alone exits 255 with "Config test connection parameter
	// (-C) provided without test mode (-T)". Discovered empirically against
	// OpenSSH 9.6 on Ubuntu 24.04. Stdout (effective config dump) is discarded;
	// non-zero exit still surfaces parse failures via stderr.
	cmd := exec.CommandContext(ctx, r.binSshd, "-T", "-C", connSpec) //nolint:gosec // G204: typed wrapper, args from typed opts struct
	cmd.Stdin = nil
	cmd.Stdout = nil // discard the effective-config dump; we only care about exit + stderr
	var serr bytes.Buffer
	cmd.Stderr = &serr
	err := cmd.Run()
	return serr.Bytes(), err
}

// SystemctlReload implements [SystemOps.SystemctlReload].
func (r *Real) SystemctlReload(ctx context.Context, unit string) error {
	res, err := r.Exec(ctx, "systemctl", "reload", unit)
	if err != nil {
		return fmt.Errorf("sysops.SystemctlReload %s: %w", unit, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.SystemctlReload %s: exit %d: %s",
			unit, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// SystemctlRestartSocket implements [SystemOps.SystemctlRestartSocket].
// SAFE-06: socket-affecting directives require restart of ssh.socket.
func (r *Real) SystemctlRestartSocket(ctx context.Context, unit string) error {
	res, err := r.Exec(ctx, "systemctl", "restart", unit)
	if err != nil {
		return fmt.Errorf("sysops.SystemctlRestartSocket %s: %w", unit, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.SystemctlRestartSocket %s: exit %d: %s",
			unit, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// SystemctlDaemonReload implements [SystemOps.SystemctlDaemonReload].
func (r *Real) SystemctlDaemonReload(ctx context.Context) error {
	res, err := r.Exec(ctx, "systemctl", "daemon-reload")
	if err != nil {
		return fmt.Errorf("sysops.SystemctlDaemonReload: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.SystemctlDaemonReload: exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Tar implements [SystemOps.Tar]. D-15 archive path uses TarCreateGzip.
func (r *Real) Tar(ctx context.Context, opts TarOpts) error {
	if r.binTar == "" {
		return fmt.Errorf("sysops: tar not installed")
	}
	var flag string
	switch opts.Mode {
	case TarCreateGzip:
		flag = "-czf"
	default:
		return fmt.Errorf("sysops.Tar: unknown mode %d", opts.Mode)
	}
	res, err := r.Exec(ctx, "tar", flag, opts.ArchivePath, opts.SourceDir)
	if err != nil {
		return fmt.Errorf("sysops.Tar %s: %w", opts.ArchivePath, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.Tar %s: exit %d: %s",
			opts.ArchivePath, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// ----------------------------------------------------------------------------
// Phase 4 mutation methods — see internal/sysops/sysops.go for the
// interface contract. These follow the Phase 3 Useradd / SshdT /
// SshdDumpConfig wrapper shape: binary-missing fast-fail, build args,
// exec via r.Exec (allowlist + timeout), interpret ExitCode → typed
// error. Architectural invariant: every Phase 4 ufw / systemd-run /
// systemctl / ip callsite lives in this file. CI guard
// scripts/check-no-exec-outside-sysops.sh enforces.
// ----------------------------------------------------------------------------

// UfwAllow implements [SystemOps.UfwAllow] (D-FW-01).
func (r *Real) UfwAllow(ctx context.Context, opts UfwAllowOpts) error {
	if r.binUfw == "" {
		return fmt.Errorf("sysops: ufw not installed")
	}
	args := []string{"allow"}
	if opts.Proto != "" {
		args = append(args, "proto", opts.Proto)
	}
	args = append(args, "from", opts.Source, "to", "any", "port", opts.Port)
	if opts.Comment != "" {
		args = append(args, "comment", opts.Comment)
	}
	res, err := r.Exec(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("sysops.UfwAllow src=%s: %w", opts.Source, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.UfwAllow src=%s: exit %d: %s",
			opts.Source, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// UfwInsert implements [SystemOps.UfwInsert] — `ufw insert <position> allow …`
// (D-FW-02 always position 1 in production).
func (r *Real) UfwInsert(ctx context.Context, position int, opts UfwAllowOpts) error {
	if r.binUfw == "" {
		return fmt.Errorf("sysops: ufw not installed")
	}
	args := []string{"insert", strconv.Itoa(position), "allow"}
	if opts.Proto != "" {
		args = append(args, "proto", opts.Proto)
	}
	args = append(args, "from", opts.Source, "to", "any", "port", opts.Port)
	if opts.Comment != "" {
		args = append(args, "comment", opts.Comment)
	}
	res, err := r.Exec(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("sysops.UfwInsert pos=%d src=%s: %w", position, opts.Source, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.UfwInsert pos=%d src=%s: exit %d: %s",
			position, opts.Source, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// UfwDelete implements [SystemOps.UfwDelete] — `ufw --force delete <ruleID>`
// (D-FW-07). The --force flag is mandatory: `ufw delete N` prompts y/N
// when stdin is not a TTY (which it never is in a sysops invocation), so
// without --force the subprocess would block until ctx timeout.
func (r *Real) UfwDelete(ctx context.Context, ruleID int) error {
	if r.binUfw == "" {
		return fmt.Errorf("sysops: ufw not installed")
	}
	res, err := r.Exec(ctx, "ufw", "--force", "delete", strconv.Itoa(ruleID))
	if err != nil {
		return fmt.Errorf("sysops.UfwDelete id=%d: %w", ruleID, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.UfwDelete id=%d: exit %d: %s",
			ruleID, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// UfwReload implements [SystemOps.UfwReload] (D-FW-04). Comments survive
// across `ufw reload` per RESEARCH §scripts/smoke-ufw.sh.
func (r *Real) UfwReload(ctx context.Context) error {
	if r.binUfw == "" {
		return fmt.Errorf("sysops: ufw not installed")
	}
	res, err := r.Exec(ctx, "ufw", "reload")
	if err != nil {
		return fmt.Errorf("sysops.UfwReload: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.UfwReload: exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// HasPublicIPv6 implements [SystemOps.HasPublicIPv6] — parses
// `ip -6 addr show scope global` and returns true when at least one
// non-link-local non-loopback IPv6 address is bound (D-FW-03 step 2).
// Empty output = no public v6 = (false, nil).
func (r *Real) HasPublicIPv6(ctx context.Context) (bool, error) {
	if r.binIp == "" {
		return false, fmt.Errorf("sysops: ip not installed")
	}
	res, err := r.Exec(ctx, "ip", "-6", "addr", "show", "scope", "global")
	if err != nil {
		return false, fmt.Errorf("sysops.HasPublicIPv6: %w", err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Errorf("sysops.HasPublicIPv6: exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// `inet6 2001:db8::1/64 scope global …` — match scope global lines.
		if strings.HasPrefix(line, "inet6 ") && strings.Contains(line, "scope global") {
			return true, nil
		}
	}
	if scErr := sc.Err(); scErr != nil {
		return false, fmt.Errorf("sysops.HasPublicIPv6 scan: %w", scErr)
	}
	return false, nil
}

// RewriteUfwIPV6 implements [SystemOps.RewriteUfwIPV6] (D-FW-03 step 3).
// Reads /etc/default/ufw, replaces (or appends) the `IPV6=<value>` line,
// and atomic-writes via AtomicWriteFile. All other lines pass through
// byte-for-byte. The path /etc/default/ufw must be on the AtomicWriteFile
// allowlist (sysops/atomic.go).
func (r *Real) RewriteUfwIPV6(ctx context.Context, value string) error {
	const path = "/etc/default/ufw"
	prior, err := r.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("sysops.RewriteUfwIPV6 read %s: %w", path, err)
	}
	// Replace the first IPV6= line in place (any leading whitespace
	// preserved is fine — we match the line key only). If the line is
	// missing, append it. Comments (#) and blank lines pass through
	// verbatim.
	lines := strings.Split(string(prior), "\n")
	out := make([]string, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Match shell-style assignment prefix only.
		if !replaced && strings.HasPrefix(trimmed, "IPV6=") {
			out = append(out, "IPV6="+value)
			replaced = true
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, "IPV6="+value)
	}
	return r.AtomicWriteFile(ctx, path, []byte(strings.Join(out, "\n")), 0o644)
}

// SystemdRunOnActive implements [SystemOps.SystemdRunOnActive]
// (D-S04-04 + D-S04-08). Composes argv:
//
//	systemd-run --on-active=<N>sec --unit=<UnitName> /bin/sh -c <Command>
//
// The verbatim `<Command>` string is NOT shell-escaped here — callers MUST
// pre-validate every embedded value (ufwcomment.Encode regex + net.ParseCIDR).
func (r *Real) SystemdRunOnActive(ctx context.Context, opts SystemdRunOpts) error {
	if r.binSystemdRun == "" {
		return fmt.Errorf("sysops: systemd-run not installed")
	}
	// Map duration to a format systemd-run accepts; integer seconds is the
	// portable lowest common denominator (`<N>sec`).
	durSpec := fmt.Sprintf("%dsec", int(opts.OnActive.Seconds()))
	res, err := r.Exec(ctx, "systemd-run",
		"--on-active="+durSpec,
		"--unit="+opts.UnitName,
		"/bin/sh", "-c", opts.Command,
	)
	if err != nil {
		return fmt.Errorf("sysops.SystemdRunOnActive unit=%s: %w", opts.UnitName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.SystemdRunOnActive unit=%s: exit %d: %s",
			opts.UnitName, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// SystemctlStop implements [SystemOps.SystemctlStop]. Non-zero exit is
// surfaced as a wrapped error; the caller (NewCancelRevertStep /
// revert.Watcher.Clear) decides whether non-existent-unit / already-stopped
// states are non-fatal.
func (r *Real) SystemctlStop(ctx context.Context, unitName string) error {
	res, err := r.Exec(ctx, "systemctl", "stop", unitName)
	if err != nil {
		return fmt.Errorf("sysops.SystemctlStop %s: %w", unitName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sysops.SystemctlStop %s: exit %d: %s",
			unitName, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// SystemctlIsActive implements [SystemOps.SystemctlIsActive]. systemctl
// is-active exits 0 for active, 3 for inactive, 4 for not-loaded. The
// non-zero exits are normal "not active" states — map to (false, nil).
// Only ctx errors / exec failures surface as Go errors.
func (r *Real) SystemctlIsActive(ctx context.Context, unitName string) (bool, error) {
	res, err := r.Exec(ctx, "systemctl", "is-active", unitName)
	if err != nil {
		return false, fmt.Errorf("sysops.SystemctlIsActive %s: %w", unitName, err)
	}
	return res.ExitCode == 0, nil
}

// SshdDumpConfig parses `sshd -T` output into a map[directive][]values.
// Directive names are lowercased; values are space-joined when the original
// line has multiple whitespace-separated fields after the key. Duplicate
// directives (e.g. HostKey appearing multiple times) accumulate.
func (r *Real) SshdDumpConfig(ctx context.Context) (map[string][]string, error) {
	res, err := r.Exec(ctx, "sshd", "-T")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sysops: sshd -T exited %d: %s", res.ExitCode, bytes.TrimSpace(res.Stderr))
	}
	out := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// sshd -T uses single spaces between key and value; split on first whitespace.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := ""
		if len(fields) > 1 {
			val = strings.Join(fields[1:], " ")
		}
		out[key] = append(out[key], val)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
