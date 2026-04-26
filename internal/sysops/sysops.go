// Package sysops is the ONLY package in the project that may touch
// /etc, call os/exec, or read the journal. Every other package interacts
// with the system through the SystemOps interface.
//
// Phase 1 surface was strictly read-only. Phase 2 introduces the first
// mutation method (AtomicWriteFile) as the D-07 carve-out for
// /etc/sftp-jailer/config.yaml — the tool's own settings file. Other
// mutation methods land in Phase 3 / Phase 4 where SAFE-03 backup
// discipline applies. Phase 2 also adds three subprocess-stream methods
// (JournalctlStream, JournalctlFollowCmd, ObserveRunStream) and the flock
// helper (AcquireRunLock) that supports OBS-02 race protection.
//
// Architectural invariant enforced by scripts/check-no-exec-outside-sysops.sh.
package sysops

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"time"
)

// FileInfo wraps unix.Stat_t essentials we need exposed through the interface.
// We do not use os.FileInfo because we need Uid/Gid for the chroot ownership
// chain walk (SETUP-01). Phase 3 adds ModTime for the S-USER-DETAIL key-table
// "added on" column (consumed by plan 03-08a).
type FileInfo struct {
	Path    string
	Mode    fs.FileMode
	UID     uint32
	GID     uint32
	IsDir   bool
	IsLink  bool
	ModTime time.Time
}

// ExecResult captures the outcome of a subprocess execution. A non-zero
// ExitCode is NOT a Go error — the caller interprets. Go errors are reserved
// for things like context cancellation or exec failures (ENOENT, permission
// denied).
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// JournalctlStreamOpts parameterizes a one-shot streaming `journalctl` invocation.
// Used by the observe-run runner to drain new sshd events from the cursor file.
type JournalctlStreamOpts struct {
	// CursorFile is the path passed to `journalctl --cursor-file=…`. The file
	// is created/updated by journalctl itself; the caller never writes to it
	// directly. A nonexistent file means "start from the beginning of the
	// available journal" — see RESEARCH §"--cursor-file semantics" for the
	// initial-baseline mitigation.
	CursorFile string

	// Unit is the systemd unit to filter on (typically "ssh" on Ubuntu 24.04).
	Unit string

	// Since is an optional --since override (test-only). In production this
	// is empty and the cursor file drives the resume point.
	Since string
}

// ObserveRunSubprocessOpts parameterizes a recursive `sftp-jailer observe-run`
// subprocess invocation. Used by the M-OBSERVE TUI modal (plan 02-08) to
// stream JSON progress events back into the program via Send.
type ObserveRunSubprocessOpts struct {
	// SelfPath: absolute path to the running binary used for the recursive
	// `sftp-jailer observe-run` invocation. When empty, defaults to
	// os.Executable().
	SelfPath string

	// CursorFile, DBPath, ConfigPath are forwarded as --cursor / --db /
	// --config flags to the child process. Each is sent only when non-empty
	// so the child uses its own defaults otherwise.
	CursorFile string
	DBPath     string
	ConfigPath string
}

// ErrLockHeld is returned from AcquireRunLock when another process already
// holds the exclusive lock. Callers compare via errors.Is.
var ErrLockHeld = errors.New("sysops: observe-run lock already held by another process")

// ----------------------------------------------------------------------------
// Phase 3 typed-opts structs — argument shapes for the new mutation methods
// added to SystemOps below. Grouped here next to JournalctlStreamOpts for
// readability.
// ----------------------------------------------------------------------------

// UseraddOpts is the typed argument shape for Useradd. Zero-value fields
// map to "let useradd pick" semantics where applicable (UID=0 → no -u flag;
// GID=0 → no -g flag, useradd creates same-name group via UPG default).
type UseraddOpts struct {
	Username           string
	UID                int    // 0 = let useradd pick; non-zero → -u <UID>
	GID                int    // 0 = useradd creates same-name group (UPG); non-zero → -g <GID>
	Home               string // -d <home>
	Shell              string // -s <shell> (typically "/usr/sbin/nologin" per pitfall B4)
	CreateHome         bool   // true → -m flag (D-12); false → -M flag (D-14 orphan reconcile)
	MemberOfSftpJailer bool   // post-useradd: gpasswd -a <user> sftp-jailer (informational; the call site invokes Gpasswd separately for compensator pairing)
}

// GpasswdOp enumerates the two group-membership operations the tool needs.
type GpasswdOp int

// GpasswdOp values mirror the gpasswd(1) flags the tool invokes.
const (
	GpasswdAdd GpasswdOp = iota // -a (add user to group)
	GpasswdDel                  // -d (delete user from group)
)

// ChageOpts is the typed argument shape for Chage. Currently only LastDay
// is exposed (D-13 force-change-next-login uses LastDay=0). Extend as new
// chage flags are needed.
type ChageOpts struct {
	LastDay int // -d <days> ("days since 1970-01-01"; 0 = force change at next login)
}

// TarMode enumerates the tar invocation shapes the tool uses.
type TarMode int

// TarMode values map to tar(1) operation flags.
const (
	TarCreateGzip TarMode = iota // -czf (create gzipped archive) — D-15 Archive path
)

// TarOpts is the typed argument shape for Tar. SourceDir is appended as the
// single source argument; the tool does not support multi-source tars.
type TarOpts struct {
	Mode        TarMode
	ArchivePath string // -f <archive>
	SourceDir   string // <source> (single dir; recursive)
}

// SshdTContextOpts is the typed argument shape for SshdTWithContext. Per
// D-21 step 4 the M-ADD-KEY verifier needs `sshd -t -C user=<u>,host=<h>,addr=<a>`
// so the validator evaluates Match-block-scoped directives for THIS user.
// Plain SshdT (no -C) only validates global config.
//
// Threat model T-03-01-09: callers MUST validate username through the
// existing `^[a-z][a-z0-9_-]{0,31}$` regex before calling — a comma or `=`
// in any field would create a malformed -C value. Host/Addr are tool-set
// literals ("localhost"/"127.0.0.1") and not user-influenced.
type SshdTContextOpts struct {
	User string
	Host string // typically "localhost"
	Addr string // typically "127.0.0.1"
}

// SystemOps is the seam between sftp-jailer and the operating system.
// Phase 1 methods are read-only; Phase 2 introduces AtomicWriteFile + the
// four subprocess/lock helpers (see package doc).
type SystemOps interface {
	// Root check (SAFE-01)
	Geteuid() int

	// Filesystem reads
	ReadFile(ctx context.Context, path string) ([]byte, error)
	ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)
	Stat(ctx context.Context, path string) (FileInfo, error)  // follows symlinks
	Lstat(ctx context.Context, path string) (FileInfo, error) // does not follow
	Glob(ctx context.Context, pattern string) ([]string, error)

	// ReadShadow returns BOTH the last-password-change-day field (field 3
	// of /etc/shadow, days since 1970-01-01 UTC) AND the password-max-days
	// field (field 5: number of days a password may be used before it must
	// be changed; conventionally >= 99999 means "no expiry policy"; an
	// empty field is reported as 0).
	//
	// Returns fs.ErrNotExist if the user is not present in /etc/shadow.
	// Returns the underlying ReadFile error for permission / missing-file
	// failures (callers should treat any error as "leave PasswordAgeDays /
	// PasswordMaxDays at -1; render `—`" — graceful degradation).
	ReadShadow(ctx context.Context, username string) (lstchg int, maxDays int, err error)

	// External command runner (allowlisted, absolute paths cached at startup).
	// Phase 1 uses this for: sshd, aa-status, nft, systemctl (read-only).
	// Phase 2 extends the allowlist with: journalctl, ufw.
	Exec(ctx context.Context, name string, args ...string) (ExecResult, error)

	// Convenience wrapper for `sshd -T` — returns parsed directive map.
	// Keys are lowercase; duplicate-key directives accumulate in the slice.
	SshdDumpConfig(ctx context.Context) (map[string][]string, error)

	// Phase 2 additions — D-07 mutation carve-out + observation pipeline.

	// AtomicWriteFile writes data to path atomically (tmp + fsync + rename).
	// The carve-out is /etc/sftp-jailer/config.yaml (D-07); other writes
	// belong in Phase 3 / Phase 4 where SAFE-03 backup discipline applies.
	AtomicWriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error

	// JournalctlStream invokes `journalctl --output=json --cursor-file=… -u <unit>`
	// and returns the started Process + stdout pipe for line-by-line scan.
	// Caller is responsible for proc.Wait() and closing stdout.
	JournalctlStream(ctx context.Context, opts JournalctlStreamOpts) (*os.Process, io.ReadCloser, error)

	// JournalctlFollowCmd returns an *exec.Cmd for `journalctl -u <unit> -f`,
	// unstarted, suitable for tea.ExecProcess. The ExecProcess hand-off
	// means the caller does NOT call Start/Run — Bubble Tea owns that.
	// CI guard exception: the exec.Command literal lives in this package.
	JournalctlFollowCmd(unit string) *exec.Cmd

	// ObserveRunStream invokes `sftp-jailer observe-run` (us, recursively)
	// with the given options as a subprocess and returns the started
	// Process + stdout pipe for the goroutine-Send pattern in M-OBSERVE.
	ObserveRunStream(ctx context.Context, opts ObserveRunSubprocessOpts) (*os.Process, io.ReadCloser, error)

	// AcquireRunLock attempts to take an exclusive flock on the path. Returns
	// a release func and nil on success, or the sentinel ErrLockHeld if
	// another process holds it.
	AcquireRunLock(ctx context.Context, path string) (release func(), err error)

	// ------------------------------------------------------------------
	// Phase 3 additions — mutation surface for users + sshd config +
	// reload + archive. Architectural invariant: every Phase 3 call site
	// for useradd/userdel/gpasswd/chpasswd/chage/tar/sshd -t/systemctl
	// reload-restart-daemon-reload/chmod/chown lives inside this package
	// (enforced by scripts/check-no-exec-outside-sysops.sh).
	// ------------------------------------------------------------------

	// Useradd creates a system user via `useradd`. Pre-flight checks
	// (/etc/shells contains /usr/sbin/nologin, UID-collision, path-walk on
	// <home> parent) are the CALLER's responsibility — the wrapper is
	// mechanical. Compensator: Userdel(ctx, opts.Username, opts.CreateHome).
	Useradd(ctx context.Context, opts UseraddOpts) error

	// Userdel removes a system user via `userdel`. removeHome=true adds -r
	// (irreversible — deletes home directory). D-15 Permanent path uses true;
	// D-15 Archive path (post-tarball) uses false.
	Userdel(ctx context.Context, username string, removeHome bool) error

	// Gpasswd manipulates group membership via `gpasswd -a/-d <user> <group>`.
	Gpasswd(ctx context.Context, op GpasswdOp, username, group string) error

	// Chpasswd sets a user's password via `chpasswd` with "<user>:<password>\n"
	// piped to stdin (NEVER argv per pitfall E3). On non-zero exit (typically
	// a pam_pwquality rejection), returns *ChpasswdError carrying stderr
	// verbatim for B5 surfacing in M-PASSWORD. Caller MUST apply a context
	// deadline (recommended 30s) — chpasswd can hang on stdin pipe.
	Chpasswd(ctx context.Context, username, password string) error

	// Chage updates password-aging via `chage`. D-13 force-change-next-login
	// sets ChageOpts.LastDay=0 (`-d 0`). WARNING: chrooted SFTP-only users
	// cannot complete password change (pitfall 2 / RH solution 24758) — the
	// CALLER is responsible for surfacing this UX warning.
	Chage(ctx context.Context, username string, opts ChageOpts) error

	// Chmod changes file mode via os.Chmod. SETUP-05 / D-12 use 0o750 on
	// <home>; D-21 verifies 0o600 on authorized_keys. Caller-supplied path
	// and mode per the SystemOps contract.
	Chmod(ctx context.Context, path string, mode fs.FileMode) error

	// Chown changes file ownership via os.Chown. SETUP-05 / D-12 set
	// <user>:<user> on <home>. uid/gid as int (negative means "no change",
	// matches os.Chown semantics).
	Chown(ctx context.Context, path string, uid, gid int) error

	// MkdirAll wraps os.MkdirAll. Typed pass-through so txn steps can stay
	// testable through sysops.Fake (W-02). Mode is umask-affected per Go
	// semantics; callers needing an explicit mode follow with Chmod.
	MkdirAll(ctx context.Context, path string, mode fs.FileMode) error

	// RemoveAll wraps os.RemoveAll. Typed pass-through paired with MkdirAll
	// for txn compensators (W-02). ErrNotExist is treated as success per
	// os.RemoveAll convention.
	RemoveAll(ctx context.Context, path string) error

	// WriteAuthorizedKeys atomically writes a per-user authorized_keys file
	// at <chrootRoot>/<username>/.ssh/authorized_keys, then chowns to
	// <username>:<username> and chmods to 0o600 (D-17, D-18). Composite
	// wrapper — fewer call sites = less surface for the architectural-tax
	// discussion in D-18. Lookup of the user's UID/GID is via os/user.Lookup
	// inside this wrapper; missing user → typed error.
	WriteAuthorizedKeys(ctx context.Context, username, chrootRoot string, keys []byte) error

	// SshdT runs `sshd -t` (config validator) WITHOUT -C user-context. Returns
	// stderr verbatim and a non-nil error on non-zero exit. SAFE-02 / D-09
	// step 4 gates every sshd reload behind a successful SshdT call.
	SshdT(ctx context.Context) (stderr []byte, err error)

	// SshdTWithContext runs `sshd -t -C user=<u>,host=<h>,addr=<a>` so the
	// validator evaluates Match-block-scoped directives for THIS user (D-21
	// step 4). Used by the M-ADD-KEY verifier (plan 03-08b) to confirm
	// that the user's chroot path actually resolves under the just-written
	// authorized_keys configuration. See SshdTContextOpts godoc for the
	// caller-validation invariant on opts.User (T-03-01-09).
	SshdTWithContext(ctx context.Context, opts SshdTContextOpts) (stderr []byte, err error)

	// SystemctlReload runs `systemctl reload <unit>`. SAFE-06 / D-09 step 5
	// service-reload path (any directive that is NOT in the socket-affecting
	// set: Port, ListenAddress, AddressFamily).
	SystemctlReload(ctx context.Context, unit string) error

	// SystemctlRestartSocket runs `systemctl restart <unit>`. SAFE-06 socket
	// path: edits to Port/ListenAddress/AddressFamily require restarting
	// ssh.socket (NOT reload of ssh.service) per Launchpad #2069041.
	SystemctlRestartSocket(ctx context.Context, unit string) error

	// SystemctlDaemonReload runs `systemctl daemon-reload`. Always paired
	// with SystemctlRestartSocket per the SAFE-06 dispatcher.
	SystemctlDaemonReload(ctx context.Context) error

	// Tar invokes the system `tar` binary. D-15 Archive path uses
	// TarCreateGzip to produce /var/lib/sftp-jailer/archive/<user>-<ISO>.tar.gz
	// before userdel.
	Tar(ctx context.Context, opts TarOpts) error
}
