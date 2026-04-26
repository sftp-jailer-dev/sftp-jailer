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
// chain walk (SETUP-01).
type FileInfo struct {
	Path   string
	Mode   fs.FileMode
	UID    uint32
	GID    uint32
	IsDir  bool
	IsLink bool
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
}
