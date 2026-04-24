// Package sysops is the ONLY package in the project that may touch
// /etc, call os/exec, or read the journal. Every other package interacts
// with the system through the SystemOps interface.
//
// Phase 1 surface: read-only. Mutation methods land in Phase 3 and Phase 4.
// Architectural invariant enforced by scripts/check-no-exec-outside-sysops.sh.
package sysops

import (
	"context"
	"io/fs"
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

// SystemOps is the seam between sftp-jailer and the operating system.
// Every Phase 1 method is read-only.
type SystemOps interface {
	// Root check (SAFE-01)
	Geteuid() int

	// Filesystem reads
	ReadFile(ctx context.Context, path string) ([]byte, error)
	ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)
	Stat(ctx context.Context, path string) (FileInfo, error)  // follows symlinks
	Lstat(ctx context.Context, path string) (FileInfo, error) // does not follow
	Glob(ctx context.Context, pattern string) ([]string, error)

	// External command runner (allowlisted, absolute paths cached at startup).
	// Phase 1 uses this for: sshd, aa-status, nft, systemctl (read-only).
	Exec(ctx context.Context, name string, args ...string) (ExecResult, error)

	// Convenience wrapper for `sshd -T` — returns parsed directive map.
	// Keys are lowercase; duplicate-key directives accumulate in the slice.
	SshdDumpConfig(ctx context.Context) (map[string][]string, error)
}
