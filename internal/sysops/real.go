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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

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

	// defaultTimeout applies to Exec() calls whose context has no deadline.
	// Bounds T-01-07 (unbounded subprocess hang).
	defaultTimeout time.Duration
}

// NewReal resolves binary paths and returns the production implementation.
// Missing binaries are non-fatal for Phase 1 — the doctor detector surfaces
// "not installed" as diagnostic state.
func NewReal() SystemOps {
	r := &Real{defaultTimeout: 10 * time.Second}
	r.binSshd, _ = exec.LookPath("sshd")
	r.binAAStatus, _ = exec.LookPath("aa-status")
	r.binNft, _ = exec.LookPath("nft")
	r.binSystemctl, _ = exec.LookPath("systemctl")
	r.binJournalctl, _ = exec.LookPath("journalctl")
	r.binUfw, _ = exec.LookPath("ufw")
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
		Path:   path,
		Mode:   fs.FileMode(st.Mode & 0o7777),
		UID:    st.Uid,
		GID:    st.Gid,
		IsDir:  (st.Mode & syscall.S_IFDIR) != 0,
		IsLink: false, // Stat follows symlinks by definition
	}, nil
}

// Lstat implements [SystemOps.Lstat] (does not follow symlinks).
func (r *Real) Lstat(_ context.Context, path string) (FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Path:   path,
		Mode:   fs.FileMode(st.Mode & 0o7777),
		UID:    st.Uid,
		GID:    st.Gid,
		IsDir:  (st.Mode & syscall.S_IFDIR) != 0,
		IsLink: (st.Mode & syscall.S_IFLNK) != 0,
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

// ReadShadow implements [SystemOps.ReadShadow] (stub for Task 2 — replaced
// in Task 3 with the production parser).
func (r *Real) ReadShadow(_ context.Context, _ string) (int, int, error) {
	return 0, 0, fmt.Errorf("ReadShadow: not implemented")
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
