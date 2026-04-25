package sysops

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// JournalctlFollowCmd returns an unstarted *exec.Cmd suitable for hand-off
// to tea.ExecProcess. Bubble Tea owns Start/Wait — the caller must NOT call
// Start, Run, or Output on the returned command.
//
// Args mirror the production journalctl invocation pattern:
//
//	journalctl -u <unit> -f --no-pager
//
// `-f` follows the journal indefinitely (the live-tail D-13 use case);
// `--no-pager` defends against journalctl paging when stdout is a TTY.
//
// CI guard exception: the literal exec.Command call lives in this package
// because internal/sysops is the sole exec seam.
func (r *Real) JournalctlFollowCmd(unit string) *exec.Cmd {
	bin := r.binJournalctl
	if bin == "" {
		// Fall back to the bare name. tea.ExecProcess will surface the
		// LookPath failure when it tries to Start the command.
		bin = "journalctl"
	}
	return exec.Command(bin, "-u", unit, "-f", "--no-pager") //nolint:gosec // G204: typed wrapper, no user-supplied strings
}

// JournalctlStream invokes `journalctl --output=json --cursor-file=… -u <unit>`
// and returns the started Process + stdout pipe for line-by-line scan via
// bufio.Scanner. The caller owns proc.Wait() and stdout.Close().
//
// Caveat (RESEARCH §"--all flag and the >4096-byte-field gotcha"): journalctl's
// JSON encoder emits null for fields larger than 4096 bytes unless `--all` is
// passed. sshd MESSAGE fields are short (~80–200 bytes typical) so we do NOT
// pass --all; an oversized field surfaces as a parse error and is classified
// as `unmatched`, which is acceptable for v1.
func (r *Real) JournalctlStream(ctx context.Context, opts JournalctlStreamOpts) (*os.Process, io.ReadCloser, error) {
	if r.binJournalctl == "" {
		return nil, nil, fmt.Errorf("sysops.JournalctlStream: journalctl not installed")
	}
	args := []string{
		"--output=json",
		"--cursor-file=" + opts.CursorFile,
		"-u", opts.Unit,
		"--no-pager",
	}
	if opts.Since != "" {
		args = append(args, "--since", opts.Since)
	}
	cmd := exec.CommandContext(ctx, r.binJournalctl, args...) //nolint:gosec // G204: typed wrapper, args from typed opts struct
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("sysops.JournalctlStream stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("sysops.JournalctlStream start: %w", err)
	}
	return cmd.Process, stdout, nil
}

// ObserveRunStream invokes `sftp-jailer observe-run` recursively on the
// running binary's path and returns the started Process + stdout pipe. Used
// by the M-OBSERVE TUI modal (plan 02-08) to stream JSON progress events
// back into the program via Send.
//
// SelfPath defaults to os.Executable() when unset. CursorFile / DBPath /
// ConfigPath flow through as --cursor / --db / --config flags only when
// non-empty.
func (r *Real) ObserveRunStream(ctx context.Context, opts ObserveRunSubprocessOpts) (*os.Process, io.ReadCloser, error) {
	self := opts.SelfPath
	if self == "" {
		s, err := os.Executable()
		if err != nil {
			return nil, nil, fmt.Errorf("sysops.ObserveRunStream self: %w", err)
		}
		self = s
	}

	args := []string{"observe-run"}
	if opts.CursorFile != "" {
		args = append(args, "--cursor", opts.CursorFile)
	}
	if opts.DBPath != "" {
		args = append(args, "--db", opts.DBPath)
	}
	if opts.ConfigPath != "" {
		args = append(args, "--config", opts.ConfigPath)
	}

	cmd := exec.CommandContext(ctx, self, args...) //nolint:gosec // G204: argv shape is fixed; opts comes from typed struct
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("sysops.ObserveRunStream stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("sysops.ObserveRunStream start: %w", err)
	}
	return cmd.Process, stdout, nil
}
