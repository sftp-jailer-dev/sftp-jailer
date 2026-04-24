// Package tui provides process-level terminal cleanup helpers used by main
// before and after the Bubble Tea program runs. It implements pitfall E2:
// write a shell script the admin can run if the TUI is killed uncleanly
// (kill -9, OOM, ssh disconnect) and the terminal is left in alt-screen /
// raw mode.
package tui

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// WriteRecoveryScript emits a shell script the admin can run if the TUI dies
// uncleanly. The script is PID-namespaced under /tmp and written mode 0700.
// Main prints the path to stderr BEFORE calling program.Run() so the path
// is in scrollback even if the program segfaults before reaching any
// cleanup code.
//
// Mode is explicitly set to 0700 via a Chmod after the write so tests can
// assert `mode & 0o700 == 0o700` regardless of the process umask.
func WriteRecoveryScript(pid int) (path string, err error) {
	path = fmt.Sprintf("/tmp/sftp-jailer-recover-%d.sh", pid)
	script := `#!/bin/sh
# Restores terminal state after a crashed sftp-jailer session.
#   stty sane             — resets line discipline (raw/echo/etc.)
#   ?1049l                — leaves the alternate screen buffer
#   ?25h                  — re-enables the cursor
#   ?1000/1002/1003/1006l — disables every mouse-reporting mode
#   ?2004l                — disables bracketed-paste mode
stty sane 2>/dev/null || true
printf '\033[?1049l\033[?25h\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?2004l' > /dev/tty
`
	// gosec G306/G302: 0o700 is intentional — the script must be executable.
	// It contains no user data; only static terminal-reset escapes.
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // G306: script must be exec
		return "", err
	}
	// os.WriteFile observes umask; re-chmod to guarantee user-rwx bits.
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // G302: script must be exec
		return "", err
	}
	return path, nil
}

// InstallSignalCleanup traps SIGTERM/SIGHUP and calls restore before
// re-raising the signal with the default handler. SIGKILL remains
// unhandlable — the recovery script is the fallback there.
//
// SIGINT is deliberately NOT trapped here: Bubble Tea's default signal
// handler (installed when the program starts) owns Ctrl-C; trapping it
// twice produces the double-handler bug described in pitfall E1.
func InstallSignalCleanup(restore func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-ch
		restore()
		signal.Reset(sig)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(sig)
	}()
}
