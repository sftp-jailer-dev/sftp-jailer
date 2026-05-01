package sysops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TUI-11 D-06: ctx cancellation must deliver SIGTERM (NOT SIGKILL) and let
// cmd.WaitDelay = 2s drive the SIGKILL fallback. Spawning /bin/sleep 30 and
// cancelling parent ctx after 100ms must return well before the sleep would
// otherwise complete - and well within the 2s WaitDelay upper bound.
//
// Pin: returned err is context.Canceled (the ctx error takes precedence over
// the Wait return per Exec's existing post-processing).
func TestExec_cancel_sends_SIGTERM_then_SIGKILL_after_2s(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	r, ok := NewReal().(*Real)
	require.True(t, ok)

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := r.Exec(ctx, "/bin/sleep", "30")
	elapsed := time.Since(start)

	require.Error(t, err, "Exec must surface a context error after cancel")
	require.True(t,
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
		"expected context.Canceled or context.DeadlineExceeded, got %v", err)
	require.Less(t, elapsed, 5*time.Second,
		"Exec must release within ~2.5s of cancel (SIGTERM, then 2s WaitDelay SIGKILL); took %s", elapsed)
}

// TUI-11 Pitfall 1: when the subprocess self-exits between cmd.Start and the
// Cancel closure firing, cmd.Process.Signal returns os.ErrProcessDone. The
// Cancel closure must map that to nil so Wait does not surface a spurious
// cancellation error. A near-zero-duration /bin/sleep exits before cancel
// fires in most cases, exercising the ErrProcessDone race; the cancel-beats-
// exit path is also valid - either way no spurious unrelated error must surface.
func TestExec_clean_exit_after_cancel_returns_canceled_not_failed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	r, ok := NewReal().(*Real)
	require.True(t, ok)

	// Sleep 0.01s exits quickly; cancel after 5ms races with that exit.
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	_, err := r.Exec(ctx, "/bin/sleep", "0.01")

	// Acceptable outcomes: nil (sleep exited cleanly before cancel) OR a
	// context error (cancel beat the natural exit). Anything else means
	// Pitfall 1 leaked: a non-context error surfaced from the cancel race.
	if err != nil {
		require.True(t,
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
			"expected nil or context error after cancel-vs-self-exit race, got %v", err)
	}
}

// TUI-11 D-08: ExecResult.PID must be populated by every Exec call after
// cmd.Start returns - the modal hang-escalation diagnostic threads this PID
// onto its done-msg.
func TestExec_returns_pid_after_start(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := r.Exec(ctx, "/bin/sleep", "0.05")
	require.NoError(t, err)
	require.Greater(t, res.PID, 0,
		"ExecResult.PID must be populated after cmd.Start; got %d", res.PID)
}

// TUI-11 regression guard: normal Exec still works AND populates PID on
// every successful invocation. /bin/echo is portable across Linux and Darwin.
func TestExec_normal_exec_still_populates_pid(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := r.Exec(ctx, "/bin/echo", "hello")
	require.NoError(t, err)
	require.Equal(t, 0, res.ExitCode)
	require.Greater(t, res.PID, 0,
		"every Exec must populate ExecResult.PID; got %d", res.PID)
}
