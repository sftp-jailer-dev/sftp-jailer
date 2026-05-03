package app_test

// SAFE-04 [C]onfirm / [V]iew countdown wiring tests
// (debug session safe04-confirm-view-keys).
//
// These tests pin the hotkey contract:
//   - C/c invokes the injected RevertCanceller with the armed unit name,
//     and a revertConfirmedMsg flashes a success/failure toast on return.
//   - V/v shows a synchronous toast describing the live deadline +
//     reverse-command count.
//   - Both keys fall through to the top screen when WantsRawKeys() is true
//     (textinput safety, mirror of the `q` gate).
//   - Without a bound canceller / armed watcher, the keys are silent
//     no-ops (no panic, no spurious toasts, no cmd).

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/tuitest"
)

// armedWatcher constructs a *revert.Watcher backed by a sysops.Fake and
// arms it with a fake systemd-run unit + deadline. Returns the watcher
// so callers can also pass it to App.SetWatcher and read .Get().
func armedWatcher(t *testing.T, deadline time.Time) *revert.Watcher {
	t.Helper()
	tmp := t.TempDir()
	revert.SetPointerPathForTest(filepath.Join(tmp, "revert.active"))
	t.Cleanup(revert.ResetPointerPathForTest)

	w := revert.New(sysops.NewFake())
	err := w.Set(context.Background(),
		"sftpj-revert-test.service",
		deadline,
		[]string{"ufw --force delete 3", "ufw reload"})
	require.NoError(t, err, "Watcher.Set arm")
	return w
}

func TestApp_C_noop_when_no_revert_armed(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	// No watcher bound, no canceller bound.
	require.NotPanics(t, func() {
		_, cmd := a.Update(keyPress('c'))
		// Without armed state, c falls through to the top screen
		// (which is a no-op in testScreen). No cmd, no panic.
		require.Nil(t, cmd, "C with no revert armed must not produce a cmd")
	})
}

func TestApp_C_falls_through_to_screen_when_not_armed(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	before := s.msgCount
	_, _ = a.Update(keyPress('c'))
	require.Greater(t, s.msgCount, before,
		"plain c must reach the top screen when no revert is armed")
}

func TestApp_C_invokes_canceller_when_armed(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	w := armedWatcher(t, time.Now().Add(2*time.Minute))
	a.SetWatcher(w)

	var calls atomic.Int32
	var gotUnit atomic.Value // string
	a.SetRevertCanceller(func(_ context.Context, unitName string) error {
		calls.Add(1)
		gotUnit.Store(unitName)
		return nil
	})

	beforeMsgs := s.msgCount
	_, cmd := a.Update(keyPress('c'))
	require.NotNil(t, cmd, "C with armed revert + canceller must return a cmd")
	require.Equal(t, beforeMsgs, s.msgCount,
		"C must NOT fall through to the top screen when armed")

	// Run the goroutine cmd; route the resulting msg back into Update.
	msg := cmd()
	require.Equal(t, int32(1), calls.Load(), "canceller must have been called exactly once")
	require.Equal(t, "sftpj-revert-test.service", gotUnit.Load().(string),
		"canceller must receive the armed unit name")

	_, toastCmd := a.Update(msg)
	require.NotNil(t, toastCmd, "success path must flash a toast (non-nil cmd)")
	require.Contains(t, a.ToastText(), "Apply confirmed",
		"success toast must surface confirmation text")
}

func TestApp_C_failure_surfaces_error_toast(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	w := armedWatcher(t, time.Now().Add(2*time.Minute))
	a.SetWatcher(w)

	wantErr := errors.New("systemctl stop boom")
	a.SetRevertCanceller(func(_ context.Context, _ string) error {
		return wantErr
	})

	_, cmd := a.Update(keyPress('c'))
	require.NotNil(t, cmd)
	msg := cmd()

	_, toastCmd := a.Update(msg)
	require.NotNil(t, toastCmd, "failure path must still flash a toast")
	got := a.ToastText()
	require.Contains(t, got, "Revert cancel failed",
		"failure toast must surface the cancel-failed prefix")
	require.Contains(t, got, "boom",
		"failure toast must include the wrapped error")
}

func TestApp_C_uppercase_and_lowercase_both_trigger(t *testing.T) {
	tuitest.ResetResolvers(t)
	for _, k := range []rune{'c', 'C'} {
		t.Run(string(k), func(t *testing.T) {
			s := &testScreen{name: "home"}
			a := app.New("v0", "u", s)
			w := armedWatcher(t, time.Now().Add(2*time.Minute))
			a.SetWatcher(w)
			var calls atomic.Int32
			a.SetRevertCanceller(func(_ context.Context, _ string) error {
				calls.Add(1)
				return nil
			})
			_, cmd := a.Update(keyPress(k))
			require.NotNil(t, cmd, "%q must trigger canceller cmd", k)
			_ = cmd()
			require.Equal(t, int32(1), calls.Load(),
				"%q must invoke canceller", k)
		})
	}
}

func TestApp_C_falls_through_when_top_screen_wants_raw_keys(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home", wantsRawKeys: true}
	a := app.New("v0", "u", s)
	w := armedWatcher(t, time.Now().Add(2*time.Minute))
	a.SetWatcher(w)
	var calls atomic.Int32
	a.SetRevertCanceller(func(_ context.Context, _ string) error {
		calls.Add(1)
		return nil
	})

	before := s.msgCount
	_, _ = a.Update(keyPress('c'))
	require.Greater(t, s.msgCount, before,
		"C must fall through to the top screen when WantsRawKeys=true")
	require.Equal(t, int32(0), calls.Load(),
		"C must NOT invoke canceller when top screen wants raw keys")
}

func TestApp_C_swallows_keystroke_when_armed_but_no_canceller_bound(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)
	w := armedWatcher(t, time.Now().Add(2*time.Minute))
	a.SetWatcher(w)
	// NOTE: no SetRevertCanceller call - simulates pre-bootstrap or
	// detached state. C should be swallowed (defensive), NOT leak to
	// the top screen.

	before := s.msgCount
	_, cmd := a.Update(keyPress('c'))
	require.Nil(t, cmd, "no canceller bound -> no cmd")
	require.Equal(t, before, s.msgCount,
		"armed C without canceller must NOT leak to the top screen")
}

func TestApp_V_flashes_countdown_toast_when_armed(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	w := armedWatcher(t, time.Now().Add(125*time.Second))
	a.SetWatcher(w)

	_, cmd := a.Update(keyPress('v'))
	require.NotNil(t, cmd, "V with armed revert must return a (toast-expire) cmd")
	got := a.ToastText()
	require.Contains(t, got, "Revert:",
		"V toast must lead with the Revert: prefix")
	require.Contains(t, got, "rollback cmd(s) queued",
		"V toast must mention the rollback-cmd count")
	require.Contains(t, got, "press C to confirm",
		"V toast must hint at the C key")
}

func TestApp_V_uppercase_and_lowercase_both_trigger(t *testing.T) {
	tuitest.ResetResolvers(t)
	for _, k := range []rune{'v', 'V'} {
		t.Run(string(k), func(t *testing.T) {
			s := &testScreen{name: "home"}
			a := app.New("v0", "u", s)
			w := armedWatcher(t, time.Now().Add(60*time.Second))
			a.SetWatcher(w)
			_, cmd := a.Update(keyPress(k))
			require.NotNil(t, cmd, "%q must trigger toast cmd", k)
			require.Contains(t, a.ToastText(), "Revert:",
				"%q must populate the toast text", k)
		})
	}
}

func TestApp_V_falls_through_to_screen_when_not_armed(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v0", "u", s)

	before := s.msgCount
	_, _ = a.Update(keyPress('v'))
	require.Greater(t, s.msgCount, before,
		"plain v must reach the top screen when no revert is armed")
	require.Empty(t, strings.TrimSpace(a.ToastText()),
		"V with no revert armed must not flash a toast")
}

func TestApp_V_falls_through_when_top_screen_wants_raw_keys(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home", wantsRawKeys: true}
	a := app.New("v0", "u", s)
	w := armedWatcher(t, time.Now().Add(60*time.Second))
	a.SetWatcher(w)

	before := s.msgCount
	_, _ = a.Update(keyPress('v'))
	require.Greater(t, s.msgCount, before,
		"V must fall through when WantsRawKeys=true (textinput safety)")
	require.Empty(t, strings.TrimSpace(a.ToastText()),
		"V must NOT flash a toast when WantsRawKeys=true")
}
