// Package observerunscreen tests for M-OBSERVE — wave-7 / plan 02-08.
//
// The goroutine + Program.Send pattern (RESEARCH Pattern 4) is intentionally
// not exercised here — it requires a real *tea.Program. We test Update msg
// handlers directly (the bulk of the logic) and rely on the integration test
// in HUMAN-UAT for the full goroutine path.
package observerunscreen_test

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/observe"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	observerunscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/observerun"
)

// keyPress mirrors the S-USERS / S-FIREWALL / S-LOGS helper.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// TestObserveRunScreen_implements_nav_Screen — compile-time check that *Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap / WantsRawKeys.
func TestObserveRunScreen_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	require.Equal(t, "observe-run", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false (no textinput)")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp(), "ShortHelp must surface esc")
}

// TestObserveRunScreen_initial_phase_is_starting — before any progress
// message arrives, View shows the "starting…" placeholder.
func TestObserveRunScreen_initial_phase_is_starting(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	require.Contains(t, m.View(), "starting observe-run")
}

// TestObserveRunScreen_progress_phase_read — feeding a Progress{Phase:read}
// via the test seam updates the read counter line.
func TestObserveRunScreen_progress_phase_read(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	m.ApplyProgressForTest(observe.Progress{Phase: observe.PhaseRead, Count: 42})
	v := m.View()
	require.Contains(t, v, "read:")
	require.Contains(t, v, "42")
}

// TestObserveRunScreen_progress_phase_classify — Phase=classify Count=42
// renders the classify counter line.
func TestObserveRunScreen_progress_phase_classify(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	m.ApplyProgressForTest(observe.Progress{Phase: observe.PhaseClassify, Count: 42})
	v := m.View()
	require.Contains(t, v, "classify:")
	require.Contains(t, v, "42")
}

// TestObserveRunScreen_progress_phase_compact — every counter visible.
func TestObserveRunScreen_progress_phase_compact(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	m.ApplyProgressForTest(observe.Progress{
		Phase: observe.PhaseCompact, Kept: 130, Compacted: 12, Dropped: 0, CountersAdded: 4,
	})
	v := m.View()
	require.Contains(t, v, "compact:")
	require.Contains(t, v, "130")
	require.Contains(t, v, "12")
	require.Contains(t, v, "4")
	require.Contains(t, v, "0")
}

// TestObserveRunScreen_skipped_phase_renders_message — skipped phase surfaces
// the Reason text (UI-SPEC line 305 — "another run in progress").
func TestObserveRunScreen_skipped_phase_renders_message(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	m.ApplyProgressForTest(observe.Progress{
		Phase: observe.PhaseSkipped, Reason: "another run in progress",
	})
	require.Contains(t, m.View(), "another run in progress")
}

// TestObserveRunScreen_done_emits_pop_status_refresh_and_complete_toast —
// after the auto-pop tick fires, the returned tea.Cmd batch contains
// nav.PopCmd, nav.StatusRefreshMsg, and nav.ObserveRunCompleteToast.
func TestObserveRunScreen_done_emits_pop_status_refresh_and_complete_toast(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	// Inject a done summary via the test seam.
	summary := observe.RunSummary{
		EventsRead: 142, CountersAdded: 4, EventsDropped: 0, Result: "success",
	}
	m.ApplyDoneForTest(summary)

	// Now simulate the auto-pop tick firing.
	cmd := m.AutoPopCmdForTest()
	require.NotNil(t, cmd, "auto-pop must emit a non-nil tea.Cmd")
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)

	var sawPop, sawRefresh, sawComplete bool
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		out := sub()
		switch v := out.(type) {
		case nav.Msg:
			if v.Intent == nav.Pop {
				sawPop = true
			}
		case nav.StatusRefreshMsg:
			sawRefresh = true
		case nav.ObserveRunCompleteToast:
			sawComplete = true
			require.Equal(t, 142, v.Events)
			require.Equal(t, 4, v.Counters)
			require.Equal(t, 0, v.Dropped)
		}
	}
	require.True(t, sawPop, "auto-pop batch must include nav.PopCmd")
	require.True(t, sawRefresh, "auto-pop batch must include nav.StatusRefreshMsg")
	require.True(t, sawComplete, "auto-pop batch must include nav.ObserveRunCompleteToast")
}

// TestObserveRunScreen_esc_sets_cancelling_and_calls_cancelFn — pre-set
// m.cancelFn via the test seam → keyPress("esc") → m.IsCancellingForTest()
// is true; the recorded mock was called.
func TestObserveRunScreen_esc_sets_cancelling_and_calls_cancelFn(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	called := false
	m.SetCancelFnForTest(context.CancelFunc(func() { called = true }))

	_, cmd := m.Update(keyPress("esc"))
	require.True(t, m.IsCancellingForTest(), "Esc must set the cancelling flag")
	require.True(t, called, "Esc must call the cancelFn")
	require.NotNil(t, cmd, "Esc on cancellable run must emit a tea.Cmd batch")

	// And it must include a cancelled toast + status refresh.
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)

	var sawCancelled, sawRefresh bool
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		out := sub()
		switch out.(type) {
		case nav.ObserveRunCancelledToast:
			sawCancelled = true
		case nav.StatusRefreshMsg:
			sawRefresh = true
		}
	}
	require.True(t, sawCancelled, "Esc batch must include nav.ObserveRunCancelledToast")
	require.True(t, sawRefresh, "Esc batch must include nav.StatusRefreshMsg")

	// View now shows the cancelling label.
	require.Contains(t, m.View(), "cancelling")
}

// TestObserveRunScreen_other_keys_swallowed — UI-SPEC line 262: every key
// except esc is swallowed (returns nil cmd; no model-state side-effect).
func TestObserveRunScreen_other_keys_swallowed(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	for _, k := range []string{"q", "c", "j"} {
		_, cmd := m.Update(keyPress(k))
		require.Nil(t, cmd, "key %q must be swallowed (cmd nil)", k)
		require.False(t, m.IsCancellingForTest(),
			"key %q must not flip the cancelling flag", k)
	}
}

// TestObserveRunScreen_keymap_only_esc — ShortHelp surfaces a single binding
// for esc/cancel.
func TestObserveRunScreen_keymap_only_esc(t *testing.T) {
	km := observerunscreen.DefaultKeyMap()
	short := km.ShortHelp()
	require.Len(t, short, 1, "ShortHelp must contain exactly one binding")
	require.Equal(t, []string{"esc"}, short[0].Keys)
}

// TestObserveRunScreen_view_renders_phase_after_progress — once compact phase
// arrives, View shows phase: compact alongside the counters.
func TestObserveRunScreen_view_renders_phase_after_progress(t *testing.T) {
	m := observerunscreen.New(nil, &sysops.Fake{}, sysops.ObserveRunSubprocessOpts{})
	m.ApplyProgressForTest(observe.Progress{Phase: observe.PhaseCompact, Kept: 1})
	v := m.View()
	require.Contains(t, v, "phase:")
	require.True(t, strings.Contains(v, "compact"),
		"View must include the current phase label; got %q", v)
}
