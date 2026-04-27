// Tests for M-FW-IPV6-FIX (Plan 04-05 Task 2). Covers the
// confirm/applying/done/error state machine plus key dispatch.
package firewallrule_test

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
)

// fixKeyPress mirrors the firewallscreen test helper.
func fixKeyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// TestNewIPv6Fix_initial_phase_is_confirm — fresh model is in
// ipv6PhaseConfirm; banner contains the leak detail.
func TestNewIPv6Fix_initial_phase_is_confirm(t *testing.T) {
	t.Parallel()

	const detail = "FW-06: ufw IPV6=no but eth0 has 2001:db8::1/64 — lockdown would silently leak v6."
	m := firewallrule.NewIPv6Fix(nil, nil, detail)

	require.Equal(t, firewallrule.IPv6PhaseConfirmForTest, m.PhaseForTest(),
		"initial phase must be ipv6PhaseConfirm")
	require.Equal(t, detail, m.LeakDetailForTest())
	require.Contains(t, m.View(), "FW-06",
		"confirm banner must mention FW-06")
	require.Contains(t, m.View(), "[A]pply fix")
	require.Contains(t, m.View(), "[C]ancel")
}

// TestIPv6Fix_apply_runs_txn_batch — pressing 'a' transitions to
// ipv6PhaseApplying and returns a non-nil tea.Cmd. Driving the
// returned cmd against a nil ops surfaces the test-path "ops is nil"
// error rather than panicking.
func TestIPv6Fix_apply_runs_txn_batch(t *testing.T) {
	t.Parallel()

	m := firewallrule.NewIPv6Fix(nil, nil, "boom")
	_, cmd := m.Update(fixKeyPress("a"))

	require.Equal(t, firewallrule.IPv6PhaseApplyingForTest, m.PhaseForTest(),
		"after 'a' phase must be ipv6PhaseApplying")
	require.NotNil(t, cmd, "applyCmd must return a non-nil tea.Cmd")
	msg := cmd()
	// On the nil-ops test path the command surfaces an ipv6AppliedMsg
	// with the "ops is nil" sentinel; we only need to confirm something
	// flowed back (indicating the goroutine ran and the state machine
	// can transition to error/done in the next Update).
	require.NotNil(t, msg, "applyCmd's tea.Msg must be non-nil")
}

// TestIPv6Fix_apply_uppercase_A_also_triggers — case-insensitive 'A'.
func TestIPv6Fix_apply_uppercase_A_also_triggers(t *testing.T) {
	t.Parallel()

	m := firewallrule.NewIPv6Fix(nil, nil, "boom")
	_, cmd := m.Update(fixKeyPress("A"))
	require.Equal(t, firewallrule.IPv6PhaseApplyingForTest, m.PhaseForTest(),
		"after 'A' phase must be ipv6PhaseApplying")
	require.NotNil(t, cmd)
}

// TestIPv6Fix_cancel_pops — 'c' / 'C' / esc all pop the modal.
func TestIPv6Fix_cancel_pops(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"c", "C", "esc"} {
		m := firewallrule.NewIPv6Fix(nil, nil, "boom")
		_, cmd := m.Update(fixKeyPress(key))
		require.NotNil(t, cmd, "cancel via %q must return a non-nil tea.Cmd", key)
		msg := cmd()
		nm, ok := msg.(nav.Msg)
		require.True(t, ok, "key=%q expected nav.Msg, got %T", key, msg)
		require.Equal(t, nav.Pop, nm.Intent,
			"key=%q must emit nav.Pop", key)
	}
}

// TestIPv6Fix_apply_error_transitions_to_phaseError — feed an
// ipv6AppliedMsg{err:...} via FeedAppliedMsgForTest; phase must
// transition to ipv6PhaseError and View must contain the error.
func TestIPv6Fix_apply_error_transitions_to_phaseError(t *testing.T) {
	t.Parallel()

	m := firewallrule.NewIPv6Fix(nil, nil, "boom")
	_, _ = m.Update(fixKeyPress("a")) // → ipv6PhaseApplying
	_, _ = m.FeedAppliedMsgForTest(errors.New("ufw restart failed"))

	require.Equal(t, firewallrule.IPv6PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.View(), "Failed to apply fix")
	require.Contains(t, m.View(), "ufw restart failed")
	require.Contains(t, m.View(), "[esc] back")
}

// TestIPv6Fix_apply_success_transitions_to_phaseDone_and_auto_pops —
// feeding a nil-error applied msg transitions to phaseDone and the
// returned cmd is a tea.Tick (eventually emits nav.Pop via autoPopMsg).
func TestIPv6Fix_apply_success_transitions_to_phaseDone_and_auto_pops(t *testing.T) {
	t.Parallel()

	m := firewallrule.NewIPv6Fix(nil, nil, "boom")
	_, _ = m.Update(fixKeyPress("a"))
	_, cmd := m.FeedAppliedMsgForTest(nil)

	require.Equal(t, firewallrule.IPv6PhaseDoneForTest, m.PhaseForTest())
	require.Contains(t, m.View(), "✓ ufw IPV6=yes applied")
	require.NotNil(t, cmd, "phaseDone must return a tea.Tick cmd")
}

// TestIPv6Fix_implements_nav_Screen — compile-time + runtime check.
func TestIPv6Fix_implements_nav_Screen(t *testing.T) {
	t.Parallel()

	var s nav.Screen = firewallrule.NewIPv6Fix(nil, nil, "")
	require.False(t, s.WantsRawKeys(),
		"M-FW-IPV6-FIX has no textinput; WantsRawKeys must be false")
	require.True(t, strings.Contains(s.Title(), "FW-06"),
		"Title must mention FW-06")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}
