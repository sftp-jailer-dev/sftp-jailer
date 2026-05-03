// Tests for M-UFW-ENABLE (Plan 08-04 Task 1). Covers the 5-phase
// state machine: preflight / confirm / applying / done / error.
// Includes the type-YES gate (exact uppercase match), [r] chain to
// addrule with AutoRevert=false, and the D-08 import regression test.
package ufwenable_test

import (
	"errors"
	"os"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/ufwenable"
)

// keyPress builds a synthetic KeyPressMsg for test driving.
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

// TestNewUfwEnable_initial_phase_is_preflight - fresh model starts in
// phasePreFlight.
func TestNewUfwEnable_initial_phase_is_preflight(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	require.Equal(t, ufwenable.PhasePreFlightForTest, m.PhaseForTest(),
		"initial phase must be phasePreFlight")
}

// TestUfwEnable_preflight_pass_to_confirm - pre-flight pass transitions
// to phaseConfirm and View contains the YES prompt.
func TestUfwEnable_preflight_pass_to_confirm(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")

	require.Equal(t, ufwenable.PhaseConfirmForTest, m.PhaseForTest(),
		"after preflight pass, phase must be phaseConfirm")
	require.Contains(t, m.View(), "Type YES (uppercase) and press Enter",
		"confirm view must show YES prompt")
	require.Contains(t, m.View(), "tcp/22",
		"confirm view must show matched-as value")
}

// TestUfwEnable_preflight_hard_block_when_no_ssh_allow - pre-flight
// with no SSH allow rule transitions to phaseError (hard-block).
func TestUfwEnable_preflight_hard_block_when_no_ssh_allow(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(false, false, "")

	require.Equal(t, ufwenable.PhaseErrorForTest, m.PhaseForTest(),
		"no SSH allow rule must produce phaseError hard-block")
	require.Contains(t, m.View(), "Cannot enable ufw: no SSH allow rule found.",
		"hard-block view must contain the hard-block message")
	require.Contains(t, m.View(), "[r] Add SSH allow rule",
		"hard-block view must offer [r] to add SSH rule")
}

// TestUfwEnable_yes_gate_rejects_lowercase_yes - "yes" (lowercase) is
// rejected; phase stays phaseConfirm with inline error.
func TestUfwEnable_yes_gate_rejects_lowercase_yes(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("yes")
	_, _ = m.Update(keyPress("enter"))

	require.Equal(t, ufwenable.PhaseConfirmForTest, m.PhaseForTest(),
		"lowercase 'yes' must NOT advance phase")
	require.Contains(t, m.InlineErrForTest(), "type YES exactly (uppercase) to confirm",
		"inline error must describe the exact uppercase requirement")
}

// TestUfwEnable_yes_gate_rejects_mixed_case_Yes - "Yes" (mixed case)
// is rejected; phase stays phaseConfirm with inline error.
func TestUfwEnable_yes_gate_rejects_mixed_case_Yes(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("Yes")
	_, _ = m.Update(keyPress("enter"))

	require.Equal(t, ufwenable.PhaseConfirmForTest, m.PhaseForTest(),
		"mixed-case 'Yes' must NOT advance phase")
	require.Contains(t, m.InlineErrForTest(), "type YES exactly (uppercase) to confirm")
}

// TestUfwEnable_yes_gate_accepts_YES_with_trailing_whitespace - "YES "
// or "YES\n" is accepted after TrimSpace (Pitfall 6 tolerance).
func TestUfwEnable_yes_gate_accepts_YES_with_trailing_whitespace(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("YES ")
	_, _ = m.Update(keyPress("enter"))

	require.Equal(t, ufwenable.PhaseApplyingForTest, m.PhaseForTest(),
		"'YES ' (trailing space) must advance to phaseApplying after TrimSpace")
}

// TestUfwEnable_apply_success_transitions_to_phaseDone - drive into
// phaseConfirm, type YES, advance to phaseApplying, then feed nil
// apply-done msg; expect phaseDone.
func TestUfwEnable_apply_success_transitions_to_phaseDone(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("YES")
	_, _ = m.Update(keyPress("enter")) // -> phaseApplying
	_, _ = m.FeedApplyDoneMsgForTest(nil)

	require.Equal(t, ufwenable.PhaseDoneForTest, m.PhaseForTest(),
		"nil apply error must transition to phaseDone")
}

// TestUfwEnable_apply_failure_transitions_to_phaseError - apply err
// transitions to phaseError and View contains the error message.
func TestUfwEnable_apply_failure_transitions_to_phaseError(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("YES")
	_, _ = m.Update(keyPress("enter")) // -> phaseApplying
	_, _ = m.FeedApplyDoneMsgForTest(errors.New("boom"))

	require.Equal(t, ufwenable.PhaseErrorForTest, m.PhaseForTest(),
		"apply error must transition to phaseError")
	require.Contains(t, m.View(), "failed to enable ufw: boom",
		"error view must contain the error message")
}

// TestUfwEnable_hard_block_r_chain_pushes_addrule_with_AutoRevert_false -
// pressing [r] from the hard-block phaseError pushes an addrule modal
// with AutoRevert=false (D-13).
func TestUfwEnable_hard_block_r_chain_pushes_addrule_with_AutoRevert_false(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(false, false, "")
	_, cmd := m.Update(keyPress("r"))

	require.NotNil(t, cmd, "[r] in hard-block must return a non-nil cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent, "[r] must push a new screen")
	require.NotNil(t, nm.Screen, "pushed screen must be non-nil")

	addruleModel, isAddrule := nm.Screen.(*firewallrule.Model)
	require.True(t, isAddrule, "pushed screen must be *firewallrule.Model, got %T", nm.Screen)
	require.False(t, addruleModel.AutoRevertForTest(),
		"D-13: addrule pushed from [r] chain must have AutoRevert=false")
}

// TestUfwEnable_esc_pops_in_phaseError - [esc] from phaseError pops
// without enabling ufw.
func TestUfwEnable_esc_pops_in_phaseError(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(false, false, "")
	_, cmd := m.Update(keyPress("esc"))

	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent, "[esc] in phaseError must pop")
}

// TestUfwEnable_esc_pops_in_phaseConfirm - [esc] from phaseConfirm pops.
func TestUfwEnable_esc_pops_in_phaseConfirm(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	_, cmd := m.Update(keyPress("esc"))

	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent, "[esc] in phaseConfirm must pop")
}

// TestUfwEnable_implements_nav_Screen - nav.Screen interface satisfied;
// WantsRawKeys returns true while phase == phaseConfirm; Title returns
// "enable ufw".
func TestUfwEnable_implements_nav_Screen(t *testing.T) {
	t.Parallel()

	var s nav.Screen = ufwenable.New(nil)
	require.Equal(t, "enable ufw", s.Title(), "Title must return 'enable ufw'")

	// WantsRawKeys must be false while in phasePreFlight.
	require.False(t, s.WantsRawKeys(),
		"WantsRawKeys must be false in phasePreFlight")

	// Advance to phaseConfirm.
	m := s.(*ufwenable.Model)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	require.True(t, s.WantsRawKeys(),
		"WantsRawKeys must be true in phaseConfirm (textinput focused)")

	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestUfwEnable_no_txn_no_revert_imports - D-08 regression: ensures
// ufwenable.go does NOT import internal/txn or internal/revert.
func TestUfwEnable_no_txn_no_revert_imports(t *testing.T) {
	t.Parallel()

	b, err := os.ReadFile("ufwenable.go")
	require.NoError(t, err)
	src := string(b)
	require.NotContains(t, src, `"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"`,
		"D-08: ufwenable must NOT import internal/txn")
	require.NotContains(t, src, `"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"`,
		"D-08: ufwenable must NOT import internal/revert")
}

// ---- Golden frame tests --------------------------------------------------------

// update controls golden file regeneration. Set UPDATE_GOLDEN=1 env var:
//
//	UPDATE_GOLDEN=1 go test ./internal/tui/screens/ufwenable/... -run TestGolden
var update = os.Getenv("UPDATE_GOLDEN") == "1"

func writeGolden(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/golden/" + name //nolint:gosec // G304: test-only golden path
	if update {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o600)) //nolint:gosec // G306: test-only golden
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: test-only golden path
	if os.IsNotExist(err) {
		// First run: seed the golden file automatically.
		require.NoError(t, os.WriteFile(path, []byte(got), 0o600), //nolint:gosec // G306: test-only golden
			"auto-seeding golden %s", name)
		return
	}
	require.NoError(t, err)
	require.Equal(t, string(want), got, "golden %s mismatch - set UPDATE_GOLDEN=1 to regenerate", name)
}

// TestGolden_preflight_pass captures the phaseConfirm (pre-flight pass) frame.
func TestGolden_preflight_pass(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	writeGolden(t, "preflight_pass.txt", m.View())
}

// TestGolden_preflight_hard_block captures the phaseError hard-block frame.
func TestGolden_preflight_hard_block(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(false, false, "")
	writeGolden(t, "preflight_hard_block.txt", m.View())
}

// TestGolden_applying captures the phaseApplying spinner frame.
func TestGolden_applying(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("YES")
	_, _ = m.Update(keyPress("enter"))
	writeGolden(t, "applying.txt", m.View())
}

// TestGolden_done captures the phaseDone success frame.
func TestGolden_done(t *testing.T) {
	t.Parallel()

	m := ufwenable.New(nil)
	_, _ = m.FeedPreFlightDoneMsgForTest(true, false, "tcp/22")
	m.SetYesInputValueForTest("YES")
	_, _ = m.Update(keyPress("enter"))
	_, _ = m.FeedApplyDoneMsgForTest(nil)
	writeGolden(t, "done.txt", m.View())
}
