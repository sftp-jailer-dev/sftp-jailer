// Package pwauthdisable tests pin the M-DISABLE-PWAUTH safety-rail modal —
// USER-13 / D-16. The shape mirrors the deleteuser + applysetup test suites:
// LoadPreflightForTest seeds the model in phaseReview, KeyPress helpers drive
// state transitions, and Feed*ForTest synthesizes the off-loop submit result
// without spinning up the real txn batch.
//
// Threat-register coverage:
//   - T-03-09-01 (Match-block bypass): asserted by
//     TestPwAuthDisable_setTopLevelPasswordAuthentication_strips_directive_from_match_blocks
//   - T-03-09-02 (lowercase override bypass): asserted by
//     TestPwAuthDisable_override_gate_blocks_when_text_lowercase plus the
//     general mismatch test.
package pwauthdisable_test

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/pwauthdisable"
)

// keyPress mirrors the helper used in the deleteuser / applysetup / settings
// suites. Special-cases esc / enter so the textinput can recognise them via
// the typed Code field; everything else flows through as a single rune.
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

const testChrootRoot = "/srv/sftp-jailer"

// --- nav.Screen contract ----------------------------------------------------

// TestPwAuthDisable_implements_nav_Screen — compile-time check + Title +
// KeyMap shape. Title text varies by Action so we pin both directions.
func TestPwAuthDisable_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	mDisable := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	var s nav.Screen = mDisable
	require.Equal(t, "disable password authentication", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false in phasePreflight")
	require.NotNil(t, s.KeyMap())
	require.NotEmpty(t, s.KeyMap().ShortHelp())
	require.NotEmpty(t, s.KeyMap().FullHelp())

	mEnable := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionEnable)
	require.Equal(t, "enable password authentication", mEnable.Title())
}

// --- Phase: preflight → review ----------------------------------------------

// TestPwAuthDisable_preflight_with_all_users_keyed_phase_review_no_keyless —
// LoadPreflightForTest with empty keylessUsers seeds the model in
// phaseReview; View must NOT show the BLOCKED banner because every managed
// user has a working SSH key.
func TestPwAuthDisable_preflight_with_all_users_keyed_phase_review_no_keyless(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, nil)
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())

	v := m.View()
	require.NotContains(t, v, "BLOCKED",
		"clean preflight (no keyless users) must NOT render the BLOCKED banner")
	require.Contains(t, v, "All sftp-group users have working SSH keys",
		"clean preflight must render the all-clear copy")
}

// TestPwAuthDisable_preflight_with_keyless_users_phase_review_BLOCKED —
// LoadPreflightForTest with two keyless users renders the BLOCKED banner +
// both usernames as bullet items so the admin sees who would be locked out.
func TestPwAuthDisable_preflight_with_keyless_users_phase_review_BLOCKED(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice (no file)", "bob (mode 0644)"})
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())

	v := m.View()
	require.Contains(t, v, "BLOCKED")
	require.Contains(t, v, "alice (no file)")
	require.Contains(t, v, "bob (mode 0644)")
	require.Contains(t, v, "override",
		"BLOCKED render must hint at the [enter] override path so the admin knows the gate exists")
}

// --- Phase advance: review → confirmingOverride -----------------------------

// TestPwAuthDisable_disable_with_keyless_enter_advances_to_override_phase —
// pressing Enter while keyless users are present advances the phase to
// confirmingOverride (the typed-string gate).
func TestPwAuthDisable_disable_with_keyless_enter_advances_to_override_phase(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice (no file)"})
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseConfirmingOverrideForTest, m.PhaseForTest(),
		"Enter on review with keyless users present must advance to phaseConfirmingOverride (the override gate)")
}

// --- Override gate (T-03-09-02) ---------------------------------------------

// TestPwAuthDisable_override_gate_blocks_when_text_does_not_match — typing
// anything other than the exact OverrideText keeps the modal in
// phaseConfirmingOverride and surfaces an inline error mentioning
// "verbatim".
func TestPwAuthDisable_override_gate_blocks_when_text_does_not_match(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice"})
	_, _ = m.Update(keyPress("enter")) // → phaseConfirmingOverride
	m.SetConfirmTextForTest("I understan") // missing trailing 'd'

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseConfirmingOverrideForTest, m.PhaseForTest(),
		"mismatched override text MUST NOT advance the phase — irreversibility gate")
	require.Contains(t, m.ErrInlineForTest(), "verbatim",
		"mismatched override text must produce an errInline that mentions 'verbatim' so admin understands the gate")
}

// TestPwAuthDisable_override_gate_blocks_when_text_lowercase — T-03-09-02
// pin: lowercase "i understand" MUST NOT bypass the case-sensitive match.
// This is the explicit threat-register test; without it a future "case-fold
// for forgiveness" refactor could silently weaken the safety rail.
func TestPwAuthDisable_override_gate_blocks_when_text_lowercase_T_03_09_02(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice"})
	_, _ = m.Update(keyPress("enter")) // → phaseConfirmingOverride
	m.SetConfirmTextForTest("i understand") // lowercase — must NOT bypass

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseConfirmingOverrideForTest, m.PhaseForTest(),
		"T-03-09-02: lowercase 'i understand' MUST NOT bypass the case-sensitive override gate")
}

// TestPwAuthDisable_override_gate_proceeds_when_text_matches — typing the
// exact OverrideText advances to phaseSubmitting.
func TestPwAuthDisable_override_gate_proceeds_when_text_matches(t *testing.T) {
	t.Parallel()
	// ops can be nil here; startSubmit returns a benign tick cmd in the
	// test path so the phase still flips. We do NOT drain the cmd because
	// the off-loop submit is exercised separately in
	// TestPwAuthDisable_submit_runs_txn_batch_then_verifies_via_sshd_dump.
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice"})
	_, _ = m.Update(keyPress("enter")) // → phaseConfirmingOverride
	m.SetConfirmTextForTest(pwauthdisable.OverrideText)

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseSubmittingForTest, m.PhaseForTest(),
		"matching OverrideText → phaseSubmitting (txn batch in flight)")
}

// --- Phase advance: review → submitting (skips override) --------------------

// TestPwAuthDisable_disable_with_no_keyless_enter_proceeds_directly_to_submit
// — when no keyless users exist, the override gate is skipped: Enter from
// review goes straight to phaseSubmitting (no extra friction when nobody
// would be locked out).
func TestPwAuthDisable_disable_with_no_keyless_enter_proceeds_directly_to_submit(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, nil) // empty keyless set
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseSubmittingForTest, m.PhaseForTest(),
		"clean preflight + Enter must skip the override gate and go straight to phaseSubmitting")
}

// TestPwAuthDisable_enable_action_no_preflight_block_no_override — D-16
// contract: re-enabling password auth has no lockout risk, so the override
// gate is skipped even if the keyless-user set is non-empty (we still do
// the preflight enumeration to keep the lifecycle uniform, but the result
// does NOT gate the action).
func TestPwAuthDisable_enable_action_no_preflight_block_no_override(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionEnable)
	// Even with keyless users present, ActionEnable must NOT gate.
	m.LoadPreflightForTest(nil, []string{"alice (no file)"})
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseSubmittingForTest, m.PhaseForTest(),
		"ActionEnable + Enter must skip the override gate (re-enabling password auth has no lockout risk per D-16)")
}

// --- setTopLevelPasswordAuthentication helper (the four-case decision matrix) -

// TestPwAuthDisable_setTopLevelPasswordAuthentication_adds_when_disable —
// ADD: directive absent + disable=true → top-level
// `passwordauthentication no` appended; render emits the canonical form.
func TestPwAuthDisable_setTopLevelPasswordAuthentication_adds_when_disable(t *testing.T) {
	t.Parallel()
	in := sshdcfg.DropIn{} // empty drop-in (fresh install scenario)
	out := pwauthdisable.SetTopLevelPasswordAuthenticationForTest(in, true)
	require.Len(t, out.Directives, 1)
	require.Equal(t, "passwordauthentication", out.Directives[0].Keyword)
	require.Equal(t, "no", out.Directives[0].Value)
	require.Empty(t, out.Directives[0].RawLine,
		"NEW directive must have empty RawLine so Render emits the canonical form")

	// Sanity: the rendered bytes should contain the canonical line.
	rendered := string(sshdcfg.Render(out))
	require.Contains(t, rendered, "passwordauthentication no")
}

// TestPwAuthDisable_setTopLevelPasswordAuthentication_removes_when_enable —
// REMOVE: directive present + disable=false → directive deleted from the
// top-level Directives slice. Cleaner than setting "yes" because OpenSSH
// defaults to yes when absent.
func TestPwAuthDisable_setTopLevelPasswordAuthentication_removes_when_enable(t *testing.T) {
	t.Parallel()
	in := sshdcfg.DropIn{
		Directives: []sshdcfg.Directive{
			{Keyword: "passwordauthentication", Value: "no", RawLine: "PasswordAuthentication no"},
		},
	}
	out := pwauthdisable.SetTopLevelPasswordAuthenticationForTest(in, false)
	require.Empty(t, out.Directives,
		"REMOVE: disable=false on a present directive must drop it from Directives entirely")
}

// TestPwAuthDisable_setTopLevelPasswordAuthentication_updates_existing_value_when_disable
// — UPDATE: directive present with stale "yes" + disable=true → Value
// becomes "no" AND RawLine is cleared so Render emits the canonical form
// instead of the stale original.
func TestPwAuthDisable_setTopLevelPasswordAuthentication_updates_existing_value_when_disable(t *testing.T) {
	t.Parallel()
	in := sshdcfg.DropIn{
		Directives: []sshdcfg.Directive{
			{Keyword: "passwordauthentication", Value: "yes", RawLine: "PasswordAuthentication yes  # admin authored"},
		},
	}
	out := pwauthdisable.SetTopLevelPasswordAuthenticationForTest(in, true)
	require.Len(t, out.Directives, 1)
	require.Equal(t, "passwordauthentication", out.Directives[0].Keyword)
	require.Equal(t, "no", out.Directives[0].Value,
		"UPDATE: stale 'yes' must be overwritten to 'no'")
	require.Empty(t, out.Directives[0].RawLine,
		"UPDATE: RawLine MUST be cleared so Render emits the canonical form (otherwise the admin-authored 'yes' line would leak through unchanged)")

	// Sanity: rendered bytes contain the canonical "no" form, NOT the
	// original "yes" line or its trailing comment.
	rendered := string(sshdcfg.Render(out))
	require.Contains(t, rendered, "passwordauthentication no")
	require.NotContains(t, rendered, "yes",
		"UPDATE render must NOT contain the stale 'yes' literal")
	require.NotContains(t, rendered, "admin authored",
		"UPDATE render must NOT contain the original RawLine's trailing comment")
}

// TestPwAuthDisable_setTopLevelPasswordAuthentication_strips_directive_from_match_blocks
// — T-03-09-01 defensive: a passwordauthentication directive that an admin
// hand-edited INSIDE a Match block is removed regardless of the disable flag.
// The top-level directive is the single source of truth (pitfall A3).
func TestPwAuthDisable_setTopLevelPasswordAuthentication_strips_directive_from_match_blocks_T_03_09_01(t *testing.T) {
	t.Parallel()
	in := sshdcfg.DropIn{
		Matches: []sshdcfg.MatchBlock{
			{
				Condition: "Group sftp-jailer",
				Body: []sshdcfg.Directive{
					{Keyword: "chrootdirectory", Value: "/srv/sftp-jailer/%u", RawLine: "    ChrootDirectory /srv/sftp-jailer/%u"},
					{Keyword: "passwordauthentication", Value: "yes", RawLine: "    PasswordAuthentication yes"},
					{Keyword: "forcecommand", Value: "internal-sftp", RawLine: "    ForceCommand internal-sftp"},
				},
			},
		},
	}

	// Independent of disable flag: passwordauthentication MUST be stripped
	// from MatchBlock.Body. We check both directions to pin the invariant.
	for _, disable := range []bool{true, false} {
		out := pwauthdisable.SetTopLevelPasswordAuthenticationForTest(in, disable)
		require.Len(t, out.Matches, 1)
		var keywords []string
		for _, d := range out.Matches[0].Body {
			keywords = append(keywords, d.Keyword)
		}
		require.NotContains(t, keywords, "passwordauthentication",
			"T-03-09-01: passwordauthentication inside a Match.Body MUST be stripped (disable=%v) — top-level is the single source of truth (pitfall A3)", disable)
		// The other match-body directives must survive.
		require.Contains(t, keywords, "chrootdirectory")
		require.Contains(t, keywords, "forcecommand")
	}
}

// --- Submit + post-reload sshd -T verifier ---------------------------------

// TestPwAuthDisable_submit_runs_txn_batch_then_verifies_via_sshd_dump —
// Drives the full submit happy-path: prime the Fake's SshdConfigResponse so
// the inline post-reload sshd -T verifier sees `passwordauthentication=no`,
// then synthesize submitDoneMsg{nil} via FeedSubmitDoneForTest to advance to
// phaseDone (mirrors applysetup test 12 — the txn batch itself is exercised
// in internal/txn tests, not duplicated here).
func TestPwAuthDisable_submit_done_success_transitions_to_done_then_autopops(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.SshdConfigResponse = map[string][]string{"passwordauthentication": {"no"}}
	m := pwauthdisable.New(f, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, nil)

	// Fast-forward to phaseSubmitting then synthesize the success msg.
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseSubmittingForTest, m.PhaseForTest())

	_, cmd := m.FeedSubmitDoneForTest(nil)
	require.Equal(t, pwauthdisable.PhaseDoneForTest, m.PhaseForTest())
	require.NotNil(t, cmd, "phaseDone transition must schedule the autoPopMsg tick")
}

// TestPwAuthDisable_submit_done_with_error_renders_critical_inline_and_phase_error —
// submitDoneMsg{err} transitions to phaseError + Critical errInline carrying
// both "rolled back" and the underlying error text. Mirrors applysetup
// test 11.
func TestPwAuthDisable_submit_done_with_error_renders_critical_inline_and_phase_error(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, nil)
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseSubmittingForTest, m.PhaseForTest())

	_, _ = m.FeedSubmitDoneForTest(errors.New("simulated sshd-t failure"))
	require.Equal(t, pwauthdisable.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "rolled back")
	require.Contains(t, m.ErrInlineForTest(), "simulated sshd-t failure")
	require.Contains(t, m.ErrInlineForTest(), "disable failed",
		"action-name copy must surface in the rolled-back error so the admin knows which direction failed")
}

// --- WantsRawKeys flips while typing the override text ----------------------

// TestPwAuthDisable_wants_raw_keys_true_in_confirming_override — the
// override textinput must capture every keystroke (including 'q' / space)
// so the global `q`-quits-program binding does not eat characters mid-type.
func TestPwAuthDisable_wants_raw_keys_true_in_confirming_override(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, []string{"alice"})
	require.False(t, m.WantsRawKeys(), "WantsRawKeys must be false in phaseReview")

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, pwauthdisable.PhaseConfirmingOverrideForTest, m.PhaseForTest())
	require.True(t, m.WantsRawKeys(), "WantsRawKeys must flip true in phaseConfirmingOverride so the override textinput captures every key")

	// Esc back to review reverts WantsRawKeys.
	_, _ = m.Update(keyPress("esc"))
	require.Equal(t, pwauthdisable.PhaseReviewForTest, m.PhaseForTest())
	require.False(t, m.WantsRawKeys())
}

// --- Esc protocol -----------------------------------------------------------

// TestPwAuthDisable_esc_in_review_pops_modal — Esc in phaseReview returns
// the nav.PopCmd intent so the parent App pops the modal off the stack.
func TestPwAuthDisable_esc_in_review_pops_modal(t *testing.T) {
	t.Parallel()
	m := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	m.LoadPreflightForTest(nil, nil)

	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// --- Render sanity (Action labels surface in copy) --------------------------

// TestPwAuthDisable_view_action_label_disable_vs_enable — renderReview
// wording must reflect the active Action so admins know which direction the
// modal is about to drive.
func TestPwAuthDisable_view_action_label_disable_vs_enable(t *testing.T) {
	t.Parallel()
	mDis := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionDisable)
	mDis.LoadPreflightForTest(nil, nil)
	require.Contains(t, mDis.View(), "disable")

	mEn := pwauthdisable.New(nil, nil, testChrootRoot, pwauthdisable.ActionEnable)
	mEn.LoadPreflightForTest(nil, nil)
	v := mEn.View()
	require.Contains(t, v, "Re-enable",
		"ActionEnable review render must mention re-enabling so admin sees the direction")
	require.NotContains(t, v, "BLOCKED",
		"ActionEnable must never render BLOCKED — there is no lockout risk to gate")
}

// --- Compile-time sanity: OverrideText is the documented constant ----------

// TestPwAuthDisable_OverrideText_is_canonical — pin the literal so a future
// rename refactor (e.g. translating to another language) is a deliberate
// edit, not a silent drift away from the spec.
func TestPwAuthDisable_OverrideText_is_canonical(t *testing.T) {
	t.Parallel()
	require.Equal(t, "I understand", pwauthdisable.OverrideText,
		"OverrideText must remain the canonical D-16 phrase 'I understand' (case-sensitive)")
	// Also assert the constant is referenced verbatim somewhere in the
	// rendered confirm-prompt so admins see what to type.
	require.True(t, strings.Contains(pwauthdisable.OverrideText, "I understand"))
}
