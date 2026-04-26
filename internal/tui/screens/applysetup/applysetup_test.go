package applysetup_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/applysetup"
)

// frozenNow returns a deterministic timestamp so the CanonicalDropIn render
// is byte-stable across test runs. Mirrors the pattern used in the
// internal/sshdcfg golden-file tests (plan 03-03).
func frozenNow() time.Time {
	return time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
}

// keyPress builds a synthetic tea.KeyPressMsg for the given key string.
// Mirrors the helper in internal/tui/screens/doctor/doctor_test.go.
func keyPress(s string) tea.KeyPressMsg {
	if s == "esc" {
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	}
	if s == "enter" {
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// newSeededModel wires a Fake-backed model and applies the deterministic
// timestamp seam before LoadProposalForTest so the rendered diff is stable.
func newSeededModel() (*applysetup.Model, *sysops.Fake) {
	f := sysops.NewFake()
	m := applysetup.New(f, "/srv/sftp-jailer")
	m.SetNowFnForTest(frozenNow)
	return m, f
}

// Test 1: Review phase renders the diff (with unified-diff `---/+++`
// headers) AND the violation Reason text when violations are present.
func TestApplySetup_review_phase_renders_diff_and_violations(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest(
		[]byte(""), // no current drop-in → all-additions diff
		"/srv/sftp-jailer",
		[]chrootcheck.Violation{{Path: "/srv", Reason: "/srv has mode 0775 (group-write); fix with: sudo chmod g-w /srv"}},
		false,
	)
	v := m.View()
	require.Contains(t, v, "/srv has mode 0775", "violation Reason text must appear in review render")
	require.Contains(t, v, "---", "unified diff must show --- header line")
	require.Contains(t, v, "+++", "unified diff must show +++ header line")
}

// Test 2: SETUP-06 advisory note appears when externalSftpServer is set.
// The styling is via lipgloss so we check substring presence, not ANSI codes.
func TestApplySetup_external_sftp_server_renders_warn_note(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, true)
	v := m.View()
	require.Contains(t, v, "external sftp-server")
	require.Contains(t, v, "SETUP-06 advisory")
}

// Test 3: Apply is BLOCKED when violations are present. Pressing 'a' must
// NOT transition out of phaseReview.
func TestApplySetup_apply_blocked_when_violations_present(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest(
		[]byte(""),
		"/srv/sftp-jailer",
		[]chrootcheck.Violation{{Path: "/srv", Reason: "group-write"}},
		false,
	)
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	_, _ = m.Update(keyPress("a"))
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest(), "Apply must be blocked while violations are present")
}

// Test 4: Apply runs the txn batch when the proposal is clean. Pressing 'a'
// transitions to phaseApplying and returns a non-nil tea.Cmd. (We don't
// actually invoke the cmd here — that's an integration concern.)
func TestApplySetup_apply_runs_txn_batch_when_clean(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	_, cmd := m.Update(keyPress("a"))
	require.Equal(t, applysetup.PhaseApplyingForTest, m.PhaseForTest())
	require.NotNil(t, cmd, "phaseApplying transition must return the off-loop tea.Cmd")
}

// Test 5 (W-05): Pressing 'e' from review focuses the textinput; typing a
// new root + Enter transitions to phaseRePreflight (NOT phaseReview),
// re-renders proposedBytes against the new root, and clears stale violations.
func TestApplySetup_edit_phase_focuses_textinput_and_returns_to_re_preflight_on_enter(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest(
		[]byte(""),
		"/srv/sftp-jailer",
		[]chrootcheck.Violation{{Path: "/srv/sftp-jailer", Reason: "stale violation from old root"}},
		false,
	)
	// Press 'e' to enter edit mode.
	_, _ = m.Update(keyPress("e"))
	require.Equal(t, applysetup.PhaseEditingRootForTest, m.PhaseForTest())

	// Simulate a textinput edit by typing characters one-by-one is brittle;
	// instead we inject the new root via the textinput's SetValue path,
	// which is what bubble's textinput does internally on key insertion.
	// Then press Enter to submit.
	feedTextInput(t, m, "/srv/custom")
	_, _ = m.Update(keyPress("enter"))

	require.Equal(t, applysetup.PhaseRePreflightForTest, m.PhaseForTest(),
		"Enter on edit-root submission must transition to phaseRePreflight (W-05), NOT phaseReview")
	require.Equal(t, "/srv/custom", m.ProposedRootForTest())
	require.Contains(t, string(m.ProposedBytesForTest()), "/srv/custom/%u",
		"proposedBytes must be re-rendered against the new root")
	require.Empty(t, m.ViolationsForTest(),
		"violations must be cleared during phaseRePreflight (W-05 anti-stale invariant)")
}

// Test 6 (T-03-06-01): Non-absolute root must be rejected with errInline.
// Phase remains phaseEditingRoot.
func TestApplySetup_edit_phase_rejects_non_absolute_root_T_03_06_01(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	_, _ = m.Update(keyPress("e"))
	require.Equal(t, applysetup.PhaseEditingRootForTest, m.PhaseForTest())

	feedTextInput(t, m, "relative/path")
	_, _ = m.Update(keyPress("enter"))

	require.Equal(t, applysetup.PhaseEditingRootForTest, m.PhaseForTest(),
		"non-absolute root must NOT advance the phase (T-03-06-01)")
	require.Contains(t, m.ErrInlineForTest(), "must be absolute")
}

// Test 7 (W-05): re-preflight completion with NEW violations restores
// phaseReview but Apply remains blocked because the new root has its own
// violations.
func TestApplySetup_re_preflight_completion_restores_phase_review_with_new_violations(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	// Enter the edit flow + submit a new root to enter phaseRePreflight.
	_, _ = m.Update(keyPress("e"))
	feedTextInput(t, m, "/srv/custom")
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, applysetup.PhaseRePreflightForTest, m.PhaseForTest())

	// Simulate the re-walk completion with violations against the new root.
	newViolations := []chrootcheck.Violation{{Path: "/srv/custom", Reason: "/srv/custom has group-write"}}
	m.FeedRePreflightForTest(newViolations, nil)

	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	require.Len(t, m.ViolationsForTest(), 1)
	require.Equal(t, "/srv/custom has group-write", m.ViolationsForTest()[0].Reason)

	// Apply must still be blocked (new violations from new root).
	_, _ = m.Update(keyPress("a"))
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest(),
		"Apply must remain blocked when re-preflight surfaces new violations")
}

// Test 8 (W-05): re-preflight completion with NO violations unblocks Apply.
func TestApplySetup_re_preflight_clean_root_unblocks_apply(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	_, _ = m.Update(keyPress("e"))
	feedTextInput(t, m, "/srv/custom")
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, applysetup.PhaseRePreflightForTest, m.PhaseForTest())

	m.FeedRePreflightForTest(nil, nil)
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	require.Empty(t, m.ViolationsForTest())

	// Apply must now succeed in transitioning to phaseApplying.
	_, cmd := m.Update(keyPress("a"))
	require.Equal(t, applysetup.PhaseApplyingForTest, m.PhaseForTest())
	require.NotNil(t, cmd)
}

// Test 9: Esc in edit mode returns to review WITHOUT applying the textinput
// change. proposedRoot and violations are unchanged.
func TestApplySetup_esc_in_edit_returns_to_review_without_applying_change(t *testing.T) {
	m, _ := newSeededModel()
	originalViolations := []chrootcheck.Violation{{Path: "/srv", Reason: "preserved across esc"}}
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", originalViolations, false)
	_, _ = m.Update(keyPress("e"))
	require.Equal(t, applysetup.PhaseEditingRootForTest, m.PhaseForTest())

	feedTextInput(t, m, "/srv/different")
	_, _ = m.Update(keyPress("esc"))

	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	require.Equal(t, "/srv/sftp-jailer", m.ProposedRootForTest(),
		"Esc in edit mode must NOT mutate proposedRoot")
	require.Len(t, m.ViolationsForTest(), 1,
		"Esc in edit mode must NOT trigger a re-walk (violations preserved)")
	require.Equal(t, "preserved across esc", m.ViolationsForTest()[0].Reason)
}

// Test 10: Esc in review pops the modal — the returned tea.Cmd produces a
// nav.Msg with Intent=Pop.
func TestApplySetup_esc_in_review_pops_modal(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)

	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// Test 11: applyDoneMsg with err transitions to phaseError + Critical
// errInline carrying both "rolled back" and the underlying error text.
func TestApplySetup_apply_done_with_error_renders_critical_inline_and_phase_error(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	m.FeedApplyDoneForTest(errors.New("simulated sshd-t failure"))

	require.Equal(t, applysetup.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "rolled back")
	require.Contains(t, m.ErrInlineForTest(), "simulated sshd-t failure")
}

// Test 12: applyDoneMsg with no error transitions to phaseDone and emits
// a tea.Cmd that ultimately produces autoPopMsg (we don't unwind the Tick
// here — Bubble Tea timers are not test-friendly without a fake clock —
// but we do assert the cmd is non-nil and the phase advanced).
func TestApplySetup_apply_done_success_transitions_to_done_then_autopops(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	_, cmd := m.FeedApplyDoneForTest(nil)

	require.Equal(t, applysetup.PhaseDoneForTest, m.PhaseForTest())
	require.NotNil(t, cmd, "phaseDone transition must schedule the autoPopMsg tick")
}

// Test 13 (W-05 explicit pin): editing the root re-runs chrootcheck against
// the NEW root, NOT the prior root. Asserted via the sysops.Fake's recorded
// Lstat calls — the Fake's chrootcheck.WalkRoot will issue Lstat for each
// component of the new root path during the re-walk.
func TestApplySetup_edit_root_re_runs_chrootcheck_against_new_root(t *testing.T) {
	f := sysops.NewFake()
	// Seed both old and new chains with clean stats so chrootcheck.WalkRoot
	// completes without errors. We're asserting on which paths got Lstat'd.
	good := sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/"] = good
	f.FileStats["/srv"] = good
	f.FileStats["/srv/sftp-jailer"] = good // old root
	f.FileStats["/srv/new"] = good         // new root

	m := applysetup.New(f, "/srv/sftp-jailer")
	m.SetNowFnForTest(frozenNow)

	// Seed in phaseReview against the OLD root with a stale violation.
	m.LoadProposalForTest(
		[]byte(""),
		"/srv/sftp-jailer",
		[]chrootcheck.Violation{{Path: "/srv/sftp-jailer", Reason: "stale from old root"}},
		false,
	)

	// Snapshot the Calls slice BEFORE the edit so we can isolate the
	// re-walk's invocations.
	priorCallCount := len(f.Calls)

	// Enter edit mode + submit /srv/new.
	_, _ = m.Update(keyPress("e"))
	feedTextInput(t, m, "/srv/new")
	_, cmd := m.Update(keyPress("enter"))
	require.Equal(t, applysetup.PhaseRePreflightForTest, m.PhaseForTest())
	require.Empty(t, m.ViolationsForTest(), "violations must be cleared immediately on edit-Enter (W-05)")
	require.NotNil(t, cmd, "edit-Enter must schedule the re-walk Cmd")

	// Drain the Cmd to exercise runRePreflight against the Fake. The cmd
	// from edit-Enter is a tea.Batch of (spinner.Tick, runRePreflight). We
	// invoke it and walk any nested batched messages until we find the
	// rePreflightLoadedMsg.
	deliverBatchedMsgs(t, m, cmd)

	// After the re-walk, phase returns to phaseReview and the Fake should
	// have recorded Lstat calls against the NEW root (/, /srv, /srv/new),
	// NOT against the old root.
	require.Equal(t, applysetup.PhaseReviewForTest, m.PhaseForTest())
	newCalls := f.Calls[priorCallCount:]
	var lstatPaths []string
	for _, c := range newCalls {
		if c.Method == "Lstat" && len(c.Args) > 0 {
			lstatPaths = append(lstatPaths, c.Args[0])
		}
	}
	require.Contains(t, lstatPaths, "/srv/new",
		"re-walk MUST Lstat the NEW root (/srv/new) — W-05 contract")
	require.NotContains(t, lstatPaths, "/srv/sftp-jailer",
		"re-walk MUST NOT Lstat the OLD root (/srv/sftp-jailer) — W-05 contract")
}

// Test 14: M-APPLY-SETUP implements nav.Screen.
func TestApplySetup_implements_nav_Screen(t *testing.T) {
	m, _ := newSeededModel()
	var s nav.Screen = m
	require.Equal(t, "apply canonical config", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys is false in phasePreflight")
	require.NotNil(t, s.KeyMap())
	require.NotEmpty(t, s.KeyMap().ShortHelp())
	require.NotEmpty(t, s.KeyMap().FullHelp())
}

// Test 15: WantsRawKeys flips true while editing the chroot-root textinput.
func TestApplySetup_wants_raw_keys_true_while_editing_root(t *testing.T) {
	m, _ := newSeededModel()
	m.LoadProposalForTest([]byte(""), "/srv/sftp-jailer", nil, false)
	require.False(t, m.WantsRawKeys(), "WantsRawKeys must be false in phaseReview")
	_, _ = m.Update(keyPress("e"))
	require.True(t, m.WantsRawKeys(), "WantsRawKeys must flip true in phaseEditingRoot")
	_, _ = m.Update(keyPress("esc"))
	require.False(t, m.WantsRawKeys(), "WantsRawKeys must revert false on Esc back to phaseReview")
}

// ---------- helpers ----------

// feedTextInput submits a string into the modal's textinput by synthesizing
// per-rune key presses through Update. Mirrors how the bubble textinput
// processes real keystrokes.
func feedTextInput(t *testing.T, m *applysetup.Model, s string) {
	t.Helper()
	for _, r := range s {
		_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
	}
}

// deliverBatchedMsgs invokes cmd, then for any tea.Cmd messages produced
// (recursively) re-invokes them, delivering only the preflight-shaped
// messages we care about back into the model's Update. Spinner ticks are
// dropped so the helper does not loop forever.
//
// This is a minimal tea-loop simulator scoped to the messages this test
// produces; it is NOT a general-purpose harness.
func deliverBatchedMsgs(t *testing.T, m *applysetup.Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	switch v := msg.(type) {
	case tea.BatchMsg:
		for _, sub := range v {
			deliverBatchedMsgs(t, m, sub)
		}
	case tea.Cmd:
		deliverBatchedMsgs(t, m, v)
	default:
		// Only deliver preflight / applyDone messages; spinner ticks are
		// dropped so this helper does not recurse indefinitely.
		name := fmt.Sprintf("%T", msg)
		if strings.Contains(name, "preflight") ||
			strings.Contains(name, "Preflight") ||
			strings.Contains(name, "applyDone") {
			_, follow := m.Update(msg)
			deliverBatchedMsgs(t, m, follow)
		}
	}
}
