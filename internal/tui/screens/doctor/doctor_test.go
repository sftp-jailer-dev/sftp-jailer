package doctorscreen_test

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/ufwenable"
)

func keyPress(s string) tea.KeyPressMsg {
	if s == "esc" {
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// The screen starts in the loading state; View shows a placeholder and no
// panic from View-on-no-report.
func TestDoctorScreen_initial_loading_view(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	v := s.View()
	require.Contains(t, v, "running diagnostic")
}

// After LoadReportForTest, View renders the six report rows and carries the
// expected severity prefixes.
func TestDoctorScreen_view_after_report(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{
		UfwIPv6:   model.UfwIPv6Report{Value: "no", Warning: true},
		Ufw:       model.UfwReport{Available: true, Inactive: false}, // v1.2.2: keep IPV6 row visible
		AppArmor:  model.AppArmorReport{Available: true, SshdLoaded: true, SshdMode: "enforce", Warning: true},
		Subsystem: model.SubsystemReport{Target: "/usr/lib/openssh/sftp-server", Warning: true},
	})
	v := s.View()
	require.Contains(t, v, "ufw IPV6=no")
	require.Contains(t, v, "sshd in enforce mode")
	require.Contains(t, v, "subsystem sftp")
}

// `esc` emits a PopCmd.
func TestDoctorScreen_esc_pops(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{})

	_, cmd := s.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// `q` also pops.
func TestDoctorScreen_q_pops(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{})

	_, cmd := s.Update(keyPress("q"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// `c` returns a non-nil batch cmd (SetClipboard + Toast flash) once a
// report is loaded; with no report, no command is emitted.
func TestDoctorScreen_c_copies_when_report_loaded(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)

	// No report yet → no clipboard action.
	_, cmd := s.Update(keyPress("c"))
	require.Nil(t, cmd, "copy before load must not emit a tea.Cmd")

	s.LoadReportForTest(model.DoctorReport{
		UfwIPv6: model.UfwIPv6Report{Value: "yes"},
	})
	_, cmd = s.Update(keyPress("c"))
	require.NotNil(t, cmd, "copy after load must emit a tea.Cmd")
}

// The Model satisfies nav.Screen (compile-time check via assignment).
func TestDoctorScreen_implements_nav_Screen(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	var s nav.Screen = doctorscreen.New(svc)
	require.Equal(t, "diagnostic", s.Title())
	require.False(t, s.WantsRawKeys())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// KeyMap exposes c + esc/q + a bindings (Apply added in plan 03-06 Task 2).
func TestDoctorScreen_keymap_bindings(t *testing.T) {
	km := doctorscreen.DefaultKeyMap()
	short := km.ShortHelp()
	require.Len(t, short, 3)
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"esc", "q", "c", "a"} {
		require.True(t, found[k], "KeyMap must expose %q", k)
	}
}

// Phase 3 plan 03-06: pressing 'a' on the doctor screen pushes
// M-APPLY-SETUP when the report indicates a SETUP-02..06 gap. The push
// is asserted by inspecting the returned tea.Cmd's payload.
func TestDoctorScreen_a_action_pushes_applysetup_when_NeedsCanonicalApply(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	// Missing canonical drop-in trips NeedsCanonicalApply.
	s.LoadReportForTest(model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: false},
	})
	_, cmd := s.Update(keyPress("a"))
	require.NotNil(t, cmd, "Apply on a gap-bearing report must emit a tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.NotNil(t, nm.Screen, "pushed screen must be non-nil")
	require.Equal(t, "apply SFTP jail configuration", nm.Screen.Title(),
		"pushed screen title must be M-APPLY-SETUP's Title()")
}

// Phase 3 plan 03-06: pressing 'a' when the report is fully clean (no gap)
// is a no-op - no modal is pushed.
func TestDoctorScreen_a_action_noop_when_canonical_already_applied(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	})
	_, cmd := s.Update(keyPress("a"))
	require.Nil(t, cmd, "Apply on a clean report must NOT push a modal")
}

// ---- Phase 8 plan 08-04: precedence dispatch + > marker + footer hint --------

// repUfwEnableOnly: NeedsCanonicalApply=false, NeedsUfwEnable=true.
func repUfwEnableOnly() model.DoctorReport {
	return model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
		Ufw:       model.UfwReport{Available: true, Inactive: true}, // ufw inactive
	}
}

// repBothGaps: NeedsCanonicalApply=true AND NeedsUfwEnable=true.
func repBothGaps() model.DoctorReport {
	return model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: false}, // canonical gap
		Ufw:         model.UfwReport{Available: true, Inactive: true},   // ufw gap
	}
}

// repNoGaps: both predicates false.
func repNoGaps() model.DoctorReport {
	return model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
		Ufw:       model.UfwReport{Available: true, Inactive: false}, // ufw active
	}
}

// TestDoctor_apply_precedence_canonical_first asserts D-14: when BOTH
// gaps are present, [a] fires canonical-apply first (highest precedence).
func TestDoctor_apply_precedence_canonical_first(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repBothGaps())

	_, cmd := s.Update(keyPress("a"))
	require.NotNil(t, cmd, "[a] on both-gaps report must emit a tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.NotNil(t, nm.Screen)
	require.Equal(t, "apply SFTP jail configuration", nm.Screen.Title(),
		"D-14: canonical-apply must fire first, not ufwenable")
}

// TestDoctor_apply_precedence_ufwenable_when_canonical_resolved fires
// ufwenable when canonical-apply is resolved (NeedsCanonicalApply=false).
func TestDoctor_apply_precedence_ufwenable_when_canonical_resolved(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repUfwEnableOnly())

	_, cmd := s.Update(keyPress("a"))
	require.NotNil(t, cmd, "[a] on ufw-only-gap report must emit a tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.NotNil(t, nm.Screen)
	_, isUfwEnable := nm.Screen.(*ufwenable.Model)
	require.True(t, isUfwEnable,
		"D-14: when canonical resolved, [a] must push *ufwenable.Model, got %T", nm.Screen)
}

// TestDoctor_apply_no_op_when_no_gap asserts that pressing [a] when
// neither predicate fires does nothing.
func TestDoctor_apply_no_op_when_no_gap(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repNoGaps())

	_, cmd := s.Update(keyPress("a"))
	require.Nil(t, cmd, "[a] on fully-clean report must be a no-op")
}

// TestDoctor_active_marker_set_for_ufwenable: when ufwenable is the
// active dispatch target, View contains "> " + "[A] Enable ufw" and
// the footer hint. D-15 belt-and-suspenders.
func TestDoctor_active_marker_set_for_ufwenable(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repUfwEnableOnly())

	view := s.View()
	require.Contains(t, view, "> ", "active > marker must be present")
	require.Contains(t, view, "[A] Enable ufw")
	require.Contains(t, view, "Press [a] to enable ufw  ([return] continue, [c] copy report)",
		"footer hint must reflect ufwenable dispatch target")
}

// TestDoctor_active_marker_for_canonical_when_both_gaps: when BOTH
// gaps are present, the > marker anchors on the canonical-apply row
// (D-14 precedence), not on [A] Enable ufw. In the rendered text,
// the [A] Enable ufw row appears inline in the ufw section, while
// [A] Apply SFTP jail configuration is appended at the end by RenderText.
// The marker must appear adjacent to [A] Apply (near end), not near [A] Enable ufw.
func TestDoctor_active_marker_for_canonical_when_both_gaps(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repBothGaps())

	view := s.View()
	idxApply := strings.Index(view, "[A] Apply SFTP jail configuration")
	idxUfw := strings.Index(view, "[A] Enable ufw")
	idxMarker := strings.Index(view, "> ")

	require.GreaterOrEqual(t, idxMarker, 0, "active > marker must be present")
	require.GreaterOrEqual(t, idxApply, 0, "[A] Apply line must be in view")

	// The > marker must appear within ~100 chars before [A] Apply (ANSI prefix adds bytes).
	require.Less(t, idxApply-idxMarker, 100,
		"marker must be close before the [A] Apply canonical-apply row")
	require.GreaterOrEqual(t, idxApply-idxMarker, 0,
		"marker must appear before [A] Apply, not after")

	// The [A] Enable ufw row appears earlier (ufw section renders before the
	// [A] Apply row which is appended last by RenderText / NeedsCanonicalApply).
	// The marker must NOT be near [A] Enable ufw.
	if idxUfw >= 0 {
		require.Greater(t, idxApply, idxUfw,
			"[A] Apply SFTP jail configuration must appear after [A] Enable ufw in render order")
		// Marker must be far from the ufw row (> 50 chars separation).
		dist := idxMarker - idxUfw
		if dist < 0 {
			dist = -dist
		}
		require.Greater(t, dist, 50,
			"marker must not be near [A] Enable ufw row (should be near [A] Apply row)")
	}
}

// TestDoctor_no_marker_when_no_active_gap: when neither predicate fires,
// no > marker is rendered.
func TestDoctor_no_marker_when_no_active_gap(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repNoGaps())

	view := s.View()
	require.NotContains(t, view, "> [A]", "no active > marker should be rendered when no gap")
}

// TestDoctor_StartupGate_does_not_auto_advance_on_healthy pins the
// refined operator-stated rule (UAT round 3, 2026-05-03):
// "ensure the diagnostics are run after the splash screen, and only
// continue to the home screen if everything is green."
//
// The doctor screen renders its report on every launch - even a clean
// all-green report. Auto-advance was removed because operators wanted
// to see the green state at every launch, not just on a broken system.
// Advance to home is operator-driven via [esc].
func TestDoctor_StartupGate_does_not_auto_advance_on_healthy(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	gate := doctorscreen.NewStartupGate(svc, func() nav.Screen {
		return &fakeNavScreen{title: "home"}
	})

	_, cmd := gate.FeedReportLoadedMsgForTest(repNoGaps(), nil)
	require.Nil(t, cmd,
		"healthy report on the startup gate must NOT auto-emit ReplaceMsg - operator advances via [esc]")
}

// TestDoctor_StartupGate_esc_advances_to_home_when_healthy: the
// operator-driven advance path. Pressing [esc] while the gate holds
// a healthy report emits nav.ReplaceMsg with the captured homeBuilder.
func TestDoctor_StartupGate_esc_advances_to_home_when_healthy(t *testing.T) {
	t.Parallel()

	homeBuilt := false
	homeBuilder := func() nav.Screen {
		homeBuilt = true
		return &fakeNavScreen{title: "home"}
	}
	svc := doctor.New(sysops.NewFake())
	gate := doctorscreen.NewStartupGate(svc, homeBuilder)
	gate.LoadReportForTest(repNoGaps())

	_, cmd := gate.Update(keyPress("esc"))
	require.NotNil(t, cmd, "[esc] on a healthy gate must return a non-nil ReplaceMsg cmd")

	msg := cmd()
	rm, ok := msg.(nav.ReplaceMsg)
	require.True(t, ok, "expected nav.ReplaceMsg, got %T", msg)
	require.NotNil(t, rm.Factory)
	_ = rm.Factory()
	require.True(t, homeBuilt, "homeBuilder factory must be invoked exactly once")
}

// TestDoctor_StartupGate_esc_quits_when_unhealthy: pressing [esc] on
// a non-green gate quits the app instead of advancing to home (no
// parent on the stack to pop to, and the gate must not let unfixed
// FAILs through).
func TestDoctor_StartupGate_esc_quits_when_unhealthy(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	gate := doctorscreen.NewStartupGate(svc, func() nav.Screen {
		return &fakeNavScreen{title: "home"}
	})
	gate.LoadReportForTest(repUfwEnableOnly())

	_, cmd := gate.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	_, isQuit := msg.(tea.QuitMsg)
	require.True(t, isQuit, "[esc] on a non-green gate must Quit, got %T", msg)
}

// fakeNavScreen is a minimal nav.Screen for gate tests.
type fakeNavScreen struct{ title string }

func (f *fakeNavScreen) Init() tea.Cmd                        { return nil }
func (f *fakeNavScreen) Update(tea.Msg) (nav.Screen, tea.Cmd) { return f, nil }
func (f *fakeNavScreen) View() string                         { return "fake:" + f.title }
func (f *fakeNavScreen) Title() string                        { return f.title }
func (f *fakeNavScreen) KeyMap() nav.KeyMap                   { return nil }
func (f *fakeNavScreen) WantsRawKeys() bool                   { return false }

// TestDoctor_DoctorRefreshMsg_resets_loading_and_returns_init_cmd
// pins the gap-F refresh contract: when ufwenable (or any mutation
// modal) emits nav.DoctorRefreshMsg as part of its pop, the doctor
// screen flips back into loading state and returns a non-nil tea.Cmd
// that re-runs the diagnostic. Without this, the operator sees the
// pre-mutation state until they restart sftp-jailer.
func TestDoctor_DoctorRefreshMsg_resets_loading_and_returns_init_cmd(t *testing.T) {
	t.Parallel()

	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(repNoGaps())
	require.False(t, s.LoadingForTest(),
		"precondition: LoadReportForTest landed the screen in non-loading state")

	_, cmd := s.Update(nav.DoctorRefreshMsg{})

	require.True(t, s.LoadingForTest(),
		"DoctorRefreshMsg must flip screen back into loading state so stale body is hidden")
	require.NotNil(t, cmd,
		"DoctorRefreshMsg must return a non-nil tea.Cmd that re-runs the async diagnostic")
}

// TestDoctor_footer_always_shows_continue_affordance: the doctor
// screen must ALWAYS surface a continue/dismiss affordance so the
// operator never sees a dead-end. Operator-stated (UAT round 4):
// the dismiss key is "Press return to continue" instead of
// "[esc] back" - reads naturally in both startup-gate (advance to
// home) and normal-back (return to previous screen) contexts.
func TestDoctor_footer_always_shows_continue_affordance(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		rep  func() model.DoctorReport
	}{
		{"no gaps (all OK)", repNoGaps},
		{"ufwenable gap only", repUfwEnableOnly},
		{"both gaps", repBothGaps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := doctor.New(sysops.NewFake())
			s := doctorscreen.New(svc)
			s.LoadReportForTest(tc.rep())

			view := s.View()
			require.Contains(t, view, "return",
				"doctor footer must always include 'return' continue affordance")
			require.Contains(t, view, "[c]",
				"doctor footer must always include [c] copy report for any report state")
		})
	}
}

// TestDoctor_StartupGate_enter_advances_to_home_when_healthy: the
// new primary dismiss key (operator-stated UAT round 4) - Enter on
// a healthy startup gate emits ReplaceMsg with the homeBuilder.
func TestDoctor_StartupGate_enter_advances_to_home_when_healthy(t *testing.T) {
	t.Parallel()

	homeBuilt := false
	homeBuilder := func() nav.Screen {
		homeBuilt = true
		return &fakeNavScreen{title: "home"}
	}
	svc := doctor.New(sysops.NewFake())
	gate := doctorscreen.NewStartupGate(svc, homeBuilder)
	gate.LoadReportForTest(repNoGaps())

	enterPress := tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
	_, cmd := gate.Update(enterPress)
	require.NotNil(t, cmd, "[enter] on a healthy gate must return a non-nil cmd")

	msg := cmd()
	rm, ok := msg.(nav.ReplaceMsg)
	require.True(t, ok, "expected nav.ReplaceMsg, got %T", msg)
	require.NotNil(t, rm.Factory)
	_ = rm.Factory()
	require.True(t, homeBuilt, "homeBuilder factory must be invoked exactly once")
}
