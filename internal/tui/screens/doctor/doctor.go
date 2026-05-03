// Package doctorscreen renders the diagnostic report as a TUI screen pushed
// onto the nav stack by the home screen's `d` binding. It invokes the
// doctor.Service asynchronously on Init, renders the report color-coded by
// severity via Lip Gloss, and supports `c` to copy the text to the clipboard
// via OSC 52 (TUI-06).
//
// The package is intentionally tiny - the heavy lifting (six detectors +
// text rendering) lives in internal/service/doctor. This screen is only a
// presentation layer wrapped around that service.
package doctorscreen

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/applysetup"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/ufwenable"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// Model is the TUI doctor screen.
type Model struct {
	svc     *doctor.Service
	report  *model.DoctorReport
	loading bool
	errText string
	toast   widgets.Toast
	keys    KeyMap

	// startupGate is set by NewStartupGate. When true, the screen is
	// the post-splash entry-point gate: it advances to the home screen
	// only when doctor.IsHealthy returns true (no [FAIL] rows). [esc]
	// quits the app instead of popping (no parent screen exists).
	startupGate bool
	// homeBuilder constructs the home screen the gate replaces itself
	// with on healthy. Captured at NewStartupGate time so the doctor
	// screen package never imports home (avoids the wire-cycle that
	// motivated the splash.HomePlaceholder pattern in the first place).
	homeBuilder func() nav.Screen
}

// reportLoadedMsg carries the report back to Update after the async Run.
type reportLoadedMsg struct {
	report model.DoctorReport
	err    error
}

// New constructs a doctor screen backed by the given service.
func New(svc *doctor.Service) *Model {
	return &Model{svc: svc, loading: true, keys: DefaultKeyMap()}
}

// NewStartupGate constructs a doctor screen that acts as the post-splash
// entry-point gate (operator-stated requirement: only continue to the
// home screen if everything is green).
//
// Behavior delta vs New:
//   - On a healthy report (doctor.IsHealthy returns true) the screen
//     auto-emits nav.ReplaceMsg with homeBuilder()'s output. The user
//     never sees the gate when the system is already configured.
//   - On a non-healthy report the screen renders normally. The operator
//     uses [a] to apply the highest-precedence fix; the post-pop
//     DoctorRefreshMsg re-runs the diagnostic; the cycle repeats until
//     IsHealthy passes and the gate advances.
//   - [esc] quits the app (no home on the stack to pop to).
//
// homeBuilder is captured here so this package never imports home (avoids
// the splash <- home <- wire cycle).
func NewStartupGate(svc *doctor.Service, homeBuilder func() nav.Screen) *Model {
	m := New(svc)
	m.startupGate = true
	m.homeBuilder = homeBuilder
	return m
}

// Init kicks off the async report load. Returns a tea.Cmd that runs the
// six detectors on a background goroutine.
func (m *Model) Init() tea.Cmd {
	svc := m.svc
	return func() tea.Msg {
		if svc == nil {
			return reportLoadedMsg{err: errNoService}
		}
		rep, err := svc.Run(context.Background())
		return reportLoadedMsg{report: rep, err: err}
	}
}

// errNoService is the sentinel used when the screen is constructed with a
// nil Service (defensive; production wiring always supplies one).
var errNoService = &stringError{"doctor: no service wired"}

type stringError struct{ s string }

func (e *stringError) Error() string { return e.s }

// Update handles the async reportLoadedMsg and keypress navigation.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case nav.DoctorRefreshMsg:
		// A mutation modal (ufwenable, applysetup, ...) just popped
		// back. Reset to loading state and re-run the async diagnostic
		// so the operator sees the post-mutation state without
		// restarting the app. errText/report are not cleared on
		// purpose - if the new run also fails the new error overwrites
		// the old; if it succeeds, m.report is replaced. m.loading=true
		// hides the stale body until then.
		m.loading = true
		m.errText = ""
		return m, m.Init()

	case reportLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.errText = msg.err.Error()
			return m, nil
		}
		r := msg.report
		m.report = &r
		// Startup gate: ALWAYS render the report after splash so the
		// operator sees the diagnostic state at every launch (operator-
		// stated requirement, refined 2026-05-03 lab UAT round 3).
		// Auto-advance was prior behavior - operator wanted to land on
		// doctor regardless of health to confirm the system is green.
		// [esc] in startup-gate mode advances to home only when healthy
		// (the "only continue to home if green" half of the rule).
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc", "q":
			// Startup-gate mode (operator-stated: "only continue to
			// home if everything is green"):
			//   - Healthy report → [esc] advances to home (replace).
			//   - Unhealthy or no report yet → [esc] quits the app
			//     (no parent on the stack, and the gate must not let
			//     unfixed FAILs through).
			if m.startupGate {
				if m.report != nil && doctor.IsHealthy(*m.report) && m.homeBuilder != nil {
					builder := m.homeBuilder
					return m, func() tea.Msg { return nav.ReplaceMsg{Factory: builder} }
				}
				return m, tea.Quit
			}
			return m, nav.PopCmd()
		case "c":
			if m.report != nil {
				text := doctor.RenderText(*m.report)
				// C6: Toast.Flash returns (Toast, tea.Cmd) - capture both so
				// the flash state survives across the tea.Cmd boundary.
				var flashCmd tea.Cmd
				m.toast, flashCmd = m.toast.Flash("copied via OSC 52")
				return m, tea.Batch(tea.SetClipboard(text), flashCmd)
			}
		case "a", "A":
			// Phase 3 / D-06: prescription action. Phase 8 / D-14: precedence
			// dispatch - canonical-apply > ufw-enable. The first matching gap
			// is fired; subsequent [a] presses fire the next gap after the
			// operator resolves the prior one. Pitfall 7: m.report != nil
			// gates the dispatch, so the post-pop Init() re-run window does
			// not double-fire.
			if m.report == nil || m.svc == nil {
				return m, nil
			}
			if doctor.NeedsCanonicalApply(*m.report) {
				return m, nav.PushCmd(applysetup.New(m.svc.Ops(), m.svc.ChrootRoot()))
			}
			if doctor.NeedsUfwEnable(*m.report) {
				return m, nav.PushCmd(ufwenable.New(m.svc.Ops()))
			}
			return m, nil
		}
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// View renders the report (color-coded) plus the toast overlay. Loading /
// error states render inline.
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("running diagnostic…")
	}
	if m.errText != "" {
		return styles.Critical.Render("doctor failed: "+m.errText) + "\n\n" + styles.Dim.Render("(esc to return)")
	}
	if m.report == nil {
		return styles.Dim.Render("(no report)")
	}
	// D-14: select the active marker substring for the highest-precedence gap.
	// D-15 belt-and-suspenders: > marker + footer hint both reflect the target.
	activeMarker := ""
	if doctor.NeedsCanonicalApply(*m.report) {
		activeMarker = "[A] Apply SFTP jail configuration"
	} else if doctor.NeedsUfwEnable(*m.report) {
		activeMarker = "[A] Enable ufw"
	}
	body := colorizeReport(doctor.RenderText(*m.report), activeMarker)

	// Footer hint: ALWAYS show [esc] back so the operator knows how to
	// leave the screen. When a dispatch is active (D-15 belt-and-suspenders),
	// prepend the prescription text. The all-OK case still shows [esc] +
	// [c] copy so the screen never appears as a dead-end.
	var footerHint string
	switch activeMarker {
	case "[A] Apply SFTP jail configuration":
		footerHint = "Press [a] to apply SFTP jail configuration  ([esc] back, [c] copy)"
	case "[A] Enable ufw":
		footerHint = "Press [a] to enable ufw  ([esc] back, [c] copy report)"
	default:
		footerHint = "[esc] back  [c] copy report"
	}
	body += "\n\n" + styles.Dim.Render(footerHint)

	if ts := m.toast.View(); ts != "" {
		body += "\n" + ts
	}
	return body
}

// colorizeReport wraps each [OK]/[WARN]/[FAIL]/[INFO] row in the matching
// Lip Gloss style. Per-line coloring (vs. per-token) keeps the alignment
// intact and is simpler to verify in tests.
//
// activeMarker, when non-empty, prepends "> " in Primary style to the first
// line that contains the substring. D-15 belt-and-suspenders: the marker is
// intentionally redundant with the footer hint. Pitfall 4: this layering
// happens HERE (TUI screen), not in render.go (which stays ANSI-free).
func colorizeReport(text string, activeMarker string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		// Prepend `> ` in Primary style if this row is the active dispatch target.
		prefixed := l
		if activeMarker != "" && strings.Contains(l, activeMarker) {
			prefixed = styles.Primary.Render("> ") + l
		}
		switch {
		case strings.HasPrefix(l, "[OK]"):
			out = append(out, styles.Success.Render(prefixed))
		case strings.HasPrefix(l, "[WARN]"):
			out = append(out, styles.Warn.Render(prefixed))
		case strings.HasPrefix(l, "[FAIL]"):
			out = append(out, styles.Critical.Render(prefixed))
		case strings.HasPrefix(l, "[INFO]"):
			out = append(out, styles.Dim.Render(prefixed))
		default:
			out = append(out, prefixed)
		}
	}
	return strings.Join(out, "\n")
}

// KeyMap describes the doctor screen's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Back  nav.KeyBinding
	Copy  nav.KeyBinding
	Apply nav.KeyBinding
}

// DefaultKeyMap returns the canonical doctor-screen bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:  nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Copy:  nav.KeyBinding{Keys: []string{"c"}, Help: "copy report"},
		Apply: nav.KeyBinding{Keys: []string{"a"}, Help: "apply SFTP jail configuration"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding { return []nav.KeyBinding{k.Back, k.Copy, k.Apply} }

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Back, k.Copy, k.Apply}}
}

// Title is shown in the help overlay header.
func (m *Model) Title() string { return "diagnostic" }

// KeyMap returns the doctor screen's KeyMap for the help overlay.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys is false - the doctor screen has no textinput.
func (m *Model) WantsRawKeys() bool { return false }

// LoadReportForTest bypasses Init and sets the report directly. Exported
// for tests so they can exercise the render / key paths without awaiting
// the async tea.Cmd.
func (m *Model) LoadReportForTest(r model.DoctorReport) {
	m.loading = false
	m.report = &r
}

// LoadingForTest exposes the loading flag so tests can assert that
// DoctorRefreshMsg flips the screen back into its loading state
// before the async re-load completes.
func (m *Model) LoadingForTest() bool { return m.loading }

// FeedReportLoadedMsgForTest constructs and delivers the unexported
// reportLoadedMsg so external-package tests can drive the gate's
// healthy / unhealthy advance branches without going through the
// async Init goroutine.
func (m *Model) FeedReportLoadedMsgForTest(rep model.DoctorReport, err error) (nav.Screen, tea.Cmd) {
	return m.Update(reportLoadedMsg{report: rep, err: err})
}
