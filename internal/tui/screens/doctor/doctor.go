// Package doctorscreen renders the diagnostic report as a TUI screen pushed
// onto the nav stack by the home screen's `d` binding. It invokes the
// doctor.Service asynchronously on Init, renders the report color-coded by
// severity via Lip Gloss, and supports `c` to copy the text to the clipboard
// via OSC 52 (TUI-06).
//
// The package is intentionally tiny — the heavy lifting (six detectors +
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
	case reportLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.errText = msg.err.Error()
			return m, nil
		}
		r := msg.report
		m.report = &r
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc", "q":
			return m, nav.PopCmd()
		case "c":
			if m.report != nil {
				text := doctor.RenderText(*m.report)
				// C6: Toast.Flash returns (Toast, tea.Cmd) — capture both so
				// the flash state survives across the tea.Cmd boundary.
				var flashCmd tea.Cmd
				m.toast, flashCmd = m.toast.Flash("copied via OSC 52")
				return m, tea.Batch(tea.SetClipboard(text), flashCmd)
			}
		case "a", "A":
			// Phase 3 / D-06: prescription action — push M-APPLY-SETUP when
			// the report indicates a SETUP-02..06 gap. NeedsCanonicalApply
			// returns true for missing drop-in / chroot-chain violation /
			// external-sftp warning. The modal sources its SystemOps via
			// doctor.Service.Ops() (single-handle ownership; plan 03-06
			// Task 1).
			if m.report != nil && m.svc != nil && doctor.NeedsCanonicalApply(*m.report) {
				return m, nav.PushCmd(applysetup.New(m.svc.Ops(), m.svc.ChrootRoot()))
			}
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
	body := colorizeReport(doctor.RenderText(*m.report))
	if ts := m.toast.View(); ts != "" {
		body += "\n" + ts
	}
	return body
}

// colorizeReport wraps each [OK]/[WARN]/[FAIL]/[INFO] row in the matching
// Lip Gloss style. Per-line coloring (vs. per-token) keeps the alignment
// intact and is simpler to verify in tests.
func colorizeReport(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "[OK]"):
			out = append(out, styles.Success.Render(l))
		case strings.HasPrefix(l, "[WARN]"):
			out = append(out, styles.Warn.Render(l))
		case strings.HasPrefix(l, "[FAIL]"):
			out = append(out, styles.Critical.Render(l))
		case strings.HasPrefix(l, "[INFO]"):
			out = append(out, styles.Dim.Render(l))
		default:
			out = append(out, l)
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
		Apply: nav.KeyBinding{Keys: []string{"a"}, Help: "apply canonical config"},
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

// WantsRawKeys is false — the doctor screen has no textinput.
func (m *Model) WantsRawKeys() bool { return false }

// LoadReportForTest bypasses Init and sets the report directly. Exported
// for tests so they can exercise the render / key paths without awaiting
// the async tea.Cmd.
func (m *Model) LoadReportForTest(r model.DoctorReport) {
	m.loading = false
	m.report = &r
}
