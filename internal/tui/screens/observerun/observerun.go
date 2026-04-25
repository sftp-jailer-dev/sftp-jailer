// Package observerunscreen renders the M-OBSERVE live-progress modal that
// streams JSON output from the `sftp-jailer observe-run` subprocess. Pushed
// by S-LOGS pressing `r` (OBS-06).
//
// The novel pattern in this file is the goroutine-Send loop (RESEARCH
// Pattern 4): Init's tea.Cmd starts the subprocess via
// sysops.ObserveRunStream and spawns a goroutine that scans stdout
// line-by-line, JSON-decodes each progress event, and Send-s it back into
// the program via *tea.Program.Send. This is the only place in the codebase
// that bridges from a long-lived subprocess into the tea program — every
// other screen receives messages via tea.Cmd return values from Update.
//
// Esc cancels: m.cancelFn() (the context.CancelFunc returned by
// context.WithCancel) sends SIGTERM to the subprocess — the cancel-on-ctx
// hook is set up by the typed wrapper in sysops.ObserveRunStream (02-02).
// The runner commits the current batch atomically before exit (cursor-file
// integrity per OBS-02). Spinner replaced with `cancelling…` (Warn) until
// the goroutine exits.
//
// On phase=done JSON line: spinner stops; modal renders the final summary
// for ~500ms (tea.Tick); then auto-pops via nav.PopCmd AND emits
// nav.StatusRefreshMsg + nav.ObserveRunCompleteToast (cross-package
// routing — see internal/tui/nav/msgs.go).
//
// UI per UI-SPEC §M-OBSERVE (lines 257-263, 327-349):
//   - Only key: Esc cancels.
//   - Other keys swallowed (UI-SPEC line 262).
//   - Layout: lipgloss.NormalBorder() with Padding(0, 2) (M-OBSERVE-only
//     padding exception per UI-SPEC line 46).
//   - Spinner: spinner.Line, color Primary.
//   - Body: phase line + counter lines + spinner footer `(esc to cancel)`.
package observerunscreen

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/observe"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// AutoPopDelay is the time the modal lingers after phase=done before it
// auto-pops to the parent S-LOGS screen. UI-SPEC line 327: "render the
// final summary for ~500ms".
const AutoPopDelay = 500 * time.Millisecond

// Model is the M-OBSERVE Bubble Tea v2 model. Constructed via New; treat
// as single-use (push, run, auto-pop).
type Model struct {
	program *tea.Program
	ops     sysops.SystemOps
	opts    sysops.ObserveRunSubprocessOpts

	// Phase-specific accumulators populated from Progress messages.
	phase         observe.Phase
	readCount     int
	classifyCount int
	compact       compactState
	done          bool
	summary       *observe.RunSummary
	skipped       bool
	skippedReason string
	errMsg        string

	// cancelFn is set by startSubprocess (or by SetCancelFnForTest). When
	// the admin presses Esc we call cancelFn and flip cancelling = true.
	cancelFn   context.CancelFunc
	cancelling bool

	spinner spinner.Model
	keys    KeyMap
}

// compactState aggregates the per-progress counters for the compact phase.
type compactState struct {
	Active        bool
	Kept          int
	Compacted     int
	Dropped       int
	CountersAdded int
}

// Messages flowing from the subprocess goroutine into Update.
//
//nolint:unused // errMsg/streamClosedMsg are emitted in production code paths
// — present for completeness and future inline error handling.
type (
	progressMsg     observe.Progress
	doneMsg         struct{ summary observe.RunSummary }
	subprocessErrMsg struct{ err error }
	startedMsg      struct{}
	streamClosedMsg struct{}
	autoPopMsg      struct{}
)

// New constructs the modal with the program reference (needed for the
// goroutine Send pattern), the sysops handle (used to spawn observe-run),
// and the typed opts (cursor / db / config paths). The program may be nil
// in unit tests that drive Update directly via the test seams.
func New(p *tea.Program, ops sysops.SystemOps, opts sysops.ObserveRunSubprocessOpts) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	return &Model{
		program: p,
		ops:     ops,
		opts:    opts,
		phase:   observe.PhaseRead, // initial display "starting"
		spinner: sp,
		keys:    DefaultKeyMap(),
	}
}

// KeyMap is the M-OBSERVE key bindings — implements nav.KeyMap.
type KeyMap struct {
	Cancel nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-OBSERVE bindings: just Esc.
func DefaultKeyMap() KeyMap {
	return KeyMap{Cancel: nav.KeyBinding{Keys: []string{"esc"}, Help: "cancel"}}
}

// ShortHelp surfaces the single Esc binding in the footer / `?` overlay.
func (k KeyMap) ShortHelp() []nav.KeyBinding { return []nav.KeyBinding{k.Cancel} }

// FullHelp mirrors ShortHelp — the modal has no power-user bindings.
func (k KeyMap) FullHelp() [][]nav.KeyBinding { return [][]nav.KeyBinding{{k.Cancel}} }

// Title implements nav.Screen.
func (m *Model) Title() string { return "observe-run" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — false because the modal has no
// textinput. UI-SPEC line 262: every key except Esc is swallowed.
func (m *Model) WantsRawKeys() bool { return false }

// SetCancelFnForTest is the unit-test seam — callers can inject a recorded
// mock cancelFn to verify Esc behaviour without spinning up a real
// subprocess.
func (m *Model) SetCancelFnForTest(fn context.CancelFunc) { m.cancelFn = fn }

// IsCancellingForTest reports whether the Esc-cancel handler has fired.
func (m *Model) IsCancellingForTest() bool { return m.cancelling }

// ApplyProgressForTest applies a Progress event directly to the model, as
// if a progressMsg had arrived from the goroutine. Bypasses Init and the
// real subprocess plumbing.
func (m *Model) ApplyProgressForTest(p observe.Progress) { m.applyProgress(p) }

// ApplyDoneForTest seeds the model with a done summary so AutoPopCmdForTest
// returns a meaningful batch.
func (m *Model) ApplyDoneForTest(s observe.RunSummary) {
	m.done = true
	m.summary = &s
}

// AutoPopCmdForTest returns the same tea.Cmd that the autoPopMsg handler
// emits in production. Lets unit tests assert on the Pop / refresh /
// complete-toast batch shape.
func (m *Model) AutoPopCmdForTest() tea.Cmd { return m.autoPopCmd() }

// Init starts the spinner ticker and spawns the observe-run subprocess.
// In unit tests where program is nil, the test seams (ApplyProgressForTest /
// SetCancelFnForTest) drive the model state directly.
func (m *Model) Init() tea.Cmd {
	tickCmd := func() tea.Msg { return m.spinner.Tick() }
	if m.program == nil {
		// Test path — no subprocess. Spinner still ticks so View renders
		// consistently.
		return tickCmd
	}
	return tea.Batch(tickCmd, m.startSubprocess())
}

// startSubprocess returns a tea.Cmd that opens the observe-run subprocess
// and spawns the goroutine that bridges stdout into the program via Send.
//
// Pattern 4 (RESEARCH §"Streaming subprocess JSON via goroutine + Program.Send"):
//   - The goroutine reads stdout line-by-line.
//   - Each line is JSON-unmarshalled into observe.Progress.
//   - program.Send(progressMsg(p)) injects each event into the tea event loop.
//   - On phase=done OR scanner end, the goroutine emits doneMsg + streamClosedMsg.
func (m *Model) startSubprocess() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelFn = cancel

		proc, stdout, err := m.ops.ObserveRunStream(ctx, m.opts)
		if err != nil {
			return subprocessErrMsg{err: err}
		}

		program := m.program
		go func() {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			var lastSummary observe.RunSummary
			for sc.Scan() {
				var p observe.Progress
				if jerr := json.Unmarshal(sc.Bytes(), &p); jerr != nil {
					// Malformed line — skip but keep scanning (T-OBS-13).
					continue
				}
				if p.Summary != nil {
					lastSummary = *p.Summary
				}
				program.Send(progressMsg(p))
				if p.Phase == observe.PhaseDone {
					break
				}
			}
			if proc != nil {
				_, _ = proc.Wait()
			}
			program.Send(doneMsg{summary: lastSummary})
			program.Send(streamClosedMsg{})
		}()

		return startedMsg{}
	}
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over the modal's six message types
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case startedMsg:
		return m, nil

	case progressMsg:
		m.applyProgress(observe.Progress(msg))
		return m, nil

	case doneMsg:
		m.done = true
		m.summary = &msg.summary
		// Render the summary for AutoPopDelay then auto-pop.
		return m, tea.Tick(AutoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case autoPopMsg:
		return m, m.autoPopCmd()

	case subprocessErrMsg:
		m.errMsg = msg.err.Error()
		return m, nil

	case streamClosedMsg:
		// Goroutine drained — nothing to do (the doneMsg path already
		// scheduled the auto-pop). On cancellation the goroutine exits via
		// the same path; the autoPopMsg from doneMsg's tick will pop the
		// modal once the subprocess exits.
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return m, m.handleEscCancel()
		}
		// Other keys swallowed (UI-SPEC line 262).
		return m, nil
	}
	return m, nil
}

// autoPopCmd builds the batch emitted on autoPopMsg: nav.PopCmd to dismiss
// the modal, nav.StatusRefreshMsg to rebuild S-LOGS' status row, and
// nav.ObserveRunCompleteToast to surface the success toast (UI-SPEC
// line 305).
func (m *Model) autoPopCmd() tea.Cmd {
	events := 0
	counters := 0
	dropped := 0
	if m.summary != nil {
		events = m.summary.EventsRead
		counters = m.summary.CountersAdded
		dropped = m.summary.EventsDropped
	}
	return tea.Batch(
		nav.PopCmd(),
		func() tea.Msg { return nav.StatusRefreshMsg{} },
		func() tea.Msg {
			return nav.ObserveRunCompleteToast{Events: events, Counters: counters, Dropped: dropped}
		},
	)
}

// handleEscCancel calls cancelFn (which sends SIGTERM to the subprocess
// via the typed wrapper in sysops.ObserveRunStream) and emits the
// cancelled toast + status refresh to S-LOGS. The toast is emitted
// immediately so the admin sees feedback even before the subprocess
// fully exits.
func (m *Model) handleEscCancel() tea.Cmd {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.cancelling = true
	count := m.readCount + m.classifyCount
	return tea.Batch(
		func() tea.Msg { return nav.ObserveRunCancelledToast{Count: count} },
		func() tea.Msg { return nav.StatusRefreshMsg{} },
	)
}

// applyProgress folds a Progress event into the per-phase accumulators.
func (m *Model) applyProgress(p observe.Progress) {
	m.phase = p.Phase
	switch p.Phase {
	case observe.PhaseRead:
		m.readCount = p.Count
	case observe.PhaseClassify:
		m.classifyCount = p.Count
	case observe.PhaseCompact:
		m.compact = compactState{
			Active:        true,
			Kept:          p.Kept,
			Compacted:     p.Compacted,
			Dropped:       p.Dropped,
			CountersAdded: p.CountersAdded,
		}
	case observe.PhaseSkipped:
		m.skipped = true
		m.skippedReason = p.Reason
	case observe.PhaseDone:
		// doneMsg arrives separately; here we just record the phase so
		// View() can render `phase: done` if invoked between the doneMsg
		// arrival and the autoPopMsg tick.
	}
}

// View renders the modal body wrapped in a NormalBorder per UI-SPEC §M-OBSERVE.
func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(styles.Primary.Render("observe-run"))
	b.WriteString("\n\n")

	if m.errMsg != "" {
		b.WriteString(styles.Critical.Render("error: " + m.errMsg))
		b.WriteString("\n")
		b.WriteString(styles.Dim.Render("(esc to dismiss)"))
		b.WriteString("\n")
		return wrapModal(b.String())
	}
	if m.skipped {
		b.WriteString(styles.Warn.Render("skipped: " + m.skippedReason))
		b.WriteString("\n")
		return wrapModal(b.String())
	}
	if m.readCount == 0 && m.classifyCount == 0 && !m.compact.Active && !m.done {
		// Pre-progress states still surface the cancelling label so the
		// admin sees feedback if Esc was pressed before any progress
		// arrived. Otherwise show the starting placeholder.
		if m.cancelling {
			b.WriteString(styles.Warn.Render("cancelling…"))
		} else {
			b.WriteString(styles.Dim.Render("starting observe-run…"))
		}
		b.WriteString("\n")
		return wrapModal(b.String())
	}

	fmt.Fprintf(&b, "phase:    %s\n", m.phase)
	if m.readCount > 0 {
		fmt.Fprintf(&b, "read:     %d events\n", m.readCount)
	}
	if m.classifyCount > 0 {
		fmt.Fprintf(&b, "classify: %d events\n", m.classifyCount)
	}
	if m.compact.Active {
		fmt.Fprintf(&b,
			"compact:  kept %d · compacted %d → %d counters · dropped %d\n",
			m.compact.Kept, m.compact.Compacted, m.compact.CountersAdded, m.compact.Dropped)
	}
	b.WriteString("\n")

	switch {
	case m.done:
		b.WriteString(styles.Success.Render("done"))
		b.WriteString("\n")
	case m.cancelling:
		b.WriteString(styles.Warn.Render("cancelling…"))
		b.WriteString("\n")
	default:
		b.WriteString(m.spinner.View() + " " + styles.Dim.Render("running…    (esc to cancel)"))
		b.WriteString("\n")
	}

	return wrapModal(b.String())
}

// wrapModal applies the M-OBSERVE-only NormalBorder + Padding(0, 2) per
// UI-SPEC line 46. (Most screens use no border — this is the modal
// exception.)
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}
