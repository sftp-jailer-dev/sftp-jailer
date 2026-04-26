// Package applysetup renders the M-APPLY-SETUP modal — the doctor-driven
// prescription surface that applies the canonical chroot-SFTP drop-in to
// /etc/ssh/sshd_config.d/50-sftp-jailer.conf via the SAFE-02/03/05/06-compliant
// txn batch (D-09 sequence).
//
// Lifecycle phases:
//
//	phasePreflight   — Init runs the asynchronous preflight: parse existing
//	                   drop-in (D-08 chroot root extraction), walk chroot
//	                   chain (chrootcheck.WalkRoot), check for external
//	                   sftp-server (SETUP-06 advisory).
//	phaseReview      — admin reviews the proposed root + diff + violations,
//	                   presses 'a' to apply, 'e' to edit the root, esc to back out.
//	phaseEditingRoot — textinput is focused; admin types a new chroot root.
//	                   Enter validates filepath.IsAbs (T-03-06-01) and triggers
//	                   phaseRePreflight; Esc reverts without changes.
//	phaseRePreflight — W-05: chrootcheck.WalkRoot is re-running against the
//	                   admin-edited root; m.violations is cleared during this
//	                   window so stale violations from the prior root cannot
//	                   trick the admin into applying. Apply is gated on
//	                   phaseReview only — handleKey refuses 'a' here.
//	phaseApplying    — txn.New(ops).Apply(ctx, txn.CanonicalApplySetupSteps(...))
//	                   is in flight inside an off-loop tea.Cmd. Spinner ticks.
//	phaseDone        — apply succeeded; modal lingers ~500ms then auto-pops.
//	phaseError       — apply failed (txn rolled back) OR preflight error;
//	                   inline Critical errInline; Esc back to doctor.
//
// Single-handle ownership: the SystemOps handle is sourced from the doctor
// service via doctor.Service.Ops() (added in plan 03-06 Task 1). The modal
// never re-derives the handle.
//
// Test seams:
//   - LoadProposalForTest: bypasses Init's async preflight and seeds the
//     model in phaseReview directly. Covers tests 1-12 of Task 2.
//   - SetNowFnForTest: pins time.Now() to a deterministic value for the
//     CanonicalDropIn timestamp so the rendered diff is stable across runs.
//
// SETUP-06 disposition: the modal surfaces an informational note when an
// external Subsystem is detected (W-01 / RESEARCH OQ-5 — auto-fix is
// deliberately deferred because it would require mutating admin-owned
// /etc/ssh/sshd_config, not just the drop-in this tool owns end-to-end).
//
// CI invariants: this package issues zero direct subprocess calls (all
// shell-out routes through the sysops seam via the txn batch — see
// scripts/check-no-exec-outside-sysops.sh). The SAFE-05 unified-diff
// renderer uses github.com/aymanbagabas/go-udiff promoted to a direct dep
// in plan 03-06 Task 1.
package applysetup

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"github.com/aymanbagabas/go-udiff"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// DropInPath is the canonical drop-in destination (D-07 / D-09 step 3).
// The tool owns this file end-to-end; admins are warned not to edit by hand.
const DropInPath = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"

// BackupDir is where the WriteSshdDropIn step deposits the prior file
// before overwriting (SAFE-03 / D-09 step 2). Created via ops.MkdirAll
// inside startApply (T-03-06-06) before the txn batch runs.
const BackupDir = "/var/lib/sftp-jailer/backups"

// AutoPopDelay is how long the modal lingers in phaseDone before
// auto-popping back to the doctor screen (mirrors observerun's M-OBSERVE
// constant for UX consistency).
const AutoPopDelay = 500 * time.Millisecond

// phase tracks the modal's state-machine position. Rendered in View.
type phase int

const (
	phasePreflight phase = iota
	phaseReview
	phaseEditingRoot
	phaseRePreflight
	phaseApplying
	phaseDone
	phaseError
)

// Model is the M-APPLY-SETUP Bubble Tea v2 model. Constructed via New and
// pushed onto the nav stack from the doctor screen's [A] action. Single-use:
// push, run, auto-pop on success / Esc-back on error.
type Model struct {
	ops sysops.SystemOps

	// preflight inputs / outputs
	proposedRoot       string
	ti                 textinput.Model
	currentBytes       []byte
	proposedBytes      []byte
	violations         []chrootcheck.Violation
	externalSftpServer bool

	// SAFE-05 diff
	diffText string
	diffVP   viewport.Model

	// runtime state
	phase     phase
	errInline string
	errFatal  bool
	spinner   spinner.Model
	toast     widgets.Toast

	// test seams
	nowFn func() time.Time
	keys  KeyMap
}

// preflightLoadedMsg carries the result of the asynchronous preflight load
// from Init's tea.Cmd back into Update.
type preflightLoadedMsg struct {
	proposedRoot       string
	currentBytes       []byte
	violations         []chrootcheck.Violation
	externalSftpServer bool
	err                error
}

// rePreflightLoadedMsg carries the result of the W-05 re-walk after the
// admin edited the chroot root. Only the violations slice is updated;
// proposedBytes / diffText were already re-rendered synchronously when the
// admin pressed Enter on the new root.
type rePreflightLoadedMsg struct {
	violations []chrootcheck.Violation
	err        error
}

// applyDoneMsg carries the txn.Tx.Apply outcome from the off-loop goroutine
// back into Update. err == nil → success → phaseDone; err != nil → rolled
// back → phaseError + Critical errInline.
type applyDoneMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that fires AutoPopDelay after a
// successful apply, telling Update to emit nav.PopCmd + the success toast.
type autoPopMsg struct{}

// New constructs the modal seeded with the default chroot root the doctor
// service exposes (typically /srv/sftp-jailer). The textinput is pre-filled
// so admins who don't want to edit just press 'a'.
func New(ops sysops.SystemOps, defaultChrootRoot string) *Model {
	ti := textinput.New()
	ti.Placeholder = defaultChrootRoot
	ti.SetValue(defaultChrootRoot)
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	vp := viewport.New(viewport.WithWidth(80), viewport.WithHeight(12))
	return &Model{
		ops:          ops,
		proposedRoot: defaultChrootRoot,
		ti:           ti,
		spinner:      sp,
		diffVP:       vp,
		phase:        phasePreflight,
		nowFn:        time.Now,
		keys:         DefaultKeyMap(),
	}
}

// SetNowFnForTest pins the timestamp source for the CanonicalDropIn render.
// Tests call this BEFORE LoadProposalForTest so the diff bytes are stable.
func (m *Model) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }

// LoadProposalForTest seeds the model in phaseReview as if preflight had
// just completed. Bypasses Init's async tea.Cmd and the real chrootcheck /
// sshdcfg parse calls. Used by tests 1-12 of Task 2 to drive the modal's
// state machine deterministically.
func (m *Model) LoadProposalForTest(currentBytes []byte, root string, violations []chrootcheck.Violation, externalSftpServer bool) {
	m.currentBytes = currentBytes
	m.proposedRoot = root
	m.ti.SetValue(root)
	m.violations = violations
	m.externalSftpServer = externalSftpServer
	m.proposedBytes = sshdcfg.CanonicalDropIn(root, m.nowFn())
	m.diffText = unified(string(m.currentBytes), string(m.proposedBytes))
	m.diffVP.SetContent(m.diffText)
	m.phase = phaseReview
}

// PhaseForTest exposes the unexported phase for assertions. Test-only.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// Phase constants exported under the For-Test suffix so tests can reference
// the state-machine values without leaking the private phase type.
const (
	PhasePreflightForTest   = int(phasePreflight)
	PhaseReviewForTest      = int(phaseReview)
	PhaseEditingRootForTest = int(phaseEditingRoot)
	PhaseRePreflightForTest = int(phaseRePreflight)
	PhaseApplyingForTest    = int(phaseApplying)
	PhaseDoneForTest        = int(phaseDone)
	PhaseErrorForTest       = int(phaseError)
)

// ProposedRootForTest exposes the current proposedRoot for assertions.
func (m *Model) ProposedRootForTest() string { return m.proposedRoot }

// ProposedBytesForTest exposes the current proposedBytes for assertions
// (in particular, the W-05 re-render-on-edit assertion that the new bytes
// reference the new root via /<root>/%u).
func (m *Model) ProposedBytesForTest() []byte { return m.proposedBytes }

// ViolationsForTest exposes the current violations slice for assertions.
func (m *Model) ViolationsForTest() []chrootcheck.Violation { return m.violations }

// ErrInlineForTest exposes the inline error string for assertions.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// FeedRePreflightForTest delivers a synthesized rePreflightLoadedMsg to
// Update without spinning up the real off-loop tea.Cmd. Used by tests 7+8
// to script the violations-found / clean-root branches.
func (m *Model) FeedRePreflightForTest(violations []chrootcheck.Violation, err error) {
	m.Update(rePreflightLoadedMsg{violations: violations, err: err})
}

// FeedApplyDoneForTest delivers a synthesized applyDoneMsg to Update.
// Used by tests 11+12 to script the success / failure branches.
func (m *Model) FeedApplyDoneForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(applyDoneMsg{err: err})
}

// KeyMap describes the modal's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Cancel nav.KeyBinding
	Edit   nav.KeyBinding
	Apply  nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-APPLY-SETUP bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel: nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Edit:   nav.KeyBinding{Keys: []string{"e"}, Help: "edit root"},
		Apply:  nav.KeyBinding{Keys: []string{"a"}, Help: "apply"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding { return []nav.KeyBinding{k.Cancel, k.Edit, k.Apply} }

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Cancel, k.Edit, k.Apply}}
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "apply canonical config" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the chroot-root textinput
// is focused so the root App forwards every key (including 'q', 'a', '/')
// into the input rather than acting on global bindings.
func (m *Model) WantsRawKeys() bool { return m.phase == phaseEditingRoot }

// Init starts the spinner ticker and the asynchronous preflight load. In
// unit tests where ops is nil, the test seams (LoadProposalForTest +
// FeedRePreflightForTest + FeedApplyDoneForTest) drive the model directly.
func (m *Model) Init() tea.Cmd {
	tickCmd := func() tea.Msg { return m.spinner.Tick() }
	if m.ops == nil {
		return tickCmd
	}
	ops := m.ops
	return tea.Batch(
		tickCmd,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return runPreflight(ctx, ops)
		},
	)
}

// runPreflight performs the synchronous preflight: parse existing drop-in
// for ChrootDirectory extraction (D-08), walk the chroot chain, check for
// external sftp-server (SETUP-06). Returns a preflightLoadedMsg.
func runPreflight(ctx context.Context, ops sysops.SystemOps) preflightLoadedMsg {
	var current []byte
	var root string
	if b, err := ops.ReadFile(ctx, DropInPath); err == nil {
		current = b
		d, _ := sshdcfg.ParseDropIn(b)
		for _, mb := range d.Matches {
			for _, dir := range mb.Body {
				if dir.Keyword == "chrootdirectory" {
					root = stripPercentSuffix(dir.Value)
					break
				}
			}
			if root != "" {
				break
			}
		}
	}
	if root == "" {
		root = "/srv/sftp-jailer"
	}
	violations, err := chrootcheck.WalkRoot(ctx, ops, root)
	if err != nil {
		return preflightLoadedMsg{err: err}
	}
	external := false
	if cfg, cerr := ops.SshdDumpConfig(ctx); cerr == nil {
		for _, v := range cfg["subsystem"] {
			if strings.Contains(v, "sftp /usr/lib/openssh/sftp-server") {
				external = true
				break
			}
		}
	}
	return preflightLoadedMsg{
		proposedRoot:       root,
		currentBytes:       current,
		violations:         violations,
		externalSftpServer: external,
	}
}

// runRePreflight (W-05) re-walks the chroot chain against a NEW root the
// admin chose in the edit-root flow. Returns just the new violations slice
// — the diff / proposedBytes were already updated synchronously in
// handleKey before this Cmd was scheduled.
func runRePreflight(ctx context.Context, ops sysops.SystemOps, newRoot string) rePreflightLoadedMsg {
	v, err := chrootcheck.WalkRoot(ctx, ops, newRoot)
	return rePreflightLoadedMsg{violations: v, err: err}
}

// stripPercentSuffix peels the per-user expansion suffix from a parsed
// ChrootDirectory value. sshd accepts /<root>/%u or /<root>/%h or a bare
// directory; we want the literal path portion for the textinput.
func stripPercentSuffix(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "/%u")
	v = strings.TrimSuffix(v, "/%h")
	return strings.TrimRight(v, "/")
}

// unified produces the SAFE-05 unified diff between the current drop-in
// bytes and the proposed canonical bytes. Empty current → all-additions
// diff; equal bytes → an explanatory "no changes" string.
func unified(oldStr, newStr string) string {
	edits := udiff.Strings(oldStr, newStr)
	u, err := udiff.ToUnified(DropInPath+".old", DropInPath+".new", oldStr, edits, 3)
	if err != nil {
		return fmt.Sprintf("(diff error: %v)", err)
	}
	if u == "" {
		return "(no changes — existing drop-in already canonical)"
	}
	return u
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over the modal's seven message types +
// keypress routing across phases.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case preflightLoadedMsg:
		if msg.err != nil {
			m.errInline = "preflight error: " + msg.err.Error()
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		m.proposedRoot = msg.proposedRoot
		m.ti.SetValue(msg.proposedRoot)
		m.currentBytes = msg.currentBytes
		m.violations = msg.violations
		m.externalSftpServer = msg.externalSftpServer
		m.proposedBytes = sshdcfg.CanonicalDropIn(msg.proposedRoot, m.nowFn())
		m.diffText = unified(string(m.currentBytes), string(m.proposedBytes))
		m.diffVP.SetContent(m.diffText)
		m.phase = phaseReview
		return m, nil

	case rePreflightLoadedMsg:
		// W-05: violations now reflect the new root; allow Apply if clean.
		if msg.err != nil {
			m.errInline = "re-preflight error: " + msg.err.Error()
			m.errFatal = false // recoverable — admin can edit root again
			m.phase = phaseError
			return m, nil
		}
		m.violations = msg.violations
		m.phase = phaseReview
		return m, nil

	case applyDoneMsg:
		if msg.err != nil {
			m.errInline = "apply failed (rolled back): " + msg.err.Error()
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		m.phase = phaseDone
		return m, tea.Tick(AutoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case autoPopMsg:
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("canonical config applied")
		return m, tea.Batch(nav.PopCmd(), flashCmd)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	if m.phase == phaseEditingRoot {
		var cmd tea.Cmd
		m.ti, cmd = m.ti.Update(msg)
		return m, cmd
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey routes keypresses based on the current phase. EditingRoot
// captures most keys into the textinput; review/done/error route to
// modal-level actions.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	if m.phase == phaseEditingRoot {
		switch msg.String() {
		case "esc":
			m.phase = phaseReview
			m.errInline = ""
			m.ti.Blur()
			return m, nil
		case "enter":
			newRoot := strings.TrimSpace(m.ti.Value())
			// Empty input keeps the prior root — admins who pressed 'e' but
			// then changed their mind get the same UX as Esc.
			if newRoot == "" {
				m.phase = phaseReview
				m.errInline = ""
				m.ti.Blur()
				return m, nil
			}
			// T-03-06-01: refuse non-absolute paths. Defense in depth alongside
			// sshd -t (D-09 step 4) which would catch a malformed drop-in.
			if !filepath.IsAbs(newRoot) {
				m.errInline = "chroot root must be absolute (e.g. /srv/sftp-jailer)"
				return m, nil
			}
			m.proposedRoot = newRoot
			m.proposedBytes = sshdcfg.CanonicalDropIn(m.proposedRoot, m.nowFn())
			m.diffText = unified(string(m.currentBytes), string(m.proposedBytes))
			m.diffVP.SetContent(m.diffText)
			// W-05: clear stale violations IMMEDIATELY and schedule a
			// re-walk against the new root. Apply is blocked while
			// phaseRePreflight (handleKey gates Apply on phaseReview only).
			m.violations = nil
			m.errInline = ""
			m.phase = phaseRePreflight
			m.ti.Blur()
			ops, root := m.ops, m.proposedRoot
			if ops == nil {
				// Test path: the test will FeedRePreflightForTest manually.
				return m, m.spinner.Tick
			}
			return m, tea.Batch(
				m.spinner.Tick,
				func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					return runRePreflight(ctx, ops, root)
				},
			)
		}
		var cmd tea.Cmd
		m.ti, cmd = m.ti.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "e":
		if m.phase == phaseReview {
			m.phase = phaseEditingRoot
			m.errInline = ""
			// Mirror settings.go's edit-mode placeholder-not-seed pattern:
			// clearing the value + showing the prior root as placeholder
			// avoids append-on-type bugs (textinput.Focus places the cursor
			// at end-of-content, so SetValue(prior) + Focus would extend
			// rather than overwrite when the admin starts typing).
			m.ti.Placeholder = m.proposedRoot
			m.ti.SetValue("")
			cmd := m.ti.Focus()
			return m, cmd
		}
	case "a", "enter":
		// Apply is gated on phaseReview AND no violations. phaseRePreflight
		// (W-05) and phaseEditingRoot are NOT eligible.
		if m.phase == phaseReview && len(m.violations) == 0 {
			return m, m.startApply()
		}
	case "j", "down":
		if m.phase == phaseReview {
			m.diffVP.ScrollDown(1)
		}
	case "k", "up":
		if m.phase == phaseReview {
			m.diffVP.ScrollUp(1)
		}
	}
	return m, nil
}

// startApply transitions to phaseApplying and returns a tea.Cmd that
// (a) ensures the backup directory exists via ops.MkdirAll (T-03-06-06),
// (b) runs the txn.CanonicalApplySetupSteps batch through txn.New(ops).Apply.
// Failure surfaces via applyDoneMsg → phaseError + Critical errInline.
func (m *Model) startApply() tea.Cmd {
	m.phase = phaseApplying
	ops, content, dispatch, now := m.ops, m.proposedBytes, txn.ReloadService, m.nowFn
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// T-03-06-06: ensure backup dir exists. Use typed sysops.MkdirAll
		// (plan 03-01 W-02). Failure here aborts before any sshd write
		// (the txn batch's first step is WriteSshdDropIn which writes the
		// backup into BackupDir; the dir must exist).
		if err := ops.MkdirAll(ctx, BackupDir, 0o700); err != nil {
			return applyDoneMsg{err: fmt.Errorf("ensure backup dir: %w", err)}
		}
		steps := txn.CanonicalApplySetupSteps(DropInPath, BackupDir, content, dispatch, now)
		tx := txn.New(ops)
		return applyDoneMsg{err: tx.Apply(ctx, steps)}
	}
}

// View renders the modal body wrapped in the M-OBSERVE-style border.
func (m *Model) View() string {
	var b strings.Builder
	switch m.phase {
	case phasePreflight:
		b.WriteString(m.spinner.View() + " loading proposal…")
	case phaseRePreflight:
		b.WriteString(m.spinner.View() + " re-validating chroot chain against new root " + m.proposedRoot + "…")
	case phaseReview, phaseEditingRoot:
		b.WriteString(styles.Primary.Render("M-APPLY-SETUP — canonical chroot-SFTP drop-in"))
		b.WriteString("\n\nchroot root:\n  ")
		if m.phase == phaseEditingRoot {
			b.WriteString(m.ti.View())
			if m.errInline != "" {
				b.WriteString("\n  " + styles.Critical.Render(m.errInline))
			}
		} else {
			b.WriteString(styles.Dim.Render(m.ti.Value()))
			b.WriteString("  " + styles.Dim.Render("(press 'e' to edit)"))
		}
		if len(m.violations) > 0 {
			b.WriteString("\n\n" + styles.Critical.Render("path-walk violations — fix before apply:"))
			for _, v := range m.violations {
				b.WriteString("\n  • " + v.Reason)
			}
		}
		if m.externalSftpServer {
			b.WriteString("\n\n" + styles.Warn.Render("note: existing Subsystem points at external sftp-server (SETUP-06 advisory only — RESEARCH OQ-5 deferred auto-fix). The canonical Match Group ForceCommand internal-sftp will override at connection time for sftp-jailer-group users; consider removing the external Subsystem entry from /etc/ssh/sshd_config manually."))
		}
		b.WriteString("\n\ndiff (SAFE-05):\n")
		b.WriteString(m.diffText)
		b.WriteString("\n\n[a] apply   [e] edit root   [esc] cancel")
	case phaseApplying:
		b.WriteString(m.spinner.View() + " applying canonical config (backup → write → sshd -t → reload → verify)…")
	case phaseDone:
		b.WriteString(styles.Success.Render("✓ canonical config applied — sshd reloaded."))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n[esc] back to doctor")
	}
	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n" + ts)
	}
	return wrapModal(b.String())
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2). Per
// UI-SPEC line 46 modals carry this border; non-modal screens do not.
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}
