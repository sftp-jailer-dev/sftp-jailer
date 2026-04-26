// Package password renders the M-PASSWORD modal — the chained-from-M-NEW-USER
// password-set surface (D-11) AND the standalone-from-S-USERS password-reset
// surface ('p' on a selected row).
//
// Two modes:
//
//   - AutoGenerateMode (default): keys.Generate(24) draws a strong password
//     that defeats pam_pwquality minclass=4 hardening (pitfall 7). The
//     password renders ONCE in monospace + offers OSC 52 copy ('c') +
//     regenerate ('r'). The admin presses Enter to submit; the call site
//     wipes m.pw immediately on success (security hygiene per T-03-04-06 +
//     T-03-07-02).
//
//   - ExplicitMode: two textinputs (password + confirm) with match
//     validation BEFORE submit. Switched into via 's' from auto-gen. Useful
//     when admins have a corporate-policy-mandated password they need to
//     set verbatim.
//
// pam_pwquality rejection (B5): chpasswd's stderr is surfaced inline in
// styles.Critical via the *sysops.ChpasswdError typed error from plan 03-01.
// Admin can fix the password and retry without re-entering the modal (Enter
// from phaseError re-runs submit).
//
// chage -d 0 (force-change-next-login, D-13): checkbox defaults OFF with a
// Warn-styled inline helper text explaining the chrooted-SFTP lockout risk
// (pitfall 2 / RH solution 24758). When toggled ON, submit runs Chpasswd
// then Chage in sequence; either failure surfaces inline.
//
// Security invariants (mirrored at the test layer):
//   - Password literal NEVER appears in any log, FakeCall.Args, or process
//     argv. The Fake records "len=N" not the password (plan 03-01 / E3).
//   - m.pw cleared after successful submit so the value doesn't linger in
//     model memory between phaseDone and modal pop.
//
// Test seams:
//   - LoadPasswordForTest(pw): bypasses keys.Generate's RNG so tests pin a
//     deterministic password value for assertion.
//   - FeedSubmitDoneForTest(err): synthesizes a submitDoneMsg for tests
//     that script the chpasswd / chage outcome.
package password

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// generatedPasswordLength is the auto-generate length. 24 chars over the
// 73-char shell-safe set comfortably defeats minclass=4 + dictionary-based
// pwquality checks (cracklib).
const generatedPasswordLength = 24

// AutoPopDelay is how long the modal lingers in phaseDone before
// auto-popping back to the parent screen.
const AutoPopDelay = 500 * time.Millisecond

// Mode discriminates the two password-set strategies.
type Mode int

const (
	// AutoGenerateMode draws a strong password via keys.Generate(24) and
	// shows it ONCE in monospace + offers OSC 52 copy. Default mode for
	// the chained-from-M-NEW-USER push.
	AutoGenerateMode Mode = iota
	// ExplicitMode presents two textinputs (password + confirm) for an
	// admin to type a chosen password. pam_pwquality stderr is surfaced
	// inline on rejection.
	ExplicitMode
)

// phase tracks the modal's state-machine position.
type phase int

const (
	// phaseShowing — auto-gen displayed; admin can c/r/s/Enter/Esc.
	phaseShowing phase = iota
	// phaseExplicit — explicit-mode textinputs focused for typing.
	phaseExplicit
	// phaseSubmitting — chpasswd (+ chage) in flight.
	phaseSubmitting
	// phaseDone — submit succeeded; auto-pop after AutoPopDelay.
	phaseDone
	// phaseError — submit failed (pam_pwquality OR chage); errInline
	// surfaced; Enter retries.
	phaseError
)

// submitDoneMsg carries the chpasswd + (optionally) chage outcome.
type submitDoneMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that pops after a successful submit.
type autoPopMsg struct{}

// Model is the M-PASSWORD Bubble Tea v2 model.
type Model struct {
	ops      sysops.SystemOps
	username string
	mode     Mode

	// Password value held during the auto-gen flow. ALWAYS cleared on
	// successful submit (m.pw = "" in submitDoneMsg{nil} branch). For
	// explicit mode the value lives in the textinputs and is similarly
	// cleared on success.
	pw string

	// Explicit-mode textinputs (only used when mode == ExplicitMode).
	pwTI      textinput.Model
	confirmTI textinput.Model
	pwFocused bool // true = pwTI focused; false = confirmTI focused

	// Force-change checkbox (chage -d 0) — DEFAULT OFF per D-13. Warn-styled
	// helper text below it explains the chrooted-SFTP lockout risk.
	forceChangeChecked bool

	phase     phase
	errInline string
	errFatal  bool
	spinner   spinner.Model
	toast     widgets.Toast
	keys      KeyMap

	// genFn is the password generator seam. Production binds keys.Generate;
	// tests can swap via LoadPasswordForTest to pin a deterministic value.
	genFn func(int) (string, error)
}

// New constructs the modal in the given mode for username. AutoGenerateMode
// draws an initial password immediately (via keys.Generate); ExplicitMode
// stays blank pending admin input.
func New(ops sysops.SystemOps, username string, mode Mode) *Model {
	pwTI := textinput.New()
	pwTI.Prompt = ""
	pwTI.CharLimit = 256
	pwTI.EchoMode = textinput.EchoPassword
	confirmTI := textinput.New()
	confirmTI.Prompt = ""
	confirmTI.CharLimit = 256
	confirmTI.EchoMode = textinput.EchoPassword
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	m := &Model{
		ops:       ops,
		username:  username,
		mode:      mode,
		pwTI:      pwTI,
		confirmTI: confirmTI,
		spinner:   sp,
		keys:      DefaultKeyMap(),
		genFn:     keys.Generate,
	}
	switch mode {
	case AutoGenerateMode:
		m.regenerate()
	case ExplicitMode:
		m.phase = phaseExplicit
		m.pwFocused = true
	}
	return m
}

// regenerate draws a fresh auto-gen password via genFn. On error sets
// phaseError + errInline.
func (m *Model) regenerate() {
	pw, err := m.genFn(generatedPasswordLength)
	if err != nil {
		m.errInline = "password generator failed: " + err.Error()
		m.errFatal = true
		m.phase = phaseError
		return
	}
	m.pw = pw
	m.phase = phaseShowing
}

// LoadPasswordForTest pins the auto-gen password to a known value. Bypasses
// keys.Generate's RNG. Use t.Cleanup to reset between tests if needed.
func (m *Model) LoadPasswordForTest(pw string) {
	m.pw = pw
	m.phase = phaseShowing
	// Lock the seam to a function returning the same pw so subsequent 'r'
	// regenerates also produce the same value (deterministic regen tests
	// can override with their own genFn).
	m.genFn = func(int) (string, error) { return pw, nil }
}

// SetGenFnForTest swaps the password generator seam. Tests use this for
// the regenerate-distinct-output assertion (different value on each call).
func (m *Model) SetGenFnForTest(fn func(int) (string, error)) {
	m.genFn = fn
	if m.mode == AutoGenerateMode && m.phase == phaseShowing {
		m.regenerate()
	}
}

// FeedSubmitDoneForTest delivers a synthesized submitDoneMsg to Update.
func (m *Model) FeedSubmitDoneForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(submitDoneMsg{err: err})
}

// PasswordForTest exposes the currently held auto-gen password for the
// hygiene-clear assertion (test 10).
func (m *Model) PasswordForTest() string { return m.pw }

// PhaseForTest exposes the unexported phase for assertions.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// ForceChangeForTest exposes the checkbox state.
func (m *Model) ForceChangeForTest() bool { return m.forceChangeChecked }

// ErrInlineForTest exposes the inline error string.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// ModeForTest exposes the mode field for assertions.
func (m *Model) ModeForTest() Mode { return m.mode }

// UsernameForTest exposes the username for assertions across the
// chained-modal handoff.
func (m *Model) UsernameForTest() string { return m.username }

// Phase constants exported under the For-Test suffix so tests can reference
// state-machine values without leaking the private phase type.
const (
	PhaseShowingForTest    = int(phaseShowing)
	PhaseExplicitForTest   = int(phaseExplicit)
	PhaseSubmittingForTest = int(phaseSubmitting)
	PhaseDoneForTest       = int(phaseDone)
	PhaseErrorForTest      = int(phaseError)
)

// Title implements nav.Screen.
func (m *Model) Title() string { return "set password — " + m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while in ExplicitMode so the
// root App forwards every key into the textinputs (including 'q', 's', 'c').
func (m *Model) WantsRawKeys() bool {
	return m.mode == ExplicitMode && (m.phase == phaseExplicit)
}

// Init implements nav.Screen.
func (m *Model) Init() tea.Cmd {
	return func() tea.Msg { return m.spinner.Tick() }
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over async messages + per-phase keypress
// routing. Each branch is small.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case submitDoneMsg:
		if msg.err != nil {
			// Surface pam_pwquality stderr verbatim if the error is the typed
			// *sysops.ChpasswdError (T-03-01 errors.As contract); otherwise
			// fall back to the underlying error message. The phase flips to
			// phaseError; admin can press Enter to retry without re-entering
			// the modal (state preserved).
			var cerr *sysops.ChpasswdError
			if errors.As(msg.err, &cerr) {
				m.errInline = "pam_pwquality rejected: " + strings.TrimSpace(string(cerr.Stderr))
			} else {
				m.errInline = "set password failed: " + msg.err.Error()
			}
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		// Hygiene-clear the password literal from model memory immediately.
		// The OSC 52 clipboard already holds it (admin's choice); we don't
		// need to keep an extra copy here.
		m.pw = ""
		m.pwTI.SetValue("")
		m.confirmTI.SetValue("")
		m.phase = phaseDone
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("password set for " + m.username)
		return m, tea.Batch(
			flashCmd,
			tea.Tick(AutoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} }),
		)

	case autoPopMsg:
		return m, nav.PopCmd()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	if m.phase == phaseExplicit {
		var cmd tea.Cmd
		if m.pwFocused {
			m.pwTI, cmd = m.pwTI.Update(msg)
		} else {
			m.confirmTI, cmd = m.confirmTI.Update(msg)
		}
		return m, cmd
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches per phase.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch m.phase {
	case phaseShowing:
		return m.handleShowingKey(msg)
	case phaseExplicit:
		return m.handleExplicitKey(msg)
	case phaseError:
		return m.handleErrorKey(msg)
	case phaseSubmitting, phaseDone:
		// Spinner / done phases ignore key input — Esc still backs out of
		// done so admins can leave fast.
		if msg.String() == "esc" || msg.String() == "q" {
			return m, nav.PopCmd()
		}
		return m, nil
	}
	return m, nil
}

// handleShowingKey handles auto-gen mode key bindings.
func (m *Model) handleShowingKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "c":
		// OSC 52 clipboard copy + toast Flash. tea.SetClipboard is the
		// bubbletea v2 path for OSC 52 emission.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("copied password via OSC 52")
		return m, tea.Batch(tea.SetClipboard(m.pw), flashCmd)
	case "r":
		m.regenerate()
		return m, nil
	case "s":
		// Switch to explicit mode. Don't carry the auto-gen pw across.
		m.mode = ExplicitMode
		m.pw = ""
		m.phase = phaseExplicit
		m.pwFocused = true
		return m, m.pwTI.Focus()
	case " ", "space", "f":
		m.forceChangeChecked = !m.forceChangeChecked
		return m, nil
	case "enter":
		return m, m.attemptSubmit()
	}
	return m, nil
}

// handleExplicitKey handles explicit mode key bindings. tab cycles between
// the two textinputs; Enter validates match + length and submits.
func (m *Model) handleExplicitKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m, nav.PopCmd()
	case "tab":
		m.pwFocused = !m.pwFocused
		if m.pwFocused {
			m.confirmTI.Blur()
			return m, m.pwTI.Focus()
		}
		m.pwTI.Blur()
		return m, m.confirmTI.Focus()
	case "enter":
		// Validate match + minimum length BEFORE submit. pam_pwquality
		// would reject too-short passwords on the box but the typed
		// validation surface gives the admin a fast local error before
		// the subprocess round-trip.
		pw := m.pwTI.Value()
		confirm := m.confirmTI.Value()
		if pw != confirm {
			m.errInline = "passwords do not match"
			m.errFatal = false
			return m, nil
		}
		if len(pw) < 8 {
			m.errInline = "password too short — min 8 chars"
			m.errFatal = false
			return m, nil
		}
		m.pw = pw
		return m, m.attemptSubmit()
	}
	var cmd tea.Cmd
	if m.pwFocused {
		m.pwTI, cmd = m.pwTI.Update(msg)
	} else {
		m.confirmTI, cmd = m.confirmTI.Update(msg)
	}
	return m, cmd
}

// handleErrorKey handles the post-error retry surface. Enter re-attempts
// submit with the current pw; Esc backs out.
func (m *Model) handleErrorKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "enter":
		m.errInline = ""
		m.errFatal = false
		// For auto-gen mode, the pw is still in m.pw. For explicit mode it
		// was carried over in m.pw before phaseSubmitting (attemptSubmit
		// captured it). Either way, re-running attemptSubmit is correct.
		return m, m.attemptSubmit()
	case "r":
		// Regenerate from error in auto-gen mode (admin saw a pwquality
		// reject and wants a fresh draw rather than a verbatim retry).
		if m.mode == AutoGenerateMode {
			m.regenerate()
			m.errInline = ""
			m.errFatal = false
			return m, nil
		}
	}
	return m, nil
}

// attemptSubmit returns a tea.Cmd that runs Chpasswd (+ optionally Chage)
// off the main loop. Empty pw aborts with errInline.
func (m *Model) attemptSubmit() tea.Cmd {
	pw := m.pw
	if strings.TrimSpace(pw) == "" {
		m.errInline = "no password to submit — regenerate or type one"
		m.errFatal = false
		return nil
	}
	m.phase = phaseSubmitting
	ops, user, force := m.ops, m.username, m.forceChangeChecked
	if ops == nil {
		// Test path: the test will FeedSubmitDoneForTest manually.
		return m.spinner.Tick
	}
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := ops.Chpasswd(ctx, user, pw); err != nil {
				return submitDoneMsg{err: err}
			}
			if force {
				if err := ops.Chage(ctx, user, sysops.ChageOpts{LastDay: 0}); err != nil {
					return submitDoneMsg{err: fmt.Errorf("chpasswd ok but chage failed: %w", err)}
				}
			}
			return submitDoneMsg{err: nil}
		},
	)
}

// View renders the modal body wrapped in the M-OBSERVE-style border.
func (m *Model) View() string {
	var b strings.Builder
	switch m.phase {
	case phaseShowing:
		b.WriteString(styles.Primary.Render("M-PASSWORD — " + m.username))
		b.WriteString("\n\n")
		b.WriteString("generated password (display once):\n  ")
		b.WriteString(monoFont(m.pw))
		b.WriteString("\n\n")
		b.WriteString(m.checkboxRow())
		if m.forceChangeChecked {
			b.WriteString("\n  ")
			b.WriteString(styles.Warn.Render(
				"⚠ chrooted SFTP-only users have no shell to host the change-password prompt — enabling this will lock them out on next connection per pitfall 2 / RH solution 24758. Use only with an OOB reset workflow."))
		}
		b.WriteString("\n\n[c] copy   [r] regenerate   [s] switch to explicit   [enter] submit   [esc] cancel")
	case phaseExplicit:
		b.WriteString(styles.Primary.Render("M-PASSWORD (explicit) — " + m.username))
		b.WriteString("\n\npassword:\n  " + m.pwTI.View())
		b.WriteString("\n\nconfirm:\n  " + m.confirmTI.View())
		if m.errInline != "" {
			b.WriteString("\n  " + styles.Critical.Render(m.errInline))
		}
		b.WriteString("\n\n")
		b.WriteString(m.checkboxRow())
		if m.forceChangeChecked {
			b.WriteString("\n  ")
			b.WriteString(styles.Warn.Render(
				"⚠ chrooted SFTP-only users have no shell to host the change-password prompt — enabling this will lock them out on next connection per pitfall 2 / RH solution 24758. Use only with an OOB reset workflow."))
		}
		b.WriteString("\n\n[tab] switch field   [enter] submit   [esc] cancel")
	case phaseSubmitting:
		b.WriteString(m.spinner.View() + " setting password (chpasswd → chage)…")
	case phaseDone:
		b.WriteString(styles.Success.Render("✓ password set for " + m.username))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n[enter] retry   [r] regenerate (auto-gen)   [esc] back")
	}
	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n" + ts)
	}
	return wrapModal(b.String())
}

// checkboxRow renders the [✓]/[ ] line for the force-change checkbox.
func (m *Model) checkboxRow() string {
	box := "[ ]"
	if m.forceChangeChecked {
		box = "[✓]"
	}
	return box + " Force change next login (chage -d 0)  " +
		styles.Dim.Render("[space] toggle")
}

// monoFont applies a faint border around the password block so it visually
// stands out from prose. lipgloss does not have a true monospace toggle in
// v2 — every terminal renders Go strings as monospace anyway — but the
// surrounding block makes the value easy to copy by eye.
func monoFont(s string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 1).
		Render(s)
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2).
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// KeyMap describes the modal's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Cancel     nav.KeyBinding
	Copy       nav.KeyBinding
	Regenerate nav.KeyBinding
	Switch     nav.KeyBinding
	Toggle     nav.KeyBinding
	Submit     nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-PASSWORD bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel:     nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Copy:       nav.KeyBinding{Keys: []string{"c"}, Help: "copy via OSC 52"},
		Regenerate: nav.KeyBinding{Keys: []string{"r"}, Help: "regenerate"},
		Switch:     nav.KeyBinding{Keys: []string{"s"}, Help: "switch to explicit"},
		Toggle:     nav.KeyBinding{Keys: []string{"space", "f"}, Help: "toggle force-change"},
		Submit:     nav.KeyBinding{Keys: []string{"enter"}, Help: "submit"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Copy, k.Regenerate, k.Submit}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Copy, k.Regenerate},
		{k.Switch, k.Toggle, k.Submit},
	}
}
