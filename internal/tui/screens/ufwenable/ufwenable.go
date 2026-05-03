// Package ufwenable is the M-UFW-ENABLE modal (FW-11 Plan 08-04).
// It runs `ufw --force enable` via sysops.EnableUFW after a confirm-
// only YES gate - NOT under the SAFE-04 timer (D-08 boundary).
//
// State machine:
//
//	phasePreFlight - Init runs ShowUFWAdded + SSH_CONNECTION check async.
//	phaseConfirm   - pre-flight pass; textinput YES gate visible.
//	phaseApplying  - sysops.EnableUFW in flight.
//	phaseDone      - success; tea.Tick(500ms) -> nav.PopCmd.
//	phaseError     - hard-block (no SSH allow rule) OR apply failure.
//
// D-08 enforcement: NO internal/revert import, NO internal/txn import.
// applyCmd calls ops.EnableUFW(ctx) DIRECTLY (P3-A SAFE-04 boundary).
package ufwenable

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// autoPopDelay is how long phaseDone lingers before the modal pops.
//
// Previously 500ms - too quick for the operator to register the green
// success line. Bumped to 1500ms so '✓ ufw enabled - rule enforcement
// active.' is clearly visible before returning to the doctor screen.
const autoPopDelay = 1500 * time.Millisecond

// phase tracks the M-UFW-ENABLE state-machine position.
type phase int

const (
	phasePreFlight phase = iota // async ShowUFWAdded + SSH_CONNECTION
	phaseConfirm                // pre-flight pass; show YES textinput
	phaseApplying               // sysops.EnableUFW in flight
	phaseDone                   // success; auto-pop after autoPopDelay
	phaseError                  // hard-block OR apply failure
)

// preFlightDoneMsg carries the pre-flight result back to Update.
type preFlightDoneMsg struct {
	err             error
	sshAllowPresent bool
	matchedAs       string
	onSSHSession    bool
}

// applyDoneMsg carries the EnableUFW outcome back to Update.
type applyDoneMsg struct {
	err error
}

// autoPopMsg pops the modal after phaseDone lingers for autoPopDelay.
type autoPopMsg struct{}

// Model is the M-UFW-ENABLE Bubble Tea v2 model.
type Model struct {
	ops sysops.SystemOps

	// pre-flight result
	sshAllowPresent bool
	matchedAs       string // "tcp/22" / "OpenSSH application profile" / ""
	onSSHSession    bool

	// input
	yesInput  textinput.Model
	inlineErr string

	// animation
	spinner spinner.Model

	// state
	phase    phase
	applyErr error

	keys KeyMap
}

// New constructs M-UFW-ENABLE. ops may be nil in unit-test paths.
func New(ops sysops.SystemOps) *Model {
	ti := textinput.New()
	ti.Placeholder = "Type YES (uppercase) and press Enter"
	ti.CharLimit = 8
	ti.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary

	return &Model{
		ops:      ops,
		phase:    phasePreFlight,
		yesInput: ti,
		spinner:  sp,
		keys:     DefaultKeyMap(),
	}
}

// ---- nav.Screen interface ---------------------------------------------------

// Title implements nav.Screen.
func (m *Model) Title() string { return "enable ufw" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen. Returns true while phaseConfirm
// so the YES textinput receives every keypress (including 'r', 'a')
// rather than triggering global nav bindings. See newuser.go:280-285
// precedent for the textinput-while-focused pattern.
func (m *Model) WantsRawKeys() bool {
	return m.phase == phaseConfirm
}

// Init implements nav.Screen. Runs the async pre-flight on entry.
// Returns tea.Batch(spinner.Tick, asyncPreFlightCmd) so the spinner
// animates during the pre-flight wait (Pitfall 2: Init must Batch the
// spinner Tick or the animation never starts).
func (m *Model) Init() tea.Cmd {
	if m.ops == nil {
		return func() tea.Msg { return preFlightDoneMsg{} }
	}
	ops := m.ops
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := ops.ShowUFWAdded(ctx)
			if err != nil {
				return preFlightDoneMsg{err: err}
			}
			rules := firewall.ParseUFWShowAdded(out)
			return preFlightDoneMsg{
				sshAllowPresent: firewall.SSHAllowPresent(rules),
				matchedAs:       firewall.SSHAllowMatchedAs(rules),
				onSSHSession:    os.Getenv("SSH_CONNECTION") != "",
			}
		},
	)
}

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch v := msg.(type) {
	case spinner.TickMsg:
		if m.phase == phasePreFlight || m.phase == phaseApplying {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(v)
			return m, cmd
		}

	case preFlightDoneMsg:
		if v.err != nil {
			// Pre-flight exec error: treat as hard-block.
			m.phase = phaseError
			m.applyErr = fmt.Errorf("pre-flight failed: %w", v.err)
			return m, nil
		}
		m.sshAllowPresent = v.sshAllowPresent
		m.matchedAs = v.matchedAs
		m.onSSHSession = v.onSSHSession
		if !v.sshAllowPresent {
			// Hard-block: no SSH allow rule found.
			m.phase = phaseError
		} else {
			m.phase = phaseConfirm
		}
		return m, nil

	case applyDoneMsg:
		if v.err != nil {
			m.phase = phaseError
			m.applyErr = v.err
			return m, nil
		}
		m.phase = phaseDone
		return m, tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case autoPopMsg:
		return m, nav.PopCmd()

	case tea.KeyPressMsg:
		return m.handleKey(v)
	}

	return m, nil
}

// handleKey routes keypresses based on the current phase.
func (m *Model) handleKey(v tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	s := v.String()
	switch m.phase {
	case phaseConfirm:
		switch s {
		case "esc":
			return m, nav.PopCmd()
		case "enter":
			val := strings.TrimSpace(m.yesInput.Value())
			// Pitfall 3: exact match, NOT strings.EqualFold.
			// Pitfall 6: TrimSpace tolerates trailing whitespace / newline.
			if val == "YES" {
				m.phase = phaseApplying
				m.inlineErr = ""
				return m, m.applyCmd()
			}
			m.inlineErr = "type YES exactly (uppercase) to confirm"
			return m, nil
		default:
			// Forward all other keys to the textinput.
			var cmd tea.Cmd
			m.yesInput, cmd = m.yesInput.Update(v)
			return m, cmd
		}

	case phaseError:
		switch s {
		case "esc":
			return m, nav.PopCmd()
		case "r":
			if !m.sshAllowPresent {
				// [r] chain: push addrule with port 22/tcp prefilled,
				// AutoRevert=false (D-13), and lockedUser="root".
				//
				// Compensator `ufw delete N + ufw reload` would fire
				// mid-ufw-enable flow and could cut SSH session, hence
				// AutoRevert=false.
				//
				// lockedUser fallback to "root": the SSH-bootstrap rule is
				// not tied to any sftp-jailer user. ufwcomment.Encode("")
				// rejects with ErrInvalidUser; "root" matches the
				// [a-z_][a-z0-9_-]{0,31} grammar and the bootstrap rule
				// gets attributed to root in the FW-08 user-IP mirror,
				// which matches its operational ownership (system rule,
				// not per-user). Same fallback applies to any future
				// firewall-rule entry point where no human user is in scope.
				screen := firewallrule.NewWithOptions(
					m.ops, nil, "22", "root",
					firewallrule.Options{AutoRevert: false, PrefillCIDR: "0.0.0.0/0"})
				return m, nav.PushCmd(screen)
			}
		}
	}
	return m, nil
}

// applyCmd runs `ufw --force enable` DIRECTLY via sysops (D-08 / P3-A):
//
// Why no txn batch (D-08): `ufw enable` exits the SAFE-04 contract.
// The compensator `ufw disable` would leave the system in a
// rules-present-but-no-enforcement state that did not exist before
// the mutation. Wrapping in txn.New(ops).Apply would imply rollback
// safety that does not exist. The mutation is invoked directly via
// sysops.EnableUFW(ctx) per STATE.md "v1.3 architectural commitments
// locked at roadmap time" (P3-A SAFE-04 boundary).
func (m *Model) applyCmd() tea.Cmd {
	if m.ops == nil {
		return func() tea.Msg {
			return applyDoneMsg{err: errors.New("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return applyDoneMsg{err: ops.EnableUFW(ctx)}
	}
}

// wrapModal wraps content in a normalBorder box with padding.
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// View renders the modal per phase.
func (m *Model) View() string {
	title := styles.Primary.Render("Enable ufw")
	switch m.phase {
	case phasePreFlight:
		body := title + "\n\n" +
			m.spinner.View() + " " + styles.Dim.Render("checking pre-flight conditions...")
		return wrapModal(body)

	case phaseConfirm:
		// SSH allow rule line.
		sshLine := styles.Success.Render("✓ SSH allow rule found: " + m.matchedAs)

		// SSH session detection.
		var sshSessionLine string
		if m.onSSHSession {
			sshSessionLine = styles.Warn.Render("⚠ active SSH session detected (SSH_CONNECTION set)")
		} else {
			sshSessionLine = styles.Dim.Render("no active SSH session detected")
		}

		// Consequences blurb (per UI-SPEC line 387).
		blurb := styles.Dim.Render(
			"Running `ufw --force enable` will activate all pending rules immediately.\n" +
				"This action cannot be automatically reversed (not under SAFE-04 timer coverage).\n" +
				"Confirm you have a valid SSH allow rule before proceeding.")

		body := title + "\n\n" +
			sshLine + "\n" +
			sshSessionLine + "\n\n" +
			blurb + "\n\n" +
			"Type YES (uppercase) and press Enter:\n" +
			m.yesInput.View()

		if m.inlineErr != "" {
			body += "\n\n" + styles.Critical.Render(m.inlineErr)
		}
		body += "\n\n" + styles.Dim.Render("[esc] cancel")
		return wrapModal(body)

	case phaseApplying:
		body := title + "\n\n" +
			m.spinner.View() + " " + styles.Dim.Render("enabling ufw...")
		return wrapModal(body)

	case phaseDone:
		body := title + "\n\n" +
			styles.Success.Render("✓ ufw enabled - rule enforcement active.")
		return wrapModal(body)

	case phaseError:
		if !m.sshAllowPresent {
			// Hard-block: no SSH allow rule.
			body := title + "\n\n" +
				styles.Critical.Render("✗ no SSH allow rule found") + "\n\n" +
				styles.Critical.Render("Cannot enable ufw: no SSH allow rule found.") + "\n\n" +
				"[r] Add SSH allow rule (port 22/tcp)   [esc] cancel"
			return wrapModal(body)
		}
		// Apply failure or pre-flight exec error.
		errMsg := ""
		if m.applyErr != nil {
			errMsg = m.applyErr.Error()
		}
		body := title + "\n\n" +
			styles.Critical.Render("failed to enable ufw: "+errMsg) + "\n\n" +
			styles.Dim.Render("[esc] back to doctor")
		return wrapModal(body)
	}
	return ""
}

// ---- KeyMap ----------------------------------------------------------------

// KeyMap describes the ufwenable modal's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Cancel  nav.KeyBinding
	AddRule nav.KeyBinding
}

// DefaultKeyMap returns the canonical ufwenable bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel:  nav.KeyBinding{Keys: []string{"esc"}, Help: "cancel"},
		AddRule: nav.KeyBinding{Keys: []string{"r"}, Help: "add SSH allow rule"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.AddRule}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Cancel, k.AddRule}}
}

// ---- Test seam exports ----------------------------------------------------

// Phase int constants for test assertions.
const (
	PhasePreFlightForTest = int(phasePreFlight)
	PhaseConfirmForTest   = int(phaseConfirm)
	PhaseApplyingForTest  = int(phaseApplying)
	PhaseDoneForTest      = int(phaseDone)
	PhaseErrorForTest     = int(phaseError)
)

// PhaseForTest exposes the current phase as int.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// FeedPreFlightDoneMsgForTest delivers a synthesized preFlightDoneMsg to Update.
func (m *Model) FeedPreFlightDoneMsgForTest(allowPresent, onSSH bool, matchedAs string) (nav.Screen, tea.Cmd) {
	return m.Update(preFlightDoneMsg{
		sshAllowPresent: allowPresent,
		matchedAs:       matchedAs,
		onSSHSession:    onSSH,
	})
}

// FeedApplyDoneMsgForTest delivers a synthesized applyDoneMsg to Update.
func (m *Model) FeedApplyDoneMsgForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(applyDoneMsg{err: err})
}

// SetYesInputValueForTest seeds the textinput value for YES-gate drive.
func (m *Model) SetYesInputValueForTest(s string) {
	m.yesInput.SetValue(s)
}

// InlineErrForTest exposes the inline error string.
func (m *Model) InlineErrForTest() string { return m.inlineErr }
