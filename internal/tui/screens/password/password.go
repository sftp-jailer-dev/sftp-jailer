// Package password renders the M-PASSWORD modal — the chained-from-M-NEW-USER
// password-set surface (D-11) AND the standalone-from-S-USERS password-reset
// surface ('p' on a selected row).
//
// FULL IMPLEMENTATION lands in plan 03-07 Task 2. Task 1 ships this skeleton
// (constructor + Mode enum + nav.Screen conformance) so the M-NEW-USER modal
// from Task 1 can already wire `nav.PushCmd(password.New(...))` on submit
// success without the package being absent. Task 2 replaces the skeleton with
// the auto-gen + explicit + OSC 52 + pam_pwquality + chage flow.
package password

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
)

// Mode discriminates the two password-set strategies. Task 2 expands the
// behavior; Task 1 ships only the type so the M-NEW-USER chained-modal push
// site type-checks.
type Mode int

const (
	// AutoGenerateMode draws a strong password via keys.Generate(24) and
	// shows it ONCE in monospace + offers OSC 52 copy. Default mode for the
	// chained-from-M-NEW-USER push.
	AutoGenerateMode Mode = iota
	// ExplicitMode presents two textinputs (password + confirm) for an admin
	// to type a chosen password. pam_pwquality stderr is surfaced inline on
	// rejection.
	ExplicitMode
)

// Model is the M-PASSWORD Bubble Tea v2 model. Task 1 ships a minimal
// nav.Screen-conformant shell; Task 2 expands.
type Model struct {
	ops      sysops.SystemOps
	username string
	mode     Mode
}

// New constructs the modal. Mandatory arg shape is preserved across Task
// 1 (skeleton) and Task 2 (full impl) so M-NEW-USER's push-on-success site
// does not need to change between commits.
func New(ops sysops.SystemOps, username string, mode Mode) *Model {
	return &Model{ops: ops, username: username, mode: mode}
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "set password — " + m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return skeletonKeyMap{} }

// WantsRawKeys implements nav.Screen. Task 2 returns true while in
// ExplicitMode (textinputs focused); Task 1 always returns false.
func (m *Model) WantsRawKeys() bool { return false }

// Init implements nav.Screen.
func (m *Model) Init() tea.Cmd { return nil }

// Update implements nav.Screen — Task 1 only pops on Esc/q so the modal can
// dismiss while the rest of the flow is under construction.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok {
		switch k.String() {
		case "esc", "q":
			return m, nav.PopCmd()
		}
	}
	return m, nil
}

// View implements nav.Screen.
func (m *Model) View() string {
	return "M-PASSWORD skeleton — Task 2 expands; Esc to dismiss."
}

// UsernameForTest exposes the username field for assertions across the
// chained-modal handoff.
func (m *Model) UsernameForTest() string { return m.username }

// ModeForTest exposes the mode field for assertions.
func (m *Model) ModeForTest() Mode { return m.mode }

// skeletonKeyMap is the placeholder nav.KeyMap implementation — Task 2
// replaces with the real KeyMap (c/r/s/space/Enter/Esc bindings).
type skeletonKeyMap struct{}

func (skeletonKeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{{Keys: []string{"esc", "q"}, Help: "back"}}
}

func (skeletonKeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{{Keys: []string{"esc", "q"}, Help: "back"}}}
}
