// Package splash implements TUI-08: the launch splash screen that shows the
// ANSI-rendered sftp-jailer logo, version, and project URL for ~1 second,
// then transitions to the home screen. The same Model is re-used (via
// NewModal) as the About overlay reached from the help menu — the modal
// variant does NOT auto-dismiss on the 1s tick.
//
// The logo is a compile-time artifact produced by scripts/render-logo.sh
// (chafa). Four variants are embedded; pickVariant selects one at runtime
// based on the terminal's detected color profile (H1 fix — uses the
// canonical github.com/charmbracelet/colorprofile package; Lip Gloss v2
// does NOT expose a DetectColorProfile function at v2.0.3).
package splash

import (
	_ "embed"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
)

//go:embed embedded/logo-truecolor.ans
var logoTruecolor string

//go:embed embedded/logo-256.ans
var logo256 string

//go:embed embedded/logo-16.ans
var logo16 string

//go:embed embedded/logo-ascii.txt
var logoASCII string

// Model renders the splash (or About) screen.
type Model struct {
	logo       string
	version    string
	projectURL string
	// modal is true when this splash is shown as a modal overlay (About).
	// In modal mode the 1s tick does not auto-dismiss and a keypress pops
	// the screen instead of replacing it with home.
	modal bool
	// width/height track the last known terminal dimensions for centering
	// (Phase 1 doesn't center — placeholder for Phase 2 polish).
	width  int
	height int
}

type tickMsg struct{}

// HomePlaceholder is the marker screen emitted through nav.ReplaceMsg when
// the splash wants to transition to home. The App layer's placeholder
// resolver (registered at startup) recognizes this type and constructs the
// real home.Model. This is the concrete DI seam (C4 fix) that keeps splash
// and home decoupled — splash does not import home, home does not import
// splash, and the App is the one place that imports both.
type HomePlaceholder struct {
	Version    string
	ProjectURL string
}

// The HomePlaceholder type satisfies nav.Screen with no-op methods; it is
// never actually rendered because the placeholder resolver swaps it out
// before the next View() is called.

// Init returns nil — the placeholder is never the live top-of-stack.
func (*HomePlaceholder) Init() tea.Cmd { return nil }

// Update returns the placeholder unchanged — never reached in practice.
func (p *HomePlaceholder) Update(tea.Msg) (nav.Screen, tea.Cmd) { return p, nil }

// View returns an empty string — never reached in practice.
func (*HomePlaceholder) View() string { return "" }

// Title returns "home" for debugging / test purposes.
func (*HomePlaceholder) Title() string { return "home-placeholder" }

// KeyMap returns an empty KeyMap.
func (*HomePlaceholder) KeyMap() nav.KeyMap { return emptyKeyMap{} }

// WantsRawKeys returns false.
func (*HomePlaceholder) WantsRawKeys() bool { return false }

// New constructs a splash screen that auto-dismisses after 1s.
func New(version, projectURL string) *Model {
	return &Model{
		logo:       pickVariant(),
		version:    version,
		projectURL: projectURL,
	}
}

// NewModal constructs a splash screen suitable for the About overlay: no
// auto-dismiss; dismisses only on a keypress, which pops the modal.
func NewModal(version, projectURL string) *Model {
	m := New(version, projectURL)
	m.modal = true
	return m
}

// pickVariant selects the best-fitting pre-rendered logo variant for the
// terminal's detected color profile. H1 fix: uses the canonical
// colorprofile.Detect API verified during planning — NOT
// lipgloss.DetectColorProfile() or lipgloss.DefaultRenderer().ColorProfile(),
// neither of which exists in Lip Gloss v2.0.3.
func pickVariant() string {
	switch colorprofile.Detect(os.Stdout, os.Environ()) {
	case colorprofile.TrueColor:
		return logoTruecolor
	case colorprofile.ANSI256:
		return logo256
	case colorprofile.ANSI:
		return logo16
	default: // ASCII, NoTTY, Unknown
		return logoASCII
	}
}

// Init returns the 2-second tick for non-modal splashes, nil for the About
// modal variant.
func (m *Model) Init() tea.Cmd {
	if m.modal {
		return nil
	}
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

// Update handles the tick (auto-dismiss) and keypresses. On dismissal the
// non-modal splash emits nav.ReplaceWithFactoryCmd carrying a
// HomePlaceholder; the App's resolver substitutes the real home.Model. The
// modal splash emits nav.PopCmd on any keypress.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch mm := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = mm.Width, mm.Height
		return m, nil
	case tickMsg:
		if !m.modal {
			return m, m.replaceWithHome()
		}
	case tea.KeyPressMsg:
		if m.modal {
			return m, nav.PopCmd()
		}
		return m, m.replaceWithHome()
	}
	return m, nil
}

func (m *Model) replaceWithHome() tea.Cmd {
	version, url := m.version, m.projectURL
	return nav.ReplaceWithFactoryCmd(func() nav.Screen {
		return &HomePlaceholder{Version: version, ProjectURL: url}
	})
}

// View renders the logo + tagline + version line.
func (m *Model) View() string {
	return fmt.Sprintf(
		"%s\n\nsftp-jailer %s\nGPL-3.0  ·  %s\n\nchrooted SFTP, hardened.",
		m.logo, m.version, m.projectURL,
	)
}

// Title returns the title used in the help overlay header.
func (m *Model) Title() string { return "sftp-jailer" }

// KeyMap returns an empty KeyMap — the splash doesn't bind any keys itself
// beyond "any key dismisses". The help overlay is a no-op here.
func (m *Model) KeyMap() nav.KeyMap { return emptyKeyMap{} }

// WantsRawKeys is false — no textinput on the splash.
func (m *Model) WantsRawKeys() bool { return false }

type emptyKeyMap struct{}

func (emptyKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKeyMap) FullHelp() [][]nav.KeyBinding { return nil }
