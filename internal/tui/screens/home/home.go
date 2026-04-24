// Package home implements the TUI home dashboard — the landing screen
// after the splash dismisses. Phase 1 ships this with stub tiles
// ("SSH: ? · Users: ? · Rules: ?"); later phases populate them from real
// sysops state.
//
// The doctorFactory hook is shipped from day one (C2 fix) so plan 01-04
// can inject the real doctor screen without modifying this file a second
// time. Plan 01-04's main.go calls home.SetDoctorFactory(...) before
// program.Run.
package home

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/about"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// doctorFactory is injected by main.go. Plan 01-04 wires the real one via
// SetDoctorFactory; until that lands, pressing 'd' opens the stub.
var doctorFactory func() nav.Screen

// SetDoctorFactory registers the constructor used when the admin presses
// 'd' to open the diagnostic. Idempotent; last-call-wins.
func SetDoctorFactory(f func() nav.Screen) { doctorFactory = f }

// Model is the home dashboard.
type Model struct {
	version    string
	projectURL string
	search     widgets.Search
	keys       KeyMap
	width      int
	height     int
}

// KeyMap is the home screen's key bindings. It implements nav.KeyMap.
type KeyMap struct {
	OpenDoctor nav.KeyBinding
	About      nav.KeyBinding
	Search     nav.KeyBinding
	Help       nav.KeyBinding
	Quit       nav.KeyBinding
}

// DefaultKeyMap returns the canonical home-screen bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		OpenDoctor: nav.KeyBinding{Keys: []string{"d"}, Help: "diagnostic"},
		About:      nav.KeyBinding{Keys: []string{"a"}, Help: "about"},
		Search:     nav.KeyBinding{Keys: []string{"/"}, Help: "search"},
		Help:       nav.KeyBinding{Keys: []string{"?"}, Help: "help"},
		Quit:       nav.KeyBinding{Keys: []string{"q", "ctrl+c"}, Help: "quit"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.OpenDoctor, k.About, k.Search, k.Help, k.Quit}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.OpenDoctor, k.About},
		{k.Search, k.Help, k.Quit},
	}
}

// New constructs a home Model. version and projectURL are passed through
// to the About overlay when the admin opens it.
func New(version, projectURL string) *Model {
	return &Model{
		version:    version,
		projectURL: projectURL,
		search:     widgets.NewSearch(),
		keys:       DefaultKeyMap(),
	}
}

// Init returns nil — home does not kick off any async work in Phase 1.
func (m *Model) Init() tea.Cmd { return nil }

// Update handles the search widget (when active) and top-level bindings.
// When the search widget is Active, nearly every message is forwarded to
// it — WantsRawKeys() returns true in that state so the root App does not
// steal the keystrokes.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = ws.Width, ws.Height
		return m, nil
	}
	if m.search.Active {
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		return m, cmd
	}
	if k, ok := msg.(tea.KeyPressMsg); ok {
		switch k.String() {
		case "d":
			if doctorFactory != nil {
				return m, nav.PushCmd(doctorFactory())
			}
			return m, nav.PushCmd(newDoctorStub())
		case "a":
			return m, nav.PushCmd(about.New(m.version, m.projectURL))
		case "/":
			m.search.Active = true
			return m, nil
		}
	}
	return m, nil
}

// View renders the dashboard.
func (m *Model) View() string {
	body := "sftp-jailer — home\n\n" +
		"SSH: ?   ·   Users: ?   ·   Rules: ?\n\n" +
		"(press d for diagnostic, a for about, ? for help, / to search, q to quit)"
	if m.search.Active {
		body = m.search.View() + "\n\n" + body
	}
	return body
}

// Title is shown in the help overlay header.
func (m *Model) Title() string { return "home" }

// KeyMap returns the home KeyMap for the help overlay.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys is true while the search textinput is focused so the root
// App forwards keystrokes to it instead of handling global 'q'.
func (m *Model) WantsRawKeys() bool { return m.search.Active }

// --- doctor stub -------------------------------------------------------

// doctorStub is a placeholder nav.Screen used when home is pressed 'd' but
// plan 01-04's real doctor screen has not been injected yet. It displays
// a single line and pops on any key.
type doctorStub struct{ keys KeyMap }

func newDoctorStub() *doctorStub { return &doctorStub{keys: DefaultKeyMap()} }

func (s *doctorStub) Init() tea.Cmd { return nil }
func (s *doctorStub) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	if _, ok := msg.(tea.KeyPressMsg); ok {
		return s, nav.PopCmd()
	}
	return s, nil
}
func (s *doctorStub) View() string {
	return "diagnostic not yet wired — see plan 01-04\n\n(press any key to return)"
}
func (s *doctorStub) Title() string       { return "doctor-stub" }
func (s *doctorStub) KeyMap() nav.KeyMap  { return emptyKeyMap{} }
func (s *doctorStub) WantsRawKeys() bool  { return false }

type emptyKeyMap struct{}

func (emptyKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKeyMap) FullHelp() [][]nav.KeyBinding { return nil }
