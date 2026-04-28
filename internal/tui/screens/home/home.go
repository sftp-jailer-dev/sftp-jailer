// Package home implements the TUI home dashboard — the landing screen
// after the splash dismisses. Phase 1 ships this with stub tiles
// ("SSH: ? · Users: ? · Rules: ?"); later phases populate them from real
// sysops state.
//
// The doctorFactory hook is shipped from day one (C2 fix) so plan 01-04
// can inject the real doctor screen without modifying this file a second
// time. Plan 01-04's main.go calls home.SetDoctorFactory(...) before
// program.Run.
//
// Phase 2 plan 02-04 adds four sibling hooks — SetUsersFactory,
// SetFirewallFactory, SetLogsFactory, SetSettingsFactory — and the matching
// u/f/l/s key bindings. Wave-3+ plans (02-05/06/07) only ADD the matching
// home.SetXFactory(...) call to main.go's runTUI; they do NOT modify this
// package. Centralising the home modifications here avoids serial conflicts
// across the wave.
package home

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/about"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// Factory hooks injected by main.go. The four wave-3+ slots ship together
// in plan 02-04 even though only usersFactory has a real screen wired in
// this plan; firewall/logs/settings are wired by 02-05/06/07 in subsequent
// waves. Pressing the corresponding key with no factory registered is a
// no-op (returns nil tea.Cmd) — defensive against an admin pressing `f`
// before 02-05 ships.
//
// Package-level globals match the existing doctorFactory pattern (C2). The
// `unused` linter does not flag exported package-level funcs by default,
// so the three not-yet-wired SetXFactory funcs do not require a nolint.
var (
	doctorFactory   func() nav.Screen
	usersFactory    func() nav.Screen
	firewallFactory func() nav.Screen
	logsFactory     func() nav.Screen
	settingsFactory func() nav.Screen
	// lockdownFactory is the Phase 4 plan 04-08 hook for the
	// S-LOCKDOWN screen. Pressed via capital `L` (lowercase `l` is
	// reserved for logs since 02-06). nil-safe — pressing L with no
	// factory registered returns nil tea.Cmd.
	lockdownFactory func() nav.Screen
)

// SetDoctorFactory registers the constructor used when the admin presses
// 'd' to open the diagnostic. Idempotent; last-call-wins.
func SetDoctorFactory(f func() nav.Screen) { doctorFactory = f }

// SetUsersFactory registers the constructor used when the admin presses
// 'u' to open the users overview. Wired by plan 02-04's runTUI bootstrap.
func SetUsersFactory(f func() nav.Screen) { usersFactory = f }

// SetFirewallFactory registers the constructor used when the admin presses
// 'f' to open the firewall view. Wired by plan 02-05 in runTUI.
func SetFirewallFactory(f func() nav.Screen) { firewallFactory = f }

// SetLogsFactory registers the constructor used when the admin presses 'l'
// to open the log viewer. Wired by plan 02-06 in runTUI.
func SetLogsFactory(f func() nav.Screen) { logsFactory = f }

// SetSettingsFactory registers the constructor used when the admin presses
// 's' to open the settings form. Wired by plan 02-07 in runTUI.
func SetSettingsFactory(f func() nav.Screen) { settingsFactory = f }

// SetLockdownFactory registers the constructor used when the admin
// presses capital `L` to open the S-LOCKDOWN flagship screen (Phase 4
// plan 04-08). Lowercase `l` is reserved for logs (02-06). Wired by
// plan 04-08's runTUI bootstrap.
func SetLockdownFactory(f func() nav.Screen) { lockdownFactory = f }

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
	OpenDoctor   nav.KeyBinding
	OpenUsers    nav.KeyBinding
	OpenFirewall nav.KeyBinding
	OpenLogs     nav.KeyBinding
	OpenSettings nav.KeyBinding
	OpenLockdown nav.KeyBinding // Phase 4 plan 04-08: capital L
	About        nav.KeyBinding
	Search       nav.KeyBinding
	Help         nav.KeyBinding
	Quit         nav.KeyBinding
}

// DefaultKeyMap returns the canonical home-screen bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		OpenDoctor:   nav.KeyBinding{Keys: []string{"d"}, Help: "diagnostic"},
		OpenUsers:    nav.KeyBinding{Keys: []string{"u"}, Help: "users"},
		OpenFirewall: nav.KeyBinding{Keys: []string{"f"}, Help: "firewall"},
		OpenLogs:     nav.KeyBinding{Keys: []string{"l"}, Help: "logs"},
		OpenSettings: nav.KeyBinding{Keys: []string{"s"}, Help: "settings"},
		OpenLockdown: nav.KeyBinding{Keys: []string{"L"}, Help: "lockdown"},
		About:        nav.KeyBinding{Keys: []string{"a"}, Help: "about"},
		Search:       nav.KeyBinding{Keys: []string{"/"}, Help: "search"},
		Help:         nav.KeyBinding{Keys: []string{"?"}, Help: "help"},
		Quit:         nav.KeyBinding{Keys: []string{"q", "ctrl+c"}, Help: "quit"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{
		k.OpenDoctor, k.OpenUsers, k.OpenFirewall, k.OpenLogs, k.OpenSettings,
		k.OpenLockdown, k.About, k.Search, k.Help, k.Quit,
	}
}

// FullHelp implements nav.KeyMap. Row 1 = nav actions opening sibling
// screens; row 2 = secondary actions (about/search/help/quit).
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.OpenDoctor, k.OpenUsers, k.OpenFirewall, k.OpenLogs, k.OpenSettings, k.OpenLockdown},
		{k.About, k.Search, k.Help, k.Quit},
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
		case "u":
			if usersFactory != nil {
				return m, nav.PushCmd(usersFactory())
			}
			return m, nil
		case "f":
			if firewallFactory != nil {
				return m, nav.PushCmd(firewallFactory())
			}
			return m, nil
		case "l":
			if logsFactory != nil {
				return m, nav.PushCmd(logsFactory())
			}
			return m, nil
		case "s":
			if settingsFactory != nil {
				return m, nav.PushCmd(settingsFactory())
			}
			return m, nil
		case "L":
			// Phase 4 plan 04-08: capital L opens S-LOCKDOWN (lowercase
			// l is logs since 02-06). nil-factory returns nil tea.Cmd
			// for defensive parity with the other factory-injection
			// paths.
			if lockdownFactory != nil {
				screen := lockdownFactory()
				if screen != nil {
					return m, nav.PushCmd(screen)
				}
			}
			return m, nil
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
		"(d diagnostic · u users · f firewall · l logs · s settings · L lockdown · a about · ? help · q quit)"
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
func (s *doctorStub) Title() string      { return "doctor-stub" }
func (s *doctorStub) KeyMap() nav.KeyMap { return emptyKeyMap{} }
func (s *doctorStub) WantsRawKeys() bool { return false }

type emptyKeyMap struct{}

func (emptyKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKeyMap) FullHelp() [][]nav.KeyBinding { return nil }
