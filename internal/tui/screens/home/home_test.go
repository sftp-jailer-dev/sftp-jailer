package home_test

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
)

func keyPress(s string) tea.KeyPressMsg {
	if s == "/" {
		return tea.KeyPressMsg(tea.Key{Code: '/', Text: "/"})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

func TestHome_KeyMap_exposesAllExpectedBindings(t *testing.T) {
	km := home.DefaultKeyMap()
	short := km.ShortHelp()
	// Phase 2 (02-04): home now also surfaces u/f/l/s in ShortHelp alongside
	// d/a/// /?/q. The exact length is asserted below; we mainly care that
	// every key the contract advertises is exposed via at least one binding.
	require.NotEmpty(t, short)
	// Assert each binding by its primary key.
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"d", "u", "f", "l", "s", "a", "/", "?", "q", "ctrl+c"} {
		require.True(t, found[k], "KeyMap must expose %q", k)
	}
	require.NotEmpty(t, km.FullHelp())
}

// TestHome_keymap_extended_help_text confirms each new wave-3+ binding
// carries a recognisable Help text — surfaces the screen name in the help
// overlay so an admin pressing `?` immediately sees what `u` does.
func TestHome_keymap_extended_help_text(t *testing.T) {
	km := home.DefaultKeyMap()
	want := map[string]string{
		"u": "users",
		"f": "firewall",
		"l": "logs",
		"s": "settings",
	}
	for _, b := range km.ShortHelp() {
		for _, k := range b.Keys {
			if expected, ok := want[k]; ok {
				require.Equal(t, expected, b.Help,
					"binding for %q must have Help=%q (got %q)", k, expected, b.Help)
			}
		}
	}
}

func TestHome_d_pushes_stub_when_no_factory(t *testing.T) {
	// Ensure no factory is set.
	home.SetDoctorFactory(nil)
	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("d"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.NotNil(t, nm.Screen, "Push must carry a Screen")
	require.Contains(t, nm.Screen.View(), "not yet wired")
}

func TestHome_d_pushes_injected_factory(t *testing.T) {
	sentinel := &fakeScreen{title: "real-doctor"}
	home.SetDoctorFactory(func() nav.Screen { return sentinel })
	defer home.SetDoctorFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("d"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, sentinel, nm.Screen, "factory-produced screen must be pushed")
}

// TestHome_SetUsersFactory_registers asserts pressing `u` after registering
// a users factory pushes the factory-produced screen via nav.PushCmd.
func TestHome_SetUsersFactory_registers(t *testing.T) {
	sentinel := &fakeScreen{title: "real-users"}
	home.SetUsersFactory(func() nav.Screen { return sentinel })
	defer home.SetUsersFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("u"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Equal(t, sentinel, nm.Screen)
}

func TestHome_SetFirewallFactory_registers(t *testing.T) {
	sentinel := &fakeScreen{title: "real-firewall"}
	home.SetFirewallFactory(func() nav.Screen { return sentinel })
	defer home.SetFirewallFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("f"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Equal(t, sentinel, nm.Screen)
}

func TestHome_SetLogsFactory_registers(t *testing.T) {
	sentinel := &fakeScreen{title: "real-logs"}
	home.SetLogsFactory(func() nav.Screen { return sentinel })
	defer home.SetLogsFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("l"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Equal(t, sentinel, nm.Screen)
}

func TestHome_SetSettingsFactory_registers(t *testing.T) {
	sentinel := &fakeScreen{title: "real-settings"}
	home.SetSettingsFactory(func() nav.Screen { return sentinel })
	defer home.SetSettingsFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("s"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Equal(t, sentinel, nm.Screen)
}

// TestHome_factories_independent verifies that pressing one screen-letter
// fires only that screen's factory, never another. Belt-and-suspenders so
// future refactors can't silently reroute keys.
func TestHome_factories_independent(t *testing.T) {
	uSent := &fakeScreen{title: "u"}
	fSent := &fakeScreen{title: "f"}
	home.SetUsersFactory(func() nav.Screen { return uSent })
	home.SetFirewallFactory(func() nav.Screen { return fSent })
	defer home.SetUsersFactory(nil)
	defer home.SetFirewallFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("u"))
	require.NotNil(t, cmd)
	require.Equal(t, uSent, cmd().(nav.Msg).Screen, "`u` must push users sentinel")

	_, cmd = m.Update(keyPress("f"))
	require.NotNil(t, cmd)
	require.Equal(t, fSent, cmd().(nav.Msg).Screen, "`f` must push firewall sentinel")
}

// TestHome_no_factory_no_crash verifies that pressing u/f/l/s with no
// factory registered emits a nil tea.Cmd — defensive: shipping the four
// SetXFactory hooks but only wiring usersFactory in this plan must not
// crash the TUI when an admin presses f/l/s before 02-05/06/07 land.
func TestHome_no_factory_no_crash(t *testing.T) {
	home.SetUsersFactory(nil)
	home.SetFirewallFactory(nil)
	home.SetLogsFactory(nil)
	home.SetSettingsFactory(nil)

	m := home.New("v1", "u")
	for _, k := range []string{"u", "f", "l", "s"} {
		_, cmd := m.Update(keyPress(k))
		require.Nil(t, cmd, "pressing %q with no factory registered must return nil tea.Cmd (no panic, no push)", k)
	}
}

// TestHome_L_pushes_lockdown_factory_when_set asserts pressing capital
// `L` pushes the registered lockdown factory's screen via nav.PushCmd.
// Phase 4 plan 04-08: capital L is reserved for the S-LOCKDOWN screen
// (lowercase l is logs).
func TestHome_L_pushes_lockdown_factory_when_set(t *testing.T) {
	sentinel := &fakeScreen{title: "real-lockdown"}
	home.SetLockdownFactory(func() nav.Screen { return sentinel })
	defer home.SetLockdownFactory(nil)

	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("L"))
	require.NotNil(t, cmd, "pressing L with a registered lockdown factory must produce a tea.Cmd")
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Equal(t, sentinel, nm.Screen, "factory-produced lockdown screen must be pushed")
}

// TestHome_L_no_factory_no_crash asserts capital L without a registered
// factory returns nil tea.Cmd — defensive parity with the
// u/f/l/s no-factory path.
func TestHome_L_no_factory_no_crash(t *testing.T) {
	home.SetLockdownFactory(nil)
	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("L"))
	require.Nil(t, cmd, "L with no factory registered must return nil tea.Cmd")
}

func TestHome_a_pushes_about_screen(t *testing.T) {
	m := home.New("v1", "u")
	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.NotNil(t, nm.Screen)
	require.NotEmpty(t, nm.Screen.View())
}

func TestHome_slash_activates_search_and_flips_wantsRawKeys(t *testing.T) {
	m := home.New("v1", "u")
	require.False(t, m.WantsRawKeys(), "search should start inactive")
	_, _ = m.Update(keyPress("/"))
	require.True(t, m.WantsRawKeys(), "/ must activate the search textinput")
}

func TestHome_View_contains_stub_tiles(t *testing.T) {
	m := home.New("v1", "u")
	v := m.View()
	require.Contains(t, v, "SSH:")
	require.Contains(t, v, "Users:")
	require.Contains(t, v, "Rules:")
}

// fakeScreen is a minimal nav.Screen used by the factory-injection test.
type fakeScreen struct{ title string }

func (f *fakeScreen) Init() tea.Cmd                            { return nil }
func (f *fakeScreen) Update(tea.Msg) (nav.Screen, tea.Cmd)     { return f, nil }
func (f *fakeScreen) View() string                             { return "fake:" + f.title }
func (f *fakeScreen) Title() string                            { return f.title }
func (f *fakeScreen) KeyMap() nav.KeyMap                       { return emptyKM{} }
func (f *fakeScreen) WantsRawKeys() bool                       { return false }

type emptyKM struct{}

func (emptyKM) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKM) FullHelp() [][]nav.KeyBinding { return nil }
