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
	require.Len(t, short, 5)
	// Assert each binding by its primary key.
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"d", "a", "/", "?", "q", "ctrl+c"} {
		require.True(t, found[k], "KeyMap must expose %q", k)
	}
	require.NotEmpty(t, km.FullHelp())
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
