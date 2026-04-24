package wire_test

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/wire"
)

// TestWire_resolvesHomePlaceholder proves that after wire.Register(), the
// App substitutes a real home screen for a splash.HomePlaceholder emitted
// through nav.ReplaceMsg — end-to-end C4 seam.
func TestWire_resolvesHomePlaceholder(t *testing.T) {
	app.ResetPlaceholderResolversForTest()
	wire.Register()

	// Seed the App with a splash; then synthesize the tick that the splash
	// would send to itself after 1s, which emits ReplaceMsg.
	s := splash.New("v9.9", "https://example.com")
	a := app.New("v9.9", "https://example.com", s)

	// Send ReplaceMsg directly carrying a HomePlaceholder factory — matches
	// what the splash's real dismissal path produces.
	_, _ = a.Update(nav.ReplaceMsg{
		Factory: func() nav.Screen {
			return &splash.HomePlaceholder{Version: "v9.9", ProjectURL: "https://example.com"}
		},
	})

	require.Equal(t, 1, a.StackLen())
	require.Equal(t, "home", a.TopTitle(),
		"wire resolver must substitute home.New for splash.HomePlaceholder")
}

// Ensure we don't accidentally match non-placeholder screens.
func TestWire_ignoresOtherScreens(t *testing.T) {
	app.ResetPlaceholderResolversForTest()
	wire.Register()

	other := &fakeScreen{title: "other"}
	a := app.New("v", "u", &fakeScreen{title: "first"})

	_, _ = a.Update(nav.ReplaceMsg{Factory: func() nav.Screen { return other }})
	require.Equal(t, "other", a.TopTitle())
}

type fakeScreen struct{ title string }

func (f *fakeScreen) Init() tea.Cmd                        { return nil }
func (f *fakeScreen) Update(tea.Msg) (nav.Screen, tea.Cmd) { return f, nil }
func (f *fakeScreen) View() string                         { return "fake:" + f.title }
func (f *fakeScreen) Title() string                        { return f.title }
func (f *fakeScreen) KeyMap() nav.KeyMap                   { return emptyKM{} }
func (f *fakeScreen) WantsRawKeys() bool                   { return false }

type emptyKM struct{}

func (emptyKM) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKM) FullHelp() [][]nav.KeyBinding { return nil }
