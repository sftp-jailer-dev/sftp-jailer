package splash_test

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
)

func TestSplash_New_Init_returns_tick(t *testing.T) {
	m := splash.New("v1.0", "https://example.com")
	cmd := m.Init()
	require.NotNil(t, cmd, "non-modal splash must arm its 2s tick via Init")
}

func TestSplash_NewModal_Init_returns_nil(t *testing.T) {
	m := splash.NewModal("v1.0", "https://example.com")
	require.Nil(t, m.Init(), "modal (About) splash must NOT auto-tick")
}

func TestSplash_KeypressDismissesNonModal_via_ReplaceMsg_with_HomePlaceholder(t *testing.T) {
	m := splash.New("v1.0", "https://example.com")
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: 'x', Text: "x"}))
	require.NotNil(t, cmd)
	msg := cmd()
	rep, ok := msg.(nav.ReplaceMsg)
	require.True(t, ok, "expected nav.ReplaceMsg, got %T", msg)
	require.NotNil(t, rep.Factory, "ReplaceMsg.Factory must be non-nil")

	out := rep.Factory()
	ph, ok := out.(*splash.HomePlaceholder)
	require.True(t, ok, "factory must produce *splash.HomePlaceholder, got %T", out)
	require.Equal(t, "v1.0", ph.Version)
	require.Equal(t, "https://example.com", ph.ProjectURL)
}

func TestSplash_KeypressModal_pops(t *testing.T) {
	m := splash.NewModal("v1.0", "https://example.com")
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: 'x', Text: "x"}))
	require.NotNil(t, cmd)
	msg := cmd()
	_, ok := msg.(nav.Msg)
	require.True(t, ok, "modal splash must emit nav.Msg for Pop")
	if nm, ok := msg.(nav.Msg); ok {
		require.Equal(t, nav.Pop, nm.Intent)
	}
}

func TestSplash_View_contains_version_and_URL(t *testing.T) {
	m := splash.New("v9.9", "https://sftp-jailer.test")
	v := m.View()
	require.Contains(t, v, "v9.9")
	require.Contains(t, v, "https://sftp-jailer.test")
	require.Contains(t, v, "GPL-3.0")
	require.Contains(t, v, "chrooted SFTP, hardened.")
}

func TestSplash_View_includes_embedded_logo(t *testing.T) {
	m := splash.New("v1.0", "https://example.com")
	v := m.View()
	// The logo is at least a handful of lines in every variant.
	require.GreaterOrEqual(t, strings.Count(v, "\n"), 5, "View should include multi-line embedded logo")
}

func TestHomePlaceholder_NoOpMethods(t *testing.T) {
	ph := &splash.HomePlaceholder{Version: "v1", ProjectURL: "u"}
	require.Nil(t, ph.Init())
	_, cmd := ph.Update(nil)
	require.Nil(t, cmd)
	require.Equal(t, "", ph.View())
	require.False(t, ph.WantsRawKeys())
	require.NotEmpty(t, ph.Title())
	require.NotNil(t, ph.KeyMap())
}
