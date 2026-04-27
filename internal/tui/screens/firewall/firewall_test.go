// Package firewallscreen tests for S-FIREWALL — the wave-4 first screen,
// pushed from home `f`. Mirrors the S-USERS test shape (key helper +
// nav.Screen compile-time check + LoadXForTest seam) per UI-SPEC §"Async /
// Loading State Contract".
package firewallscreen_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	firewallscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// keyPress mirrors the S-USERS helper. Special-cases esc + arrow keys.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Text: ""})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// TestFirewallScreen_implements_nav_Screen — compile-time check that Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap / WantsRawKeys.
func TestFirewallScreen_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = firewallscreen.New(nil)
	require.Equal(t, "firewall", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false in the inactive-search default state")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestFirewallScreen_loading_state — initial View shows the loading copy.
func TestFirewallScreen_loading_state(t *testing.T) {
	m := firewallscreen.New(nil)
	require.Contains(t, m.View(), "reading firewall rules…")
}

// TestFirewallScreen_LoadRulesForTest_flat_mode — feeding rules via the
// test seam bypasses Init+Enumerate; flat-mode View must render every
// supplied rule's id and user.
func TestFirewallScreen_LoadRulesForTest_flat_mode(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 1, Proto: "v4", Port: "22", Source: "203.0.113.7", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
		{ID: 2, Proto: "v4", Port: "22", Source: "198.51.100.42", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=bob", User: "bob"},
		{ID: 3, Proto: "v4", Port: "22", Source: "192.0.2.1", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=carol", User: "carol"},
	}, nil)
	v := m.View()
	for _, want := range []string{"1", "2", "3", "alice", "bob", "carol"} {
		require.Contains(t, v, want, "flat-mode View must contain %q; got %q", want, v)
	}
}

// TestFirewallScreen_by_user_mode — pressing `g` toggles to per-user
// grouped view (FW-04). Each user gets a section header.
func TestFirewallScreen_by_user_mode(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 1, Proto: "v4", Port: "22", Source: "203.0.113.7", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
		{ID: 2, Proto: "v4", Port: "22", Source: "198.51.100.5", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
		{ID: 3, Proto: "v4", Port: "22", Source: "192.0.2.1", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=carol", User: "carol"},
	}, nil)
	_, _ = m.Update(keyPress("g"))
	v := m.View()
	require.Contains(t, v, "user: alice", "by-user header for alice missing; got %q", v)
	require.Contains(t, v, "user: carol", "by-user header for carol missing; got %q", v)
	require.Contains(t, v, "2 rules", "alice has 2 rules; rule-count missing in section header; got %q", v)
	require.Contains(t, v, "view: by user", "footer must indicate by-user mode; got %q", v)
}

// TestFirewallScreen_by_user_mode_omits_zero_rule_users — by-user mode
// should never render a "user: nobody — 0 rules" header. (The data source
// only contains rules so this is automatically true; we assert it.)
func TestFirewallScreen_by_user_mode_omits_zero_rule_users(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 1, Proto: "v4", Port: "22", Source: "203.0.113.7", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
	}, nil)
	_, _ = m.Update(keyPress("g"))
	v := m.View()
	require.NotContains(t, v, "0 rules",
		"by-user mode should not list zero-rule users; got %q", v)
}

// TestFirewallScreen_ErrBadVersion_renders_question_mark — rules where
// ParseErr == ufwcomment.ErrBadVersion render the user column as `?`.
func TestFirewallScreen_ErrBadVersion_renders_question_mark(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{
			ID: 7, Proto: "v4", Port: "22", Source: "10.0.0.5",
			Action: "ALLOW IN", RawComment: "sftpj:v=2:user=future",
			ParseErr: ufwcomment.ErrBadVersion,
		},
	}, nil)
	v := m.View()
	require.Contains(t, v, "?", "ErrBadVersion must render `?` in user column; got %q", v)
}

// TestFirewallScreen_ufw_inactive_empty_state — UI-SPEC line 357.
func TestFirewallScreen_ufw_inactive_empty_state(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest(nil, firewall.ErrUFWInactive)
	v := m.View()
	require.Contains(t, v, "No SFTP-tagged firewall rules.")
}

// TestFirewallScreen_other_error_renders_error_state — UI-SPEC line 358.
func TestFirewallScreen_other_error_renders_error_state(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest(nil, errors.New("ufw: command not found"))
	v := m.View()
	require.Contains(t, v, "Could not read firewall:")
	require.Contains(t, v, "ufw: command not found")
}

// TestFirewallScreen_copy_emits_SetClipboard — pressing `c` on a loaded
// rule returns a non-nil tea.Cmd; invoking it produces a tea.BatchMsg whose
// concatenated message string contains the expected raw line content.
func TestFirewallScreen_copy_emits_SetClipboard(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 5, Proto: "v4", Port: "22", Source: "203.0.113.7", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
	}, nil)
	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd, "`c` on a loaded rule must emit a tea.Cmd")
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)
	found := false
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		s := fmt.Sprintf("%v", sub())
		if strings.Contains(s, "203.0.113.7") {
			found = true
			break
		}
	}
	require.True(t, found, "batch must include a clipboard sub-cmd whose message stringifies to the rule line")

	// Toast must announce the OSC 52 copy.
	require.Contains(t, m.View(), "copied rule via OSC 52")
}

// TestFirewallScreen_search_active_flips_WantsRawKeys — pressing `/`
// activates the search widget; pressing esc deactivates.
func TestFirewallScreen_search_active_flips_WantsRawKeys(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 1, Source: "203.0.113.7", User: "alice"},
	}, nil)
	require.False(t, m.WantsRawKeys())
	_, _ = m.Update(keyPress("/"))
	require.True(t, m.WantsRawKeys(), "after `/`, WantsRawKeys must be true")
	_, _ = m.Update(keyPress("esc"))
	require.False(t, m.WantsRawKeys(), "after esc, search must clear and WantsRawKeys back to false")
}

// TestFirewallScreen_keymap_bindings — assert the S-FIREWALL bindings list.
func TestFirewallScreen_keymap_bindings(t *testing.T) {
	km := firewallscreen.DefaultKeyMap()
	short := km.ShortHelp()
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"esc", "q", "/", "enter", "g", "c"} {
		require.True(t, found[k], "ShortHelp must expose %q", k)
	}
}

// TestFirewallScreen_esc_pops — esc/q pops back to home.
func TestFirewallScreen_esc_pops(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{{ID: 1}}, nil)
	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	nm, ok := cmd().(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", cmd())
	require.Equal(t, nav.Pop, nm.Intent)
}

// TestFirewallScreen_default_view_is_flat — initial loaded state shows
// the `view: flat` footer indicator.
func TestFirewallScreen_default_view_is_flat(t *testing.T) {
	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{
		{ID: 1, Proto: "v4", Port: "22", Source: "203.0.113.7", Action: "ALLOW IN", RawComment: "sftpj:v=1:user=alice", User: "alice"},
	}, nil)
	require.Contains(t, m.View(), "view: flat")
}

// stubScreen is a tiny nav.Screen used by the factory-injection tests.
type stubScreen struct{ name string }

func (s *stubScreen) Init() tea.Cmd                            { return nil }
func (s *stubScreen) Update(tea.Msg) (nav.Screen, tea.Cmd)     { return s, nil }
func (s *stubScreen) View() string                             { return s.name }
func (s *stubScreen) Title() string                            { return s.name }
func (s *stubScreen) KeyMap() nav.KeyMap                       { return stubKeyMap{} }
func (s *stubScreen) WantsRawKeys() bool                       { return false }

type stubKeyMap struct{}

func (stubKeyMap) ShortHelp() []nav.KeyBinding   { return nil }
func (stubKeyMap) FullHelp() [][]nav.KeyBinding  { return nil }

// TestSFirewall_a_pushes_addrule_when_factory_set — pressing 'a' on
// S-FIREWALL must emit a nav.Push carrying whatever the registered
// AddRuleFactory returns. Plan 04-05 Task 3 wires this so the home
// screen's bootstrap can register the M-ADD-RULE constructor without
// the firewall package importing internal/tui/screens/firewallrule
// (factory-injection avoids the cycle).
func TestSFirewall_a_pushes_addrule_when_factory_set(t *testing.T) {
	defer firewallscreen.SetAddRuleFactory(nil) // cleanup global

	stub := &stubScreen{name: "M-ADD-RULE"}
	firewallscreen.SetAddRuleFactory(func() nav.Screen { return stub })

	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{{ID: 1}}, nil)
	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd, "'a' with factory set must emit a non-nil tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Same(t, nav.Screen(stub), nm.Screen,
		"pushed screen must be the factory's return value")
}

// TestSFirewall_a_noop_when_factory_nil — pressing 'a' with no factory
// registered is a clean no-op (no panic, no cmd).
func TestSFirewall_a_noop_when_factory_nil(t *testing.T) {
	firewallscreen.SetAddRuleFactory(nil)

	m := firewallscreen.New(nil)
	m.LoadRulesForTest([]firewall.Rule{{ID: 1}}, nil)
	_, cmd := m.Update(keyPress("a"))
	require.Nil(t, cmd, "'a' without factory must be a no-op")
}
