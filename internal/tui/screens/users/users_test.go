// Package usersscreen tests for S-USERS — the wave-3 first screen, pushed
// from home `u`. Mirrors the doctor screen's test shape (key helper +
// nav.Screen compile-time check + LoadXForTest seam) per UI-SPEC §"Async /
// Loading State Contract" line 313.
package usersscreen_test

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	usersscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/users"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// keyPress mirrors the doctor screen's helper. Special-cases esc + `/` so
// the textinput-based search widget receives a recognisable Code field.
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

// TestUsersScreen_implements_nav_Screen — compile-time check that Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap / WantsRawKeys.
func TestUsersScreen_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = usersscreen.New(nil)
	require.Equal(t, "users", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false in the inactive-search default state")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestUsersScreen_loading_state — initial View shows the loading copy
// (UI-SPEC line 320: "loading users…").
func TestUsersScreen_loading_state(t *testing.T) {
	m := usersscreen.New(nil)
	require.Contains(t, m.View(), "loading users…")
}

// TestUsersScreen_LoadRowsForTest_renders_rows — feeding rows via the test
// seam bypasses Init+enumerate; View must render every supplied row's
// username, uid, and chroot.
func TestUsersScreen_LoadRowsForTest_renders_rows(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{
		{Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice", KeysCount: 2, IPAllowlistCount: 1},
	}, nil)
	v := m.View()
	require.Contains(t, v, "alice")
	require.Contains(t, v, "1001")
	require.Contains(t, v, "/srv/sftp/alice")
}

// TestUsersScreen_renders_INFO_rows_in_Info_style — the D-12 INFO rows must
// (a) appear at all, (b) carry the literal `[INFO]` prefix, (c) carry the
// orphan detail, and (d) carry the `[fix in Phase 3]` hint.
func TestUsersScreen_renders_INFO_rows_in_Info_style(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest(nil, []users.InfoRow{{
		Kind:   users.InfoOrphan,
		Detail: "/srv/sftp/wendy (uid 1042) — no backing system user",
		Hint:   "[fix in Phase 3]",
	}})
	v := m.View()
	require.Contains(t, v, "[INFO]")
	require.Contains(t, v, "/srv/sftp/wendy")
	require.Contains(t, v, "[fix in Phase 3]")
}

// TestUsersScreen_keymap_bindings — assert the S-USERS bindings list
// (UI-SPEC §S-USERS): esc/q (back), / (search), enter (detail), s (sort),
// S (reverse sort, full-help only), c (copy).
func TestUsersScreen_keymap_bindings(t *testing.T) {
	km := usersscreen.DefaultKeyMap()
	short := km.ShortHelp()
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"esc", "q", "/", "enter", "s", "c"} {
		require.True(t, found[k], "ShortHelp must expose %q", k)
	}
	// Full help additionally surfaces the reverse-sort binding (S).
	full := km.FullHelp()
	require.NotEmpty(t, full)
	foundFull := map[string]bool{}
	for _, row := range full {
		for _, b := range row {
			for _, k := range b.Keys {
				foundFull[k] = true
			}
		}
	}
	require.True(t, foundFull["S"], "FullHelp must surface the reverse-sort `S` binding")
}

// TestUsersScreen_search_active_flips_WantsRawKeys — pressing `/` activates
// the search widget so the root App must forward subsequent keystrokes (q
// included) into the textinput. Pressing esc deactivates.
func TestUsersScreen_search_active_flips_WantsRawKeys(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	require.False(t, m.WantsRawKeys())
	_, _ = m.Update(keyPress("/"))
	require.True(t, m.WantsRawKeys(), "after `/`, WantsRawKeys must be true")
	_, _ = m.Update(keyPress("esc"))
	require.False(t, m.WantsRawKeys(), "after esc, search must clear and WantsRawKeys back to false")
}

// TestUsersScreen_sort_cycle — UI-SPEC line 214: 5 successive `s` presses
// must cycle through username → uid → last-login → first-seen-IP →
// allowlist-count → username and back. The footer renders the active sort
// label so View() can be substring-asserted.
func TestUsersScreen_sort_cycle(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	want := []string{"username", "uid", "last-login", "first-seen-IP", "allowlist-count", "username"}
	require.Contains(t, m.View(), "sort: "+want[0],
		"initial sort axis must be username; got View=%s", m.View())
	for i := 1; i < len(want); i++ {
		_, _ = m.Update(keyPress("s"))
		require.Contains(t, m.View(), "sort: "+want[i],
			"after %d `s` presses, sort axis must be %q; got View=%s", i, want[i], m.View())
	}
}

// TestUsersScreen_sort_reverse_toggles_arrow — `S` toggles the direction;
// the footer renders `↓` (default) or `↑` (reversed).
func TestUsersScreen_sort_reverse_toggles_arrow(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	require.Contains(t, m.View(), "↓", "default sort direction is ↓")
	_, _ = m.Update(keyPress("S"))
	require.Contains(t, m.View(), "↑", "after `S`, direction toggles to ↑")
}

// TestUsersScreen_copy_emits_SetClipboard — pressing `c` on a loaded row
// returns a non-nil tea.Cmd; invoking it produces a tea.BatchMsg containing
// at minimum the SetClipboard command. We assert by introspecting the
// returned message — for SetClipboard specifically Bubble Tea v2 returns
// a tea.SetClipboardMsg as the underlying tea.Msg.
func TestUsersScreen_copy_emits_SetClipboard(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{
		Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice",
		KeysCount: 2, IPAllowlistCount: 1,
	}}, nil)
	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd, "`c` on a loaded row must emit a tea.Cmd")
	msg := cmd()
	// tea.Batch → tea.BatchMsg, which is a slice of tea.Cmd. Walk it and
	// look for any sub-cmd that produces a SetClipboardMsg.
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)
	foundClipboard := false
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		if _, isClip := sub().(tea.SetClipboardMsg); isClip {
			foundClipboard = true
			break
		}
	}
	require.True(t, foundClipboard, "batch must include a SetClipboardMsg command")
}

// TestUsersScreen_copy_no_op_when_no_rows — `c` with no rows must not panic
// and must not emit a SetClipboard.
func TestUsersScreen_copy_no_op_when_no_rows(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest(nil, nil)
	_, cmd := m.Update(keyPress("c"))
	if cmd == nil {
		return // acceptable: nothing to copy → no cmd
	}
	// If a cmd is returned it must NOT be a clipboard cmd.
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			if sub == nil {
				continue
			}
			_, isClip := sub().(tea.SetClipboardMsg)
			require.False(t, isClip, "no rows → no clipboard write")
		}
	}
}

// TestUsersScreen_empty_state — UI-SPEC line 354: "No SFTP users found."
func TestUsersScreen_empty_state(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest(nil, nil)
	require.Contains(t, m.View(), "No SFTP users found.")
}

// TestUsersScreen_esc_pops — UI-SPEC §S-USERS: esc/q pops back to home.
func TestUsersScreen_esc_pops(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	nm, ok := cmd().(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", cmd())
	require.Equal(t, nav.Pop, nm.Intent)
}

func TestUsersScreen_q_pops(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	_, cmd := m.Update(keyPress("q"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// TestUsersScreen_cursor_movement — j/k (and arrow keys) move the cursor
// among the real-row indices; selected row carries a marker (e.g. `▌` or
// reverse-video) so a substring assertion on View can detect it. We rely
// on the cursor position rendering ahead of the username for the selected
// row only.
func TestUsersScreen_cursor_movement(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{
		{Username: "alice", UID: 1001},
		{Username: "bob", UID: 1002},
	}, nil)
	v := m.View()
	// alice is the default (cursor index 0); bob is unselected. Look for the
	// marker `▌` or `>` or reverse-video sequence ahead of one but not the
	// other. The screen impl is free to choose any marker; we assert that
	// switching the cursor relocates the marker.
	_, _ = m.Update(keyPress("j"))
	v2 := m.View()
	require.NotEqual(t, v, v2, "pressing `j` must change View() (cursor moved to bob)")
	require.Contains(t, v2, "alice", "alice still rendered after cursor moves")
	require.Contains(t, v2, "bob", "bob still rendered after cursor moves")
}

// TestUsersScreen_search_filters_rows — typing into the active search
// widget restricts which rows the View renders. After typing `bob`, the
// rendered View must include `bob` and exclude `alice`.
func TestUsersScreen_search_filters_rows(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{
		{Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice"},
		{Username: "bob", UID: 1002, ChrootPath: "/srv/sftp/bob"},
	}, nil)
	// Activate search.
	_, _ = m.Update(keyPress("/"))
	require.True(t, m.WantsRawKeys())
	for _, r := range "bob" {
		_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
	}
	v := m.View()
	require.Contains(t, v, "bob")
	require.False(t, strings.Contains(v, "alice"),
		"search query `bob` must exclude alice; got View=%s", v)
}
