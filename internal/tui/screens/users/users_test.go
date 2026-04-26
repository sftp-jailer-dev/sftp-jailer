// Package usersscreen tests for S-USERS — the wave-3 first screen, pushed
// from home `u`. Mirrors the doctor screen's test shape (key helper +
// nav.Screen compile-time check + LoadXForTest seam) per UI-SPEC §"Async /
// Loading State Contract" line 313.
package usersscreen_test

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/deleteuser"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/newuser"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/userdetail"
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

// TestUsersScreen_copy_emits_clipboard_cmd — pressing `c` on a loaded row
// returns a non-nil tea.Cmd; invoking it produces a tea.BatchMsg whose
// concatenated message string contains the expected TSV row content. We
// cannot assert on the exact internal SetClipboardMsg type (it is
// unexported in bubbletea v2), so we walk the batch and stringify each
// produced message — the OSC52 setClipboardMsg is `type setClipboardMsg
// string`, so its fmt.Sprintf form contains the row text.
func TestUsersScreen_copy_emits_clipboard_cmd(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest([]users.Row{{
		Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice",
		KeysCount: 2, IPAllowlistCount: 1,
	}}, nil)
	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd, "`c` on a loaded row must emit a tea.Cmd")
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)
	found := false
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		s := fmt.Sprintf("%v", sub())
		if strings.Contains(s, "alice") && strings.Contains(s, "1001") {
			found = true
			break
		}
	}
	require.True(t, found, "batch must include a sub-cmd whose message stringifies to the TSV row content")

	// Toast must announce the OSC 52 copy per UI-SPEC line 301.
	require.Contains(t, m.View(), "copied user row via OSC 52")
}

// TestUsersScreen_copy_no_op_when_no_rows — `c` with no rows must not panic
// and must not emit a clipboard write.
func TestUsersScreen_copy_no_op_when_no_rows(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest(nil, nil)
	_, cmd := m.Update(keyPress("c"))
	if cmd == nil {
		return // acceptable: nothing to copy → no cmd
	}
	// If a cmd is returned, no sub-message must contain a row payload.
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			if sub == nil {
				continue
			}
			s := fmt.Sprintf("%v", sub())
			require.False(t, strings.Contains(s, "/srv/sftp/"),
				"no rows → no clipboard write should ever carry a row payload; got %q", s)
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

// TestUsersScreen_renders_legend_with_threshold_values — UI-SPEC §S-USERS
// password-age legend (02-11 / SC #3 A+): a single muted line below the
// table that explains the four buckets and substitutes the live cfg
// thresholds. The exact wording is part of the contract — admins read
// this to understand the colored "fresh / aging / stale" hints.
func TestUsersScreen_renders_legend_with_threshold_values(t *testing.T) {
	cfg := &config.Settings{PasswordAgingDays: 180, PasswordStaleDays: 365}
	m := usersscreen.NewWithConfig(nil, cfg, nil, "")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	v := m.View()
	require.Contains(t, v,
		"pwd age: ∞ = no expiry policy · fresh < 180d · aging < 365d · stale ≥ 365d",
		"legend wording must substitute cfg thresholds verbatim; got View=%s", v)
}

// TestUsersScreen_renders_legend_with_custom_thresholds — verifies the
// legend reflects whatever the admin configured rather than hardcoded
// defaults. Sanity-check on the substitution path.
func TestUsersScreen_renders_legend_with_custom_thresholds(t *testing.T) {
	cfg := &config.Settings{PasswordAgingDays: 30, PasswordStaleDays: 90}
	m := usersscreen.NewWithConfig(nil, cfg, nil, "")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	v := m.View()
	require.Contains(t, v, "fresh < 30d", "legend must use cfg.PasswordAgingDays")
	require.Contains(t, v, "aging < 90d", "legend must use cfg.PasswordStaleDays for aging cap")
	require.Contains(t, v, "stale ≥ 90d", "legend must use cfg.PasswordStaleDays for stale floor")
}

// TestUsersScreen_renders_indefinite_for_max_99999 — when a row carries
// PasswordMaxDays >= 99999, the rendered "pwd age" cell shows the ∞
// sentinel rather than a numeric "Nd (…)" form.
func TestUsersScreen_renders_indefinite_for_max_99999(t *testing.T) {
	cfg := &config.Settings{PasswordAgingDays: 180, PasswordStaleDays: 365}
	m := usersscreen.NewWithConfig(nil, cfg, nil, "")
	m.LoadRowsForTest([]users.Row{{
		Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice",
		PasswordAgeDays: 50, PasswordMaxDays: 99999,
	}}, nil)
	v := m.View()
	require.Contains(t, v, "∞",
		"PasswordMaxDays>=99999 must render as ∞ in the pwd-age column; got View=%s", v)
	require.NotContains(t, v, "50d",
		"the indefinite branch wins over the numeric branch; got View=%s", v)
}

// TestUsersScreen_renders_status_hint_for_aging — exercises the live
// rendering path for the "Nd (aging)" bucket. Verifies that the screen
// calls FormatPasswordAge rather than the old `Nd` form.
func TestUsersScreen_renders_status_hint_for_aging(t *testing.T) {
	cfg := &config.Settings{PasswordAgingDays: 180, PasswordStaleDays: 365}
	m := usersscreen.NewWithConfig(nil, cfg, nil, "")
	m.LoadRowsForTest([]users.Row{{
		Username: "alice", UID: 1001, ChrootPath: "/srv/sftp/alice",
		PasswordAgeDays: 200, PasswordMaxDays: 90, // bounded max, age ≥ aging, < stale
	}}, nil)
	v := m.View()
	require.Contains(t, v, "(aging)",
		"age=200, aging=180, stale=365 must render the (aging) hint; got View=%s", v)
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

// ============================================================================
// Phase 3 plan 03-07 tests — n / p / Enter-on-INFO + cursor extension
// ============================================================================

// TestUsersScreen_n_keybinding_pushes_new_user_when_ops_set — pressing 'n'
// with ops != nil pushes a *newuser.Model onto the nav stack.
func TestUsersScreen_n_keybinding_pushes_new_user_when_ops_set(t *testing.T) {
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	_, cmd := m.Update(keyPress("n"))
	require.NotNil(t, cmd, "pressing 'n' with ops set must return a Push tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent, "expected Push intent")
	_, isNewUser := nm.Screen.(*newuser.Model)
	require.True(t, isNewUser, "pushed screen must be *newuser.Model, got %T", nm.Screen)
}

// TestUsersScreen_n_keybinding_noop_when_ops_nil — pressing 'n' on a
// model constructed via the legacy New() (ops=nil) is a no-op.
func TestUsersScreen_n_keybinding_noop_when_ops_nil(t *testing.T) {
	m := usersscreen.New(nil)
	m.LoadRowsForTest(nil, nil)
	_, cmd := m.Update(keyPress("n"))
	require.Nil(t, cmd, "pressing 'n' with ops=nil must be a no-op")
}

// TestUsersScreen_p_keybinding_pushes_password_modal_with_selected_username
// — pressing 'p' on a selected real row pushes M-PASSWORD with that user.
func TestUsersScreen_p_keybinding_pushes_password_modal_with_selected_username(t *testing.T) {
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)
	// Cursor defaults to 0 (first real row).
	_, cmd := m.Update(keyPress("p"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok)
	require.Equal(t, nav.Push, nm.Intent)
	pm, isPwModel := nm.Screen.(*password.Model)
	require.True(t, isPwModel, "pushed screen must be *password.Model, got %T", nm.Screen)
	require.Equal(t, "alice", pm.UsernameForTest(),
		"M-PASSWORD must carry the selected row's username")
}

// TestUsersScreen_p_keybinding_noop_when_no_selected_row — pressing 'p'
// with no real rows is a no-op.
func TestUsersScreen_p_keybinding_noop_when_no_selected_row(t *testing.T) {
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest(nil, nil)
	_, cmd := m.Update(keyPress("p"))
	require.Nil(t, cmd, "pressing 'p' with no selectable rows must be a no-op")
}

// TestUsersScreen_enter_on_orphan_INFO_pushes_newuser_NewFromOrphan —
// Enter on an orphan-kind INFO row pushes M-NEW-USER constructed via
// NewFromOrphan (carrying the UID + GID for B-03).
func TestUsersScreen_enter_on_orphan_INFO_pushes_newuser_NewFromOrphan(t *testing.T) {
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest(nil, []users.InfoRow{{
		Kind: users.InfoOrphan, Detail: "/srv/sftp-jailer/orphan99 (no backing system user)",
		Hint: "[fix in Phase 3]",
		Dir:  "/srv/sftp-jailer/orphan99", UID: 5555, GID: 5555,
	}})
	m.SetInfoCursorForTest(0)
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	nu, isNewUser := nm.Screen.(*newuser.Model)
	require.True(t, isNewUser, "pushed screen must be *newuser.Model, got %T", nm.Screen)
	require.True(t, nu.IsOrphanForTest(),
		"Enter-on-orphan-INFO must push NewFromOrphan (isOrphan=true) — B-03 contract")
	require.Equal(t, 5555, nu.OrphanGIDForTest(),
		"orphan GID must propagate from InfoRow into the new-user modal (B-03)")
}

// TestUsersScreen_enter_on_missing_config_INFO_toasts_doctor_pointer —
// Enter on a missing-match / missing-chroot INFO row flashes a toast
// pointing the admin at the doctor [A] action; no Push.
func TestUsersScreen_enter_on_missing_config_INFO_toasts_doctor_pointer(t *testing.T) {
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest(nil, []users.InfoRow{{
		Kind:   users.InfoMissingMatch,
		Detail: "no Match Group sftp* block in any drop-in",
		Hint:   "[fix in Phase 3]",
	}})
	m.SetInfoCursorForTest(0)
	_, cmd := m.Update(keyPress("enter"))
	// Toast.Flash returns a tea.Cmd that ticks expire — we don't drive it
	// (would block 2s). Existence of the cmd + toast text in View is the
	// assertion.
	require.NotNil(t, cmd, "missing-config Enter must Flash a toast")
	require.Contains(t, m.View(), "doctor",
		"missing-config Enter must surface doctor pointer in the toast")
	require.Contains(t, m.View(), "[A]",
		"missing-config Enter must mention the [A] apply action")
}

// TestUsersScreen_KeyMap_includes_New_and_Password_bindings — the KeyMap
// surfaces 'n' (New) and 'p' (Password) bindings with help text.
func TestUsersScreen_KeyMap_includes_New_and_Password_bindings(t *testing.T) {
	km := usersscreen.DefaultKeyMap()
	require.NotEmpty(t, km.New.Keys, "KeyMap.New must have keys")
	require.NotEmpty(t, km.New.Help, "KeyMap.New must have help text")
	require.NotEmpty(t, km.Password.Keys, "KeyMap.Password must have keys")
	require.NotEmpty(t, km.Password.Help, "KeyMap.Password must have help text")
	require.Contains(t, km.New.Keys, "n")
	require.Contains(t, km.Password.Keys, "p")
}

// ============================================================================
// Phase 3 plan 03-08a tests — k / d / Enter-on-real-row routing
// + W-03 regression guards (n/p still wired)
// ============================================================================

// TestUsersScreen_k_keybinding_pushes_userdetail — pressing 'k' on a
// selected real row pushes a *userdetail.Model.
func TestUsersScreen_k_keybinding_pushes_userdetail(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001, ChrootPath: "/srv/sftp-jailer/alice", HomePath: "/srv/sftp-jailer/alice"}}, nil)

	_, cmd := m.Update(keyPress("k"))
	require.NotNil(t, cmd, "pressing 'k' on a selected real row must return a Push tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	ud, isUD := nm.Screen.(*userdetail.Model)
	require.True(t, isUD, "pushed screen must be *userdetail.Model, got %T", nm.Screen)
	require.Equal(t, "alice", ud.UsernameForTest(),
		"S-USER-DETAIL must carry the selected row's username")
}

// TestUsersScreen_d_keybinding_pushes_deleteuser — pressing 'd' on a
// selected real row pushes a *deleteuser.Model.
func TestUsersScreen_d_keybinding_pushes_deleteuser(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001, ChrootPath: "/srv/sftp-jailer/alice", HomePath: "/srv/sftp-jailer/alice"}}, nil)

	_, cmd := m.Update(keyPress("d"))
	require.NotNil(t, cmd, "pressing 'd' on a selected real row must return a Push tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	_, isDU := nm.Screen.(*deleteuser.Model)
	require.True(t, isDU, "pushed screen must be *deleteuser.Model, got %T", nm.Screen)
}

// TestUsersScreen_enter_on_real_row_pushes_userdetail — Enter on a real
// row pushes S-USER-DETAIL (the slot reserved by plan 03-07's
// handleEnter).
func TestUsersScreen_enter_on_real_row_pushes_userdetail(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001, ChrootPath: "/srv/sftp-jailer/alice", HomePath: "/srv/sftp-jailer/alice"}}, nil)
	// Cursor defaults to 0 (real row); infoCursor = -1.

	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd, "Enter on a real row must push S-USER-DETAIL")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok)
	require.Equal(t, nav.Push, nm.Intent)
	_, isUD := nm.Screen.(*userdetail.Model)
	require.True(t, isUD, "Enter on real row pushes *userdetail.Model, got %T", nm.Screen)
}

// TestUsersScreen_k_with_no_selected_row_is_noop_or_navigates — pressing
// 'k' with no real row selected (e.g. cursor on INFO) must NOT push
// S-USER-DETAIL; it falls through to cursor-up navigation.
func TestUsersScreen_k_with_no_real_row_does_not_push(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest(nil, []users.InfoRow{{Kind: users.InfoOrphan, Detail: "orphan dir", Hint: "[fix in Phase 3]"}})
	m.SetInfoCursorForTest(0)

	_, cmd := m.Update(keyPress("k"))
	if cmd != nil {
		// If a cmd was returned, it must NOT be a Push of *userdetail.Model.
		msg := cmd()
		if nm, ok := msg.(nav.Msg); ok && nm.Intent == nav.Push {
			_, isUD := nm.Screen.(*userdetail.Model)
			require.False(t, isUD,
				"'k' with cursor on INFO row (no selected real row) must NOT push S-USER-DETAIL")
		}
	}
}

// TestUsersScreen_d_with_no_selected_row_is_noop — pressing 'd' with
// cursor on INFO row (or empty list) must be a no-op.
func TestUsersScreen_d_with_no_selected_row_is_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest(nil, nil)

	_, cmd := m.Update(keyPress("d"))
	require.Nil(t, cmd, "pressing 'd' with no rows must be a no-op")
}

// TestUsersScreen_KeyMap_includes_Keys_and_Delete_bindings — KeyMap.Keys
// and KeyMap.Delete fields exist with help text.
func TestUsersScreen_KeyMap_includes_Keys_and_Delete_bindings(t *testing.T) {
	t.Parallel()
	km := usersscreen.DefaultKeyMap()
	require.NotEmpty(t, km.Keys.Keys, "KeyMap.Keys must have keys")
	require.NotEmpty(t, km.Keys.Help, "KeyMap.Keys must have help text")
	require.NotEmpty(t, km.Delete.Keys, "KeyMap.Delete must have keys")
	require.NotEmpty(t, km.Delete.Help, "KeyMap.Delete must have help text")
	require.Contains(t, km.Keys.Keys, "k")
	require.Contains(t, km.Delete.Keys, "d")
}

// TestUsersScreen_KeyMap_preserves_New_and_Password_bindings_from_03_07
// — W-03 regression guard. KeyMap.New AND KeyMap.Password fields must
// STILL exist after plan 03-08a's wiring change. If a regression deletes
// the n/p bindings this test fails to build.
func TestUsersScreen_KeyMap_preserves_New_and_Password_bindings_from_03_07(t *testing.T) {
	t.Parallel()
	km := usersscreen.DefaultKeyMap()
	require.NotEmpty(t, km.New.Keys, "W-03: KeyMap.New must STILL exist after plan 03-08a wiring change")
	require.NotEmpty(t, km.Password.Keys, "W-03: KeyMap.Password must STILL exist")
	require.Contains(t, km.New.Keys, "n", "W-03: 'n' binding still present")
	require.Contains(t, km.Password.Keys, "p", "W-03: 'p' binding still present")
}

// TestUsersScreen_n_and_p_keybindings_still_route_to_newuser_and_password
// — W-03 regression guard. Re-execute the corresponding plan-03-07
// dispatch behavior against the new code: 'n' still pushes
// *newuser.Model; 'p' on a selected row still pushes *password.Model.
func TestUsersScreen_n_and_p_keybindings_still_route_to_newuser_and_password(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	cfg := config.Defaults()
	m := usersscreen.NewWithConfig(nil, &cfg, f, "/srv/sftp-jailer")
	m.LoadRowsForTest([]users.Row{{Username: "alice", UID: 1001}}, nil)

	// W-03: 'n' still pushes M-NEW-USER.
	_, cmd := m.Update(keyPress("n"))
	require.NotNil(t, cmd, "W-03: 'n' must STILL push M-NEW-USER after plan 03-08a")
	nm := cmd().(nav.Msg)
	_, isNU := nm.Screen.(*newuser.Model)
	require.True(t, isNU, "W-03: 'n' pushed screen must STILL be *newuser.Model")

	// W-03: 'p' on the selected row still pushes M-PASSWORD.
	_, cmd2 := m.Update(keyPress("p"))
	require.NotNil(t, cmd2, "W-03: 'p' must STILL push M-PASSWORD after plan 03-08a")
	nm2 := cmd2().(nav.Msg)
	_, isPW := nm2.Screen.(*password.Model)
	require.True(t, isPW, "W-03: 'p' pushed screen must STILL be *password.Model")
}
