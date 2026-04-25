// Package settingsscreen tests for S-SETTINGS — wave-6 / plan 02-07.
//
// Mirrors the S-USERS / S-FIREWALL / S-LOGS test shape (key helper +
// nav.Screen compile-time check + LoadXForTest seam) per UI-SPEC §S-SETTINGS.
// First WantsRawKeys-true-while-editing surface in the project: every
// edit-mode test verifies the flip.
package settingsscreen_test

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	settingsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/settings"
)

// keyPress mirrors the helper used in S-USERS / S-FIREWALL / S-LOGS tests.
// Special-cases esc / enter / arrow keys so the textinput receives a
// recognisable Code field; everything else is passed as a single rune.
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

// drainCmd recursively unwraps a tea.Cmd by calling it and returning the
// resulting message — a tiny helper so we can inspect what handlers emit
// without writing an entire tea.Program harness.
func drainCmd(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	return cmd()
}

// configPath is the path used in every test — keeps assertions terse.
const configPath = "/etc/sftp-jailer/config.yaml"

// --- nav.Screen contract ----------------------------------------------------

// TestSettingsScreen_implements_nav_Screen — compile-time check that *Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap / WantsRawKeys.
func TestSettingsScreen_implements_nav_Screen(t *testing.T) {
	ops := sysops.NewFake()
	var s nav.Screen = settingsscreen.New(ops, configPath)
	require.Equal(t, "settings", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false in the default (non-editing) state")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestSettingsScreen_loading_state — initial View shows the loading copy.
func TestSettingsScreen_loading_state(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	require.Contains(t, m.View(), "loading config…")
}

// --- LoadSettingsForTest seam + render --------------------------------------

// TestSettingsScreen_LoadSettingsForTest_renders_three_fields — feeding
// settings via the test seam bypasses Init; View must render every field name
// and the corresponding value per UI-SPEC §S-SETTINGS.
func TestSettingsScreen_LoadSettingsForTest_renders_three_fields(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Settings{
		DetailRetentionDays: 90,
		DBMaxSizeMB:         500,
		CompactAfterDays:    90,
	})
	out := m.View()
	for _, label := range []string{"detail_retention_days", "db_max_size_mb", "compact_after_days"} {
		require.Contains(t, out, label, "View must include field label %q", label)
	}
	for _, value := range []string{"90", "500"} {
		require.Contains(t, out, value, "View must include field value %q", value)
	}
}

// TestSettingsScreen_renders_config_path — the footer breadcrumb shows the
// config file path so admins know where the rewritten file lives.
func TestSettingsScreen_renders_config_path(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())
	require.Contains(t, m.View(), configPath)
}

// --- Edit mode entry --------------------------------------------------------

// TestSettingsScreen_e_enters_edit_mode — pressing `e` flips m.editing AND
// flips WantsRawKeys() to true (so the root App forwards digits into the
// textinput rather than acting on global `q`).
func TestSettingsScreen_e_enters_edit_mode(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())

	require.False(t, m.WantsRawKeys(), "precondition: not editing")
	_, _ = m.Update(keyPress("e"))
	require.True(t, m.WantsRawKeys(), "WantsRawKeys must be true after entering edit mode")
}

// TestSettingsScreen_enter_on_field_enters_edit_mode — Enter is a synonym
// for `e` when not editing (per UI-SPEC §S-SETTINGS line 470).
func TestSettingsScreen_enter_on_field_enters_edit_mode(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())

	_, _ = m.Update(keyPress("enter"))
	require.True(t, m.WantsRawKeys(), "Enter on a non-edit-mode row must enter edit mode")
}

// TestSettingsScreen_WantsRawKeys_false_when_not_editing — default state
// returns false so global `q` quits cleanly.
func TestSettingsScreen_WantsRawKeys_false_when_not_editing(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())
	require.False(t, m.WantsRawKeys())
}

// --- Edit mode cancel -------------------------------------------------------

// TestSettingsScreen_esc_in_edit_cancels — Esc in edit mode reverts the
// textinput value (does NOT save) and exits edit mode. The original setting
// remains unchanged in m.settings.
func TestSettingsScreen_esc_in_edit_cancels(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	original := config.Settings{DetailRetentionDays: 90, DBMaxSizeMB: 500, CompactAfterDays: 90}
	m.LoadSettingsForTest(original)

	// Enter edit mode on detail_retention_days (cursor 0 by default).
	_, _ = m.Update(keyPress("e"))
	require.True(t, m.WantsRawKeys())

	// Type some digits — they go into the textinput.
	for _, r := range "999" {
		_, _ = m.Update(keyPress(string(r)))
	}

	// Esc cancels.
	_, _ = m.Update(keyPress("esc"))
	require.False(t, m.WantsRawKeys(), "Esc must exit edit mode")

	// View must still show the original 90 — NOT 999.
	out := m.View()
	require.Contains(t, out, "90")
	// AtomicWriteFile must NEVER have been called on a cancel.
	for _, c := range ops.Calls {
		require.NotEqual(t, "AtomicWriteFile", c.Method, "cancel must not write")
	}
}

// --- Edit mode validation failure -------------------------------------------

// TestSettingsScreen_save_validates_first_and_keeps_edit_on_failure — a
// below-floor value (50 MB on db_max_size_mb) keeps the screen in edit mode
// AND surfaces an inline error AND does NOT write.
func TestSettingsScreen_save_validates_first_and_keeps_edit_on_failure(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Settings{DetailRetentionDays: 90, DBMaxSizeMB: 500, CompactAfterDays: 90})

	// Move cursor to db_max_size_mb (field index 1).
	_, _ = m.Update(keyPress("j"))
	// Enter edit mode.
	_, _ = m.Update(keyPress("e"))
	require.True(t, m.WantsRawKeys())

	// Replace value with "50" (below the 100 MB floor).
	for _, r := range "50" {
		_, _ = m.Update(keyPress(string(r)))
	}
	// Press Enter — attempt save.
	_, _ = m.Update(keyPress("enter"))

	require.True(t, m.WantsRawKeys(), "validation failure must keep the model in edit mode")
	out := m.View()
	require.Contains(t, out, "100", "inline error must mention the 100 MB floor")
	// AtomicWriteFile must NOT have been called.
	for _, c := range ops.Calls {
		require.NotEqual(t, "AtomicWriteFile", c.Method, "validation failure must not write")
	}
}

// --- Edit mode save success -------------------------------------------------

// TestSettingsScreen_save_succeeds_writes_atomically — a valid edit on
// detail_retention_days writes via AtomicWriteFile (the ONLY mutation seam
// per OBS-05 / D-07) and exits edit mode.
func TestSettingsScreen_save_succeeds_writes_atomically(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Settings{DetailRetentionDays: 90, DBMaxSizeMB: 500, CompactAfterDays: 90})

	// Edit detail_retention_days (cursor 0).
	_, _ = m.Update(keyPress("e"))
	for _, r := range "60" {
		_, _ = m.Update(keyPress(string(r)))
	}
	// Save.
	_, cmd := m.Update(keyPress("enter"))
	// Drain the cmd — the production handler emits a tea.Msg from the save
	// goroutine; we feed it back into the model so the post-save state
	// transitions (toast flash, exit edit mode) execute.
	if msg := drainCmd(cmd); msg != nil {
		_, _ = m.Update(msg)
	}

	require.False(t, m.WantsRawKeys(), "successful save must exit edit mode")

	// AtomicWriteFile must have been called exactly once on the configPath.
	var writeCalls int
	for _, c := range ops.Calls {
		if c.Method == "AtomicWriteFile" {
			writeCalls++
			require.Equal(t, configPath, c.Args[0], "AtomicWriteFile must target the config path")
		}
	}
	require.Equal(t, 1, writeCalls, "AtomicWriteFile must have been called exactly once")

	// View should now show "60" (the new value) and a toast for the saved field.
	out := m.View()
	require.Contains(t, out, "60", "View must show the updated value after save")
	require.Contains(t, out, "saved detail_retention_days", "Toast must announce the saved field")
}

// --- KeyMap shape -----------------------------------------------------------

// TestSettingsScreen_keymap_bindings_default — the ShortHelp surface must
// expose movement, edit, and back bindings.
func TestSettingsScreen_keymap_bindings_default(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	km := m.KeyMap()
	short := km.ShortHelp()
	flat := flattenHelp(short)

	require.True(t, containsHelpFor(flat, "edit"), "ShortHelp must include 'edit' binding")
	require.True(t, containsHelpFor(flat, "back"), "ShortHelp must include 'back' binding")
	// Movement binding — accept any of "↑↓", "j", "k" so the helper labels
	// are not over-pinned at the test layer.
	require.True(t,
		containsHelpFor(flat, "move") || containsHelpFor(flat, "↑↓") || containsHelpFor(flat, "j"),
		"ShortHelp must include a movement binding")
}

// --- Cursor movement --------------------------------------------------------

// TestSettingsScreen_j_k_move_cursor — j moves cursor down (within bounds);
// k moves up.
func TestSettingsScreen_j_k_move_cursor(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())

	// Default cursor on field 0 — `> detail_retention_days`.
	out := m.View()
	require.Contains(t, out, "> detail_retention_days", "cursor must start on the first field")

	// j → cursor on field 1 (db_max_size_mb).
	_, _ = m.Update(keyPress("j"))
	out = m.View()
	require.Contains(t, out, "> db_max_size_mb", "j must move cursor to the second field")

	// k → back to field 0.
	_, _ = m.Update(keyPress("k"))
	out = m.View()
	require.Contains(t, out, "> detail_retention_days", "k must move cursor back to the first field")
}

// --- Esc outside edit mode pops ---------------------------------------------

// TestSettingsScreen_esc_outside_edit_pops — Esc when not editing returns
// the nav.PopCmd intent (so the parent App pops this screen off the stack).
func TestSettingsScreen_esc_outside_edit_pops(t *testing.T) {
	ops := sysops.NewFake()
	m := settingsscreen.New(ops, configPath)
	m.LoadSettingsForTest(config.Defaults())

	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd, "Esc outside edit mode must emit a tea.Cmd")
	msg := cmd()
	navMsg, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, navMsg.Intent, "Esc must emit Pop")
}

// --- Init triggers config.Load ----------------------------------------------

// TestSettingsScreen_init_loads_via_config_Load — Init returns a tea.Cmd
// that reads from sysops.ReadFile (config.Load's read seam). This pins the
// behaviour: the screen never bypasses the seam.
func TestSettingsScreen_init_loads_via_config_Load(t *testing.T) {
	ops := sysops.NewFake()
	// File missing → config.Load returns Defaults() with nil err. We just
	// assert that the cmd executes ReadFile via ops.
	m := settingsscreen.New(ops, configPath)
	cmd := m.Init()
	require.NotNil(t, cmd, "Init must return a non-nil tea.Cmd")
	_ = cmd() // execute the goroutine body so ReadFile is recorded

	// Drain Calls to find ReadFile on the configPath.
	var found bool
	for _, c := range ops.Calls {
		if c.Method == "ReadFile" && len(c.Args) >= 1 && c.Args[0] == configPath {
			found = true
			break
		}
	}
	require.True(t, found, "Init's tea.Cmd must call ops.ReadFile(configPath); calls: %v", ops.Calls)
}

// --- helpers ---------------------------------------------------------------

func flattenHelp(b []nav.KeyBinding) []nav.KeyBinding { return b }

func containsHelpFor(bindings []nav.KeyBinding, label string) bool {
	for _, b := range bindings {
		if strings.EqualFold(b.Help, label) {
			return true
		}
		for _, k := range b.Keys {
			if strings.EqualFold(k, label) {
				return true
			}
		}
	}
	return false
}

// _ = sysops.SystemOps placeholder kept so the import is honoured even when
// the test list pares down during refactors.
var _ sysops.SystemOps = sysops.NewFake()

// _ = fmt.Sprintf to keep the fmt import alive across compile tweaks.
var _ = fmt.Sprintf
