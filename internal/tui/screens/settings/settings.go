// Package settingsscreen renders the writable retention-settings form per
// CONTEXT.md D-07 / OBS-05. This is the ONLY mutation surface in Phase 2;
// writes /etc/sftp-jailer/config.yaml exclusively via internal/config.Save
// which routes through internal/sysops.AtomicWriteFile.
//
// First WantsRawKeys-true-while-editing surface in the project: while
// m.editing is true, the screen returns true from WantsRawKeys() so the
// root App forwards every key (including `q`) into the textinput rather
// than quitting the program. This mirrors the pattern home.go ships for
// its search widget (see internal/tui/screens/home/home.go::WantsRawKeys).
//
// UI per UI-SPEC §S-SETTINGS (lines 453-493):
//   - Three editable rows: detail_retention_days, db_max_size_mb, compact_after_days
//   - Cursor row prefixed with `> `; non-cursor rows prefixed with `  `
//   - Edit mode: cursor row renders `> name [value▌]` with the textinput focused
//   - Save toast: `saved <field-name>` (e.g. `saved db_max_size_mb`)
//   - Inline validation error: `must be …` in styles.Warn under the field
//   - Inline save error: `cannot save: {err}` in styles.Critical
//   - Footer (default): `↑↓·move  e·edit  esc·back`
//   - Footer (edit mode): `enter·save  esc·cancel  ?·rules`
//
// Architectural invariants:
//   - This package never imports os or os/exec. Every file write flows
//     through config.Save → sysops.AtomicWriteFile.
//   - The `scripts/check-no-raw-config-write.sh` CI guard (shipped in
//     plan 02-07 Task 2) enforces this contract at the build layer.
package settingsscreen

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/textinput"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// fieldKind enumerates the three editable retention rows. Order matches
// UI-SPEC §S-SETTINGS — the cursor cycle goes top-to-bottom from
// detail_retention_days to compact_after_days.
type fieldKind int

const (
	// fieldDetail is the detail_retention_days knob (default 90).
	fieldDetail fieldKind = iota
	// fieldDBMax is the db_max_size_mb knob (default 500).
	fieldDBMax
	// fieldCompact is the compact_after_days knob (default = detail_retention_days).
	fieldCompact

	// fieldKindCount is the modulus sentinel for cursor wrap math; place
	// new fields BEFORE this constant.
	fieldKindCount
)

// name returns the snake_case yaml key for a field — also the toast suffix
// shown after a successful save.
func (k fieldKind) name() string {
	switch k {
	case fieldDetail:
		return "detail_retention_days"
	case fieldDBMax:
		return "db_max_size_mb"
	case fieldCompact:
		return "compact_after_days"
	}
	return "unknown"
}

// hint is the right-side dimmed annotation per UI-SPEC line 461-463.
func (k fieldKind) hint() string {
	switch k {
	case fieldDetail:
		return "(default 90)"
	case fieldDBMax:
		return "(default 500)"
	case fieldCompact:
		return "(must be ≤ detail_retention_days)"
	}
	return ""
}

// settingsLoadedMsg carries the config.Load result from Init's goroutine
// back into Update.
type settingsLoadedMsg struct {
	settings config.Settings
	err      error
}

// savedMsg carries the config.Save outcome from the goroutine that performs
// the atomic write back into Update so the post-save state transitions
// (clear edit mode + flash toast) execute on the main loop.
type savedMsg struct {
	settings config.Settings
	field    fieldKind
	err      error
}

// Model is the S-SETTINGS Bubble Tea v2 model.
type Model struct {
	ops  sysops.SystemOps
	path string

	// Loaded state.
	settings config.Settings
	loading  bool
	loadErr  string

	// Edit-mode state.
	cursor    fieldKind
	editing   bool
	ti        textinput.Model
	errInline string // either validation Warn copy or Critical save-error copy
	errFatal  bool   // true when errInline should render in Critical (save-error)

	// Toast (save confirmation) and key bindings.
	toast widgets.Toast
	keys  KeyMap
	width int
}

// New constructs the screen wired to ops + the absolute config-file path.
// ops may be nil in unit tests that drive the screen via LoadSettingsForTest;
// path is required even in tests because the View shows it.
func New(ops sysops.SystemOps, path string) *Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 8 // 99999999 — way more than any retention or MB knob.
	return &Model{
		ops:     ops,
		path:    path,
		loading: true,
		ti:      ti,
		keys:    DefaultKeyMap(),
	}
}

// Init kicks off the async config.Load. If ops is nil (test path), Init
// returns nil — the test is expected to call LoadSettingsForTest before
// any View().
func (m *Model) Init() tea.Cmd {
	ops, path := m.ops, m.path
	if ops == nil {
		return nil
	}
	return func() tea.Msg {
		// Generous timeout — config.Load reads a tiny YAML file via the
		// sysops seam. 30s mirrors the doctor / users defensive bound.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := config.Load(ctx, ops, path)
		return settingsLoadedMsg{settings: s, err: err}
	}
}

// LoadSettingsForTest bypasses Init and sets the loaded state directly.
// Mirrors usersscreen.LoadRowsForTest / firewallscreen.LoadRulesForTest.
func (m *Model) LoadSettingsForTest(s config.Settings) {
	m.loading = false
	m.loadErr = ""
	m.settings = s
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "settings" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the textinput is focused
// (m.editing) so the root App forwards every keystroke (including `q` and
// digits) into the input rather than acting on global key bindings.
//
// First WantsRawKeys-true-while-editing surface in the codebase. Pattern
// is reusable for any future write-form screen.
func (m *Model) WantsRawKeys() bool { return m.editing }

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case settingsLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.loadErr = msg.err.Error()
			return m, nil
		}
		m.settings = msg.settings
		return m, nil

	case savedMsg:
		if msg.err != nil {
			// Surface the save error inline (Critical styling) and stay in
			// edit mode so the admin can retry without re-entering edit.
			m.errInline = "cannot save: " + msg.err.Error()
			m.errFatal = true
			return m, nil
		}
		// Successful save: replace settings, clear edit mode, flash toast.
		m.settings = msg.settings
		m.editing = false
		m.errInline = ""
		m.errFatal = false
		m.ti.Blur()
		m.ti.SetValue("")
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("saved " + msg.field.name())
		return m, flashCmd

	case tea.KeyPressMsg:
		if m.editing {
			return m.handleEditKey(msg)
		}
		return m.handleNavKey(msg)
	}

	// Toast TTL — every non-key, non-load message lets the toast tick down.
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleNavKey routes key presses when NOT in edit mode.
func (m *Model) handleNavKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "j", "down":
		if m.cursor < fieldKindCount-1 {
			m.cursor++
		}
		return m, nil
	case "k", "up":
		if m.cursor > fieldDetail {
			m.cursor--
		}
		return m, nil
	case "e", "enter":
		// Enter edit mode — focus the textinput. The current value is
		// rendered as the textinput's placeholder so the admin sees what
		// they're replacing; pressing keys appends to an empty input. This
		// keeps the typing semantics simple (no in-place edit-cursor
		// shenanigans) and matches the UI-SPEC line 476 example where the
		// admin types a fresh number to replace the old one.
		m.editing = true
		m.errInline = ""
		m.errFatal = false
		m.ti.SetValue("")
		m.ti.Placeholder = strconv.Itoa(m.currentValue())
		return m, m.ti.Focus()
	}
	return m, nil
}

// handleEditKey routes key presses when m.editing is true. Esc cancels
// without saving; Enter attempts a save (validates first); every other key
// types into the textinput.
func (m *Model) handleEditKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Cancel — restore the textinput state but do NOT touch m.settings.
		m.editing = false
		m.errInline = ""
		m.errFatal = false
		m.ti.SetValue("")
		m.ti.Blur()
		return m, nil
	case "enter":
		return m, m.attemptSave()
	}
	// Forward to the textinput so digits land in the input value.
	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

// currentValue returns the current value for the cursor field.
func (m *Model) currentValue() int {
	switch m.cursor {
	case fieldDetail:
		return m.settings.DetailRetentionDays
	case fieldDBMax:
		return m.settings.DBMaxSizeMB
	case fieldCompact:
		return m.settings.CompactAfterDays
	}
	return 0
}

// valueFor returns the value for an arbitrary field (used by the row
// renderer in View — independent of cursor position).
func (m *Model) valueFor(k fieldKind) int {
	switch k {
	case fieldDetail:
		return m.settings.DetailRetentionDays
	case fieldDBMax:
		return m.settings.DBMaxSizeMB
	case fieldCompact:
		return m.settings.CompactAfterDays
	}
	return 0
}

// attemptSave validates the candidate settings (with the pending edit
// applied) and, on success, returns a tea.Cmd that performs the atomic
// write off the main loop. On validation failure the inline error is set
// and nil is returned (no save happens).
func (m *Model) attemptSave() tea.Cmd {
	v, err := strconv.Atoi(strings.TrimSpace(m.ti.Value()))
	if err != nil {
		m.errInline = "must be a positive integer"
		m.errFatal = false
		return nil
	}
	candidate := m.settings
	switch m.cursor {
	case fieldDetail:
		candidate.DetailRetentionDays = v
	case fieldDBMax:
		candidate.DBMaxSizeMB = v
	case fieldCompact:
		candidate.CompactAfterDays = v
	}
	if errs := config.Validate(candidate); len(errs) > 0 {
		// First error per field is the most relevant — surfaces the
		// floor/ceiling/range message to the admin.
		m.errInline = errs[0].Error()
		m.errFatal = false
		return nil
	}
	// Validation passed — perform the atomic write off the main loop. The
	// goroutine emits a savedMsg back into Update.
	ops, path, field := m.ops, m.path, m.cursor
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := config.Save(ctx, ops, path, candidate)
		return savedMsg{settings: candidate, field: field, err: err}
	}
}

// View renders the screen.
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("loading config…")
	}
	if m.loadErr != "" {
		return styles.Critical.Render("Could not load config: "+m.loadErr) +
			"\n\n" + styles.Dim.Render("(esc to return)")
	}

	var b strings.Builder
	b.WriteString(styles.Primary.Render("settings — retention"))
	b.WriteString("\n\n")

	// Render the three field rows.
	for k := fieldDetail; k < fieldKindCount; k++ {
		marker := "  "
		if k == m.cursor {
			marker = "> "
		}
		var valStr string
		if k == m.cursor && m.editing {
			valStr = "[" + m.ti.View() + "]"
		} else {
			valStr = strconv.Itoa(m.valueFor(k))
		}
		row := fmt.Sprintf("%s%-22s %-12s %s",
			marker, k.name(), valStr, styles.Dim.Render(k.hint()))
		if k == m.cursor && !m.editing {
			row = styles.Primary.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")

		// Inline error under the cursor row.
		if k == m.cursor && m.errInline != "" {
			style := styles.Warn
			if m.errFatal {
				style = styles.Critical
			}
			b.WriteString("    ")
			b.WriteString(style.Render(m.errInline))
			b.WriteString("\n")
		}
	}

	// Separator + config-path breadcrumb (UI-SPEC §S-SETTINGS lines 465-467).
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render("  ─────────────────────────────────────────────"))
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render("  config file: " + m.path))
	b.WriteString("\n")

	// Footer — different copy depending on edit mode.
	b.WriteString("\n")
	if m.editing {
		b.WriteString(styles.Dim.Render("enter·save  esc·cancel  ?·rules"))
	} else {
		b.WriteString(styles.Dim.Render("↑↓·move  e·edit  esc·back"))
	}

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return b.String()
}

// KeyMap holds the S-SETTINGS bindings — implements nav.KeyMap.
type KeyMap struct {
	Move        nav.KeyBinding
	Edit        nav.KeyBinding
	SaveOrEnter nav.KeyBinding
	Cancel      nav.KeyBinding
	Rules       nav.KeyBinding
}

// DefaultKeyMap returns the canonical S-SETTINGS bindings per UI-SPEC §S-SETTINGS.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Move:        nav.KeyBinding{Keys: []string{"↑", "↓", "j", "k"}, Help: "move"},
		Edit:        nav.KeyBinding{Keys: []string{"e"}, Help: "edit"},
		SaveOrEnter: nav.KeyBinding{Keys: []string{"enter"}, Help: "save"},
		Cancel:      nav.KeyBinding{Keys: []string{"esc"}, Help: "back"},
		Rules:       nav.KeyBinding{Keys: []string{"?"}, Help: "rules"},
	}
}

// ShortHelp surfaces the bindings for the footer / `?` overlay's compact
// mode. Mirrors the per-screen shape: nav + primary action + back.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Move, k.Edit, k.Cancel}
}

// FullHelp returns the two-row layout: navigation + edit on row 1, and
// cancel + rules on row 2.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Move, k.Edit, k.SaveOrEnter},
		{k.Cancel, k.Rules},
	}
}
