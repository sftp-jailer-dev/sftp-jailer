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
//   - Plus one Phase 3 dispatch row (USER-13): password_authentication.
//     Unlike the editable rows, this row's value lives in
//     /etc/ssh/sshd_config.d/50-sftp-jailer.conf (NOT config.yaml) and
//     pressing Enter pushes M-DISABLE-PWAUTH onto the nav stack rather
//     than entering inline-edit mode (D-16: the safety rail is in the
//     modal's preflight + override gate, not in a free-text edit).
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
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/pwauthdisable"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// fieldKind enumerates the editable retention rows plus the Phase 3 USER-13
// dispatch row. Order matches UI-SPEC §S-SETTINGS — the cursor cycle goes
// top-to-bottom from detail_retention_days through password_authentication.
//
// Editable rows live in /etc/sftp-jailer/config.yaml and route through
// inline edit-mode → config.Save. The dispatch row (fieldPasswordAuthN)
// is fundamentally different: its value lives in
// /etc/ssh/sshd_config.d/50-sftp-jailer.conf, so pressing Enter on it
// pushes M-DISABLE-PWAUTH instead of entering inline-edit mode (D-16:
// the modal carries the preflight + override gate; this row is just the
// entry point).
type fieldKind int

const (
	// fieldDetail is the detail_retention_days knob (default 90).
	fieldDetail fieldKind = iota
	// fieldDBMax is the db_max_size_mb knob (default 500).
	fieldDBMax
	// fieldCompact is the compact_after_days knob (default = detail_retention_days).
	fieldCompact
	// fieldPasswordAuthN is the Phase 3 USER-13 dispatch row. Pressing
	// Enter here pushes M-DISABLE-PWAUTH onto the nav stack with an
	// Action chosen from m.pwAuthCurrent (yes → ActionDisable, no →
	// ActionEnable, unknown → ActionDisable as the safest default since
	// the modal's preflight will surface the lockout risk before any
	// write).
	fieldPasswordAuthN
	// fieldLockdownWindow is the Phase 4 LOCK-04 / D-L0204-01 knob —
	// observation lookback window the LOCK-02 proposal generator uses.
	// Routes through the standard inline-edit mechanic (textinput +
	// validate-on-Enter + atomic Save). Default 90; range [1, 3650].
	fieldLockdownWindow

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
	case fieldPasswordAuthN:
		return "password_authentication"
	case fieldLockdownWindow:
		return "lockdown.proposal_window_days"
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
	case fieldPasswordAuthN:
		return "(globally allow / disallow password auth — managed users without keys block disable)"
	case fieldLockdownWindow:
		return "days (proposal lookback; default 90)"
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

// pwAuthLoadedMsg (Phase 3 / USER-13) carries the live sshd -T value of
// passwordauthentication back from the Init's async dump. value is one of
// "yes", "no", or "unknown" (the latter when SshdDumpConfig errors or the
// directive is absent — both of which mean we cannot pre-compute the modal
// Action and must fall back to the safer ActionDisable when the admin
// presses Enter).
type pwAuthLoadedMsg struct {
	value string
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

	// Phase 3 USER-13 — dependencies + cached live state for the
	// fieldPasswordAuthN dispatch row. usersEnum + chrootRoot are passed
	// straight through to pwauthdisable.New on Push; pwAuthCurrent is
	// populated by Init's async sshd -T branch.
	usersEnum     *users.Enumerator
	chrootRoot    string
	pwAuthCurrent string // "yes" | "no" | "unknown"

	// Toast (save confirmation) and key bindings.
	toast widgets.Toast
	keys  KeyMap
	width int
}

// New constructs the screen wired to ops + the absolute config-file path
// + the Phase 3 dependencies needed by the fieldPasswordAuthN dispatch
// row (M-DISABLE-PWAUTH preflight enumerates sftp-group users via
// usersEnum and walks per-user authorized_keys under chrootRoot).
//
// ops may be nil in unit tests that drive the screen via
// LoadSettingsForTest; path is required even in tests because the View
// shows it. usersEnum / chrootRoot may be nil/"" in tests that do not
// exercise the fieldPasswordAuthN dispatch path.
func New(ops sysops.SystemOps, path string, usersEnum *users.Enumerator, chrootRoot string) *Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 8 // 99999999 — way more than any retention or MB knob.
	return &Model{
		ops:           ops,
		path:          path,
		loading:       true,
		ti:            ti,
		keys:          DefaultKeyMap(),
		usersEnum:     usersEnum,
		chrootRoot:    chrootRoot,
		pwAuthCurrent: "unknown", // until pwAuthLoadedMsg arrives
	}
}

// Init kicks off the async config.Load PLUS the Phase 3 sshd -T dump that
// surfaces the live PasswordAuthentication value into the dispatch row.
// If ops is nil (test path), Init returns nil — the test is expected to
// call LoadSettingsForTest (and optionally feed pwAuthLoadedMsg) before
// any View().
func (m *Model) Init() tea.Cmd {
	ops, path := m.ops, m.path
	if ops == nil {
		return nil
	}
	loadCmd := func() tea.Msg {
		// Generous timeout — config.Load reads a tiny YAML file via the
		// sysops seam. 30s mirrors the doctor / users defensive bound.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := config.Load(ctx, ops, path)
		return settingsLoadedMsg{settings: s, err: err}
	}
	pwAuthCmd := func() tea.Msg {
		// `sshd -T` (no -C) reports global directives only — exactly what
		// we need for the top-level PasswordAuthentication value. Any
		// error or absent key collapses to "unknown" so the row still
		// renders something the admin can act on.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := ops.SshdDumpConfig(ctx)
		if err != nil {
			return pwAuthLoadedMsg{value: "unknown"}
		}
		vals, ok := cfg["passwordauthentication"]
		if !ok || len(vals) == 0 {
			return pwAuthLoadedMsg{value: "unknown"}
		}
		v := strings.ToLower(strings.TrimSpace(vals[0]))
		if v != "yes" && v != "no" {
			return pwAuthLoadedMsg{value: "unknown"}
		}
		return pwAuthLoadedMsg{value: v}
	}
	return tea.Batch(loadCmd, pwAuthCmd)
}

// LoadSettingsForTest bypasses Init and sets the loaded state directly.
// Mirrors usersscreen.LoadRowsForTest / firewallscreen.LoadRulesForTest.
func (m *Model) LoadSettingsForTest(s config.Settings) {
	m.loading = false
	m.loadErr = ""
	m.settings = s
}

// SetPwAuthCurrentForTest pokes the cached sshd -T value of
// passwordauthentication so tests can drive the fieldPasswordAuthN
// dispatch row without staging a Fake SshdConfigResponse + waiting on
// the async pwAuthLoadedMsg. Accepted: "yes", "no", "unknown" — any
// other value is normalised to "unknown" (matching pwAuthLoadedMsg's
// own clamp in Init).
func (m *Model) SetPwAuthCurrentForTest(value string) {
	switch value {
	case "yes", "no", "unknown":
		m.pwAuthCurrent = value
	default:
		m.pwAuthCurrent = "unknown"
	}
}

// PwAuthCurrentForTest exposes the cached value for assertions.
func (m *Model) PwAuthCurrentForTest() string { return m.pwAuthCurrent }

// CursorForTest exposes the cursor index as an int so tests in the _test
// package can drive the row selection without leaking the private
// fieldKind type.
func (m *Model) CursorForTest() int { return int(m.cursor) }

// SetCursorForTest pokes the cursor to a specific row index. Bounded to
// the legal range; out-of-range values clamp to fieldDetail (0).
func (m *Model) SetCursorForTest(idx int) {
	if idx < 0 || fieldKind(idx) >= fieldKindCount {
		m.cursor = fieldDetail
		return
	}
	m.cursor = fieldKind(idx)
}

// PasswordAuthNRowIndexForTest exposes the field-row index for
// fieldPasswordAuthN so tests can SetCursor + assert without depending on
// the enum's iota position drifting in a future refactor.
const PasswordAuthNRowIndexForTest = int(fieldPasswordAuthN)

// LockdownWindowRowIndexForTest exposes the field-row index for
// fieldLockdownWindow (Phase 4 / LOCK-04) so tests can SetCursor +
// assert without depending on the enum's iota position drifting.
const LockdownWindowRowIndexForTest = int(fieldLockdownWindow)

// EditingForTest exposes the inline-edit-mode flag for assertions.
func (m *Model) EditingForTest() bool { return m.editing }

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

	case pwAuthLoadedMsg:
		// Phase 3 USER-13 — cache the live value for the dispatch row.
		// "unknown" is a legal terminal value (caller handles the
		// fall-back to ActionDisable inside handleNavKey).
		m.pwAuthCurrent = msg.value
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
		// Phase 3 USER-13 — fieldPasswordAuthN dispatches to
		// M-DISABLE-PWAUTH instead of entering inline-edit mode. The
		// modal carries its own preflight + override gate (D-16); we
		// just pick the Action based on the cached live value.
		//
		// Action selection:
		//   "yes" → ActionDisable (the typical USER-13 path)
		//   "no"  → ActionEnable  (re-enable; no preflight gate per D-16)
		//   "unknown" → ActionDisable as the safe default — the modal's
		//               preflight will surface lockout risk before any
		//               write so even a wrongly-guessed direction still
		//               cannot lock users out without the override.
		if m.cursor == fieldPasswordAuthN {
			action := pwauthdisable.ActionDisable
			if m.pwAuthCurrent == "no" {
				action = pwauthdisable.ActionEnable
			}
			return m, nav.PushCmd(pwauthdisable.New(m.ops, m.usersEnum, m.chrootRoot, action))
		}
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
	case fieldLockdownWindow:
		return m.settings.LockdownProposalWindowDays
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
	case fieldLockdownWindow:
		return m.settings.LockdownProposalWindowDays
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
	case fieldLockdownWindow:
		candidate.LockdownProposalWindowDays = v
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

	// Render the field rows. Editable rows render their numeric value via
	// valueFor; the Phase 3 dispatch row (fieldPasswordAuthN) renders the
	// cached sshd -T value with a Dim/Warn/Success colour cue and never
	// shows the textinput (m.editing is false-by-construction for it
	// because the dispatch path skips the inline edit-mode toggle).
	for k := fieldDetail; k < fieldKindCount; k++ {
		marker := "  "
		if k == m.cursor {
			marker = "> "
		}
		var valStr string
		switch {
		case k == fieldPasswordAuthN:
			// Dispatch row — render the cached sshd -T value with a
			// directional colour cue: yes=Warn (an open footgun), no=Success
			// (the safe state), unknown=Dim (we couldn't tell).
			switch m.pwAuthCurrent {
			case "yes":
				valStr = styles.Warn.Render("yes")
			case "no":
				valStr = styles.Success.Render("no")
			default:
				valStr = styles.Dim.Render("unknown")
			}
		case k == m.cursor && m.editing:
			valStr = "[" + m.ti.View() + "]"
		default:
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
