// Package usersscreen renders the SFTP users overview as a TUI screen
// pushed onto the nav stack by the home screen's `u` binding.
//
// Mirrors the doctor screen's async-load + LoadXForTest seam pattern
// (see internal/tui/screens/doctor/doctor.go and the 01-04 SUMMARY
// "async Run in TUI screen" decision):
//
//   - Init() returns a tea.Cmd that calls users.Enumerator.Enumerate on a
//     background goroutine and emits a rowsLoadedMsg back to Update.
//   - LoadRowsForTest(rows, infos) bypasses the tea.Cmd for unit tests
//     so screen logic (search, sort, copy) is exercised without the I/O.
//
// UI per UI-SPEC §S-USERS:
//   - INFO pseudo-rows (D-12) render at the top of the table in styles.Info
//     with the literal "[fix in Phase 3]" hint.
//   - Real rows show user / uid / chroot / pwd-age / keys / last-login /
//     first-seen-IP / IP-allowlist count.
//   - `/` opens fuzzy search (USER-02); `Esc` cancels search.
//   - `s` cycles sort axis, `S` toggles direction; footer renders
//     "sort: <axis> <↓|↑>".
//   - `c` copies the selected row as TSV via OSC 52 (tea.SetClipboard);
//     toast flashes "copied user row via OSC 52".
//   - `Enter` is reserved for the user-detail modal (deferred — Phase 2 ships
//     list-only per UI-SPEC line 162); `Enter` is currently a no-op.
//
// This package never imports os/exec or os directly — every system read flows
// through users.Enumerator (which itself uses sysops). The package is a
// presentation layer wrapped around the data layer shipped in 02-03.
package usersscreen

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/dustin/go-humanize"
	"github.com/sahilm/fuzzy"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/deleteuser"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/newuser"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/userdetail"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// deleteUserFwRulesFactory is the package-level seam for Plan 04-06 to
// inject the M-DELETE-RULE-by-user constructor. Mirrors the
// home.SetXFactory pattern from 02-04 and the firewallrule plan-04-05
// seam — pressing 'D' (uppercase, W1 keybind deviation) on a selected
// real row invokes the factory with the username.
//
// W1 deviation: lowercase 'd' is reserved for Phase 3 03-08a's
// M-DELETE-USER (delete user account); uppercase 'D' is the new path
// for "delete all firewall rules for this user" so muscle memory from
// the UAT-validated Phase 3 flow is preserved. CONTEXT.md
// "Integration Points" amended to reflect the resolved keybind.
//
// nil-factory path is a no-op (e.g. test paths that don't exercise
// the FW-rule delete).
var deleteUserFwRulesFactory func(username string) nav.Screen

// SetDeleteUserFwRulesFactory registers the M-DELETE-RULE-by-user
// constructor. Called once at TUI bootstrap. Pass nil to clear (test
// cleanup).
func SetDeleteUserFwRulesFactory(fn func(username string) nav.Screen) {
	deleteUserFwRulesFactory = fn
}

// SortAxis enumerates the columns the `s` cycle rotates through.
//
// Order matches UI-SPEC §S-USERS line 214:
//
//	username → uid → last-login → first-seen-IP → allowlist-count → username
//
// SortAxisCount is the modulus used to wrap the cycle.
type SortAxis int

const (
	// SortByUsername sorts by Username (alphabetical, case-insensitive).
	SortByUsername SortAxis = iota
	// SortByUID sorts by UID (numeric).
	SortByUID
	// SortByLastLogin sorts by LastLoginNs (ns timestamp; 0 = never).
	SortByLastLogin
	// SortByFirstSeenIP sorts by FirstSeenIP (string, empty last).
	SortByFirstSeenIP
	// SortByAllowlistCount sorts by IPAllowlistCount (numeric).
	SortByAllowlistCount

	// SortAxisCount is the number of distinct sort axes — used for the `s`
	// cycle modulus. Place new axes BEFORE this sentinel.
	SortAxisCount
)

// label returns the footer label per UI-SPEC line 401 ("sort: last-login ↓").
func (s SortAxis) label() string {
	switch s {
	case SortByUsername:
		return "username"
	case SortByUID:
		return "uid"
	case SortByLastLogin:
		return "last-login"
	case SortByFirstSeenIP:
		return "first-seen-IP"
	case SortByAllowlistCount:
		return "allowlist-count"
	}
	return "username"
}

// rowsLoadedMsg carries the enumerate result back to Update.
type rowsLoadedMsg struct {
	rows  []users.Row
	infos []users.InfoRow
	err   error
}

// Model is the S-USERS Bubble Tea v2 model.
type Model struct {
	enum *users.Enumerator

	// cfg drives the password-age column legend + per-row formatting.
	// Never nil after construction — New / NewWithConfig fall back to
	// config.Defaults() when called with a nil pointer.
	cfg *config.Settings

	// Phase 3 plan 03-07: ops + chrootRoot enable the n / p / Enter-on-INFO
	// flows that push M-NEW-USER and M-PASSWORD modals onto the nav stack.
	// Both are nil-tolerant: when ops is nil (legacy New / test path) the
	// 'n' / 'p' / Enter-on-INFO handlers no-op so existing tests stay green.
	ops        sysops.SystemOps
	chrootRoot string

	// Loaded data — populated either from rowsLoadedMsg or LoadRowsForTest.
	rows    []users.Row
	infos   []users.InfoRow
	loading bool
	errText string

	// Filtered view of `rows`. When search is empty/inactive this is the
	// same slice as `rows`. The cursor indexes into `filtered`, NOT `rows`.
	filtered []users.Row

	// UI state.
	cursor         int
	sortAxis       SortAxis
	sortDescending bool
	search         widgets.Search
	toast          widgets.Toast
	keys           KeyMap
	width          int

	// Phase 3 plan 03-07: infoCursor extends the cursor across the INFO
	// pseudo-rows. -1 = cursor is on a real row (m.cursor); >= 0 = cursor
	// is on infos[infoCursor] (Enter routes to the kind-specific handler).
	// j/k navigation cycles infos → filtered → infos (wrap) — see
	// handleNavKey for the math.
	infoCursor int
}

// New constructs the screen wired to enum (the data-layer composer shipped
// in 02-03). enum may be nil in unit tests that drive the screen via
// LoadRowsForTest. The password-age thresholds default to
// config.Defaults() — callers that have a loaded config.Settings should
// use [NewWithConfig] instead.
//
// Phase 3 plan 03-07: this legacy constructor leaves ops + chrootRoot at
// their zero values, which makes the 'n' / 'p' / Enter-on-INFO handlers
// no-op. Production wiring should use NewWithConfig with the full ops +
// chrootRoot pair so the M-NEW-USER + M-PASSWORD modals are reachable.
func New(enum *users.Enumerator) *Model {
	return NewWithConfig(enum, nil, nil, "")
}

// NewWithConfig is the canonical constructor — accepts the enumerator,
// the loaded *config.Settings (drives the password-age column formatting
// + legend), the SystemOps handle (for the M-NEW-USER + M-PASSWORD
// modal pushes), and the resolved chroot root path. ops + chrootRoot may
// be nil/empty in unit tests; the 'n' / 'p' / Enter-on-INFO handlers
// no-op when ops is nil. A nil cfg falls back to config.Defaults().
func NewWithConfig(enum *users.Enumerator, cfg *config.Settings, ops sysops.SystemOps, chrootRoot string) *Model {
	if cfg == nil {
		d := config.Defaults()
		cfg = &d
	}
	return &Model{
		enum:       enum,
		cfg:        cfg,
		ops:        ops,
		chrootRoot: chrootRoot,
		loading:    true,
		keys:       DefaultKeyMap(),
		search:     widgets.NewSearch(),
		infoCursor: -1,
	}
}

// Init kicks off the async enumerate. If enum is nil (test path), Init
// returns nil — the test is expected to call LoadRowsForTest before any
// View().
func (m *Model) Init() tea.Cmd {
	enum := m.enum
	if enum == nil {
		return nil
	}
	return func() tea.Msg {
		// Use a background context with a generous timeout. Enumerate
		// reads /etc/group + /etc/passwd + sshd_config drop-ins +
		// /var/lib/sftp-jailer/observations.db + ufw status — wall time
		// should be well under 1s on any realistic box, but we cap at 30s
		// to mirror the doctor screen's defensive bound.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rows, infos, err := enum.Enumerate(ctx)
		return rowsLoadedMsg{rows: rows, infos: infos, err: err}
	}
}

// LoadRowsForTest bypasses Init+Enumerate and sets the loaded state
// directly. Mirrors doctorscreen.LoadReportForTest.
func (m *Model) LoadRowsForTest(rows []users.Row, infos []users.InfoRow) {
	m.loading = false
	m.errText = ""
	m.rows = rows
	m.infos = infos
	m.applySortAndFilter()
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "users" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the search textinput is
// focused so the root App forwards letters into the input rather than
// quitting on `q`.
func (m *Model) WantsRawKeys() bool { return m.search.Active }

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case rowsLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.errText = msg.err.Error()
			return m, nil
		}
		m.rows = msg.rows
		m.infos = msg.infos
		m.applySortAndFilter()
		return m, nil

	case tea.KeyPressMsg:
		// Search is greedy when active — every key (except esc) types into
		// the textinput; esc deactivates and clears.
		if m.search.Active {
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			m.applySortAndFilter()
			return m, cmd
		}
		return m.handleKey(msg)
	}

	// Toast TTL.
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey routes key presses when search is inactive.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "/":
		var cmd tea.Cmd
		m.search, cmd = m.search.Activate()
		return m, cmd
	case "s":
		m.sortAxis = (m.sortAxis + 1) % SortAxisCount
		m.applySortAndFilter()
		return m, nil
	case "S":
		m.sortDescending = !m.sortDescending
		m.applySortAndFilter()
		return m, nil
	case "c":
		return m.handleCopy()
	case "n":
		// Phase 3 plan 03-07 / D-11: 'n' pushes M-NEW-USER (fresh-create).
		// Gated on ops != nil so legacy callers (New + LoadRowsForTest in
		// existing tests) stay no-op.
		if m.ops == nil {
			return m, nil
		}
		return m, nav.PushCmd(newuser.New(m.ops, m.chrootRoot))
	case "p":
		// Phase 3 plan 03-07 / D-13: 'p' pushes M-PASSWORD for the
		// selected user (auto-gen mode). No-op when no row is selected
		// or ops is nil.
		if m.ops == nil {
			return m, nil
		}
		r := m.selectedRow()
		if r == nil {
			return m, nil
		}
		return m, nav.PushCmd(password.New(m.ops, r.Username, password.AutoGenerateMode))
	case "k":
		// Phase 3 plan 03-08a / D-22: 'k' pushes S-USER-DETAIL for the
		// selected user (the detail screen carries the keys table +
		// single-key delete UX). No-op when no row is selected or ops is
		// nil. Shadows the existing 'k' as cursor-up only when the
		// cursor is on a real row — j/k navigation is preserved by
		// falling through to the down-case below when there is no
		// row to "open".
		if m.ops != nil {
			if r := m.selectedRow(); r != nil {
				return m, nav.PushCmd(userdetail.New(m.ops, m.chrootRoot, r.Username))
			}
		}
		// Fall through to the j/k cursor-up handler when there is no
		// real-row to open (INFO-row cursor or empty list).
		m.moveCursorUp()
		return m, nil
	case "d":
		// Phase 3 plan 03-08a / D-15: 'd' pushes M-DELETE-USER for the
		// selected user. No-op when no row is selected or ops is nil.
		if m.ops == nil {
			return m, nil
		}
		if r := m.selectedRow(); r != nil {
			return m, nav.PushCmd(deleteuser.New(m.ops, m.chrootRoot, r.Username, r.HomePath))
		}
		return m, nil
	case "D":
		// Plan 04-06: 'D' (uppercase) pushes M-DELETE-RULE in
		// ModeByUser for the selected real row. W1 keybind deviation
		// preserves Phase 3 03-08a's lowercase 'd' = delete user
		// account contract; uppercase 'D' is the new firewall-rule
		// path. No-op when no row is selected or factory is nil.
		if deleteUserFwRulesFactory == nil {
			return m, nil
		}
		if r := m.selectedRow(); r != nil {
			screen := deleteUserFwRulesFactory(r.Username)
			if screen != nil {
				return m, nav.PushCmd(screen)
			}
		}
		return m, nil
	case "enter":
		return m.handleEnter()
	case "j", "down":
		m.moveCursorDown()
	case "up":
		// Phase 3 plan 03-08a: 'k' is now S-USER-DETAIL push (case "k"
		// above). Arrow-key navigation 'up' still moves the cursor up;
		// the 'k' case above falls through to moveCursorUp() when no
		// real row is selected (INFO row / empty list) so admins on a
		// non-real-row cursor can still vi-navigate up with 'k'.
		m.moveCursorUp()
	case "g":
		// Top — go to first INFO row if any, else first real row.
		if len(m.infos) > 0 {
			m.infoCursor = 0
			m.cursor = 0
		} else {
			m.infoCursor = -1
			m.cursor = 0
		}
	case "G":
		// Bottom — go to last real row if any, else last INFO row.
		if n := len(m.filtered); n > 0 {
			m.cursor = n - 1
			m.infoCursor = -1
		} else if len(m.infos) > 0 {
			m.infoCursor = len(m.infos) - 1
		}
	}
	return m, nil
}

// moveCursorDown advances the cursor through INFO rows and then real rows.
// Layout (top-to-bottom): infos[0..N-1] then filtered[0..M-1]. The
// infoCursor sentinel (-1) means "on a real row at m.cursor"; >=0 means
// "on infos[infoCursor]".
func (m *Model) moveCursorDown() {
	if m.infoCursor >= 0 {
		// Currently on an INFO row.
		if m.infoCursor < len(m.infos)-1 {
			m.infoCursor++
			return
		}
		// Last INFO row — fall through to first real row (if any).
		if len(m.filtered) > 0 {
			m.infoCursor = -1
			m.cursor = 0
		}
		return
	}
	// On a real row.
	if m.cursor < len(m.filtered)-1 {
		m.cursor++
	}
}

// moveCursorUp is the inverse of moveCursorDown.
func (m *Model) moveCursorUp() {
	if m.infoCursor >= 0 {
		if m.infoCursor > 0 {
			m.infoCursor--
		}
		return
	}
	// On a real row at m.cursor.
	if m.cursor > 0 {
		m.cursor--
		return
	}
	// At the top of the real rows — fall through to the last INFO row.
	if len(m.infos) > 0 {
		m.infoCursor = len(m.infos) - 1
	}
}

// handleEnter dispatches the Enter key based on cursor position.
//
// Phase 3 plan 03-07 D-06 + D-14:
//   - infoCursor >= 0 (Enter on an INFO row): branch on InfoRow.Kind.
//     orphan        → push newuser.NewFromOrphan (D-14, B-03)
//     missing-match → toast "open doctor and press [A] to apply canonical config"
//     missing-chroot → same toast (same fix path)
//   - infoCursor == -1 (Enter on a real row): no-op for now
//     (S-USER-DETAIL lands in plan 03-08a).
func (m *Model) handleEnter() (nav.Screen, tea.Cmd) {
	if m.infoCursor >= 0 && m.infoCursor < len(m.infos) {
		info := m.infos[m.infoCursor]
		switch info.Kind {
		case users.InfoOrphan:
			if m.ops == nil {
				return m, nil
			}
			return m, nav.PushCmd(newuser.NewFromOrphan(m.ops, m.chrootRoot, info))
		case users.InfoMissingMatch, users.InfoMissingChroot:
			var flashCmd tea.Cmd
			m.toast, flashCmd = m.toast.Flash(
				"open doctor (d) and press [A] to apply canonical config")
			return m, flashCmd
		}
	}
	// Real-row Enter: Phase 3 plan 03-08a — push S-USER-DETAIL.
	if m.ops != nil {
		if r := m.selectedRow(); r != nil {
			return m, nav.PushCmd(userdetail.New(m.ops, m.chrootRoot, r.Username))
		}
	}
	return m, nil
}

// selectedRow returns the currently-selected real Row, or nil if the cursor
// is on an INFO row (or there are no real rows).
func (m *Model) selectedRow() *users.Row {
	if m.infoCursor >= 0 {
		return nil
	}
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return nil
	}
	return &m.filtered[m.cursor]
}

// SetInfoCursorForTest exposes a direct cursor poke so unit tests don't
// have to drive j/k navigation across an arbitrary number of INFO rows
// to land on the one they want to assert against.
func (m *Model) SetInfoCursorForTest(idx int) {
	m.infoCursor = idx
	if idx >= 0 {
		m.cursor = 0 // sentinel — handleEnter only consults infoCursor
	}
}

// handleCopy emits the OSC 52 SetClipboard cmd + toast flash for the
// currently-selected row. No-op when there is no selection.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return m, nil
	}
	text := rowAsTSV(m.filtered[m.cursor], m.cfg)
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied user row via OSC 52")
	return m, tea.Batch(tea.SetClipboard(text), flashCmd)
}

// rowAsTSV serialises a Row in the column order rendered by the table —
// tab-separated for paste-friendliness in Excel / Numbers / Sheets.
//
// Last-login ns timestamp 0 is rendered as "never" rather than the unix
// epoch — surfaced in the UI the same way (UI-SPEC line 380). The
// password-age column flows through users.FormatPasswordAge so the TSV
// path matches the live render verbatim (single source of truth for the
// "Nd (fresh|aging|stale)" / ∞ / — vocabulary).
func rowAsTSV(r users.Row, cfg *config.Settings) string {
	pwdAge := users.FormatPasswordAge(r.PasswordAgeDays, r.PasswordMaxDays, cfg.PasswordAgingDays, cfg.PasswordStaleDays)
	lastLogin := "never"
	if r.LastLoginNs > 0 {
		lastLogin = humanize.Time(time.Unix(0, r.LastLoginNs))
	}
	firstSeen := r.FirstSeenIP
	if firstSeen == "" {
		firstSeen = "—"
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%d\t%s\t%s\t%d",
		r.Username, r.UID, r.ChrootPath, pwdAge, r.KeysCount, lastLogin, firstSeen, r.IPAllowlistCount,
	)
}

// applySortAndFilter (re)computes the filtered slice from rows + sort +
// search. Resets cursor to 0 if it would now point past the end.
//
// Search uses sahilm/fuzzy against a compound "username + chroot path"
// string (USER-02 column scope per the must_haves).
func (m *Model) applySortAndFilter() {
	// Sort first so that filtering preserves the visible order.
	sort.SliceStable(m.rows, func(i, j int) bool {
		return m.lessFn(m.rows[i], m.rows[j])
	})

	// Filter: when search inactive or empty, filtered = rows (cheap copy).
	q := strings.TrimSpace(m.search.Value())
	if !m.search.Active || q == "" {
		m.filtered = m.rows
	} else {
		// Build the search corpus in the same row order so fuzzy match
		// indices map back 1:1.
		corpus := make([]string, len(m.rows))
		for i, r := range m.rows {
			corpus[i] = r.Username + " " + r.ChrootPath
		}
		matches := fuzzy.Find(q, corpus)
		m.filtered = make([]users.Row, 0, len(matches))
		for _, mm := range matches {
			m.filtered = append(m.filtered, m.rows[mm.Index])
		}
	}

	if m.cursor >= len(m.filtered) {
		m.cursor = 0
	}
}

// lessFn returns the comparator for the current sort axis + direction.
// Default direction is ascending for username/uid/first-seen-IP; descending
// for last-login + allowlist-count makes more practical sense (admin wants
// "most recent" + "highest count" first). The `S` toggle inverts whatever
// the default direction is.
func (m *Model) lessFn(a, b users.Row) bool {
	var less bool
	switch m.sortAxis {
	case SortByUsername:
		less = strings.ToLower(a.Username) < strings.ToLower(b.Username)
	case SortByUID:
		less = a.UID < b.UID
	case SortByLastLogin:
		// Most-recent first by default (descending by ns).
		less = a.LastLoginNs > b.LastLoginNs
	case SortByFirstSeenIP:
		less = a.FirstSeenIP < b.FirstSeenIP
	case SortByAllowlistCount:
		// Highest count first by default.
		less = a.IPAllowlistCount > b.IPAllowlistCount
	default:
		less = strings.ToLower(a.Username) < strings.ToLower(b.Username)
	}
	if m.sortDescending {
		return !less
	}
	return less
}

// View renders the screen body.
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("loading users…")
	}
	if m.errText != "" {
		return styles.Critical.Render("Could not enumerate users: "+m.errText) +
			"\n\n" + styles.Dim.Render("(esc to return)")
	}
	if len(m.rows) == 0 && len(m.infos) == 0 {
		// Empty-state copy per UI-SPEC line 354-355.
		return "No SFTP users found.\n\n" + styles.Dim.Render(
			"(no group matching sftp* and no ChrootDirectory configured —\n"+
				"see diagnostic screen for details, or apply canonical config in Phase 3.)")
	}

	var b strings.Builder

	// Header line — title with row count (excluding INFO pseudo-rows per
	// UI-SPEC line 370).
	b.WriteString(styles.Primary.Render(
		fmt.Sprintf("users — %d rows", len(m.filtered))))
	b.WriteString("\n\n")

	// Search prompt — shown above table when active.
	if m.search.Active {
		b.WriteString(m.search.View())
		b.WriteString("\n\n")
	}

	// INFO pseudo-rows render at the TOP, in the new Info token (cyan).
	// Phase 3 plan 03-07: when m.infoCursor == i, prefix the row with the
	// `▌ ` cursor marker so admins see which INFO row is selected for
	// Enter-on-INFO dispatch (orphan reconcile / canonical-config toast).
	for i, info := range m.infos {
		marker := "  "
		if i == m.infoCursor {
			marker = "▌ "
		}
		b.WriteString(marker)
		b.WriteString(styles.Info.Render(
			fmt.Sprintf("[INFO] %s: %s", info.Kind, info.Detail)))
		b.WriteString("  ")
		b.WriteString(styles.Dim.Render(info.Hint))
		b.WriteString("\n")
	}
	if len(m.infos) > 0 {
		b.WriteString(styles.Dim.Render(strings.Repeat("─", 78)))
		b.WriteString("\n")
	}

	// Column header — Primary accent per UI-SPEC line 75. The pwd-age
	// column is 14 chars wide to fit the longest formatted value
	// ("Nd (aging)" / "Nd (stale)" / "Nd (fresh)" / "∞" / "—").
	b.WriteString(styles.Primary.Render(fmt.Sprintf(
		"  %-12s %6s  %-30s %-14s %4s  %-12s %-16s %4s",
		"user", "uid", "chroot", "pwd age", "keys", "last login", "first seen", "IPs")))
	b.WriteString("\n")

	// Real rows — selected row prefixed with `▌` (cursor marker); others
	// with two spaces. Avoids reverse-video so substring assertions in
	// tests remain stable across terminal profiles.
	//
	// pwd-age column flows through users.FormatPasswordAge so the live
	// render and the TSV/clipboard path share a single source of truth
	// (the truth-tested format helper). Threshold values come from the
	// injected *config.Settings.
	for i, r := range m.filtered {
		marker := "  "
		if i == m.cursor {
			marker = "▌ "
		}
		pwdAge := users.FormatPasswordAge(r.PasswordAgeDays, r.PasswordMaxDays, m.cfg.PasswordAgingDays, m.cfg.PasswordStaleDays)
		lastLogin := "never"
		if r.LastLoginNs > 0 {
			lastLogin = humanize.Time(time.Unix(0, r.LastLoginNs))
		}
		firstSeen := r.FirstSeenIP
		if firstSeen == "" {
			firstSeen = "—"
		}
		row := fmt.Sprintf(
			"%s%-12s %6d  %-30s %-14s %4d  %-12s %-16s %4d",
			marker,
			truncate(r.Username, 12),
			r.UID,
			truncate(r.ChrootPath, 30),
			pwdAge,
			r.KeysCount,
			lastLogin,
			truncate(firstSeen, 16),
			r.IPAllowlistCount,
		)
		if i == m.cursor {
			row = styles.Primary.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}

	// Password-age legend (02-11 / SC #3 A+) — substituted with live
	// thresholds so admins see the actual buckets the cfg drives. The
	// muted style places it beneath the table without competing with
	// the data rows for attention.
	b.WriteString(styles.Dim.Render(fmt.Sprintf(
		"pwd age: ∞ = no expiry policy · fresh < %dd · aging < %dd · stale ≥ %dd",
		m.cfg.PasswordAgingDays, m.cfg.PasswordStaleDays, m.cfg.PasswordStaleDays)))
	b.WriteString("\n")

	// Footer — sort indicator on its own line, then short help.
	arrow := "↓"
	if m.sortDescending {
		arrow = "↑"
	}
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(fmt.Sprintf("sort: %s %s", m.sortAxis.label(), arrow)))
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(
		"↑↓·move  /·search  enter·detail  s·sort  c·copy  esc·back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return b.String()
}

// truncate clips s to width with a trailing "…" marker. Pure-display
// helper — never called on data destined for the clipboard.
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

// KeyMap is the S-USERS key bindings — implements nav.KeyMap.
type KeyMap struct {
	Back        nav.KeyBinding
	Search      nav.KeyBinding
	Detail      nav.KeyBinding
	SortCycle   nav.KeyBinding
	SortReverse nav.KeyBinding
	Copy        nav.KeyBinding
	// Phase 3 plan 03-07 additions:
	New      nav.KeyBinding // 'n' → push M-NEW-USER
	Password nav.KeyBinding // 'p' → push M-PASSWORD on selected row
	// Phase 3 plan 03-08a additions:
	Keys   nav.KeyBinding // 'k' → push S-USER-DETAIL on selected real row
	Delete nav.KeyBinding // 'd' → push M-DELETE-USER on selected real row
	// Plan 04-06 addition (W1 keybind deviation):
	DeleteFwRules nav.KeyBinding // 'D' → push M-DELETE-RULE-byUser via factory
}

// DefaultKeyMap returns the canonical S-USERS bindings per UI-SPEC §S-USERS.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:          nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Search:        nav.KeyBinding{Keys: []string{"/"}, Help: "search"},
		Detail:        nav.KeyBinding{Keys: []string{"enter"}, Help: "detail"},
		SortCycle:     nav.KeyBinding{Keys: []string{"s"}, Help: "sort"},
		SortReverse:   nav.KeyBinding{Keys: []string{"S"}, Help: "reverse sort"},
		Copy:          nav.KeyBinding{Keys: []string{"c"}, Help: "copy row"},
		New:           nav.KeyBinding{Keys: []string{"n"}, Help: "new user"},
		Password:      nav.KeyBinding{Keys: []string{"p"}, Help: "set password"},
		Keys:          nav.KeyBinding{Keys: []string{"k"}, Help: "keys (S-USER-DETAIL)"},
		Delete:        nav.KeyBinding{Keys: []string{"d"}, Help: "delete user"},
		DeleteFwRules: nav.KeyBinding{Keys: []string{"D"}, Help: "delete all FW rules for user"},
	}
}

// ShortHelp surfaces the bindings shown in the footer / `?` overlay's
// compact mode. Reverse-sort is a power-user flag, kept to FullHelp only.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{
		k.Back, k.Search, k.Detail, k.SortCycle, k.Copy,
		k.New, k.Password, k.Keys, k.Delete, k.DeleteFwRules,
	}
}

// FullHelp shows five columns: nav row (back/search/detail), action row
// (sort/reverse-sort/copy), Phase 3 mutation row (new/password), the
// per-row mutation row from plan 03-08a (keys/delete), and the new
// FW-rule row added by plan 04-06 (delete-fw-rules).
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Back, k.Search, k.Detail},
		{k.SortCycle, k.SortReverse, k.Copy},
		{k.New, k.Password},
		{k.Keys, k.Delete},
		{k.DeleteFwRules},
	}
}
