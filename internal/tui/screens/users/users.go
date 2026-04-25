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

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

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
}

// New constructs the screen wired to enum (the data-layer composer shipped
// in 02-03). enum may be nil in unit tests that drive the screen via
// LoadRowsForTest.
func New(enum *users.Enumerator) *Model {
	return &Model{
		enum:    enum,
		loading: true,
		keys:    DefaultKeyMap(),
		search:  widgets.NewSearch(),
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
	case "enter":
		// User-detail modal deferred (UI-SPEC line 162: Phase 2 ships
		// list-only; detail-modal-on-Enter is acknowledged but not
		// mandated for v1 land). No-op for now.
		return m, nil
	case "j", "down":
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "g":
		m.cursor = 0
	case "G":
		if n := len(m.filtered); n > 0 {
			m.cursor = n - 1
		}
	}
	return m, nil
}

// handleCopy emits the OSC 52 SetClipboard cmd + toast flash for the
// currently-selected row. No-op when there is no selection.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return m, nil
	}
	text := rowAsTSV(m.filtered[m.cursor])
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied user row via OSC 52")
	return m, tea.Batch(tea.SetClipboard(text), flashCmd)
}

// rowAsTSV serialises a Row in the column order rendered by the table —
// tab-separated for paste-friendliness in Excel / Numbers / Sheets.
//
// Last-login ns timestamp 0 is rendered as "never" rather than the unix
// epoch — surfaced in the UI the same way (UI-SPEC line 380).
func rowAsTSV(r users.Row) string {
	pwdAge := "—"
	if r.PasswordAgeDays >= 0 {
		pwdAge = fmt.Sprintf("%dd", r.PasswordAgeDays)
	}
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
	for _, info := range m.infos {
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

	// Column header — Primary accent per UI-SPEC line 75.
	b.WriteString(styles.Primary.Render(fmt.Sprintf(
		"  %-12s %6s  %-30s %-8s %4s  %-12s %-16s %4s",
		"user", "uid", "chroot", "pwd age", "keys", "last login", "first seen", "IPs")))
	b.WriteString("\n")

	// Real rows — selected row prefixed with `▌` (cursor marker); others
	// with two spaces. Avoids reverse-video so substring assertions in
	// tests remain stable across terminal profiles.
	for i, r := range m.filtered {
		marker := "  "
		if i == m.cursor {
			marker = "▌ "
		}
		pwdAge := "—"
		if r.PasswordAgeDays >= 0 {
			pwdAge = fmt.Sprintf("%dd", r.PasswordAgeDays)
		}
		lastLogin := "never"
		if r.LastLoginNs > 0 {
			lastLogin = humanize.Time(time.Unix(0, r.LastLoginNs))
		}
		firstSeen := r.FirstSeenIP
		if firstSeen == "" {
			firstSeen = "—"
		}
		row := fmt.Sprintf(
			"%s%-12s %6d  %-30s %-8s %4d  %-12s %-16s %4d",
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
}

// DefaultKeyMap returns the canonical S-USERS bindings per UI-SPEC §S-USERS.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:        nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Search:      nav.KeyBinding{Keys: []string{"/"}, Help: "search"},
		Detail:      nav.KeyBinding{Keys: []string{"enter"}, Help: "detail"},
		SortCycle:   nav.KeyBinding{Keys: []string{"s"}, Help: "sort"},
		SortReverse: nav.KeyBinding{Keys: []string{"S"}, Help: "reverse sort"},
		Copy:        nav.KeyBinding{Keys: []string{"c"}, Help: "copy row"},
	}
}

// ShortHelp surfaces the bindings shown in the footer / `?` overlay's
// compact mode. Reverse-sort is a power-user flag, kept to FullHelp only.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Back, k.Search, k.Detail, k.SortCycle, k.Copy}
}

// FullHelp shows two columns: nav row (back/search/detail) and action row
// (sort/reverse-sort/copy).
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Back, k.Search, k.Detail},
		{k.SortCycle, k.SortReverse, k.Copy},
	}
}
