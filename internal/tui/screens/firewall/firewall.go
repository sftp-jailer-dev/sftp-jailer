// Package firewallscreen renders the SFTP-tagged ufw firewall rules
// (FW-01 / FW-04) as a TUI screen pushed by the home screen's `f`
// binding. Async load via firewall.Enumerate. The `g` toggle flips
// between flat-rules view and per-user reverse mapping (FW-04).
//
// UI per UI-SPEC §S-FIREWALL:
//   - Flat mode columns: id, proto, port, source, user, comment
//   - By-user mode: per-user section header `user: <name> — N rules` (Primary)
//     followed by indented rule rows; users with zero rules NOT listed.
//   - Rules where ufwcomment.Decode returned ErrBadVersion (a future v=2
//     binary's comment, per Phase 1 plan 01-05 forward-compat) render the
//     user column as `?` in styles.Warn — visible surface of the
//     forward-compat decision (FW-01 acceptance row 4).
//   - Rules where ParseErr is ErrNotOurs (no sftpj prefix) render the user
//     column as `—` in styles.Dim so the admin still sees the rule.
//   - `c` copies the raw rule line via OSC 52 (tea.SetClipboard); toast
//     announces "copied rule via OSC 52".
//   - `/` opens fuzzy search; `Enter` is reserved for the rule-detail
//     modal (deferred to follow-up; v1 is no-op like S-USERS Enter).
//   - Empty state on ErrUFWInactive uses UI-SPEC line 357 copy.
//
// This package never imports os/exec or os directly — every system read flows
// through firewall.Enumerate (which itself uses sysops). Mirrors the S-USERS
// shape (async-load, LoadXForTest seam, OSC 52 + toast wiring) — see
// internal/tui/screens/users/users.go for the canonical template.
package firewallscreen

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/sahilm/fuzzy"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// ViewMode toggles between flat-rules and per-user-grouped layouts.
type ViewMode int

const (
	// ViewFlat renders all rules in a single table — the default.
	ViewFlat ViewMode = iota
	// ViewByUser groups rules by Rule.User; users with zero rules are
	// NOT listed (admin uses S-USERS for that).
	ViewByUser
)

// rulesLoadedMsg carries the firewall.Enumerate result back to Update.
type rulesLoadedMsg struct {
	rules []firewall.Rule
	err   error
}

// Model is the S-FIREWALL Bubble Tea v2 model.
type Model struct {
	ops sysops.SystemOps

	// Loaded data — populated either from rulesLoadedMsg or LoadRulesForTest.
	rules   []firewall.Rule
	err     error
	loading bool

	// Filtered view. When search is empty/inactive this aliases m.rules.
	// Cursor indexes into m.filtered, NOT m.rules.
	filtered []firewall.Rule

	// UI state.
	cursor int
	view   ViewMode
	search widgets.Search
	toast  widgets.Toast
	keys   KeyMap
	width  int
}

// New constructs the screen wired to ops (the sysops handle used by
// firewall.Enumerate). ops may be nil in unit tests that drive the screen
// via LoadRulesForTest.
func New(ops sysops.SystemOps) *Model {
	return &Model{
		ops:     ops,
		loading: true,
		keys:    DefaultKeyMap(),
		search:  widgets.NewSearch(),
	}
}

// Init kicks off the async firewall.Enumerate. If ops is nil (test path),
// Init returns nil — the test is expected to call LoadRulesForTest before
// any View().
func (m *Model) Init() tea.Cmd {
	ops := m.ops
	if ops == nil {
		return nil
	}
	return func() tea.Msg {
		// Generous timeout: ufw status numbered runs in well under 1s on a
		// realistic box, but cap at 30s mirroring the doctor / users
		// screen's defensive bound.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rules, err := firewall.Enumerate(ctx, ops)
		return rulesLoadedMsg{rules: rules, err: err}
	}
}

// LoadRulesForTest bypasses Init+Enumerate and sets the loaded state
// directly. Mirrors usersscreen.LoadRowsForTest from 02-04.
func (m *Model) LoadRulesForTest(rules []firewall.Rule, err error) {
	m.loading = false
	m.rules = rules
	m.err = err
	m.applyFilter()
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "firewall" }

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

	case rulesLoadedMsg:
		m.loading = false
		m.rules = msg.rules
		m.err = msg.err
		m.applyFilter()
		return m, nil

	case tea.KeyPressMsg:
		// When search is active, every key (except esc, which the widget
		// handles) types into the textinput.
		if m.search.Active {
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			m.applyFilter()
			return m, cmd
		}
		return m.handleKey(msg)
	}

	// Toast TTL.
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey routes key presses when search is inactive.
//
// Note: 'g' here SHADOWS the Vim-style "go to first row" gg motion on this
// screen — UI-SPEC §S-FIREWALL allocates `g` to the by-user toggle. To go
// to the first row, use `↑↑↑`. Documented in the help footer.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "/":
		var cmd tea.Cmd
		m.search, cmd = m.search.Activate()
		return m, cmd
	case "g":
		if m.view == ViewFlat {
			m.view = ViewByUser
		} else {
			m.view = ViewFlat
		}
		return m, nil
	case "c":
		return m.handleCopy()
	case "enter":
		// Rule-detail modal deferred (mirrors S-USERS Enter no-op from
		// 02-04). Footer still advertises `enter·detail` so admin habit-
		// builds for Phase 4 when the modal lands.
		return m, nil
	case "j", "down":
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "G":
		if n := len(m.filtered); n > 0 {
			m.cursor = n - 1
		}
	}
	return m, nil
}

// handleCopy emits the OSC 52 SetClipboard cmd + toast flash for the
// currently-selected rule. No-op when there is no selection.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return m, nil
	}
	text := ruleAsRawLine(m.filtered[m.cursor])
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied rule via OSC 52")
	return m, tea.Batch(tea.SetClipboard(text), flashCmd)
}

// ruleAsRawLine reconstructs a ufw-status-style raw line for the rule —
// best-effort; consumers paste this into bug reports or chat. Format:
//
//	[N] <port> <ACTION> <source>     # <RawComment>
//
// (RawComment may be empty.)
func ruleAsRawLine(r firewall.Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%2d] %s %s %s", r.ID, r.Port, r.Action, r.Source)
	if r.RawComment != "" {
		fmt.Fprintf(&b, "     # %s", r.RawComment)
	}
	return b.String()
}

// applyFilter (re)computes the filtered slice from rules + search query.
// Filtering operates on the rules slice in place; sort order is the
// original Enumerate order (numbered rule order — mirrors `ufw status
// numbered`). Resets cursor to 0 if it would now point past the end.
//
// Search uses sahilm/fuzzy against a compound "user + source" string per
// UI-SPEC §S-FIREWALL must_haves.
func (m *Model) applyFilter() {
	q := strings.TrimSpace(m.search.Value())
	if !m.search.Active || q == "" {
		m.filtered = m.rules
	} else {
		corpus := make([]string, len(m.rules))
		for i, r := range m.rules {
			corpus[i] = r.User + " " + r.Source
		}
		matches := fuzzy.Find(q, corpus)
		m.filtered = make([]firewall.Rule, 0, len(matches))
		for _, mm := range matches {
			m.filtered = append(m.filtered, m.rules[mm.Index])
		}
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = 0
	}
}

// View renders the screen body.
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("reading firewall rules…")
	}
	if errors.Is(m.err, firewall.ErrUFWInactive) {
		// UI-SPEC line 357 copy verbatim.
		return "No SFTP-tagged firewall rules.\n\n" +
			styles.Dim.Render("(open `f` to add per-user allow rules in Phase 4 —\nfor now, the SFTP port is open to all sources.)")
	}
	if m.err != nil {
		// UI-SPEC line 358 copy.
		return styles.Critical.Render(fmt.Sprintf("Could not read firewall: %s", m.err)) +
			"\n\n" + styles.Dim.Render("(diagnostic screen will report the missing tool — press `q` then `d`.)")
	}

	var b strings.Builder
	b.WriteString(styles.Primary.Render(
		fmt.Sprintf("firewall — %d rules", len(m.filtered))))
	b.WriteString("\n\n")

	if m.search.Active {
		b.WriteString(m.search.View())
		b.WriteString("\n\n")
	}

	if m.view == ViewByUser {
		b.WriteString(m.renderByUser())
	} else {
		b.WriteString(m.renderFlat())
	}

	// Footer.
	mode := "flat"
	if m.view == ViewByUser {
		mode = "by user"
	}
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(fmt.Sprintf("view: %s", mode)))
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(
		"↑↓·move  /·search  enter·detail  g·toggle group  c·copy  esc·back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return b.String()
}

// renderFlat renders the flat-mode table.
func (m *Model) renderFlat() string {
	var b strings.Builder

	// Column header.
	b.WriteString(styles.Primary.Render(fmt.Sprintf(
		"  %3s  %5s  %-8s %-30s %-12s %s",
		"id", "proto", "port", "source", "user", "comment")))
	b.WriteString("\n")

	if len(m.filtered) == 0 {
		b.WriteString(styles.Dim.Render("  (no rules match)"))
		b.WriteString("\n")
		return b.String()
	}

	for i, r := range m.filtered {
		marker := "  "
		if i == m.cursor {
			marker = "▌ "
		}
		userCell := renderUserCell(r)
		row := fmt.Sprintf(
			"%s%3d  %5s  %-8s %-30s %-12s %s",
			marker,
			r.ID,
			r.Proto,
			truncate(r.Port, 8),
			truncate(r.Source, 30),
			userCell,
			truncate(r.RawComment, 40),
		)
		if i == m.cursor {
			row = styles.Primary.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}
	return b.String()
}

// renderByUser groups m.filtered by Rule.User and renders one section per
// user. Users with zero rules are skipped (the data source carries only
// rules that exist, but we additionally drop any rule with empty User —
// e.g. ErrNotOurs / non-sftpj rules — from the by-user view since they
// belong to no user). Users sorted alphabetically.
func (m *Model) renderByUser() string {
	groups := map[string][]firewall.Rule{}
	for _, r := range m.filtered {
		// Skip rules with no user binding (foreign rules / ErrBadVersion
		// rules with empty User). They show up in flat mode; by-user mode
		// is the per-admin-user reverse mapping (FW-04) — anything without
		// a user is irrelevant here.
		if r.User == "" {
			continue
		}
		groups[r.User] = append(groups[r.User], r)
	}

	if len(groups) == 0 {
		return styles.Dim.Render("(no per-user firewall rules)\n")
	}

	users := make([]string, 0, len(groups))
	for u := range groups {
		users = append(users, u)
	}
	sort.Strings(users)

	var b strings.Builder
	for _, u := range users {
		rules := groups[u]
		b.WriteString(styles.Primary.Render(fmt.Sprintf(
			"user: %s — %d rules", u, len(rules))))
		b.WriteString("\n")
		for _, r := range rules {
			fmt.Fprintf(&b, "  [%2d] %s %s %s\n",
				r.ID, r.Proto, r.Port, r.Source)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// renderUserCell formats the user column for a rule with the visible
// surface of the forward-compat decision: ErrBadVersion → `?` in Warn;
// ErrNotOurs (or empty user) → `—` in Dim; otherwise the username.
func renderUserCell(r firewall.Rule) string {
	if errors.Is(r.ParseErr, ufwcomment.ErrBadVersion) {
		return styles.Warn.Render("?")
	}
	if r.User == "" {
		return styles.Dim.Render("—")
	}
	return r.User
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

// KeyMap is the S-FIREWALL key bindings — implements nav.KeyMap.
type KeyMap struct {
	Back        nav.KeyBinding
	Search      nav.KeyBinding
	Detail      nav.KeyBinding
	ToggleGroup nav.KeyBinding
	Copy        nav.KeyBinding
}

// DefaultKeyMap returns the canonical S-FIREWALL bindings per UI-SPEC
// §S-FIREWALL footer line.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:        nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Search:      nav.KeyBinding{Keys: []string{"/"}, Help: "search"},
		Detail:      nav.KeyBinding{Keys: []string{"enter"}, Help: "detail"},
		ToggleGroup: nav.KeyBinding{Keys: []string{"g"}, Help: "group"},
		Copy:        nav.KeyBinding{Keys: []string{"c"}, Help: "copy rule"},
	}
}

// ShortHelp surfaces the bindings in the footer / `?` overlay's compact
// mode.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Back, k.Search, k.Detail, k.ToggleGroup, k.Copy}
}

// FullHelp shows two columns: nav row (back/search/detail) and action
// row (toggle-group/copy).
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Back, k.Search, k.Detail},
		{k.ToggleGroup, k.Copy},
	}
}
