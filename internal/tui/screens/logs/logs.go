// Package logsscreen renders ingested SFTP events from the observation
// store in a split-pane layout (wide mode ≥120 cols) or a list-only
// layout (narrow mode). The `F` key suspends the TUI to run
// `journalctl -u ssh -f` via tea.ExecProcess; `r` triggers an on-demand
// observe-run via M-OBSERVE (modal lives in plan 02-08; until then,
// pressing `r` shows a placeholder toast).
//
// Architectural notes (this plan introduces three patterns new to the
// project):
//
//  1. Split-pane layout via lipgloss.JoinHorizontal with a 120-col
//     breakpoint (D-06 / RESEARCH Pattern 5).
//  2. tea.ExecProcess for live-tail subprocess hand-off — the *exec.Cmd
//     literal lives inside internal/sysops (CI guard); this package only
//     calls m.ops.JournalctlFollowCmd("ssh").
//  3. State-driven status row styling (Healthy / Stale / Schema-drift)
//     with dustin/go-humanize.Time for relative timestamps (D-08).
//
// Mirrors the S-USERS / S-FIREWALL template (async-load via Init+queries,
// LoadXForTest seam, OSC 52 + Toast wiring) — see
// internal/tui/screens/users/users.go for the canonical template.
package logsscreen

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/dustin/go-humanize"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// Layout / status thresholds.
const (
	// SplitBreakpoint is the terminal-width cutoff for split-pane vs
	// list-only mode (D-06 / RESEARCH Pattern 5).
	SplitBreakpoint = 120
	// SepWidth is the byte-width of the split-pane separator column.
	SepWidth = 1
	// StaleDuration is the threshold beyond which the status row renders
	// in styles.Warn instead of healthy styling (D-08 / UI-SPEC line 282).
	StaleDuration = 14 * 24 * time.Hour
	// EventLimit caps the FilterEvents query — matches the 02-01 default
	// (T-OBS-03 accept-disposition for offset-based paging at v1).
	EventLimit = 500
)

// observerunFactory is registered by main.go in plan 02-08 (M-OBSERVE).
// S-LOGS calls it when 'r' is pressed; until 02-08 lands, the factory is
// nil and pressing 'r' shows a placeholder toast.
var observerunFactory func() nav.Screen

// SetObserveRunFactory registers the constructor used when the admin
// presses `r` to push the M-OBSERVE modal. Wired by plan 02-08; calling
// with nil disarms the hook (used by tests to assert the placeholder
// toast path).
func SetObserveRunFactory(f func() nav.Screen) { observerunFactory = f }

// tierFilter cycles through the 5 filter states (`t` keypress). When
// tierAll is selected, FilterOpts.Tier is left empty and the query
// returns all tiers; for the other 4 the tierFilter.String() value is
// passed verbatim as opts.Tier — the classifier (02-01) emits the same
// 4 strings.
type tierFilter int

const (
	tierAll tierFilter = iota
	tierSuccess
	tierTargeted
	tierNoise
	tierUnmatched
	tierFilterCount // sentinel — modulus for the cycle
)

func (t tierFilter) String() string {
	switch t {
	case tierAll:
		return "all"
	case tierSuccess:
		return "success"
	case tierTargeted:
		return "targeted"
	case tierNoise:
		return "noise"
	case tierUnmatched:
		return "unmatched"
	}
	return "all"
}

// Message types (exported via constructors only — internal to package).
type eventsLoadedMsg struct {
	events []store.Event
	err    error
}

type statusLoadedMsg struct {
	status store.StatusRow
	err    error
}

type liveTailFinishedMsg struct{ err error }

// statusRefreshMsg is the local refresh-trigger when M-OBSERVE closes.
// In plan 02-08 this will be promoted to nav.StatusRefreshMsg for
// cross-package routing; today the type is unexported because no other
// package needs to send it.
type statusRefreshMsg struct{}

// Model is the S-LOGS Bubble Tea v2 model.
type Model struct {
	queries *store.Queries
	ops     sysops.SystemOps

	// Loaded data — populated either from messages or LoadXForTest seams.
	events       []store.Event
	status       store.StatusRow
	loading      bool
	statusLoaded bool
	errText      string

	// UI state.
	cursor int
	tier   tierFilter
	width  int
	height int
	search widgets.Search
	toast  widgets.Toast
	keys   KeyMap
}

// New constructs the screen wired to queries (the 02-01 read layer) and
// ops (the sysops handle for live-tail). Either may be nil in unit tests
// that drive the screen via LoadEventsForTest / LoadStatusForTest; the
// `F` keypress requires ops to be non-nil (otherwise it no-ops).
func New(queries *store.Queries, ops sysops.SystemOps) *Model {
	return &Model{
		queries: queries,
		ops:     ops,
		loading: true,
		keys:    DefaultKeyMap(),
		search:  widgets.NewSearch(),
	}
}

// Init kicks off two parallel async loads — the event list and the
// status row — via tea.Batch. If queries is nil (test path), Init returns
// nil and the test is expected to call LoadEventsForTest /
// LoadStatusForTest before any View().
func (m *Model) Init() tea.Cmd {
	if m.queries == nil {
		return nil
	}
	return tea.Batch(m.loadEvents(), m.loadStatus())
}

// loadEvents returns a tea.Cmd that calls FilterEvents with the current
// tier filter. Re-issued whenever the tier filter changes (`t`) so the
// SQL filter — not just a client-side filter — drives the visible set.
func (m *Model) loadEvents() tea.Cmd {
	q := m.queries
	if q == nil {
		return nil
	}
	opts := m.currentFilterOpts()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs, err := q.FilterEvents(ctx, opts)
		return eventsLoadedMsg{events: evs, err: err}
	}
}

// loadStatus returns a tea.Cmd that calls StatusRow. Re-issued on
// statusRefreshMsg (M-OBSERVE close, plan 02-08).
func (m *Model) loadStatus() tea.Cmd {
	q := m.queries
	if q == nil {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := q.StatusRow(ctx)
		return statusLoadedMsg{status: s, err: err}
	}
}

// currentFilterOpts returns the FilterOpts for the active tier filter.
// The search query is applied client-side over the loaded slice — the
// observation DB doesn't have a "fuzzy match" SQL operator and v1 caps
// at 500 rows so the client-side cost is trivial.
func (m *Model) currentFilterOpts() store.FilterOpts {
	opts := store.FilterOpts{Limit: EventLimit}
	if m.tier != tierAll {
		opts.Tier = m.tier.String()
	}
	return opts
}

// LoadEventsForTest bypasses Init+FilterEvents and sets the loaded events
// directly. Mirrors usersscreen.LoadRowsForTest from 02-04.
func (m *Model) LoadEventsForTest(evs []store.Event, err error) {
	m.loading = false
	m.events = evs
	if err != nil {
		m.errText = err.Error()
	} else {
		m.errText = ""
	}
	if m.cursor >= len(m.events) {
		m.cursor = 0
	}
}

// LoadStatusForTest bypasses StatusRow and sets the status row directly.
func (m *Model) LoadStatusForTest(s store.StatusRow) {
	m.statusLoaded = true
	m.status = s
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "logs" }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the search textinput
// is focused so the root App forwards letters into the input rather than
// quitting on `q`.
func (m *Model) WantsRawKeys() bool { return m.search.Active }

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case eventsLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.errText = msg.err.Error()
		} else {
			m.errText = ""
			m.events = msg.events
		}
		if m.cursor >= len(m.events) {
			m.cursor = 0
		}
		return m, nil

	case statusLoadedMsg:
		m.statusLoaded = true
		if msg.err == nil {
			m.status = msg.status
		}
		return m, nil

	case statusRefreshMsg:
		return m, m.loadStatus()

	case liveTailFinishedMsg:
		// Resume; nothing to update. Errors from the subprocess (e.g.
		// ENOENT for journalctl) are surfaced via the user's terminal
		// scrollback during the ExecProcess hand-off — we deliberately
		// do not toast on liveTailFinishedMsg.err to avoid double-reporting.
		return m, nil

	case tea.KeyPressMsg:
		// Search is greedy when active.
		if m.search.Active {
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
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
	case "F":
		// tea.ExecProcess hand-off — Bubble Tea owns Start/Wait. The
		// *exec.Cmd literal lives in internal/sysops; this package never
		// imports os/exec (architectural invariant
		// scripts/check-no-exec-outside-sysops.sh).
		if m.ops == nil {
			return m, nil
		}
		cmd := m.ops.JournalctlFollowCmd("ssh")
		return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
			return liveTailFinishedMsg{err: err}
		})
	case "r":
		if observerunFactory != nil {
			return m, nav.PushCmd(observerunFactory())
		}
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("observe-run modal coming in plan 02-08")
		return m, flashCmd
	case "c":
		return m.handleCopy()
	case "t":
		m.tier = (m.tier + 1) % tierFilterCount
		// Re-issue the events query with the new tier filter applied at
		// the SQL layer. Empty tier means "all"; the SQL idiom in 02-01's
		// FilterEvents (`(? = '' OR tier = ?)`) handles both shapes.
		return m, m.loadEvents()
	case "enter":
		// Wide mode: no-op (cursor movement already updates the right
		// pane live).
		// Narrow mode: detail-modal push deferred to v1.x — UI-SPEC line
		// 446 lists this; the RawJSON is copyable via `c` and the
		// wide-mode pane already shows full detail. Mirrors S-USERS /
		// S-FIREWALL Enter no-op.
		return m, nil
	case "j", "down":
		if m.cursor < len(m.events)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "g":
		m.cursor = 0
	case "G":
		if n := len(m.events); n > 0 {
			m.cursor = n - 1
		}
	}
	return m, nil
}

// handleCopy emits the OSC 52 SetClipboard cmd + toast flash for the
// currently-selected event's RawJSON. No-op when there is no selection
// or the event has no RawJSON.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.events) {
		return m, nil
	}
	raw := m.events[m.cursor].RawJSON
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied raw record via OSC 52")
	return m, tea.Batch(tea.SetClipboard(raw), flashCmd)
}

// View renders the screen body.
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("loading events…")
	}
	if m.errText != "" {
		return styles.Critical.Render("Could not open observation DB: "+m.errText) +
			"\n\n" + styles.Dim.Render("(check /var/lib/sftp-jailer/observations.db ownership.)")
	}
	if len(m.events) == 0 && m.status.DetailCount == 0 {
		// UI-SPEC line 359 empty-state copy verbatim.
		return "No events recorded yet.\n\n" + styles.Dim.Render(
			"Press `r` to run the observer now, or wait for the\nweekly systemd timer.")
	}

	var b strings.Builder
	b.WriteString(styles.Primary.Render(
		fmt.Sprintf("logs — %d events", len(m.events))))
	b.WriteString("\n")
	b.WriteString(m.renderStatusRow())
	b.WriteString("\n\n")

	// Search prompt above the body when active.
	if m.search.Active {
		b.WriteString(m.search.View())
		b.WriteString("\n\n")
	}

	if m.width >= SplitBreakpoint && m.width > 0 {
		b.WriteString(m.renderSplit())
	} else {
		b.WriteString(m.renderListOnly())
	}

	// Footer — current tier filter on its own line, then short help.
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(fmt.Sprintf("tier: %s", m.tier.String())))
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(
		"↑↓·move  /·search  enter·detail  F·live-tail  r·observe  c·copy  t·tier  esc·back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return b.String()
}

// renderStatusRow renders the D-08 status header in one of three states
// per UI-SPEC lines 280–286:
//
//   - Schema drift (Critical) — current schema > ExpectedSchemaVersion;
//     observer disabled message.
//   - Stale (Warn whole row) — last_run > StaleDuration ago.
//   - Healthy — Schema seg in Primary, rest in Dim.
//
// LastSuccessNs == 0 renders as "last run never" (RESEARCH §"Code
// Examples" line 1465 — branch on IsZero first).
func (m *Model) renderStatusRow() string {
	if !m.statusLoaded {
		return styles.Dim.Render("loading status…")
	}
	if m.status.SchemaVersion > store.ExpectedSchemaVersion {
		return styles.Critical.Render(fmt.Sprintf(
			"Schema v%d (binary expects v%d) — observer disabled — apt upgrade sftp-jailer",
			m.status.SchemaVersion, store.ExpectedSchemaVersion))
	}
	var lastRunTxt string
	if m.status.LastSuccessNs == 0 {
		lastRunTxt = "never"
	} else {
		lastRunTxt = humanize.Time(time.Unix(0, m.status.LastSuccessNs))
	}
	base := fmt.Sprintf("Schema v%d • %d events • %d counters • last run %s",
		m.status.SchemaVersion, m.status.DetailCount, m.status.CounterCount, lastRunTxt)
	isStale := m.status.LastSuccessNs != 0 &&
		time.Since(time.Unix(0, m.status.LastSuccessNs)) > StaleDuration
	if isStale {
		return styles.Warn.Render(base)
	}
	// Healthy — Schema seg in Primary, rest in Dim.
	schemaSeg := styles.Primary.Render(fmt.Sprintf("Schema v%d", m.status.SchemaVersion))
	rest := styles.Dim.Render(fmt.Sprintf(" • %d events • %d counters • last run %s",
		m.status.DetailCount, m.status.CounterCount, lastRunTxt))
	return schemaSeg + rest
}

// renderSplit composes the wide-mode split-pane via lipgloss.JoinHorizontal
// with a single separator column. RESEARCH Pattern 5 (lines 497–524).
func (m *Model) renderSplit() string {
	leftW := (m.width - SepWidth) * 60 / 100
	rightW := m.width - SepWidth - leftW
	if leftW < 1 {
		leftW = 1
	}
	if rightW < 1 {
		rightW = 1
	}
	left := lipgloss.NewStyle().Width(leftW).Render(m.renderList(leftW))
	sep := "│"
	right := lipgloss.NewStyle().Width(rightW).Render(m.renderDetailPane(rightW))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, sep, right)
}

// renderListOnly renders the list at full terminal width.
func (m *Model) renderListOnly() string { return m.renderList(m.width) }

// renderList produces the events table — UI-SPEC line 432 columns:
// ts(UTC) / user / src / tier glyph. Selection in reverse-video; tier
// colours via colorByTier.
func (m *Model) renderList(_ int) string {
	var b strings.Builder
	b.WriteString(styles.Dim.Render("ts(UTC)         user      src             t"))
	b.WriteString("\n")
	for i, e := range m.events {
		ts := time.Unix(0, e.TsUnixNs).UTC().Format("15:04:05")
		line := fmt.Sprintf("%-15s %-9s %-15s %s",
			ts, displayN(e.User, 9), displayN(e.SourceIP, 15), tierGlyph(e.Tier))
		line = colorByTier(e.Tier, line)
		if i == m.cursor {
			line = lipgloss.NewStyle().Reverse(true).Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// renderDetailPane produces the right-pane key/value layout for the
// currently-selected event. Empty/no-selection → a faint placeholder.
func (m *Model) renderDetailPane(w int) string {
	if m.cursor >= len(m.events) {
		return styles.Dim.Render("(no event selected)")
	}
	return RenderDetail(m.events[m.cursor], w)
}

// displayN pads s to exactly n columns (truncating with ellipsis if
// needed). Used for the fixed-width list columns. Empty strings render
// as `—` followed by enough spaces.
func displayN(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if s == "" {
		// Fill with `—` followed by padding.
		out := "—"
		if n > 1 {
			out += strings.Repeat(" ", n-1)
		}
		return out
	}
	if len(s) > n {
		if n <= 1 {
			return s[:n]
		}
		return s[:n-1] + "…"
	}
	return s + strings.Repeat(" ", n-len(s))
}

// colorByTier styles the rendered line by classification tier. success →
// Success (green), targeted → Critical (red+bold), noise → Info (cyan,
// added in 02-04), unmatched → Warn (amber). Unknown tiers fall through
// unstyled.
func colorByTier(tier, line string) string {
	switch tier {
	case "success":
		return styles.Success.Render(line)
	case "targeted":
		return styles.Critical.Render(line)
	case "noise":
		return styles.Info.Render(line)
	case "unmatched":
		return styles.Warn.Render(line)
	}
	return line
}

// KeyMap is the S-LOGS key bindings — implements nav.KeyMap.
type KeyMap struct {
	Back      nav.KeyBinding
	Search    nav.KeyBinding
	LiveTail  nav.KeyBinding
	RunNow    nav.KeyBinding
	Copy      nav.KeyBinding
	Detail    nav.KeyBinding
	TierCycle nav.KeyBinding
}

// DefaultKeyMap returns the canonical S-LOGS bindings per UI-SPEC §S-LOGS
// footer + must_haves.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:      nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Search:    nav.KeyBinding{Keys: []string{"/"}, Help: "filter"},
		LiveTail:  nav.KeyBinding{Keys: []string{"F"}, Help: "live-tail"},
		RunNow:    nav.KeyBinding{Keys: []string{"r"}, Help: "observe-run"},
		Copy:      nav.KeyBinding{Keys: []string{"c"}, Help: "copy raw"},
		Detail:    nav.KeyBinding{Keys: []string{"enter"}, Help: "detail"},
		TierCycle: nav.KeyBinding{Keys: []string{"t"}, Help: "tier filter"},
	}
}

// ShortHelp surfaces the bindings in the footer / `?` overlay's compact
// mode. Detail (Enter) and tier-cycle (t) live in FullHelp only — they're
// power-user / exploratory bindings and the footer is already busy.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Back, k.Search, k.LiveTail, k.RunNow, k.Copy}
}

// FullHelp shows two columns: nav row (back/search/detail) and action
// row (live-tail/observe-run/copy/tier).
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Back, k.Search, k.Detail},
		{k.LiveTail, k.RunNow, k.Copy, k.TierCycle},
	}
}
