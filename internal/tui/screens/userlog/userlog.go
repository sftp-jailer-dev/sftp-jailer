// Package userlog renders the M-USER-LOG modal: a per-user observation
// slice opened from S-USERS by pressing uppercase L on a real row.
//
// Plan 06-03 / TUI-10 contract:
//   - D-01: uppercase L on S-USERS pushes M-USER-LOG. Lowercase d
//     (S-USER-DETAIL) and uppercase D (M-DELETE-USER-FW-RULES) are
//     unchanged - regression guards in users.go and users_test.go.
//   - D-02: 5-column row layout matches S-LOGS wide-mode (ts UTC | user |
//     source IP | tier glyph | raw excerpt). OSC 52 copies the focused row.
//   - D-03: header strip renders LOG-06 tier counts via
//     Queries.PerUserBreakdown. Per Pitfall 5 the existing PerUserBreakdown
//     signature was extended (Plan 06-03 Task 1) to take a sinceNs filter
//     so the displayed numbers match the windowDays stated in the strip.
//   - D-04: time window read from config.LockdownProposalWindowDays
//     (default 90, range [1, 3650]). Avoids config-knob proliferation.
//   - D-05: empty-state copy "No login attempts for <user> in the last
//     <N> days." (verbatim, no em-dash).
//
// Architectural notes:
//   - Modal is a regular nav.Screen pushed onto the nav stack from S-USERS.
//   - Init dispatches both queries in parallel via tea.Batch. The
//     PerUserBreakdown call provides the windowed tier counts; FilterEvents
//     provides the last-20 raw rows in ts-DESC order.
//   - Cursor cycles through the rows (j/k); 'c' copies the focused row text
//     via tea.SetClipboard (OSC 52). 'esc' / 'q' pops the modal.
//   - Modal frame uses NormalBorder + Padding(0, 2) per the M-OBSERVE /
//     M-ADD-KEY pattern (RESEARCH Pattern 3).
//
// Threat model (PLAN 06-03 §threat_model):
//   - T-06-03-02: SQL placeholders only; PerUserBreakdown sinceNs flows via
//     `?` placeholder. Username is pre-validated upstream.
//   - T-06-03-03: FilterEvents Limit=20 caps memory + render cost.
//   - T-06-03-04: nil-factory path in S-USERS makes the L keybind a no-op
//     when this screen is not wired in.
package userlog

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	logsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/logs"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// EventLimit is the row cap for the M-USER-LOG modal. Mirrors the
// FilterEvents.Limit convention used by S-LOGS but scoped to 20 here so
// the modal stays compact and a misbehaving observer cannot blow up the
// admin's terminal (T-06-03-03 mitigation).
const EventLimit = 20

// loadedBreakdownMsg carries the PerUserBreakdown result back into Update.
type loadedBreakdownMsg struct {
	ub  store.UserBreakdown
	err error
}

// loadedEventsMsg carries the FilterEvents result back into Update.
type loadedEventsMsg struct {
	events []store.Event
	err    error
}

// Model is the M-USER-LOG Bubble Tea v2 model. Constructed via New; one
// instance per push. Treat as single-use - the data is loaded once on Init
// and the modal does not refresh in-place (admin can pop + re-open to
// re-fetch).
type Model struct {
	username   string
	queries    *store.Queries
	settings   *config.Settings
	windowDays int

	breakdown store.UserBreakdown
	events    []store.Event

	cursor int
	width  int

	// Track per-load completion so View() can render the loaded shape
	// even when only one of the two queries has returned.
	breakdownLoaded bool
	eventsLoaded    bool

	errBreakdown error
	errEvents    error

	keys KeyMap
}

// KeyMap is the M-USER-LOG key bindings - implements nav.KeyMap.
type KeyMap struct {
	Back nav.KeyBinding
	Up   nav.KeyBinding
	Down nav.KeyBinding
	Copy nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-USER-LOG bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back: nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Up:   nav.KeyBinding{Keys: []string{"k", "up"}, Help: "up"},
		Down: nav.KeyBinding{Keys: []string{"j", "down"}, Help: "down"},
		Copy: nav.KeyBinding{Keys: []string{"c"}, Help: "copy row"},
	}
}

// ShortHelp surfaces the bindings shown in the footer / `?` overlay.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Back, k.Up, k.Down, k.Copy}
}

// FullHelp mirrors ShortHelp - the modal has no power-user bindings.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Back, k.Up, k.Down, k.Copy}}
}

// New constructs the modal for username, wired to queries (the read layer
// shipped in 02-01 + extended in Plan 06-03 Task 1) and the loaded
// settings (drives the time window). queries may be nil in unit tests
// that exercise rendering without the data layer; settings MUST NOT be
// nil - the production caller in cmd/sftp-jailer/main.go always passes
// the koanf-loaded handle.
func New(username string, queries *store.Queries, settings *config.Settings) *Model {
	wd := 0
	if settings != nil {
		wd = settings.LockdownProposalWindowDays
	}
	if wd <= 0 {
		// Defensive default - matches config.Defaults() so the modal
		// renders sensibly even if the caller hands a half-built
		// Settings literal.
		wd = config.Defaults().LockdownProposalWindowDays
	}
	return &Model{
		username:   username,
		queries:    queries,
		settings:   settings,
		windowDays: wd,
		keys:       DefaultKeyMap(),
	}
}

// RowCountForTest exposes the rendered row count (post Limit cap) so unit
// tests can assert the 20-row cap without relying on View() string scraping.
func (m *Model) RowCountForTest() int { return len(m.events) }

// Title implements nav.Screen. Returns the username so the breadcrumb
// surfaces whose log is being viewed (matches the M-OBSERVE / M-PASSWORD
// per-screen-title convention).
func (m *Model) Title() string { return m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen - false because the modal has no
// textinput.
func (m *Model) WantsRawKeys() bool { return false }

// Init dispatches both queries in parallel via tea.Batch. If queries is
// nil (test path that drives rendering directly) Init returns nil.
func (m *Model) Init() tea.Cmd {
	if m.queries == nil {
		return nil
	}
	return tea.Batch(m.loadBreakdown(), m.loadEvents())
}

// sinceNs returns the windowed cutoff timestamp in ns, derived from
// time.Now() and m.windowDays. Both PerUserBreakdown and FilterEvents
// receive this same value so the header chips and the row list stay in
// sync (Pitfall 5 close).
func (m *Model) sinceNs() int64 {
	return time.Now().Add(-time.Duration(m.windowDays) * 24 * time.Hour).UnixNano()
}

// loadBreakdown returns a tea.Cmd that fetches the windowed per-tier
// counts. Uses the Plan 06-03 Task 1 sinceNs surface so the displayed
// counts match "Last N days".
func (m *Model) loadBreakdown() tea.Cmd {
	q := m.queries
	if q == nil {
		return nil
	}
	user := m.username
	sinceNs := m.sinceNs()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ub, err := q.PerUserBreakdown(ctx, user, sinceNs)
		return loadedBreakdownMsg{ub: ub, err: err}
	}
}

// loadEvents returns a tea.Cmd that fetches the last EventLimit raw events
// for the user within the configured window. SinceNs ensures the rows
// match the header strip's window assertion.
func (m *Model) loadEvents() tea.Cmd {
	q := m.queries
	if q == nil {
		return nil
	}
	opts := store.FilterOpts{
		User:    m.username,
		SinceNs: m.sinceNs(),
		Limit:   EventLimit,
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs, err := q.FilterEvents(ctx, opts)
		return loadedEventsMsg{events: evs, err: err}
	}
}

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case loadedBreakdownMsg:
		m.breakdownLoaded = true
		if msg.err != nil {
			m.errBreakdown = msg.err
			return m, nil
		}
		m.breakdown = msg.ub
		return m, nil

	case loadedEventsMsg:
		m.eventsLoaded = true
		if msg.err != nil {
			m.errEvents = msg.err
			return m, nil
		}
		m.events = msg.events
		if m.cursor >= len(m.events) {
			m.cursor = 0
		}
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey routes key presses for the modal.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
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
	case "c":
		return m.handleCopy()
	}
	return m, nil
}

// handleCopy emits an OSC 52 SetClipboard cmd for the focused row's
// serialized text. No-op when there is no focused row.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.events) {
		return m, nil
	}
	text := serializeRow(m.events[m.cursor])
	return m, tea.SetClipboard(text)
}

// serializeRow returns a tab-separated string carrying the focused row's
// fields for paste-friendly clipboard handoff. Mirrors the rowAsTSV idiom
// in usersscreen.handleCopy (single source of truth for "what got copied"
// in tests + production).
func serializeRow(e store.Event) string {
	ts := time.Unix(0, e.TsUnixNs).UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s",
		ts, e.User, e.SourceIP, e.Tier, e.RawMessage)
}

// View renders the modal body wrapped in a NormalBorder per the
// M-OBSERVE / M-ADD-KEY pattern (RESEARCH Pattern 3).
func (m *Model) View() string {
	var b strings.Builder

	// Header line - bold username.
	b.WriteString(styles.Primary.Render(m.username))
	b.WriteString("\n")

	// Tier strip - "Last N days · success S · targeted T · noise N · unmatched U".
	// Middle-dot separator (NOT em-dash) per the project-wide memory rule.
	b.WriteString(styles.Dim.Render(m.renderTierStrip()))
	b.WriteString("\n\n")

	// Empty state - if both loads completed AND nothing to render, show
	// the verbatim D-05 copy.
	if m.isEmpty() {
		b.WriteString(fmt.Sprintf("No login attempts for %s in the last %d days.",
			m.username, m.windowDays))
		b.WriteString("\n")
		return wrapModal(b.String())
	}

	// Loading shim - if either load is still in flight, surface that so
	// the admin sees feedback. View() can be called between Init's
	// dispatch and the goroutine returning.
	if !m.breakdownLoaded || !m.eventsLoaded {
		b.WriteString(styles.Dim.Render("loading..."))
		b.WriteString("\n")
		return wrapModal(b.String())
	}

	// Column header.
	b.WriteString(styles.Dim.Render("ts(UTC)         user      src             t  raw"))
	b.WriteString("\n")

	// Rows - up to EventLimit, in ts-DESC order from FilterEvents.
	for i, e := range m.events {
		ts := time.Unix(0, e.TsUnixNs).UTC().Format("15:04:05")
		raw := e.RawMessage
		if len(raw) > 40 {
			raw = raw[:39] + "..."
		}
		line := fmt.Sprintf("%-15s %s %s %s  %s",
			ts,
			logsscreen.DisplayN(e.User, 9),
			logsscreen.DisplayN(e.SourceIP, 15),
			logsscreen.TierGlyph(e.Tier),
			raw)
		line = logsscreen.ColorByTier(e.Tier, line)
		marker := "  "
		if i == m.cursor {
			marker = "> "
			line = lipgloss.NewStyle().Reverse(true).Render(line)
		}
		b.WriteString(marker)
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Footer help.
	b.WriteString("\n")
	b.WriteString(styles.Dim.Render("j/k move  c copy  esc back"))
	b.WriteString("\n")

	return wrapModal(b.String())
}

// renderTierStrip composes the per-window tier-count line. Reads counts
// from m.breakdown so the values match PerUserBreakdown's sinceNs window.
func (m *Model) renderTierStrip() string {
	return fmt.Sprintf("Last %d days  -  success %d  -  targeted %d  -  noise %d  -  unmatched %d",
		m.windowDays,
		tierCount(m.breakdown, "success"),
		tierCount(m.breakdown, "targeted"),
		tierCount(m.breakdown, "noise"),
		tierCount(m.breakdown, "unmatched"))
}

// tierCount returns the count for tier from ub (0 if absent).
func tierCount(ub store.UserBreakdown, tier string) int {
	for _, t := range ub.Tiers {
		if t.Tier == tier {
			return int(t.Count)
		}
	}
	return 0
}

// isEmpty reports whether the modal has no data to render. True only when
// both loads completed AND breakdown has no positive tier counts AND
// events is empty - so the empty-state copy never flashes during loading.
func (m *Model) isEmpty() bool {
	if !m.breakdownLoaded || !m.eventsLoaded {
		return false
	}
	if len(m.events) > 0 {
		return false
	}
	for _, t := range m.breakdown.Tiers {
		if t.Count > 0 {
			return false
		}
	}
	return true
}

// wrapModal applies the M-USER-LOG modal frame: NormalBorder + Padding(0, 2)
// per RESEARCH Pattern 3 (matches M-OBSERVE / M-ADD-KEY).
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}
