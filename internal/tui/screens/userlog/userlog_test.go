// Package userlog tests pin the M-USER-LOG modal contract from Plan 06-03 /
// TUI-10. The modal is opened by S-USERS pressing uppercase L on a real row
// and renders a per-user observation slice: header chips with windowed tier
// counts (PerUserBreakdown) plus the last 20 raw events (FilterEvents)
// styled in the S-LOGS wide-mode 5-column layout. Window source: the
// koanf-loaded config.LockdownProposalWindowDays (D-04).
package userlog_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/userlog"
)

// keyPress mirrors the S-USERS / S-FIREWALL / S-LOGS test helper.
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

// newSeededDB opens + migrates a tmp DB and returns a *store.Queries handle
// suitable for driving the userlog model's Init path. Mirrors the helper
// in internal/store/queries_test.go.
func newSeededDB(t *testing.T) (*store.Store, *store.Queries) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s, store.NewQueries(s)
}

// insertRun inserts an observation_runs row and returns its rowid.
func insertRun(t *testing.T, w *sql.DB, result string, finishedAtNs int64) int64 {
	t.Helper()
	res, err := w.ExecContext(context.Background(),
		`INSERT INTO observation_runs(started_at_unix_ns, finished_at_unix_ns, result)
		 VALUES (?, ?, ?)`,
		finishedAtNs-1, finishedAtNs, result)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// insertObservation inserts one observations row.
func insertObservation(t *testing.T, w *sql.DB, runID int64, ts int64, tier, user, ip, eventType string) {
	t.Helper()
	_, err := w.ExecContext(context.Background(),
		`INSERT INTO observations(ts_unix_ns, tier, user, source_ip, event_type, raw_message, raw_json, pid, run_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, tier, user, ip, eventType, "raw msg", "{}", 0, runID)
	require.NoError(t, err)
}

// runInit drives the model through its async-load lifecycle: Init returns a
// tea.Batch of two query Cmds; we invoke them synchronously and feed the
// resulting messages into Update so the model populates breakdown + events
// without a real tea.Program.
func runInit(t *testing.T, m *userlog.Model) {
	t.Helper()
	cmd := m.Init()
	require.NotNil(t, cmd, "Init must return a tea.Cmd")
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "Init must return a tea.Batch of breakdown+events loads; got %T", msg)
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		_, _ = m.Update(sub())
	}
}

// settings constructs a minimal *config.Settings with a custom proposal
// window. Other fields are filled with config.Defaults() so Save/Validate
// invariants hold.
func settings(windowDays int) *config.Settings {
	d := config.Defaults()
	d.LockdownProposalWindowDays = windowDays
	return &d
}

// TestUserLog_implements_nav_Screen is the compile-time + runtime guard
// that *userlog.Model satisfies the nav.Screen contract.
func TestUserLog_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	var s nav.Screen = userlog.New("alice", nil, settings(90))
	require.Equal(t, "alice", s.Title(), "Title surfaces the username so the breadcrumb shows whose log we are viewing")
	require.False(t, s.WantsRawKeys(), "no textinput on the modal")
	require.NotNil(t, s.KeyMap())
}

// TestUserLog_renders_header_and_rows pins the happy-path render: tier
// counters within the configured window AND the rows table populated from
// FilterEvents. Mirrors PerUserBreakdown's group-by-tier output and
// S-LOGS' 5-col layout.
func TestUserLog_renders_header_and_rows(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())
	for i := 0; i < 5; i++ {
		insertObservation(t, s.W, runID, now.Add(-time.Duration(i+1)*time.Hour).UnixNano(), "success", "alice", "10.0.0.1", "auth_pwd_ok")
	}
	for i := 0; i < 3; i++ {
		insertObservation(t, s.W, runID, now.Add(-time.Duration(i+10)*time.Hour).UnixNano(), "noise", "alice", "10.0.0.2", "auth_pwd_fail")
	}
	insertObservation(t, s.W, runID, now.Add(-2*time.Hour).UnixNano(), "targeted", "alice", "10.0.0.3", "auth_pwd_fail")

	m := userlog.New("alice", q, settings(90))
	runInit(t, m)
	v := m.View()

	require.Contains(t, v, "alice", "header surfaces the username")
	require.Contains(t, v, "Last 90 days", "header strip names the active window")
	require.Contains(t, v, "success 5", "tier strip shows windowed success count")
	require.Contains(t, v, "noise 3", "tier strip shows windowed noise count")
	require.Contains(t, v, "targeted 1", "tier strip shows windowed targeted count")
	require.Contains(t, v, "10.0.0.1", "row layout includes source IP")
}

// TestUserLog_empty_state_copy pins D-05 verbatim: no events in window,
// no breakdown counts > 0 - the modal renders the exact empty-state line
// "No login attempts for <user> in the last <N> days."
func TestUserLog_empty_state_copy(t *testing.T) {
	t.Parallel()
	_, q := newSeededDB(t)

	m := userlog.New("alice", q, settings(90))
	runInit(t, m)

	require.Contains(t, m.View(), "No login attempts for alice in the last 90 days.")
}

// TestUserLog_c_copies_focused_row_via_OSC52 pins the OSC 52 contract:
// pressing 'c' on a focused row emits a tea.Cmd that produces a clipboard
// message containing the row's raw text. Mirrors the assertion idiom in
// users_test.go::TestUsersScreen_copy_emits_clipboard_cmd.
func TestUserLog_c_copies_focused_row_via_OSC52(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())
	for i := 0; i < 3; i++ {
		insertObservation(t, s.W, runID, now.Add(-time.Duration(i+1)*time.Hour).UnixNano(), "success", "alice", "10.0.0.1", "auth_pwd_ok")
	}

	m := userlog.New("alice", q, settings(90))
	runInit(t, m)

	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd, "'c' on a focused row must emit a non-nil tea.Cmd")
	msg := cmd()

	// Walk any tea.BatchMsg or single message looking for a clipboard
	// payload that contains the focused row's text. The setClipboardMsg
	// type is unexported in bubbletea v2; its fmt.Sprintf form reveals the
	// payload.
	found := false
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			if sub == nil {
				continue
			}
			if strings.Contains(fmt.Sprintf("%v", sub()), "10.0.0.1") {
				found = true
				break
			}
		}
	} else if strings.Contains(fmt.Sprintf("%v", msg), "10.0.0.1") {
		found = true
	}
	require.True(t, found, "the OSC 52 payload must include the focused row's source IP; got %v", msg)
}

// TestUserLog_window_read_from_config pins Pitfall 5: the windowDays driving
// the header strip MUST come from settings.LockdownProposalWindowDays, AND
// the same window must filter both PerUserBreakdown(sinceNs) AND
// FilterEvents(SinceNs). Otherwise tier counts would be lifetime while
// the row list is windowed - misleading.
func TestUserLog_window_read_from_config(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())
	insertObservation(t, s.W, runID, now.Add(-30*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.1", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-100*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.2", "auth_pwd_ok")
	insertObservation(t, s.W, runID, now.Add(-200*24*time.Hour).UnixNano(), "success", "alice", "10.0.0.3", "auth_pwd_ok")

	m := userlog.New("alice", q, settings(60))
	runInit(t, m)
	v := m.View()

	require.Contains(t, v, "Last 60 days", "header strip MUST mirror settings.LockdownProposalWindowDays")
	require.Contains(t, v, "success 1", "windowed counts MUST exclude rows older than 60 days; got View=%s", v)
	require.NotContains(t, v, "10.0.0.2", "row outside the window must be filtered out (was -100 days)")
	require.NotContains(t, v, "10.0.0.3", "row outside the window must be filtered out (was -200 days)")
}

// TestUserLog_renders_at_most_20_events pins the 20-row cap (FilterEvents
// Limit=20 enforced at the query layer). Mitigates T-06-03-03 (DoS via
// unbounded list).
func TestUserLog_renders_at_most_20_events(t *testing.T) {
	t.Parallel()
	s, q := newSeededDB(t)
	now := time.Now()
	runID := insertRun(t, s.W, "success", now.UnixNano())
	// Seed 50 success events, all within window.
	for i := 0; i < 50; i++ {
		insertObservation(t, s.W, runID, now.Add(-time.Duration(i+1)*time.Minute).UnixNano(), "success", "alice", fmt.Sprintf("10.0.0.%d", i+1), "auth_pwd_ok")
	}

	m := userlog.New("alice", q, settings(90))
	runInit(t, m)

	require.LessOrEqual(t, m.RowCountForTest(), 20,
		"FilterEvents Limit=20 must cap the rendered row count regardless of seeded volume")
}
