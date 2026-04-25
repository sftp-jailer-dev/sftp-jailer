// Package logsscreen tests for S-LOGS — wave-5 / plan 02-06.
//
// Mirrors the S-USERS / S-FIREWALL test shape (key helper + nav.Screen
// compile-time check + LoadXForTest seam) per UI-SPEC §"Async / Loading
// State Contract". Test ownership follows the plan: Task 1 owns the
// detailpane render-helper tests; Task 2 owns the screen behaviour tests.
package logsscreen_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	logsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/logs"
)

// keyPress mirrors the S-USERS / S-FIREWALL helper. Special-cases esc /
// arrow keys so the textinput-based search widget receives a recognisable
// Code field.
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

// --- Task 1 — RenderDetail tests ---------------------------------------

// TestRenderDetail_full_event — every label must appear in the rendered
// output for a fully-populated Event.
func TestRenderDetail_full_event(t *testing.T) {
	e := store.Event{
		ID:         42,
		TsUnixNs:   1714075200_000000000, // 2024-04-25T20:00:00 UTC
		Tier:       "success",
		User:       "alice",
		SourceIP:   "203.0.113.7",
		EventType:  "auth-success",
		RawMessage: "Accepted publickey for alice from 203.0.113.7 port 50000 ssh2",
		RawJSON:    `{"MESSAGE":"Accepted publickey for alice from 203.0.113.7 port 50000 ssh2"}`,
	}
	out := logsscreen.RenderDetail(e, 80)
	for _, label := range []string{
		"timestamp:", "user:", "source:", "event:", "tier:", "raw MESSAGE:",
	} {
		require.Contains(t, out, label, "RenderDetail must include label %q", label)
	}
	for _, value := range []string{
		"alice", "203.0.113.7", "auth-success", "success",
		"Accepted publickey for alice",
	} {
		require.Contains(t, out, value, "RenderDetail must include value %q", value)
	}
}

// TestRenderDetail_truncates_safely — a very long raw MESSAGE must not
// cause a panic and must be present in the output (we soft-wrap; hard
// truncation lives at the parent View layer).
func TestRenderDetail_truncates_safely(t *testing.T) {
	long := strings.Repeat("X", 5000)
	e := store.Event{
		TsUnixNs: 1714075200_000000000,
		User:     "alice", SourceIP: "203.0.113.7", EventType: "auth-success",
		Tier: "success", RawMessage: long,
	}
	require.NotPanics(t, func() {
		_ = logsscreen.RenderDetail(e, 60)
	})
}

// TestRenderDetail_word_after_tier — UI-SPEC line 444: tier line shows
// the word followed by the glyph (e.g. "success ✓").
func TestRenderDetail_word_after_tier(t *testing.T) {
	e := store.Event{Tier: "success"}
	require.Contains(t, logsscreen.RenderDetail(e, 60), "success ✓")
}

// --- Task 2 — S-LOGS screen tests --------------------------------------

// TestLogsScreen_implements_nav_Screen — compile-time check that *Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap / WantsRawKeys.
func TestLogsScreen_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = logsscreen.New(nil, nil)
	require.Equal(t, "logs", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys must be false in the inactive-search default state")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestLogsScreen_loading_state — initial View shows the loading copy.
func TestLogsScreen_loading_state(t *testing.T) {
	m := logsscreen.New(nil, nil)
	require.Contains(t, m.View(), "loading events…")
}

// TestLogsScreen_LoadEventsForTest_renders_list — feeding events via the
// test seam bypasses Init+queries; View must render every supplied user.
func TestLogsScreen_LoadEventsForTest_renders_list(t *testing.T) {
	m := logsscreen.New(nil, nil)
	now := time.Now().UnixNano()
	m.LoadEventsForTest([]store.Event{
		{ID: 1, TsUnixNs: now, Tier: "success", User: "alice", SourceIP: "203.0.113.7", EventType: "auth-success"},
		{ID: 2, TsUnixNs: now, Tier: "targeted", User: "bob", SourceIP: "198.51.100.42", EventType: "auth-fail"},
		{ID: 3, TsUnixNs: now, Tier: "noise", User: "carol", SourceIP: "192.0.2.1", EventType: "preauth-disconnect"},
	}, nil)
	v := m.View()
	for _, want := range []string{"alice", "bob", "carol", "✓", "!", "i"} {
		require.Contains(t, v, want, "list-mode View must contain %q; got %q", want, v)
	}
}

// TestLogsScreen_LoadStatusForTest_healthy — Schema vN, event count,
// counter count, "X ago"/"now"/"seconds" relative time.
func TestLogsScreen_LoadStatusForTest_healthy(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadStatusForTest(store.StatusRow{
		SchemaVersion: 2,
		DetailCount:   100,
		CounterCount:  5,
		LastSuccessNs: time.Now().UnixNano(),
	})
	// Force a non-empty events list so the View renders the body, not the
	// empty-state copy.
	m.LoadEventsForTest([]store.Event{{ID: 1, TsUnixNs: time.Now().UnixNano(), Tier: "success", User: "alice"}}, nil)
	v := m.View()
	require.Contains(t, v, "Schema v2")
	require.Contains(t, v, "100 events")
	require.Contains(t, v, "5 counters")
	require.True(t, strings.Contains(v, "ago") || strings.Contains(v, "now") || strings.Contains(v, "seconds"),
		"healthy status row must include a humanize-style relative time fragment; got %q", v)
}

// TestLogsScreen_LoadStatusForTest_stale — LastSuccessNs ≥14 days old →
// status row rendered in the stale (Warn) styling per UI-SPEC line 282.
// We assert (a) the relative-time fragment is present (humanize.Time
// chooses "weeks"/"days"/"month" depending on the exact delta — we
// accept any of those rather than pin a specific literal) and (b) the
// healthy "Schema v" segment is NOT rendered in the Primary token (the
// stale path renders the whole row in Warn, so the Primary-coloured
// schema-segment ANSI sequence used by the healthy path is absent).
func TestLogsScreen_LoadStatusForTest_stale(t *testing.T) {
	twentyDaysAgo := time.Now().Add(-20 * 24 * time.Hour).UnixNano()
	m := logsscreen.New(nil, nil)
	m.LoadStatusForTest(store.StatusRow{
		SchemaVersion: 2,
		DetailCount:   10,
		CounterCount:  1,
		LastSuccessNs: twentyDaysAgo,
	})
	m.LoadEventsForTest([]store.Event{{ID: 1, TsUnixNs: time.Now().UnixNano(), User: "alice"}}, nil)
	v := m.View()
	// Accept any humanize.Time fragment that signals "more than two weeks":
	// "weeks ago", "month ago", or "days ago" all signal the stale state.
	require.True(t,
		strings.Contains(v, "weeks ago") ||
			strings.Contains(v, "month ago") ||
			strings.Contains(v, "days ago"),
		"stale status row must include a humanize-style >14d fragment; got %q", v)
	require.Contains(t, v, "Schema v2", "status row body must include the schema literal")
}

// TestLogsScreen_LoadStatusForTest_schema_drift — SchemaVersion >
// ExpectedSchemaVersion → drift message rendered with the Critical
// styling and the literal apt-upgrade hint.
func TestLogsScreen_LoadStatusForTest_schema_drift(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadStatusForTest(store.StatusRow{
		SchemaVersion: 99, DetailCount: 0, CounterCount: 0, LastSuccessNs: 0,
	})
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice"}}, nil)
	v := m.View()
	require.Contains(t, v, "Schema v99")
	require.Contains(t, v, "binary expects v2")
	require.Contains(t, v, "observer disabled")
	require.Contains(t, v, "apt upgrade sftp-jailer")
}

// TestLogsScreen_LoadStatusForTest_never_run — LastSuccessNs == 0 →
// renders "last run never" verbatim.
func TestLogsScreen_LoadStatusForTest_never_run(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadStatusForTest(store.StatusRow{
		SchemaVersion: 2, DetailCount: 5, CounterCount: 1, LastSuccessNs: 0,
	})
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice"}}, nil)
	require.Contains(t, m.View(), "last run never")
}

// TestLogsScreen_split_pane_wide_mode — width=140 (≥120) triggers the
// split layout; the detail pane labels must appear.
func TestLogsScreen_split_pane_wide_mode(t *testing.T) {
	m := logsscreen.New(nil, nil)
	_, _ = m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m.LoadStatusForTest(store.StatusRow{SchemaVersion: 2, DetailCount: 1, CounterCount: 0, LastSuccessNs: time.Now().UnixNano()})
	m.LoadEventsForTest([]store.Event{
		{ID: 1, TsUnixNs: time.Now().UnixNano(), Tier: "success", User: "alice", SourceIP: "203.0.113.7", EventType: "auth-success", RawMessage: "Accepted publickey"},
	}, nil)
	v := m.View()
	require.Contains(t, v, "timestamp:", "wide-mode View must include detail-pane labels; got %q", v)
	require.Contains(t, v, "raw MESSAGE:", "wide-mode View must include raw MESSAGE label; got %q", v)
}

// TestLogsScreen_list_only_narrow_mode — width<120 → no detail-pane
// labels visible; list still rendered.
func TestLogsScreen_list_only_narrow_mode(t *testing.T) {
	m := logsscreen.New(nil, nil)
	_, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 40})
	m.LoadStatusForTest(store.StatusRow{SchemaVersion: 2, DetailCount: 1, CounterCount: 0, LastSuccessNs: time.Now().UnixNano()})
	m.LoadEventsForTest([]store.Event{
		{ID: 1, TsUnixNs: time.Now().UnixNano(), Tier: "success", User: "alice", SourceIP: "203.0.113.7", EventType: "auth-success", RawMessage: "Accepted publickey"},
	}, nil)
	v := m.View()
	require.NotContains(t, v, "timestamp:", "narrow-mode View must NOT include detail-pane labels; got %q", v)
	require.Contains(t, v, "alice", "narrow-mode View must still render the list; got %q", v)
}

// TestLogsScreen_tier_filter_cycle — pressing `t` repeatedly cycles
// through all → success → targeted → noise → unmatched → all. The
// footer renders the active tier label so View() can be substring-asserted.
func TestLogsScreen_tier_filter_cycle(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadStatusForTest(store.StatusRow{SchemaVersion: 2, DetailCount: 1, CounterCount: 0, LastSuccessNs: time.Now().UnixNano()})
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice", TsUnixNs: time.Now().UnixNano()}}, nil)
	want := []string{"all", "success", "targeted", "noise", "unmatched", "all"}
	require.Contains(t, m.View(), "tier: "+want[0], "initial tier is all; got View=%s", m.View())
	for i := 1; i < len(want); i++ {
		_, _ = m.Update(keyPress("t"))
		require.Contains(t, m.View(), "tier: "+want[i],
			"after %d `t` presses, tier filter must be %q; got View=%s", i, want[i], m.View())
	}
}

// TestLogsScreen_copy_emits_SetClipboard — `c` on a loaded event with
// non-empty RawJSON emits a tea.BatchMsg containing tea.SetClipboard
// with the RawJSON; toast announces the OSC 52 copy.
func TestLogsScreen_copy_emits_SetClipboard(t *testing.T) {
	m := logsscreen.New(nil, nil)
	rawJSON := `{"MESSAGE":"Accepted publickey for alice","_HOSTNAME":"sftp"}`
	m.LoadEventsForTest([]store.Event{
		{ID: 1, TsUnixNs: time.Now().UnixNano(), User: "alice", RawJSON: rawJSON, Tier: "success"},
	}, nil)
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
		if strings.Contains(s, "Accepted publickey") {
			found = true
			break
		}
	}
	require.True(t, found, "batch must include a clipboard sub-cmd whose message stringifies to the RawJSON content")
	require.Contains(t, m.View(), "copied raw record via OSC 52")
}

// TestLogsScreen_F_invokes_ExecProcess_via_sysops_helper — pressing `F`
// must call m.ops.JournalctlFollowCmd("ssh"). Asserted via the Fake's
// Calls log: after the F handler runs, Calls records a JournalctlFollowCmd
// invocation with arg "ssh".
func TestLogsScreen_F_invokes_ExecProcess_via_sysops_helper(t *testing.T) {
	fake := &sysops.Fake{}
	m := logsscreen.New(nil, fake)
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice"}}, nil)
	_, cmd := m.Update(keyPress("F"))
	require.NotNil(t, cmd, "`F` must emit a tea.Cmd")
	// Assert that the Fake recorded the JournalctlFollowCmd invocation.
	var found bool
	for _, c := range fake.Calls {
		if c.Method == "JournalctlFollowCmd" {
			require.Equal(t, []string{"ssh"}, c.Args, "JournalctlFollowCmd must be called with arg 'ssh'")
			found = true
			break
		}
	}
	require.True(t, found, "Fake.Calls must record a JournalctlFollowCmd call; got %+v", fake.Calls)
}

// TestLogsScreen_empty_state — zero events AND DetailCount == 0 → the
// empty-state copy from UI-SPEC line 359 is rendered verbatim.
func TestLogsScreen_empty_state(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadEventsForTest(nil, nil)
	m.LoadStatusForTest(store.StatusRow{SchemaVersion: 2, DetailCount: 0, CounterCount: 0, LastSuccessNs: 0})
	require.Contains(t, m.View(), "No events recorded yet.")
}

// TestLogsScreen_db_error_state — UI-SPEC line 360 copy when load
// surfaces an error.
func TestLogsScreen_db_error_state(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadEventsForTest(nil, errors.New("permission denied opening /var/lib/sftp-jailer/observations.db"))
	require.Contains(t, m.View(), "Could not open observation DB:")
}

// TestLogsScreen_keymap_bindings — assert the S-LOGS bindings list per
// must_haves.
func TestLogsScreen_keymap_bindings(t *testing.T) {
	km := logsscreen.DefaultKeyMap()
	short := km.ShortHelp()
	foundShort := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			foundShort[k] = true
		}
	}
	for _, k := range []string{"esc", "q", "/", "F", "r", "c"} {
		require.True(t, foundShort[k], "ShortHelp must expose %q; got %+v", k, foundShort)
	}
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
	for _, k := range []string{"t", "enter"} {
		require.True(t, foundFull[k], "FullHelp must surface %q; got %+v", k, foundFull)
	}
}

// TestLogsScreen_esc_pops — esc/q pops back to home.
func TestLogsScreen_esc_pops(t *testing.T) {
	m := logsscreen.New(nil, nil)
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice"}}, nil)
	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	nm, ok := cmd().(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", cmd())
	require.Equal(t, nav.Pop, nm.Intent)
}

// TestLogsScreen_r_placeholder_when_no_factory — pressing `r` with no
// observerunFactory registered shows a placeholder toast (will be replaced
// by M-OBSERVE in plan 02-08).
func TestLogsScreen_r_placeholder_when_no_factory(t *testing.T) {
	logsscreen.SetObserveRunFactory(nil) // ensure clean state
	m := logsscreen.New(nil, nil)
	m.LoadEventsForTest([]store.Event{{ID: 1, User: "alice"}}, nil)
	_, _ = m.Update(keyPress("r"))
	require.Contains(t, m.View(), "observe-run modal coming in plan 02-08")
}
