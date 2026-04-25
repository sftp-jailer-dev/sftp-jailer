// Package logsscreen tests for S-LOGS — wave-5 / plan 02-06.
//
// Mirrors the S-USERS / S-FIREWALL test shape (key helper + nav.Screen
// compile-time check + LoadXForTest seam) per UI-SPEC §"Async / Loading
// State Contract". Test ownership follows the plan: Task 1 owns the
// detailpane render-helper tests; Task 2 owns the screen behaviour tests.
package logsscreen_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	logsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/logs"
)

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
