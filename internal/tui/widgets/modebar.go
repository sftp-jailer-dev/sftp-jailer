package widgets

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// ModeBar is the always-visible top-of-app strip (D-L0809-03 + D-S04-03).
// Renders MODE: OPEN/STAGING/LOCKED/UNKNOWN normally; switches to
// "⏱ REVERTING IN M:SS — [C]onfirm [V]iew countdown" (Critical-red) when a
// SAFE-04 revert is armed. The REVERTING render OVERRIDES the MODE words —
// admins always see the countdown when the timer is live, regardless of
// which screen they navigate to.
//
// Value-receiver discipline: the App holds this by value. Mutations return
// new values via SetMode / Update. Mirror toast.go's value-receiver pattern
// (the C6 fix from Phase 1 plan 01-02 — Bubble Tea passes values by copy
// through tea.Cmd closures, so pointer-receiver mutations would be silently
// dropped).
type ModeBar struct {
	mode      firewall.Mode
	ruleCount int
	userCount int

	// watcherRef is the SAFE-04 armed-revert source of truth (Plan 04-04).
	// nil is valid (test paths or pre-bootstrap construction); View() falls
	// back to the MODE branch.
	watcherRef *revert.Watcher

	// forceArmed is the test-only override. When non-nil, View renders
	// REVERTING using this state regardless of watcherRef. Production code
	// MUST NOT touch this field; the SetForceArmedForTest helper enforces
	// the test-only naming convention.
	forceArmed *revert.State
}

// ModeBarTickMsg is emitted every 1s by TickCmd to drive countdown
// re-renders. Update() consumes it as a no-op (the time math lives in
// View()); the App's Update routes it to ModeBar and re-arms the next
// TickCmd to keep the cycle alive.
type ModeBarTickMsg struct{}

// NewModeBar constructs a ModeBar bound to the given watcher reference.
// Pass nil if no watcher is available (e.g. tests that don't exercise the
// REVERTING branch). The default mode is ModeUnknown — callers must call
// SetMode after Enumerate to populate the real classification.
func NewModeBar(watcher *revert.Watcher) ModeBar {
	return ModeBar{watcherRef: watcher, mode: firewall.ModeUnknown}
}

// SetMode updates the mode + counts. Returns a new ModeBar value (C6
// pattern). Callers (S-FIREWALL post-mutation, S-LOCKDOWN post-commit,
// app bootstrap) hold the App which re-assigns the field:
//
//	a.modebar = a.modebar.SetMode(firewall.DetectMode(rules, "22"), n, m)
func (b ModeBar) SetMode(mode firewall.Mode, ruleCount, userCount int) ModeBar {
	b.mode = mode
	b.ruleCount = ruleCount
	b.userCount = userCount
	return b
}

// SetForceArmedForTest overrides watcherRef-based armed detection. Returns
// a new ModeBar value. Pass nil to unset.
//
// TEST-ONLY. Production code must not call this — the watcherRef bound at
// construction time is the SAFE-04 source of truth.
func (b ModeBar) SetForceArmedForTest(s *revert.State) ModeBar {
	b.forceArmed = s
	return b
}

// armedState returns the current armed revert state, or nil when nothing
// is armed. Reads forceArmed first (test override), then watcher.Get().
func (b ModeBar) armedState() *revert.State {
	if b.forceArmed != nil {
		return b.forceArmed
	}
	if b.watcherRef == nil {
		return nil
	}
	return b.watcherRef.Get()
}

// View renders the banner. Always returns a non-empty string — app.View
// pre-pends it above the active screen body so every screen carries the
// MODE / REVERTING context (D-L0809-03 + D-S04-03).
//
// REVERTING takes precedence over MODE: when watcher.Get() returns
// non-nil, the countdown banner replaces the MODE words entirely
// (admins always see the live timer, regardless of which screen they're
// on).
func (b ModeBar) View() string {
	if armed := b.armedState(); armed != nil {
		remaining := time.Until(time.Unix(0, armed.DeadlineUnixNs))
		return styles.Critical.Render(fmt.Sprintf(
			"⏱ REVERTING IN %s — [C]onfirm [V]iew countdown",
			formatDuration(remaining)))
	}
	switch b.mode {
	case firewall.ModeOpen:
		return styles.Warn.Render("MODE: OPEN — observing")
	case firewall.ModeStaging:
		return styles.Info.Render(fmt.Sprintf(
			"MODE: STAGING — %d rules staged", b.ruleCount))
	case firewall.ModeLocked:
		return styles.Success.Render(fmt.Sprintf(
			"MODE: LOCKED — %d allow rules, %d users",
			b.ruleCount, b.userCount))
	default:
		return styles.Dim.Render("MODE: UNKNOWN — no SFTP-port rules")
	}
}

// Update consumes ModeBarTickMsg as a no-op (re-rendering is driven by
// the next View() call) and returns the same widget value. Other messages
// pass through unchanged. Returns a new ModeBar value (C6 pattern) so the
// App's Update can route ticks here without a no-op switch case.
func (b ModeBar) Update(msg tea.Msg) ModeBar {
	switch msg.(type) {
	case ModeBarTickMsg:
		// Re-rendering happens automatically the next time View() is
		// called; the time math lives in View(). This case exists so
		// the App's Update can route ticks through here uniformly with
		// the toast/help widgets.
	}
	return b
}

// TickCmd returns a command that emits ModeBarTickMsg every second. The
// App's Init batches this with the per-screen Init cmds; the Update
// re-arms it after each tick to keep the cycle alive.
//
// CPU cost: one re-render per second is negligible (T-04-09-01 accept).
func TickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return ModeBarTickMsg{}
	})
}

// formatDuration produces "M:SS" for non-negative durations and "0:00"
// for negative/zero. d.Round(time.Second) makes the floor deterministic
// across renders (without rounding, "5m07.4s" and "5m07.6s" both truncate
// to "5:07" via int(d.Seconds()), which is fine — but the round form
// expresses the contract explicitly).
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	total := int(d.Seconds())
	m := total / 60
	s := total % 60
	return fmt.Sprintf("%d:%02d", m, s)
}
