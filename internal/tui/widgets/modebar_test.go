package widgets

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
)

// Operator-stated rule (2026-05-03 lab UAT): the modebar firewall state
// renders as binary LOCKED / UNLOCKED. The internal firewall.Mode enum
// keeps its 4 values; only the modebar render is binarized. UNLOCKED
// covers ModeOpen, ModeStaging, and ModeUnknown - each carries a state
// qualifier so the operator does not lose context.

func TestModeBar_renders_UNLOCKED_when_mode_is_ModeOpen(t *testing.T) {
	t.Parallel()
	b := NewModeBar(nil).SetMode(firewall.ModeOpen, 0, 0)
	view := b.View()
	require.Contains(t, view, "FIREWALL MODE: UNLOCKED")
	require.Contains(t, view, "observing only")
	require.NotContains(t, view, "FIREWALL MODE: LOCKED",
		"ModeOpen must NOT render the green MODE: LOCKED label")
}

func TestModeBar_renders_UNLOCKED_for_STAGING_with_rule_count(t *testing.T) {
	t.Parallel()
	b := NewModeBar(nil).SetMode(firewall.ModeStaging, 5, 0)
	view := b.View()
	require.Contains(t, view, "FIREWALL MODE: UNLOCKED")
	require.Contains(t, view, "5 rules staged")
	require.Contains(t, view, "not enforced")
}

func TestModeBar_renders_LOCKED_with_rule_and_user_count(t *testing.T) {
	t.Parallel()
	b := NewModeBar(nil).SetMode(firewall.ModeLocked, 12, 3)
	view := b.View()
	require.Contains(t, view, "FIREWALL MODE: LOCKED")
	require.Contains(t, view, "12 allow rules")
	require.Contains(t, view, "3 users")
}

func TestModeBar_renders_UNLOCKED_for_default_unknown(t *testing.T) {
	t.Parallel()
	b := NewModeBar(nil).SetMode(firewall.ModeUnknown, 0, 0)
	view := b.View()
	require.Contains(t, view, "FIREWALL MODE: UNLOCKED")
	require.Contains(t, view, "no SFTP allow rules yet")
}

func TestModeBar_renders_REVERTING_when_armed_overrides_mode(t *testing.T) {
	t.Parallel()
	deadline := time.Now().Add(2*time.Minute + 53*time.Second)
	b := NewModeBar(nil).
		SetMode(firewall.ModeOpen, 0, 0).
		SetForceArmedForTest(&revert.State{
			UnitName:       "sftpj-revert-1.service",
			DeadlineUnixNs: deadline.UnixNano(),
		})
	view := b.View()
	require.Contains(t, view, "REVERTING IN")
	require.NotContains(t, view, "FIREWALL MODE: UNLOCKED") // overridden
	// The remaining time should be approximately 2:53 (allow ±1s for test scheduling).
	require.True(t,
		strings.Contains(view, "2:53") ||
			strings.Contains(view, "2:52"),
		"expected remaining ~2:53, got: %s", view)
}

func TestModeBar_REVERTING_at_deadline_reads_zero(t *testing.T) {
	t.Parallel()
	deadline := time.Now().Add(-time.Second) // already past
	b := NewModeBar(nil).SetForceArmedForTest(&revert.State{DeadlineUnixNs: deadline.UnixNano()})
	view := b.View()
	require.Contains(t, view, "REVERTING IN 0:00")
}

func TestModeBar_Update_routes_tick_msg_returns_same_value(t *testing.T) {
	t.Parallel()
	b := NewModeBar(nil).SetMode(firewall.ModeStaging, 7, 0)
	got := b.Update(ModeBarTickMsg{})
	// Update is a no-op for tick (re-rendering happens via View); the
	// returned value must still render the same MODE state.
	view := got.View()
	require.Contains(t, view, "FIREWALL MODE: UNLOCKED")
	require.Contains(t, view, "7 rules staged")
}

func TestTickCmd_returns_non_nil_command(t *testing.T) {
	t.Parallel()
	cmd := TickCmd()
	require.NotNil(t, cmd)
}

func TestFormatDuration_negative_renders_zero(t *testing.T) {
	t.Parallel()
	require.Equal(t, "0:00", formatDuration(-time.Second))
}

func TestFormatDuration_minutes_seconds_format(t *testing.T) {
	t.Parallel()
	require.Equal(t, "5:07", formatDuration(5*time.Minute+7*time.Second))
	require.Equal(t, "0:42", formatDuration(42*time.Second))
	require.Equal(t, "10:00", formatDuration(10*time.Minute))
}
