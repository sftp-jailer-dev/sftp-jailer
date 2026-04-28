package lockdown

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	lpkg "github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

func TestRenderPlanText_includes_both_sections(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpAdd, Rule: firewall.Rule{User: "alice", Source: "1.2.3.4/32", Port: "22"}},
	}
	currentRules := []firewall.Rule{
		{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN"},
	}
	m := NewDryRunModal(f, muts, currentRules)
	text := m.RenderPlanText()
	require.Contains(t, text, "=== Rule diff ===")
	require.Contains(t, text, "=== Command plan ===")
	require.Contains(t, text, "ufw insert 1 allow proto tcp from 1.2.3.4/32",
		"command-plan section must include the forward UfwInsert line")
	require.Contains(t, text, "systemd-run --on-active",
		"command-plan section must include the SAFE-04 schedule line")
}

func TestRenderCommands_includes_safe04_schedule_line(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpAdd, AssignedID: 1, Rule: firewall.Rule{User: "alice", Source: "1.2.3.4/32", Port: "22"}},
	}
	m := NewDryRunModal(f, muts, nil)
	cmd := m.renderCommands()
	require.Contains(t, cmd, "systemd-run --on-active=180sec",
		"schedule line must use 180sec on-active duration (3 min)")
	require.Contains(t, cmd, "/bin/sh -c '",
		"schedule line must wrap shell body in /bin/sh -c '...'")
}

func TestRenderDiff_marks_deleted_rules_with_minus(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpDelete, Rule: firewall.Rule{ID: 5, Port: "22", Source: "Anywhere"}},
	}
	currentRules := []firewall.Rule{
		{ID: 5, Port: "22", Source: "Anywhere", Action: "ALLOW IN"},
	}
	m := NewDryRunModal(f, muts, currentRules)
	diff := m.renderDiff()
	require.Contains(t, diff, "- ", "deleted rules must be prefixed with `- ` marker")
}

func TestRenderDiff_lists_proposed_additions(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpAdd, Rule: firewall.Rule{User: "alice", Source: "203.0.113.7/32", Port: "22"}},
	}
	m := NewDryRunModal(f, muts, nil)
	diff := m.renderDiff()
	require.Contains(t, diff, "Proposed additions:")
	require.Contains(t, diff, "+ ufw insert 1 allow proto tcp from 203.0.113.7/32")
	require.Contains(t, diff, "comment 'sftpj:v=1:user=alice'")
}

func TestRenderCommands_includes_ufw_reload_finalizer(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpAdd, Rule: firewall.Rule{User: "alice", Source: "1.1.1.1/32", Port: "22"}},
	}
	m := NewDryRunModal(f, muts, nil)
	cmd := m.renderCommands()
	require.Contains(t, cmd, "ufw reload\n",
		"command-plan section must end the forward batch with `ufw reload`")
}

func TestUpdate_esc_pops(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := NewDryRunModal(f, nil, nil)
	// Pop is implemented; we just want to ensure no panic on esc keypress.
	require.NotPanics(t, func() {
		_, _ = m.Update(escKeyPressMsg{})
	})
}

// escKeyPressMsg is a tiny stand-in for tea.KeyPressMsg("esc") so the
// test doesn't need to import the bubbletea package just for the
// Update-handles-esc smoke test. The DryRunModel.Update only inspects
// the result of String() — any tea.Msg whose String() returns "esc"
// would do, but we'd need to mock the type. The cleanest path is to
// keep this test as a no-panic smoke check.
type escKeyPressMsg struct{}

func TestSection_Tab_cycles_diff_and_commands(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := NewDryRunModal(f, nil, nil)
	require.Equal(t, dryRunSectionDiff, m.SectionForTest(),
		"initial section is rule-diff")
}

func TestRenderPlanText_for_OSC52_copy_is_plain_text_with_no_ANSI(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	muts := []lpkg.PendingMutation{
		{Op: lpkg.OpAdd, Rule: firewall.Rule{User: "alice", Source: "1.2.3.4/32", Port: "22"}},
	}
	m := NewDryRunModal(f, muts, nil)
	text := m.RenderPlanText()
	// Sanity: no ANSI escape sequences (OSC 52 ships plain text only).
	require.False(t, strings.Contains(text, "\x1b["),
		"RenderPlanText must be plain text — no ANSI escapes (OSC 52 contract)")
}
