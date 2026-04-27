// Tests for M-DELETE-RULE (Plan 04-06) — three-mode discriminator
// (ModeByID / ModeByUser / ModeBySource) + load+confirm+commit phase
// machine + descending-by-ID sort for the txn batch (D-FW-07 strategy 1).
//
// Tests intentionally focus on the synchronous load/filter + state-
// machine surface; the async commit path's full SAFE-04 + systemd-run
// timer interaction is exercised end-to-end by the empirical UAT in
// Plan 04-10.
package firewallrule_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
)

// TestNewDeleteByID_initial_phase_skips_loading — ModeByID has the
// rule already; Init should NOT call firewall.Enumerate. The phase
// transitions directly to phaseConfirm with one target.
func TestNewDeleteByID_initial_phase_skips_loading(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	rule := firewall.Rule{
		ID: 5, User: "alice", Source: "203.0.113.7/32", Port: "22",
		RawComment: "sftpj:v=1:user=alice",
	}
	m := firewallrule.NewDeleteByID(f, nil, rule)
	cmd := m.Init()
	// ModeByID — payload already known; Init returns nil (no async load).
	require.Nil(t, cmd, "ModeByID Init must NOT spawn an Enumerate goroutine")
	require.Equal(t, firewallrule.DeletePhaseConfirmForTest, m.PhaseForTest(),
		"ModeByID skips loading and lands in phaseConfirm")
	require.Len(t, m.TargetsForTest(), 1)
	require.Equal(t, 5, m.TargetsForTest()[0].ID)
}

// TestNewDeleteByUser_loading_filters_to_matching_user — ModeByUser
// runs Enumerate, then keeps only rules where r.User == username AND
// r.ParseErr == nil.
func TestNewDeleteByUser_loading_filters_to_matching_user(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout: []byte(`Status: active

[ 1] 22/tcp                     ALLOW IN    1.2.3.4/32                 # sftpj:v=1:user=alice
[ 2] 22/tcp                     ALLOW IN    5.6.7.8/32                 # sftpj:v=1:user=bob
[ 3] 22/tcp                     ALLOW IN    9.0.0.1/32                 # sftpj:v=1:user=alice
`),
	}
	m := firewallrule.NewDeleteByUser(f, nil, "alice")
	cmd := m.Init()
	require.NotNil(t, cmd, "ModeByUser Init must spawn an Enumerate goroutine")
	msg := cmd()

	// Feed the loaded message back so the model transitions to phaseConfirm.
	_, _ = m.Update(msg)
	require.Equal(t, firewallrule.DeletePhaseConfirmForTest, m.PhaseForTest())
	require.Len(t, m.TargetsForTest(), 2,
		"only alice's rules; bob's row must be filtered out")
	for _, r := range m.TargetsForTest() {
		require.Equal(t, "alice", r.User)
	}
}

// TestNewDeleteBySource_loading_filters_by_source — ModeBySource
// retains rules where r.Source == source verbatim.
func TestNewDeleteBySource_loading_filters_by_source(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout: []byte(`Status: active

[ 1] 22/tcp                     ALLOW IN    1.2.3.4/32                 # sftpj:v=1:user=alice
[ 2] 22/tcp                     ALLOW IN    5.6.7.8/32                 # sftpj:v=1:user=bob
[ 3] 22/tcp                     ALLOW IN    1.2.3.4/32                 # sftpj:v=1:user=carol
`),
	}
	m := firewallrule.NewDeleteBySource(f, nil, "1.2.3.4/32")
	cmd := m.Init()
	require.NotNil(t, cmd)
	msg := cmd()

	_, _ = m.Update(msg)
	require.Equal(t, firewallrule.DeletePhaseConfirmForTest, m.PhaseForTest())
	require.Len(t, m.TargetsForTest(), 2,
		"two rules match source 1.2.3.4/32 (alice + carol)")
	for _, r := range m.TargetsForTest() {
		require.Equal(t, "1.2.3.4/32", r.Source)
	}
}

// TestNewDeleteByUser_no_matches_renders_warn_view — when Enumerate
// returns no rules for the requested user, the View must render the
// "no rules found" warning copy referencing the username.
func TestNewDeleteByUser_no_matches_renders_warn_view(t *testing.T) {
	t.Parallel()
	m := firewallrule.NewDeleteByUser(sysops.NewFake(), nil, "ghost")
	m.LoadTargetsForTest(nil)
	require.Equal(t, firewallrule.DeletePhaseConfirmForTest, m.PhaseForTest())
	require.Contains(t, m.View(), "ghost",
		"no-matches view must mention the username; got %q", m.View())
	require.Contains(t, m.View(), "No rules found",
		"no-matches view must surface 'No rules found'; got %q", m.View())
}

// TestDeleteModel_ModeByUser_targets_sorted_descending_for_commit — the
// commit batch must sort target IDs DESCENDING per D-FW-07 strategy 1
// (lower IDs don't shift after a higher delete). When commitCmd runs
// against a Fake, the recorded UfwDelete calls must follow descending
// order.
func TestDeleteModel_ModeByUser_targets_sorted_descending_for_commit(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Empty atomic-write allowlist tweak not needed (no AtomicWriteFile in
	// this batch path), but the SAFE-04 schedule step needs SystemdRunOpts
	// scriptability. Default Fake returns nil from SystemdRunOnActive.

	m := firewallrule.NewDeleteByUser(f, nil, "alice")
	m.LoadTargetsForTest([]firewall.Rule{
		{ID: 3, User: "alice", Source: "1.2.3.4/32", Port: "22", RawComment: "sftpj:v=1:user=alice"},
		{ID: 1, User: "alice", Source: "5.6.7.8/32", Port: "22", RawComment: "sftpj:v=1:user=alice"},
		{ID: 5, User: "alice", Source: "9.0.0.1/32", Port: "22", RawComment: "sftpj:v=1:user=alice"},
	})

	// Drive commit synchronously via the test seam.
	cmd := m.CommitCmdForTest()
	require.NotNil(t, cmd)
	_ = cmd() // executes the goroutine body inline

	// Inspect Fake.Calls — extract the order of UfwDelete invocations.
	var deleteOrder []string
	for _, c := range f.Calls {
		if c.Method == "UfwDelete" {
			deleteOrder = append(deleteOrder, c.Args[0])
		}
	}
	require.Equal(t,
		[]string{"id=5", "id=3", "id=1"},
		deleteOrder,
		"UfwDelete calls must be in descending-ID order per D-FW-07 strategy 1")
}

// TestDeleteModel_commit_arms_safe04_schedule_first — the commit batch
// must call SystemdRunOnActive (NewScheduleRevertStep) BEFORE any
// UfwDelete (D-S04-09 step 3 ordering). Ensures partial-failure rollback
// can stop the timer.
func TestDeleteModel_commit_arms_safe04_schedule_first(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()

	m := firewallrule.NewDeleteByUser(f, nil, "alice")
	m.LoadTargetsForTest([]firewall.Rule{
		{ID: 7, User: "alice", Source: "1.2.3.4/32", Port: "22", RawComment: "sftpj:v=1:user=alice"},
	})

	cmd := m.CommitCmdForTest()
	require.NotNil(t, cmd)
	_ = cmd()

	// Find indices of SystemdRunOnActive vs first UfwDelete in Calls.
	scheduleIdx, deleteIdx := -1, -1
	for i, c := range f.Calls {
		if c.Method == "SystemdRunOnActive" && scheduleIdx == -1 {
			scheduleIdx = i
		}
		if c.Method == "UfwDelete" && deleteIdx == -1 {
			deleteIdx = i
		}
	}
	require.NotEqual(t, -1, scheduleIdx, "SystemdRunOnActive must be invoked")
	require.NotEqual(t, -1, deleteIdx, "UfwDelete must be invoked")
	require.Less(t, scheduleIdx, deleteIdx,
		"D-S04-09 step 3: Schedule arms BEFORE the FW mutation")
}

// TestDeleteModel_ModeByID_commit_uses_payload_rule_in_reverse_payload —
// the SAFE-04 reverse-cmd payload renders an `ufw insert <ID> …` for
// each deleted rule (lockdown.RenderReverseCommands with OpDelete).
// ModeByID with Source="203.0.113.7/32" must include that source string
// in the systemd-run ExecStart Command (T-04-06-04 mitigation: full
// reverse-cmd reconstructs the deleted rule byte-for-byte).
func TestDeleteModel_ModeByID_commit_uses_payload_rule_in_reverse_payload(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()

	rule := firewall.Rule{
		ID: 9, User: "alice", Source: "203.0.113.7/32", Port: "22",
		RawComment: "sftpj:v=1:user=alice",
	}
	m := firewallrule.NewDeleteByID(f, nil, rule)
	require.Nil(t, m.Init())
	require.Equal(t, firewallrule.DeletePhaseConfirmForTest, m.PhaseForTest())

	cmd := m.CommitCmdForTest()
	require.NotNil(t, cmd)
	_ = cmd()

	// Locate the SystemdRunOnActive call and assert the verbatim Command
	// arg includes a `ufw insert 9 …` segment quoting the source CIDR.
	var sdrCmd string
	for _, c := range f.Calls {
		if c.Method == "SystemdRunOnActive" {
			// Args carry the SystemdRunOpts fields; one of them is `cmd=<verbatim>`.
			for _, a := range c.Args {
				if len(a) >= 4 && a[:4] == "cmd=" {
					sdrCmd = a[4:]
					break
				}
			}
		}
	}
	require.NotEmpty(t, sdrCmd, "SystemdRunOnActive cmd argv must be recorded")
	require.Contains(t, sdrCmd, "ufw insert 9",
		"reverse-cmd must include `ufw insert 9` for the deleted rule")
	require.Contains(t, sdrCmd, "203.0.113.7/32",
		"reverse-cmd must reconstruct the source CIDR")
	require.Contains(t, sdrCmd, "ufw reload",
		"reverse-cmd must include the trailing `ufw reload` finalizer")
}

// TestDeleteModel_targetsLoadedMsg_with_error_lands_phaseError — when
// Enumerate fails (network down, ufw missing, ctx canceled), the model
// must land in phaseError with the wrapped error visible in the View.
func TestDeleteModel_targetsLoadedMsg_with_error_lands_phaseError(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Drive the error path via the test seam — directly synthesise a
	// loaded-msg with a non-nil error.
	m := firewallrule.NewDeleteByUser(f, nil, "alice")
	m.FeedTargetsLoadedMsgForTest(nil, context.DeadlineExceeded)
	require.Equal(t, firewallrule.DeletePhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.View(), "context deadline exceeded")
}

// TestDeleteModel_implements_nav_Screen — compile-time + runtime check
// that the model satisfies nav.Screen.
func TestDeleteModel_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	m := firewallrule.NewDeleteByID(sysops.NewFake(), nil, firewall.Rule{ID: 1})
	require.Equal(t, "Delete firewall rule(s)", m.Title())
	require.False(t, m.WantsRawKeys(),
		"M-DELETE-RULE has no textinput; WantsRawKeys must always be false")
	km := m.KeyMap()
	require.NotNil(t, km)
}

// TestDeleteModel_RebuildUserIPs_called_on_success — after a successful
// commit batch, the modal must call store.RebuildUserIPs to keep the
// FW-08 mirror in sync (W2 — best-effort cache rebuild). This is
// pinned by the post-Apply hook; failure of the call does NOT roll back.
//
// Test note: instead of wiring a real *store.Queries (which would
// require sqlite + schema setup), we rely on the symbol-presence
// acceptance grep (RebuildUserIPs in deleterule.go) plus the executor's
// downstream `go test ./...` integration in Task 1's automated verify.
// This test asserts the Calls record shows post-commit Enumerate ran
// (the input to RebuildUserIPs).
func TestDeleteModel_post_commit_enumerate_runs(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("Status: active\n"),
	}
	m := firewallrule.NewDeleteByID(f, nil, firewall.Rule{
		ID: 1, User: "alice", Source: "1.2.3.4/32", Port: "22",
		RawComment: "sftpj:v=1:user=alice",
	})
	require.Nil(t, m.Init())
	cmd := m.CommitCmdForTest()
	require.NotNil(t, cmd)
	_ = cmd()

	// Count `ufw status numbered` invocations — there should be at least
	// 1 from the post-commit Enumerate that feeds RebuildUserIPs (W2).
	// Fake.Exec records argv as separate args: ["ufw", "status", "numbered"].
	var enumCount int
	for _, c := range f.Calls {
		if c.Method == "Exec" && len(c.Args) >= 3 &&
			c.Args[0] == "ufw" && c.Args[1] == "status" && c.Args[2] == "numbered" {
			enumCount++
		}
	}
	require.GreaterOrEqual(t, enumCount, 1,
		"post-commit Enumerate must run for the W2 FW-08 mirror rebuild input")
}
