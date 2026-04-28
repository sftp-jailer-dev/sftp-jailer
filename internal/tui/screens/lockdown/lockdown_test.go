package lockdown

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// Task 1a tests — frame, state machine, admin-IP guard, augmenter.

func TestAugmentWithZeroConnUsers_adds_missing_users_with_ZeroConn_true(t *testing.T) {
	t.Parallel()
	props := []lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "203.0.113.7/32"}}},
	}
	all := []users.Row{
		{Username: "alice"},
		{Username: "bob"},
	}
	out := augmentWithZeroConnUsers(props, all)
	require.Len(t, out, 2)
	// Sorted ASC by user — alice then bob.
	require.Equal(t, "alice", out[0].User)
	require.Equal(t, "bob", out[1].User)
	require.False(t, out[0].ZeroConn, "alice has IPs → ZeroConn=false")
	require.True(t, out[1].ZeroConn, "bob has no IPs → ZeroConn=true")
	require.Empty(t, out[1].IPs, "bob has empty IPs")
}

func TestAugmentWithZeroConnUsers_no_missing_users_returns_input_sorted(t *testing.T) {
	t.Parallel()
	props := []lockdown.Proposal{
		{User: "bob", IPs: []lockdown.ProposedIP{{Source: "1.2.3.4/32"}}},
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "5.6.7.8/32"}}},
	}
	all := []users.Row{{Username: "alice"}, {Username: "bob"}}
	out := augmentWithZeroConnUsers(props, all)
	require.Len(t, out, 2)
	require.Equal(t, "alice", out[0].User)
	require.Equal(t, "bob", out[1].User)
}

func TestAdminIPCovered_console_session_returns_true(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.SetAdminIPForTest("") // console session — guard inactive
	require.True(t, m.AdminIPCoveredForTest())
}

func TestAdminIPCovered_admin_in_proposed_set_returns_true(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "203.0.113.0/24"}}},
	}, firewall.ModeOpen)
	m.SetAdminIPForTest("203.0.113.7")
	require.True(t, m.AdminIPCoveredForTest())
}

func TestAdminIPCovered_admin_not_in_proposed_returns_false(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "1.1.1.1/32"}}},
	}, firewall.ModeOpen)
	m.SetAdminIPForTest("203.0.113.7")
	require.False(t, m.AdminIPCoveredForTest())
}

func TestAdminIPCovered_exact_ip_match(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "203.0.113.7/32"}}},
	}, firewall.ModeOpen)
	m.SetAdminIPForTest("203.0.113.7")
	require.True(t, m.AdminIPCoveredForTest())
}

func TestAdminIPCovered_ipv6_in_cidr(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "2001:db8::/64"}}},
	}, firewall.ModeOpen)
	m.SetAdminIPForTest("2001:db8::1")
	require.True(t, m.AdminIPCoveredForTest())
}

func TestPhase_initial_state_is_loading(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	require.Equal(t, screenLoading, m.Phase())
}

func TestLoadProposalsForTest_transitions_to_editing(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice"},
	}, firewall.ModeOpen)
	require.Equal(t, screenEditing, m.Phase())
}

func TestTitle_returns_progressive_lockdown(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	require.Equal(t, "Progressive lockdown", m.Title())
}

// ---- Task 1b tests — commit + rollback + composeCommitReverseCmds + ----
// detectAddrFamily + RebuildUserIPs wiring.

// fakeStore is a recording mock of storeQ — captures RebuildUserIPs
// invocations so we can assert post-commit / post-rollback wiring.
type fakeStore struct {
	calls int
	rules []firewall.Rule
	err   error
}

func (f *fakeStore) RebuildUserIPs(_ context.Context, rules []firewall.Rule, _ func() time.Time) error {
	f.calls++
	f.rules = rules
	return f.err
}

func TestComposeCommitReverseCmds_add_emits_grep_placeholder(t *testing.T) {
	t.Parallel()
	muts := []lockdown.PendingMutation{
		{Op: lockdown.OpAdd, Rule: firewall.Rule{User: "alice", Source: "203.0.113.7/32", Port: "22"}},
	}
	out := composeCommitReverseCmds(muts, "22", false)
	require.NotEmpty(t, out, "must emit at least the grep + reload lines")
	joined := strings.Join(out, "\n")
	require.Contains(t, joined, "ufw status numbered | grep -F 'sftpj:v=1:user=alice'",
		"OpAdd reverse must use comment-grep placeholder (B2 contract)")
	require.Contains(t, joined, "ufw --force delete $ID",
		"OpAdd reverse must delete by resolved ID")
	require.Equal(t, "ufw reload", out[len(out)-1],
		"trailing finalizer must be `ufw reload`")
}

func TestComposeCommitReverseCmds_delete_uses_RenderReverseCommands(t *testing.T) {
	t.Parallel()
	muts := []lockdown.PendingMutation{
		{Op: lockdown.OpDelete, Rule: firewall.Rule{
			ID: 5, Source: "Anywhere", Port: "22", Action: "ALLOW IN", RawComment: "",
		}},
	}
	out := composeCommitReverseCmds(muts, "22", false)
	require.NotEmpty(t, out)
	joined := strings.Join(out, "\n")
	// RenderReverseCommands shape: `ufw insert <originalID> allow proto tcp from <Source> to any port <Port>`.
	require.Contains(t, joined, "ufw insert 5 allow proto tcp from",
		"OpDelete reverse must reconstruct original ID via RenderReverseCommands")
	require.Equal(t, "ufw reload", out[len(out)-1])
}

func TestComposeCommitReverseCmds_mixed_batch_no_duplicate_reload(t *testing.T) {
	t.Parallel()
	muts := []lockdown.PendingMutation{
		{Op: lockdown.OpAdd, Rule: firewall.Rule{User: "alice", Source: "1.1.1.1/32", Port: "22"}},
		{Op: lockdown.OpDelete, Rule: firewall.Rule{ID: 5, Source: "Anywhere", Port: "22", Action: "ALLOW IN"}},
		{Op: lockdown.OpAdd, Rule: firewall.Rule{User: "bob", Source: "2.2.2.2/32", Port: "22"}},
	}
	out := composeCommitReverseCmds(muts, "22", false)
	// Count occurrences of "ufw reload" — must be exactly 1 (the trailing finalizer).
	reloadCount := 0
	for _, line := range out {
		if line == "ufw reload" {
			reloadCount++
		}
	}
	require.Equal(t, 1, reloadCount,
		"mixed batch must emit exactly ONE `ufw reload` (W3 — strip RenderReverseCommands' own reload)")
}

func TestComposeCommitReverseCmds_empty_returns_nil(t *testing.T) {
	t.Parallel()
	out := composeCommitReverseCmds(nil, "22", false)
	require.Nil(t, out, "empty mutations → nil reverse-cmds (no spurious reload)")
	out = composeCommitReverseCmds(nil, "22", true)
	require.Nil(t, out, "empty mutations → nil reverse-cmds even with restoreCatchAll=true "+
		"(no spurious catch-all-re-add; nothing to revert)")
}

func TestComposeCommitReverseCmds_restoreCatchAll_prepends_ufw_allow_from_any(t *testing.T) {
	t.Parallel()
	muts := []lockdown.PendingMutation{
		{Op: lockdown.OpAdd, Rule: firewall.Rule{User: "alice", Source: "203.0.113.7/32", Port: "22"}},
	}
	out := composeCommitReverseCmds(muts, "22", true)
	require.NotEmpty(t, out)
	// First line must be the catch-all re-add — mirrors rollbackCmd's
	// catch-all-re-add command shape (B3 — the inverse direction).
	require.Equal(t, "ufw allow proto tcp from any to any port 22", out[0],
		"BUG-04-A/C SAFE-04 reverse: restoreCatchAll=true must prepend catch-all re-add line")
	require.Equal(t, "ufw reload", out[len(out)-1],
		"trailing finalizer remains `ufw reload`")
}

func TestDetectAddrFamily_v4(t *testing.T) {
	t.Parallel()
	require.Equal(t, "v4", detectAddrFamily("203.0.113.7/32"))
	require.Equal(t, "v4", detectAddrFamily("10.0.0.0/8"))
}

func TestDetectAddrFamily_v6(t *testing.T) {
	t.Parallel()
	require.Equal(t, "v6", detectAddrFamily("2001:db8::/64"))
	require.Equal(t, "v6", detectAddrFamily("fe80::/10"))
}

func TestDetectAddrFamily_bare_ip(t *testing.T) {
	t.Parallel()
	require.Equal(t, "v4", detectAddrFamily("203.0.113.7"))
	require.Equal(t, "v6", detectAddrFamily("2001:db8::1"))
}

func TestDetectAddrFamily_empty_falls_back_to_v4(t *testing.T) {
	t.Parallel()
	require.Equal(t, "v4", detectAddrFamily(""))
	require.Equal(t, "v4", detectAddrFamily("not-a-cidr"))
}

// TestBuildPendingMutations_emits_only_OpAdd_in_OPEN_mode_post_BUG_04_A
// pins the BUG-04-A + BUG-04-C gap-closure refactor: buildPendingMutations
// no longer emits OpDelete entries for catch-alls. The catch-all-removal
// responsibility moves to commitCmd's step list via
// txn.NewUfwDeleteCatchAllByEnumerateStep — a position-independent
// dual-family-aware step landed by Plan 04-12.
//
// Pre-fix shape (the original test name was *_one_add_per_ip_plus_catchall_delete*):
//   - 2 OpAdd + 1 OpDelete-with-stale-catch-all-id.
//
// Post-fix shape:
//   - 2 OpAdd only. catch-all removal happens at Apply time inside the
//     new step, not via the muts pipeline.
//
// The pre-fix shape suffered BUG-04-A (stale id after position-shift) +
// BUG-04-C (only one of the v4/v6 catch-alls deleted on dual-family
// hosts) — both empirically caught by Plan 04-10's UAT.
func TestBuildPendingMutations_emits_only_OpAdd_in_OPEN_mode_post_BUG_04_A(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{
			{Source: "203.0.113.7/32", Tier: "success"},
			{Source: "203.0.113.8/32", Tier: "success"},
		}},
	}, firewall.ModeOpen)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
	})

	muts := m.buildPendingMutations()
	require.Len(t, muts, 2, "BUG-04-A/C: catch-all delete moved to commitCmd's step list; "+
		"buildPendingMutations now returns ONLY OpAdd entries")

	for _, mut := range muts {
		require.Equal(t, lockdown.OpAdd, mut.Op,
			"BUG-04-A/C: zero OpDelete entries — catch-all removal handled by NewUfwDeleteCatchAllByEnumerateStep at Apply time")
		require.Equal(t, "alice", mut.Rule.User)
		require.Equal(t, "22", mut.Rule.Port)
		require.Equal(t, "v4", mut.Rule.Proto)
	}
}

func TestBuildPendingMutations_no_catchall_delete_when_mode_is_LOCKED(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "1.1.1.1/32"}}},
	}, firewall.ModeLocked)
	m.SetCurrentRulesForTest(nil)

	muts := m.buildPendingMutations()
	for _, mut := range muts {
		require.Equal(t, lockdown.OpAdd, mut.Op,
			"LOCKED mode: no catch-all to delete; all mutations are OpAdd")
	}
}

func TestCommitCmd_calls_RebuildUserIPs_when_store_set(t *testing.T) {
	t.Parallel()
	// Fake ops scripted: SystemdRunOnActive nil; UfwInsert nil;
	// UfwDelete nil; UfwReload nil; Exec ufw status numbered returns
	// a minimal valid output (no rules → empty Enumerate; that's fine
	// for the rebuild assertion — we just need the path to run).
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"),
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "203.0.113.7/32"}}},
	}, firewall.ModeOpen)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
	})
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.commitCmd()
	require.NotNil(t, cmd)
	msg := cmd()
	committed, ok := msg.(committedMsg)
	require.True(t, ok, "commitCmd must return committedMsg, got %T", msg)
	require.NoError(t, committed.err, "commit must succeed against happy-path Fake")
	require.Equal(t, 1, store.calls, "commitCmd must invoke RebuildUserIPs once on success")
}

func TestRollbackCmd_reverse_uses_comment_grep_signature(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"),
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{{Source: "203.0.113.7/32"}}},
	}, firewall.ModeLocked)
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.rollbackCmd()
	require.NotNil(t, cmd)
	msg := cmd()
	rb, ok := msg.(rollbackDoneMsg)
	require.True(t, ok, "rollbackCmd must return rollbackDoneMsg, got %T", msg)
	require.NoError(t, rb.err, "rollback must succeed against happy-path Fake")

	// Find the SystemdRunOnActive call in the Fake's exec log and
	// inspect its Command argument for the comment-grep + signature
	// pattern (B3 contract).
	var systemdRunCall *sysops.FakeCall
	for i := range f.Calls {
		if f.Calls[i].Method == "SystemdRunOnActive" {
			systemdRunCall = &f.Calls[i]
			break
		}
	}
	require.NotNil(t, systemdRunCall, "rollbackCmd must arm SAFE-04 timer via SystemdRunOnActive")

	cmdStr := strings.Join(systemdRunCall.Args, " ")
	require.Contains(t, cmdStr, "grep -E 'allow +22/tcp.*Anywhere'",
		"rollback reverse must use signature-grep for the catch-all (B3)")
	require.Contains(t, cmdStr, "grep -v sftpj",
		"rollback reverse must exclude sftpj-commented rules (B3)")
}

func TestRollbackCmd_calls_RebuildUserIPs_when_store_set(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"),
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest(nil, firewall.ModeLocked)
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.rollbackCmd()
	msg := cmd()
	rb, ok := msg.(rollbackDoneMsg)
	require.True(t, ok)
	require.NoError(t, rb.err)
	require.Equal(t, 1, store.calls, "rollbackCmd must invoke RebuildUserIPs once on success")
}

// ---- Plan 04-13 (BUG-04-A + BUG-04-C consumer wiring) ----
//
// These tests pin the post-fix commitCmd shape: when m.currentMode is
// OPEN or STAGING, commitCmd appends txn.NewUfwDeleteCatchAllByEnumerateStep
// (Plan 04-12) AFTER the per-IP UfwInsert steps and BEFORE the trailing
// UfwReload step. LOCKED-mode commits do NOT append the step (no catch-
// all to remove; appending would still be safe-no-op but skipping is
// cleaner and saves an Enumerate round-trip).

// ufwStatusDualFamilyFixture mirrors Plan 04-12's fixture used in
// internal/txn tests: a v4 catch-all (id=1) + v6 catch-all (id=2) +
// sftpj rule (id=3). Models a default Ubuntu 24.04 box (IPV6=yes).
func ufwStatusDualFamilyFixture() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// ufwStatusV6OnlyAfterFirstDeleteFixture: ufw renumbered after the v4
// catch-all was deleted. v6 catch-all is now id=1, sftpj is id=2.
func ufwStatusV6OnlyAfterFirstDeleteFixture() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 2] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// ufwStatusSftpjOnlyFixture: both catch-alls gone, only sftpj remains.
func ufwStatusSftpjOnlyFixture() []byte {
	return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    1.2.3.4                    # sftpj:v=1:user=alice
`)
}

// TestCommitCmd_OPEN_mode_appends_NewUfwDeleteCatchAllByEnumerateStep is
// the headline regression test for BUG-04-A + BUG-04-C — the empirical
// failure modes from Plan 04-10's UAT. This test PROVES the production
// commitCmd path emits the dual-family catch-all deletion sequence on a
// realistic Ubuntu 24.04 fixture.
//
// Pre-fix: commitCmd composed [Schedule, UfwInsert × N, UfwDelete(stale-id), Reload].
//   - Stale id was captured at SetCurrentRulesForTest time (id=1).
//   - After UfwInsert × N, ufw shifted catch-all to id=2 (position-shift) → BUG-04-A.
//   - Even with the right id, only ONE of the v4/v6 catch-alls was scheduled for delete → BUG-04-C.
//
// Post-fix: commitCmd composes [Schedule, UfwInsert × N, NewUfwDeleteCatchAllByEnumerateStep, Reload].
//   - The new step re-Enumerates at Apply time → fresh ids → BUG-04-A closed.
//   - The new step iterates and deletes ALL catch-alls → BUG-04-C closed.
func TestCommitCmd_OPEN_mode_appends_NewUfwDeleteCatchAllByEnumerateStep(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Stateful Enumerate: dual-family on first call (during the new step's
	// Apply-time re-Enumerate-and-delete loop), v6-only after the first
	// delete, sftpj-only after the second delete (loop terminates), then
	// one more for the post-Apply FW-08 mirror-rebuild.
	// Production order of Enumerate calls during commitCmd:
	//   - Inside NewUfwDeleteCatchAllByEnumerateStep.Apply (3 calls — see below)
	//   - Post-Apply FW-08 rebuild (1 call)
	// Total: 4 scripted responses queued.
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusDualFamilyFixture()},             // step iter 0: find v4 catch-all id=1 → delete
		{ExitCode: 0, Stdout: ufwStatusV6OnlyAfterFirstDeleteFixture()}, // step iter 1: find v6 catch-all id=1 → delete
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},              // step iter 2: no catch-all → return
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},              // post-Apply rebuild
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{
			{Source: "203.0.113.7/32", Tier: "success"},
			{Source: "203.0.113.8/32", Tier: "success"},
		}},
	}, firewall.ModeOpen)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
		{ID: 2, Port: "22", Proto: "v6", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
	})
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.commitCmd()
	require.NotNil(t, cmd)
	msg := cmd()
	committed, ok := msg.(committedMsg)
	require.True(t, ok)
	require.NoError(t, committed.err, "commitCmd must succeed against the dual-family fixture")

	// Count call types.
	insertCount, deleteCount, reloadCount, scheduleCount := 0, 0, 0, 0
	for _, c := range f.Calls {
		switch c.Method {
		case "UfwInsert":
			insertCount++
		case "UfwDelete":
			deleteCount++
		case "UfwReload":
			reloadCount++
		case "SystemdRunOnActive":
			scheduleCount++
		}
	}
	require.Equal(t, 2, insertCount, "two UfwInsert calls (alice's two IPs)")
	require.Equal(t, 2, deleteCount,
		"BUG-04-C: dual-family hosts have v4+v6 catch-alls; commitCmd must delete BOTH "+
			"via NewUfwDeleteCatchAllByEnumerateStep's loop")
	require.Equal(t, 1, reloadCount, "trailing UfwReload finalizer (W3 dedup)")
	require.Equal(t, 1, scheduleCount, "SAFE-04 SystemdRunOnActive armed first")
}

// TestCommitCmd_STAGING_mode_also_appends_catchall_step pins that
// STAGING → LOCKED (catch-all + sftpj coexist; commit removes catch-all)
// also routes through the new step. Zero new OpAdds, but the catch-all
// deletion is still wired.
func TestCommitCmd_STAGING_mode_also_appends_catchall_step(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusV6OnlyAfterFirstDeleteFixture()}, // step iter 0: find v6 catch-all id=1 → delete
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},              // step iter 1: no catch-all → return
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},              // post-Apply rebuild
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	// STAGING-mode: a single re-add IP for alice so that
	// buildPendingMutations produces ≥1 OpAdd (commitCmd's pre-flight
	// rejects empty mutation sets). The catch-all removal is the
	// MODE-changing action; the OpAdd is incidental but realistic.
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{
			{Source: "203.0.113.7/32", Tier: "success"},
		}},
	}, firewall.ModeStaging)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Proto: "v6", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
		{ID: 2, Port: "22", Source: "1.2.3.4/32", Action: "ALLOW IN",
			RawComment: "sftpj:v=1:user=alice", User: "alice"},
	})
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.commitCmd()
	msg := cmd()
	committed, ok := msg.(committedMsg)
	require.True(t, ok)
	require.NoError(t, committed.err)

	deleteCount, insertCount := 0, 0
	for _, c := range f.Calls {
		switch c.Method {
		case "UfwDelete":
			deleteCount++
		case "UfwInsert":
			insertCount++
		}
	}
	require.Equal(t, 1, insertCount, "STAGING → LOCKED: one new OpAdd from the proposal")
	require.Equal(t, 1, deleteCount, "STAGING → LOCKED: NewUfwDeleteCatchAllByEnumerateStep "+
		"removes the single catch-all even when buildPendingMutations only emits OpAdd entries")
}

// TestCommitCmd_LOCKED_mode_does_NOT_append_catchall_step pins that the
// step is conditional on currentMode. LOCKED-mode commits (e.g. adding
// a new per-user IP after lockdown) should NOT append the step (no
// catch-all to remove; appending would still be safe-no-op but skipping
// is cleaner and saves an Enumerate round-trip).
func TestCommitCmd_LOCKED_mode_does_NOT_append_catchall_step(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Only ONE Enumerate call expected: the post-Apply FW-08 rebuild.
	// The step is NOT appended, so its Apply-time Enumerate calls don't happen.
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "bob", IPs: []lockdown.ProposedIP{{Source: "10.0.0.1/32", Tier: "manual"}}},
	}, firewall.ModeLocked)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Source: "1.2.3.4/32", Action: "ALLOW IN",
			RawComment: "sftpj:v=1:user=alice", User: "alice"},
	})
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.commitCmd()
	msg := cmd()
	committed, ok := msg.(committedMsg)
	require.True(t, ok)
	require.NoError(t, committed.err)

	deleteCount := 0
	for _, c := range f.Calls {
		if c.Method == "UfwDelete" {
			deleteCount++
		}
	}
	require.Equal(t, 0, deleteCount, "LOCKED-mode commit: NewUfwDeleteCatchAllByEnumerateStep "+
		"must NOT be appended (no catch-all to remove)")
}

// TestCommitCmd_OPEN_mode_position_shift_does_NOT_break_commit is the
// empirical BUG-04-A scenario. Same setup as
// TestCommitCmd_OPEN_mode_appends_NewUfwDeleteCatchAllByEnumerateStep
// but explicitly notes via doc-comment that this would have FAILED in
// the pre-fix world: the catch-all id captured at SetCurrentRulesForTest
// time (id=1) was deleted by `ufw insert 1` shifting it to id=2; the
// OLD UfwDelete(stale-id-1) would have hit the just-inserted alice rule.
// Post-fix, NewUfwDeleteCatchAllByEnumerateStep re-Enumerates at Apply
// time and finds the fresh id (whatever it is — id=2 after the inserts,
// or compacted to id=1 if ufw renumbers eagerly).
func TestCommitCmd_OPEN_mode_position_shift_does_NOT_break_commit(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Same dual-family fixture sequence as above — the test expectation
	// is structural (no stale id in the txn batch) rather than a
	// numerical id assertion (which is brittle vs. ufw's renumbering).
	f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
		{ExitCode: 0, Stdout: ufwStatusDualFamilyFixture()},
		{ExitCode: 0, Stdout: ufwStatusV6OnlyAfterFirstDeleteFixture()},
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},
		{ExitCode: 0, Stdout: ufwStatusSftpjOnlyFixture()},
	}

	store := &fakeStore{}
	m := New(f, nil, nil, nil, "22", 90)
	m.LoadProposalsForTest([]lockdown.Proposal{
		{User: "alice", IPs: []lockdown.ProposedIP{
			{Source: "203.0.113.7/32", Tier: "success"},
			{Source: "203.0.113.8/32", Tier: "success"},
		}},
	}, firewall.ModeOpen)
	m.SetCurrentRulesForTest([]firewall.Rule{
		{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
		{ID: 2, Port: "22", Proto: "v6", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""},
	})
	m.SetStore(store)
	m.SetNowFnForTest(func() time.Time { return time.Unix(1700000000, 0) })

	cmd := m.commitCmd()
	msg := cmd()
	committed, ok := msg.(committedMsg)
	require.True(t, ok)
	require.NoError(t, committed.err,
		"BUG-04-A: pre-fix commit would fail because UfwDelete(stale-id-1) targeted "+
			"the just-inserted alice rule. Post-fix the new step re-Enumerates → fresh ids "+
			"→ correct catch-all deleted regardless of position shift.")

	// The deletion path must NOT have targeted any of the alice sftpj
	// rules — assert by inspecting the recorded UfwDelete calls. The
	// dual-family fixture's first Enumerate sees alice at id=3; if the
	// pre-fix code had captured id=1 at SetCurrentRulesForTest time,
	// after `ufw insert 1` × 2 alice's rule would have shifted to id=3
	// and the catch-all to id=3 (or id=2 depending on renumbering). The
	// new step deletes catch-alls only — never sftpj rules.
	deleteIDs := []string{}
	for _, c := range f.Calls {
		if c.Method == "UfwDelete" {
			deleteIDs = append(deleteIDs, strings.Join(c.Args, " "))
		}
	}
	// Two UfwDelete calls, both targeting catch-all ids surfaced by
	// re-Enumerate (id=1 then id=1 after the v4 was deleted).
	require.Len(t, deleteIDs, 2, "exactly two UfwDelete calls (v4 + v6 catch-alls)")
	require.Equal(t, "id=1", deleteIDs[0],
		"first delete targets the v4 catch-all at fresh id=1 (NOT the sftpj rule)")
	require.Equal(t, "id=1", deleteIDs[1],
		"second delete targets the v6 catch-all at id=1 after ufw renumbering "+
			"(post-fix re-Enumerate provides the FRESH id; pre-fix would have used a stale capture)")
}
