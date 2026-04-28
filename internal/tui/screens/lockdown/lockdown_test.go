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
	out := composeCommitReverseCmds(muts, "22")
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
	out := composeCommitReverseCmds(muts, "22")
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
	out := composeCommitReverseCmds(muts, "22")
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
	out := composeCommitReverseCmds(nil, "22")
	require.Nil(t, out, "empty mutations → nil reverse-cmds (no spurious reload)")
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

func TestBuildPendingMutations_emits_one_add_per_ip_plus_catchall_delete_in_OPEN_mode(t *testing.T) {
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
	require.Len(t, muts, 3, "2 OpAdd + 1 OpDelete (catch-all)")

	addCount, deleteCount := 0, 0
	for _, mut := range muts {
		switch mut.Op {
		case lockdown.OpAdd:
			addCount++
			require.Equal(t, "alice", mut.Rule.User)
			require.Equal(t, "22", mut.Rule.Port)
			require.Equal(t, "v4", mut.Rule.Proto, "address family detected from CIDR")
		case lockdown.OpDelete:
			deleteCount++
			require.Equal(t, 1, mut.Rule.ID, "catch-all delete by ID=1")
			require.Equal(t, "", mut.Rule.RawComment, "catch-all has no sftpj comment")
			require.Equal(t, "Anywhere", mut.Rule.Source)
		}
	}
	require.Equal(t, 2, addCount)
	require.Equal(t, 1, deleteCount)
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
