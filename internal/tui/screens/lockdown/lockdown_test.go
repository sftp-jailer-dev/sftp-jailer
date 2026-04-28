package lockdown

import (
	"testing"

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
