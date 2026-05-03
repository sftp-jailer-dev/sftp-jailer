package firewall

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadPendingFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec
	require.NoError(t, err, "fixture %s", name)
	return b
}

func TestParseUFWShowAdded_port_22_tcp(t *testing.T) {
	rules := ParseUFWShowAdded(loadPendingFixture(t, "ufw-show-added-ssh-port.txt"))
	require.GreaterOrEqual(t, len(rules), 1)
	// First rule should be allow 22/tcp.
	require.Equal(t, "allow", rules[0].Action)
	require.Equal(t, "22", rules[0].Port)
	require.Equal(t, "tcp", rules[0].Proto)
}

func TestParseUFWShowAdded_OpenSSH_app_profile(t *testing.T) {
	rules := ParseUFWShowAdded(loadPendingFixture(t, "ufw-show-added-ssh-openssh.txt"))
	require.GreaterOrEqual(t, len(rules), 1)
	require.Equal(t, "allow", rules[0].Action)
	require.Equal(t, "OpenSSH", rules[0].AppProfile)
}

func TestParseUFWShowAdded_no_ssh_rules(t *testing.T) {
	rules := ParseUFWShowAdded(loadPendingFixture(t, "ufw-show-added-no-ssh.txt"))
	require.False(t, SSHAllowPresent(rules))
}

func TestParseUFWShowAdded_v6_only_allow_passes_predicate(t *testing.T) {
	rules := ParseUFWShowAdded(loadPendingFixture(t, "ufw-show-added-ipv6-only.txt"))
	require.True(t, SSHAllowPresent(rules),
		"v6-only allow rule must satisfy family-agnostic predicate per D-10")
}

func TestParseUFWShowAdded_empty_returns_empty_slice(t *testing.T) {
	rules := ParseUFWShowAdded(loadPendingFixture(t, "ufw-show-added-empty.txt"))
	require.Empty(t, rules)
	require.False(t, SSHAllowPresent(rules))
}

func TestSSHAllowPresent_port_22_tcp(t *testing.T) {
	require.True(t, SSHAllowPresent([]AddedRule{{Action: "allow", Port: "22", Proto: "tcp"}}))
}

func TestSSHAllowPresent_bare_port_22(t *testing.T) {
	// `ufw allow 22` with no proto specifier should also count (covers
	// tcp+udp; we accept Proto=="").
	require.True(t, SSHAllowPresent([]AddedRule{{Action: "allow", Port: "22", Proto: ""}}))
}

func TestSSHAllowPresent_openssh_profile(t *testing.T) {
	require.True(t, SSHAllowPresent([]AddedRule{{Action: "allow", AppProfile: "OpenSSH"}}))
}

func TestSSHAllowPresent_deny_22_tcp_not_a_match(t *testing.T) {
	require.False(t, SSHAllowPresent([]AddedRule{{Action: "deny", Port: "22", Proto: "tcp"}}))
}

func TestSSHAllowPresent_unrelated_port(t *testing.T) {
	require.False(t, SSHAllowPresent([]AddedRule{{Action: "allow", Port: "8080", Proto: "tcp"}}))
}

func TestSSHAllowMatchedAs_returns_first_match_openssh(t *testing.T) {
	rules := []AddedRule{
		{Action: "allow", AppProfile: "OpenSSH"},
		{Action: "allow", Port: "22", Proto: "tcp"},
	}
	require.Equal(t, "OpenSSH application profile", SSHAllowMatchedAs(rules))
}

func TestSSHAllowMatchedAs_returns_first_match_port(t *testing.T) {
	rules := []AddedRule{{Action: "allow", Port: "22", Proto: "tcp"}}
	require.Equal(t, "tcp/22", SSHAllowMatchedAs(rules))
}

func TestSSHAllowMatchedAs_no_match_returns_empty(t *testing.T) {
	require.Equal(t, "", SSHAllowMatchedAs([]AddedRule{{Action: "deny", Port: "22"}}))
}

func TestParseUFWShowAdded_ignores_comment_named_OpenSSH(t *testing.T) {
	in := []byte("ufw allow proto tcp from 0.0.0.0/0 to any port 22 comment 'OpenSSH-fake'\n")
	rules := ParseUFWShowAdded(in)
	require.Len(t, rules, 1)
	require.Equal(t, "", rules[0].AppProfile, "comment named OpenSSH must not become AppProfile")
	require.Equal(t, "22", rules[0].Port)
}
