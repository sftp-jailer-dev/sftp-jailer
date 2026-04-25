// Package firewall_test exercises the typed reader over `ufw status numbered`
// output, including ufwcomment.Decode integration for the per-user reverse
// lookup (FW-04) and forward-compat handling for v>=2 comments.
package firewall_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// loadFixture reads testdata/<name> and returns it as scripted Exec stdout.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err, "fixture %s", name)
	return b
}

// scriptUfw seeds f.ExecResponses with a successful `ufw status numbered`
// returning the named fixture's stdout.
func scriptUfw(t *testing.T, f *sysops.Fake, fixture string) {
	t.Helper()
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		Stdout:   loadFixture(t, fixture),
		ExitCode: 0,
	}
}

// TestEnumerate_mixed: 6 rules — 2 system-default, 3 sftpj v=1, 1 sftpj v=2.
// Verifies ID parse, Proto v4/v6 detection, RawComment carry, User decode,
// and ParseErr=ErrBadVersion for the v=2 forward-compat row.
func TestEnumerate_mixed(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-mixed.txt")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, rules, 6)

	// Rule 1: SSH default IPv4 — has comment but not sftpj.
	require.Equal(t, 1, rules[0].ID)
	require.Equal(t, "v4", rules[0].Proto)
	require.Equal(t, "SSH default", rules[0].RawComment)
	require.Equal(t, "", rules[0].User)
	require.True(t, errors.Is(rules[0].ParseErr, ufwcomment.ErrNotOurs),
		"non-sftpj comment should report ErrNotOurs, got %v", rules[0].ParseErr)

	// Rule 2: SSH default IPv6.
	require.Equal(t, 2, rules[1].ID)
	require.Equal(t, "v6", rules[1].Proto)

	// Rule 3: sftpj alice IPv4.
	require.Equal(t, 3, rules[2].ID)
	require.Equal(t, "v4", rules[2].Proto)
	require.Equal(t, "203.0.113.7", rules[2].Source)
	require.Equal(t, "sftpj:v=1:user=alice", rules[2].RawComment)
	require.Equal(t, "alice", rules[2].User)
	require.NoError(t, rules[2].ParseErr)

	// Rule 4: sftpj bob IPv4.
	require.Equal(t, 4, rules[3].ID)
	require.Equal(t, "bob", rules[3].User)

	// Rule 5: sftpj carol IPv6.
	require.Equal(t, 5, rules[4].ID)
	require.Equal(t, "v6", rules[4].Proto)
	require.Equal(t, "carol", rules[4].User)

	// Rule 6: sftpj v=2 — forward-compat. User must be empty; ParseErr is ErrBadVersion.
	require.Equal(t, 6, rules[5].ID)
	require.Equal(t, "", rules[5].User, "v>=2 must blank User so UI renders ?")
	require.True(t, errors.Is(rules[5].ParseErr, ufwcomment.ErrBadVersion),
		"v=2 must surface ErrBadVersion, got %v", rules[5].ParseErr)
}

// TestEnumerate_no_rules: Status: active with header but no rule lines.
// Expect empty slice + nil error (NOT a nil slice with error).
func TestEnumerate_no_rules(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-no-rules.txt")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.NoError(t, err)
	require.Empty(t, rules)
}

// TestEnumerate_inactive: Status: inactive must surface ErrUFWInactive so the
// S-FIREWALL screen renders the actionable empty state.
func TestEnumerate_inactive(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-inactive.txt")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.Nil(t, rules)
	require.True(t, errors.Is(err, firewall.ErrUFWInactive),
		"expected ErrUFWInactive, got %v", err)
}

// TestEnumerate_with_spaces_in_to: source field "Anywhere on eth0" must not
// crash the parser; ID is parsed and a Rule is emitted.
func TestEnumerate_with_spaces_in_to(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-with-spaces-in-to.txt")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Equal(t, 1, rules[0].ID)
	require.Equal(t, "alice", rules[0].User)
	require.Equal(t, 2, rules[1].ID)
	require.Equal(t, "bob", rules[1].User)
}

// TestEnumerate_malformed: a line missing the [N] prefix is silently dropped;
// surrounding well-formed rules still parse cleanly.
func TestEnumerate_malformed(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-malformed.txt")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, rules, 2, "broken line dropped, two well-formed rules survive")
	require.Equal(t, 1, rules[0].ID)
	require.Equal(t, "alice", rules[0].User)
	require.Equal(t, 3, rules[1].ID)
	require.Equal(t, "bob", rules[1].User)
}

// TestEnumerate_uses_sysops_Exec: assert exactly one Exec call recorded
// with argv ["ufw", "status", "numbered"]. Locks the sysops seam contract.
func TestEnumerate_uses_sysops_Exec(t *testing.T) {
	f := sysops.NewFake()
	scriptUfw(t, f, "ufw-status-numbered-no-rules.txt")

	_, err := firewall.Enumerate(context.Background(), f)
	require.NoError(t, err)

	var execCalls []sysops.FakeCall
	for _, c := range f.Calls {
		if c.Method == "Exec" {
			execCalls = append(execCalls, c)
		}
	}
	require.Len(t, execCalls, 1)
	require.Equal(t, []string{"ufw", "status", "numbered"}, execCalls[0].Args)
}

// TestEnumerate_ufw_not_installed: Fake.ExecError simulates ENOENT; Enumerate
// returns a wrapped error containing the substring "ufw" so callers can render
// "ufw not installed" without depending on a specific sentinel.
func TestEnumerate_ufw_not_installed(t *testing.T) {
	f := sysops.NewFake()
	f.ExecError = errors.New("exec: \"ufw\": executable file not found in $PATH")

	rules, err := firewall.Enumerate(context.Background(), f)
	require.Nil(t, rules)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ufw")
}
