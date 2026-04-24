// Package observe_test exercises the four-tier sshd-event classifier and
// the journalctl JSON line parser.
//
// The D2 regression test (pitfall D2 in PITFALLS.md) is the load-bearing
// contract here: "Failed password for invalid user xyz" must classify
// as noise, while "Failed password for alice" (valid system user) must
// classify as targeted. The difference is one word in the sshd log line.
// Phase 2's observer pipeline and Phase 4's LOCK-* features hang on this
// distinction — get it wrong and legitimate users look like attack noise
// or attackers look like legitimate users.
package observe_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/observe"
)

func loadFixture(t *testing.T, name string) observe.SshdEvent {
	t.Helper()
	b, err := os.ReadFile("testdata/journalctl/" + name) //nolint:gosec // G304: test-only, fixture path is committed testdata
	require.NoError(t, err)
	e, err := observe.Parse(b)
	require.NoError(t, err)
	return e
}

func TestClassify_success_pubkey(t *testing.T) {
	e := loadFixture(t, "success.json")
	c := observe.Classify(e)
	require.Equal(t, observe.TierSuccess, c.Tier)
	require.Equal(t, "alice", c.User)
	require.Equal(t, "203.0.113.5", c.SourceIP)
}

func TestClassify_noise_invalid_user(t *testing.T) {
	e := loadFixture(t, "invalid-user.json")
	c := observe.Classify(e)
	require.Equal(t, observe.TierNoise, c.Tier,
		"D2 regression: 'Failed password for invalid user xyz' MUST be noise, not targeted")
	require.Equal(t, "xyz", c.User)
	require.Equal(t, "203.0.113.99", c.SourceIP)
}

func TestClassify_targeted_wrong_password(t *testing.T) {
	e := loadFixture(t, "wrong-password.json")
	c := observe.Classify(e)
	require.Equal(t, observe.TierTargeted, c.Tier,
		"D2 regression: 'Failed password for alice' (valid user) MUST be targeted, not noise")
	require.Equal(t, "alice", c.User)
	require.Equal(t, "203.0.113.99", c.SourceIP)
}

func TestClassify_unmatched(t *testing.T) {
	e := loadFixture(t, "unmatched.json")
	c := observe.Classify(e)
	require.Equal(t, observe.TierUnmatched, c.Tier)
}

// Additional in-line cases that aren't worth a separate fixture.

func TestClassify_invalid_user_alt_shape(t *testing.T) {
	c := observe.Classify(observe.SshdEvent{
		Raw: "Invalid user root from 198.51.100.50 port 55555",
	})
	require.Equal(t, observe.TierNoise, c.Tier)
	require.Equal(t, "root", c.User)
	require.Equal(t, "198.51.100.50", c.SourceIP)
}

func TestClassify_success_password(t *testing.T) {
	c := observe.Classify(observe.SshdEvent{
		Raw: "Accepted password for bob from 198.51.100.2 port 44000 ssh2",
	})
	require.Equal(t, observe.TierSuccess, c.Tier)
	require.Equal(t, "bob", c.User)
	require.Equal(t, "198.51.100.2", c.SourceIP)
}

func TestClassify_unmatched_garbage(t *testing.T) {
	c := observe.Classify(observe.SshdEvent{
		Raw: "some random message that doesn't match any sshd pattern",
	})
	require.Equal(t, observe.TierUnmatched, c.Tier)
}

// Parser tests — pure json.Unmarshal + string→int coercion, no exec.

func TestParse_journalctl_line(t *testing.T) {
	b, err := os.ReadFile("testdata/journalctl/success.json")
	require.NoError(t, err)
	e, err := observe.Parse(b)
	require.NoError(t, err)
	require.Equal(t, 1234, e.PID)
	require.Equal(t, "sshd", e.Identifier)
	require.Equal(t, "6", e.Priority)
	require.NotZero(t, e.Timestamp)
	require.Contains(t, e.Raw, "Accepted publickey for alice")
}

func TestParse_missing_message(t *testing.T) {
	_, err := observe.Parse([]byte(`{"__REALTIME_TIMESTAMP":"123"}`))
	require.Error(t, err)
}

func TestParse_malformed_json(t *testing.T) {
	_, err := observe.Parse([]byte(`{not valid json`))
	require.Error(t, err)
}
