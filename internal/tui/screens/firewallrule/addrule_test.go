// Package firewallrule tests for M-ADD-RULE (Plan 04-05) — input
// validation surface (CIDR strict / promote bare IP / reject zone-id /
// warn loopback+link-local) + locked-user constructor path +
// WantsRawKeys phase discipline.
//
// Tests intentionally focus on the synchronous attemptParse + state
// machine surface; the async preflight + commit paths are exercised
// end-to-end by the empirical UAT in Plan 04-10 + the integration of
// txn / sysops Fakes (covered by their own test suites).
package firewallrule_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
)

// TestAttemptParse_bare_ipv4_promotes_to_slash_32 — table-driven CIDR
// validation per D-FW-CIDR rules (M-ADD-RULE input validation):
//
//   - Bare IPv4 → /32; bare IPv6 → /128.
//   - Strict CIDR via net.ParseCIDR — rejects 300.0.0.1/24 and
//     leading-zero octets and obviously malformed strings.
//   - Empty input rejected with "source CIDR is required".
//   - Zone-id (% suffix) rejected — link-local-with-zone is local-only.
func TestAttemptParse_bare_ipv4_promotes_to_slash_32(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantSource  string // expected normalized; "" if validation should fail
		wantErrSub  string // substring of expected errInline; "" if accept
		wantWarnSub string // substring of expected warnInline; "" if no warning
	}{
		{name: "bare_ipv4_promoted", raw: "203.0.113.7", wantSource: "203.0.113.7/32"},
		{name: "ipv4_cidr_passthrough", raw: "203.0.113.0/24", wantSource: "203.0.113.0/24"},
		{name: "bare_ipv6_promoted", raw: "2001:db8::1", wantSource: "2001:db8::1/128"},
		{name: "ipv6_cidr_passthrough", raw: "2001:db8::/64", wantSource: "2001:db8::/64"},
		{name: "empty_rejected", raw: "", wantErrSub: "source CIDR is required"},
		{name: "whitespace_rejected", raw: "   ", wantErrSub: "source CIDR is required"},
		{name: "malformed_rejected", raw: "203.0.113.999", wantErrSub: "not a valid IP or CIDR"},
		{name: "out_of_range_cidr_rejected", raw: "300.0.0.1/24", wantErrSub: "invalid CIDR"},
		{name: "garbage_rejected", raw: "notanip", wantErrSub: "not a valid IP or CIDR"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := firewallrule.New(nil, nil, "22", "")
			m.SetCIDRInputForTest(tc.raw)
			m.AttemptParseForTest()

			if tc.wantErrSub != "" {
				require.Contains(t, m.ErrInlineForTest(), tc.wantErrSub,
					"raw=%q expected errInline to contain %q; got %q",
					tc.raw, tc.wantErrSub, m.ErrInlineForTest())
				require.Empty(t, m.NormalizedSourceForTest(),
					"on validation failure normalizedSource must remain empty")
				return
			}
			require.Empty(t, m.ErrInlineForTest(),
				"raw=%q expected accept; got errInline=%q", tc.raw, m.ErrInlineForTest())
			require.Equal(t, tc.wantSource, m.NormalizedSourceForTest())
		})
	}
}

// TestAttemptParse_loopback_warns_but_does_not_reject — loopback IPs
// produce a non-blocking warning but accept; errInline stays empty.
func TestAttemptParse_loopback_warns_but_does_not_reject(t *testing.T) {
	t.Parallel()
	m := firewallrule.New(nil, nil, "22", "")
	m.SetCIDRInputForTest("127.0.0.1")
	m.AttemptParseForTest()

	require.Empty(t, m.ErrInlineForTest(),
		"loopback must NOT produce errInline; got %q", m.ErrInlineForTest())
	require.NotEmpty(t, m.WarnInlineForTest(),
		"loopback must produce a warnInline message")
	require.True(t, strings.Contains(m.WarnInlineForTest(), "loopback"),
		"warnInline must mention loopback; got %q", m.WarnInlineForTest())
	require.Equal(t, "127.0.0.1/32", m.NormalizedSourceForTest())
}

// TestAttemptParse_link_local_warns — fe80:: addresses produce a
// warning but are not rejected.
func TestAttemptParse_link_local_warns(t *testing.T) {
	t.Parallel()
	m := firewallrule.New(nil, nil, "22", "")
	m.SetCIDRInputForTest("fe80::1")
	m.AttemptParseForTest()

	require.Empty(t, m.ErrInlineForTest())
	require.NotEmpty(t, m.WarnInlineForTest(),
		"link-local must produce a warnInline message")
	require.True(t, strings.Contains(m.WarnInlineForTest(), "link-local"),
		"warnInline must mention link-local; got %q", m.WarnInlineForTest())
	require.Equal(t, "fe80::1/128", m.NormalizedSourceForTest())
}

// TestAttemptParse_zone_id_rejected — IPv6 with zone-id (% suffix) is
// rejected as not internet-routable.
func TestAttemptParse_zone_id_rejected(t *testing.T) {
	t.Parallel()
	m := firewallrule.New(nil, nil, "22", "")
	m.SetCIDRInputForTest("fe80::1%eth0")
	m.AttemptParseForTest()

	require.Contains(t, m.ErrInlineForTest(), "zone-id",
		"zone-id rejection must mention zone-id; got %q", m.ErrInlineForTest())
	require.Empty(t, m.NormalizedSourceForTest())
}

// TestNew_locked_user_path — when New is called with a non-empty
// lockedUser, userLocked is true and userField is pre-populated.
func TestNew_locked_user_path(t *testing.T) {
	t.Parallel()

	mLocked := firewallrule.New(nil, nil, "22", "alice")
	require.True(t, mLocked.UserLockedForTest(), "lockedUser='alice' must set userLocked=true")
	require.Equal(t, "alice", mLocked.UserFieldForTest())

	mUnlocked := firewallrule.New(nil, nil, "22", "")
	require.False(t, mUnlocked.UserLockedForTest(),
		"empty lockedUser must leave userLocked=false (admin picks user)")
	require.Equal(t, "", mUnlocked.UserFieldForTest())
}

// TestWantsRawKeys_true_in_phaseInput_and_phaseError — D-FW-CIDR
// requires the source-CIDR textinput to receive 'q' as a typed letter
// (not as the global quit shortcut). WantsRawKeys must return true in
// phaseInput AND phaseError; false in all other phases.
func TestWantsRawKeys_true_in_phaseInput_and_phaseError(t *testing.T) {
	t.Parallel()

	m := firewallrule.New(nil, nil, "22", "")
	require.True(t, m.WantsRawKeys(), "default phase=phaseInput → WantsRawKeys true")

	m.LoadStateForTest(firewallrule.PhasePreflightForTest, "203.0.113.7/32", "alice", "", "")
	require.False(t, m.WantsRawKeys(), "phasePreflight → WantsRawKeys false")

	m.LoadStateForTest(firewallrule.PhaseReviewForTest, "203.0.113.7/32", "alice", "", "")
	require.False(t, m.WantsRawKeys(), "phaseReview → WantsRawKeys false")

	m.LoadStateForTest(firewallrule.PhaseCommittingForTest, "203.0.113.7/32", "alice", "", "")
	require.False(t, m.WantsRawKeys(), "phaseCommitting → WantsRawKeys false")

	m.LoadStateForTest(firewallrule.PhaseDoneForTest, "203.0.113.7/32", "alice", "", "")
	require.False(t, m.WantsRawKeys(), "phaseDone → WantsRawKeys false")

	m.LoadStateForTest(firewallrule.PhaseErrorForTest, "203.0.113.7/32", "alice", "", "boom")
	require.True(t, m.WantsRawKeys(), "phaseError → WantsRawKeys true")
}
