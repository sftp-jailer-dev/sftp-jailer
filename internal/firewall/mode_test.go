// Package firewall — Phase 4 plan 04-03 Task 1 RED gate.
//
// These tests pin the four-state classifier DetectMode (D-L0809-02) and the
// Mode enum's String() formatting. The tests live in `package firewall`
// (internal — not _test) so the unexported portMatches helper isn't a
// blocker if a sibling file ever exercises it indirectly.
package firewall

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

func TestDetectMode_classifies_all_four_states(t *testing.T) {
	t.Parallel()
	catchAll := Rule{ID: 1, Port: "22", Source: "Anywhere", Action: "ALLOW IN", RawComment: ""}
	sftpjRule := Rule{ID: 2, Port: "22", Source: "203.0.113.7/32", Action: "ALLOW IN",
		RawComment: "sftpj:v=1:user=alice", User: "alice"}

	cases := []struct {
		name  string
		rules []Rule
		want  Mode
	}{
		{"open", []Rule{catchAll}, ModeOpen},
		{"staging", []Rule{catchAll, sftpjRule}, ModeStaging},
		{"locked", []Rule{sftpjRule}, ModeLocked},
		{"unknown_empty", []Rule{}, ModeUnknown},
		{"unknown_other_port", []Rule{{ID: 3, Port: "8080", Source: "Anywhere", Action: "ALLOW IN"}}, ModeUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, DetectMode(tc.rules, "22"))
		})
	}
}

func TestDetectMode_port_with_tcp_suffix(t *testing.T) {
	t.Parallel()
	rules := []Rule{{ID: 1, Port: "22/tcp", Source: "Anywhere", Action: "ALLOW IN"}}
	require.Equal(t, ModeOpen, DetectMode(rules, "22"))
}

func TestDetectMode_string_formatting(t *testing.T) {
	t.Parallel()
	require.Equal(t, "open", ModeOpen.String())
	require.Equal(t, "staging", ModeStaging.String())
	require.Equal(t, "locked", ModeLocked.String())
	require.Equal(t, "unknown", ModeUnknown.String())
}

// TestDetectMode_skips_forward_compat_rules pins that ParseErr != nil rules
// (e.g. ufwcomment.ErrBadVersion from a newer binary's v=2 comment) are
// NOT classified as sftpj rules — they're treated as opaque foreign rules
// per the forward-compat contract from internal/ufwcomment.
func TestDetectMode_skips_forward_compat_rules(t *testing.T) {
	t.Parallel()
	forwardCompat := Rule{
		ID: 7, Port: "22", Source: "203.0.113.7/32", Action: "ALLOW IN",
		RawComment: "sftpj:v=2:user=alice",
		User:       "", // Decode left it empty
		ParseErr:   ufwcomment.ErrBadVersion,
	}
	// Forward-compat rule alone — no catch-all, no v=1 sftpj rule → UNKNOWN.
	require.Equal(t, ModeUnknown, DetectMode([]Rule{forwardCompat}, "22"))
}

// TestDetectMode_ignores_deny_rules pins that DENY rules don't qualify as
// catch-alls or sftpj rules — only ALLOW (action contains "ALLOW") matters.
func TestDetectMode_ignores_deny_rules(t *testing.T) {
	t.Parallel()
	denyAll := Rule{ID: 1, Port: "22", Source: "Anywhere", Action: "DENY IN", RawComment: ""}
	require.Equal(t, ModeUnknown, DetectMode([]Rule{denyAll}, "22"))
}
