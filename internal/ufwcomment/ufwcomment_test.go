// Package ufwcomment_test exercises the Encode + Decode grammar lock for
// the sftp-jailer ufw rule comment schema (sftpj:v=1:user=<name>).
//
// The comment is the load-bearing contract for the user↔IP mapping that
// Phase 4's progressive lockdown depends on - Phase 2 reads these comments
// to render the firewall-view reverse-lookup (FW-04), Phase 4 writes them
// when adding allow rules (FW-02). Any regression here silently corrupts
// that mapping.
package ufwcomment_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

func TestEncode_valid(t *testing.T) {
	c, err := ufwcomment.Encode("alice")
	require.NoError(t, err)
	require.Equal(t, "sftpj:v=1:user=alice", c)
}

func TestEncode_underscore_prefix(t *testing.T) {
	_, err := ufwcomment.Encode("_bob")
	require.NoError(t, err)
}

func TestEncode_empty(t *testing.T) {
	_, err := ufwcomment.Encode("")
	require.ErrorIs(t, err, ufwcomment.ErrInvalidUser)
}

func TestEncode_uppercase_rejected(t *testing.T) {
	_, err := ufwcomment.Encode("Alice")
	require.ErrorIs(t, err, ufwcomment.ErrInvalidUser)
}

func TestEncode_shell_metachar_rejected(t *testing.T) {
	for _, bad := range []string{"alice;rm", "alice|grep", "alice$x", "alice`x`", "alice\"x", "alice'x", "alice x", "alice\\x"} {
		_, err := ufwcomment.Encode(bad)
		require.ErrorIs(t, err, ufwcomment.ErrInvalidUser, "input: %q", bad)
	}
}

func TestEncode_32_chars_max(t *testing.T) {
	u32 := strings.Repeat("a", 32)
	_, err := ufwcomment.Encode(u32)
	require.NoError(t, err)

	u33 := strings.Repeat("a", 33)
	_, err = ufwcomment.Encode(u33)
	require.ErrorIs(t, err, ufwcomment.ErrInvalidUser)
}

func TestDecode_v1_happy(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:v=1:user=alice")
	require.NoError(t, err)
	require.Equal(t, 1, p.Version)
	require.Equal(t, "alice", p.User)
}

func TestDecode_v0_legacy(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:user=alice")
	require.NoError(t, err)
	require.Equal(t, 0, p.Version)
	require.Equal(t, "alice", p.User)
}

func TestDecode_v2_forward(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:v=2:user=alice")
	require.ErrorIs(t, err, ufwcomment.ErrBadVersion)
	require.Equal(t, 2, p.Version)
}

// TestDecode_v1_subnet_shape_decoded pins the post-Phase-9 positive
// contract for the FW-10 subnet shape: Decode returns nil error and
// classifies as KindSubnet with the parsed reason. Replaces the
// pre-extension RED gate from Task 1's first commit.
func TestDecode_v1_subnet_shape_decoded(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:v=1:scope=subnet:reason=rfc1918")
	require.NoError(t, err)
	require.Equal(t, 1, p.Version)
	require.Equal(t, ufwcomment.KindSubnet, p.Kind)
	require.Equal(t, ufwcomment.ReasonRFC1918, p.SubnetReason)
	require.Equal(t, "", p.User)
}

func TestDecode_not_ours(t *testing.T) {
	_, err := ufwcomment.Decode("my random comment")
	require.ErrorIs(t, err, ufwcomment.ErrNotOurs)
}

func TestDecode_invalid_user_in_v1(t *testing.T) {
	_, err := ufwcomment.Decode("sftpj:v=1:user=ALICE")
	require.ErrorIs(t, err, ufwcomment.ErrInvalidUser)
}

func TestDecode_empty(t *testing.T) {
	_, err := ufwcomment.Decode("")
	require.ErrorIs(t, err, ufwcomment.ErrNotOurs)
}

func TestRoundTrip_valid_users(t *testing.T) {
	users := []string{"a", "_b", "b-c", "sftp_user1", strings.Repeat("a", 32)}
	for _, u := range users {
		c, err := ufwcomment.Encode(u)
		require.NoError(t, err, "encode %q", u)
		p, err := ufwcomment.Decode(c)
		require.NoError(t, err, "decode %q", c)
		require.Equal(t, u, p.User)
		require.Equal(t, 1, p.Version)
	}
}

// FuzzRoundTrip: anything Encode accepts, Decode must return unchanged.
func FuzzRoundTrip(f *testing.F) {
	f.Add("alice")
	f.Add("sftp_user1")
	f.Add("_bob-99")
	f.Fuzz(func(t *testing.T, user string) {
		c, err := ufwcomment.Encode(user)
		if err != nil {
			return
		}
		p, err := ufwcomment.Decode(c)
		require.NoError(t, err)
		require.Equal(t, user, p.User)
		require.Equal(t, ufwcomment.Version, p.Version)
	})
}

// FuzzDecodeNeverPanics: Decode must not panic on arbitrary input.
// Seeds include malformed sftpj: prefixes, traversal attempts, NUL bytes,
// and (post-FW-10) the new v=1 subnet-shape variants so the three-way
// classifier's branches are exercised by every fuzz iteration.
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add("sftpj:v=1:user=alice")
	f.Add("not_ours")
	f.Add("sftpj:v=1:user=")
	f.Add("sftpj:v=1:user=../etc/passwd")
	f.Add("sftpj:")
	f.Add("sftpj:v=")
	f.Add("sftpj:v=abc:user=x")
	f.Add("\x00sftpj:v=1:user=a")
	// FW-10 subnet-shape seeds (Phase 9 09-CONTEXT.md D-24).
	f.Add("sftpj:v=1:scope=subnet:reason=rfc1918")
	f.Add("sftpj:v=1:scope=subnet:reason=")
	f.Add("sftpj:v=1:scope=other:reason=rfc1918")
	f.Add("sftpj:v=1:scope=subnet:reason=\x00")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = ufwcomment.Decode(s)
	})
}

func TestEncodeSubnet_all_reasons_roundtrip(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{ufwcomment.ReasonRFC1918, "sftpj:v=1:scope=subnet:reason=rfc1918"},
		{ufwcomment.ReasonRFC4193, "sftpj:v=1:scope=subnet:reason=rfc4193"},
		{ufwcomment.ReasonLinkLocal, "sftpj:v=1:scope=subnet:reason=link-local"},
		{ufwcomment.ReasonOperator, "sftpj:v=1:scope=subnet:reason=operator"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.reason, func(t *testing.T) {
			got, err := ufwcomment.EncodeSubnet(c.reason)
			require.NoError(t, err)
			require.Equal(t, c.want, got)

			p, err := ufwcomment.Decode(got)
			require.NoError(t, err)
			require.Equal(t, ufwcomment.Version, p.Version)
			require.Equal(t, ufwcomment.KindSubnet, p.Kind)
			require.Equal(t, c.reason, p.SubnetReason)
			require.Equal(t, "", p.User)
		})
	}
}

// TestSubnetCommentByteCaps pins the empirical byte counts for each
// subnet shape. CONTEXT.md D-06 originally said link-local is 38 bytes;
// the actual longest is 40 bytes (Researcher Pitfall 1). All shapes must
// fit under MaxComment=64.
func TestSubnetCommentByteCaps(t *testing.T) {
	cases := []struct {
		reason string
		bytes  int
	}{
		{ufwcomment.ReasonRFC1918, 37},
		{ufwcomment.ReasonRFC4193, 37},
		{ufwcomment.ReasonLinkLocal, 40}, // longest; D-06 said 38, empirical is 40
		{ufwcomment.ReasonOperator, 38},
	}
	for _, c := range cases {
		c := c
		t.Run(c.reason, func(t *testing.T) {
			got, err := ufwcomment.EncodeSubnet(c.reason)
			require.NoError(t, err)
			require.Equal(t, c.bytes, len(got),
				"subnet comment for reason=%q must be %d bytes (per RQ-12 Pitfall 1)", c.reason, c.bytes)
			require.LessOrEqual(t, len(got), ufwcomment.MaxComment,
				"subnet comment must fit in MaxComment cap")
		})
	}
}

func TestEncodeSubnet_invalid_reasons(t *testing.T) {
	cases := []string{"", "unknown", "RFC1918", "rfc1918 ", "rfc4194", "private"}
	for _, r := range cases {
		r := r
		t.Run(r, func(t *testing.T) {
			_, err := ufwcomment.EncodeSubnet(r)
			require.ErrorIs(t, err, ufwcomment.ErrInvalidReason)
		})
	}
}

func TestDecode_v1_subnet_invalid_reason(t *testing.T) {
	cases := []string{
		"sftpj:v=1:scope=subnet:reason=garbage",
		"sftpj:v=1:scope=subnet:reason=",
		"sftpj:v=1:scope=subnet:reason=RFC1918",
		"sftpj:v=1:scope=other:reason=rfc1918",
		"sftpj:v=1:scope=subnet",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			p, err := ufwcomment.Decode(c)
			require.ErrorIs(t, err, ufwcomment.ErrBadVersion)
			require.Equal(t, ufwcomment.KindUnknown, p.Kind, "error-path Parsed must leave Kind at zero value")
		})
	}
}

// TestDecode_v0_legacy_kind_is_KindUser pins the per-D-02 invariant that
// legacy v=0 successful decode sets Kind=KindUser (NOT KindUnknown). This
// matters for downstream callers that switch on p.Kind rather than
// p.User != "".
func TestDecode_v0_legacy_kind_is_KindUser(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:user=alice")
	require.NoError(t, err)
	require.Equal(t, 0, p.Version)
	require.Equal(t, ufwcomment.KindUser, p.Kind)
	require.Equal(t, "alice", p.User)
}

func TestDecode_v1_user_kind_is_KindUser(t *testing.T) {
	p, err := ufwcomment.Decode("sftpj:v=1:user=alice")
	require.NoError(t, err)
	require.Equal(t, 1, p.Version)
	require.Equal(t, ufwcomment.KindUser, p.Kind)
	require.Equal(t, "alice", p.User)
	require.Equal(t, "", p.SubnetReason)
}
