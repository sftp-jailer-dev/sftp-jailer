// Package ufwcomment_test exercises the Encode + Decode grammar lock for
// the sftp-jailer ufw rule comment schema (sftpj:v=1:user=<name>).
//
// The comment is the load-bearing contract for the user↔IP mapping that
// Phase 4's progressive lockdown depends on — Phase 2 reads these comments
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
// Seeds include malformed sftpj: prefixes, traversal attempts, NUL bytes.
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add("sftpj:v=1:user=alice")
	f.Add("not_ours")
	f.Add("sftpj:v=1:user=")
	f.Add("sftpj:v=1:user=../etc/passwd")
	f.Add("sftpj:")
	f.Add("sftpj:v=")
	f.Add("sftpj:v=abc:user=x")
	f.Add("\x00sftpj:v=1:user=a")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = ufwcomment.Decode(s)
	})
}
