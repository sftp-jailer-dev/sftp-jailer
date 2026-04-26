// Package keys_test exercises the M-PASSWORD (D-13 / USER-06) auto-
// generated strong-password helper. The generator must defeat
// pwquality.conf hardening (minclass=4) which Ubuntu 24.04 admins
// commonly apply — every output MUST contain at least one of upper, lower,
// digit, symbol (pitfall 7).
package keys_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
)

// TestGenerate_length_24_returns_24_characters pins the requested length.
// Loops 100 times to catch any silent re-roll bug that would change the
// length (the rejection-sampling loop must restart with a fresh buffer
// of the same size, not append).
func TestGenerate_length_24_returns_24_characters(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, err := keys.Generate(24)
		require.NoError(t, err)
		require.Len(t, s, 24, "iteration %d", i)
	}
}

// TestGenerate_length_8_minimum_accepted verifies the documented minimum
// boundary (length=8) succeeds.
func TestGenerate_length_8_minimum_accepted(t *testing.T) {
	s, err := keys.Generate(8)
	require.NoError(t, err)
	require.Len(t, s, 8)
}

// TestGenerate_length_below_8_rejected verifies the typed error message
// for the length-floor violation.
func TestGenerate_length_below_8_rejected(t *testing.T) {
	_, err := keys.Generate(7)
	require.Error(t, err)
	require.Contains(t, err.Error(), "length must be >= 8")
}

// TestGenerate_uses_only_chars_from_charset verifies every output character
// is in the documented 73-char set [A-Za-z0-9!@#$%^&*_-]. A 100-iteration
// sample is large enough to hit every char-class bucket multiple times.
func TestGenerate_uses_only_chars_from_charset(t *testing.T) {
	allowed := regexp.MustCompile(`^[A-Za-z0-9!@#$%^&*_-]+$`)
	for i := 0; i < 100; i++ {
		s, err := keys.Generate(24)
		require.NoError(t, err)
		require.True(t, allowed.MatchString(s),
			"iteration %d: %q contains a char outside the documented set", i, s)
	}
}

// TestGenerate_includes_all_four_classes verifies the minclass=4 hardening
// gate (pitfall 7) — every output MUST contain at least one upper, one
// lower, one digit, one symbol. The internal hasAllClasses helper is the
// implementation contract; this test verifies it actually ships.
func TestGenerate_includes_all_four_classes(t *testing.T) {
	hasUpper := regexp.MustCompile(`[A-Z]`)
	hasLower := regexp.MustCompile(`[a-z]`)
	hasDigit := regexp.MustCompile(`[0-9]`)
	hasSymbol := regexp.MustCompile(`[!@#$%^&*_\-]`)

	for i := 0; i < 100; i++ {
		s, err := keys.Generate(24)
		require.NoError(t, err)
		require.True(t, hasUpper.MatchString(s), "iter %d: missing upper in %q", i, s)
		require.True(t, hasLower.MatchString(s), "iter %d: missing lower in %q", i, s)
		require.True(t, hasDigit.MatchString(s), "iter %d: missing digit in %q", i, s)
		require.True(t, hasSymbol.MatchString(s), "iter %d: missing symbol in %q", i, s)
	}
}

// TestGenerate_distinct_outputs is a sanity check against accidental
// seed-fixing or a degenerate RNG path. 100 length-24 outputs from
// crypto/rand with rejection sampling should collide with vanishingly
// small probability (~ 100^2 / 73^24 ≈ 10^-40).
func TestGenerate_distinct_outputs(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		s, err := keys.Generate(24)
		require.NoError(t, err)
		_, dup := seen[s]
		require.False(t, dup, "iteration %d collided with prior output: %q", i, s)
		seen[s] = struct{}{}
	}
	// Belt-and-suspenders: also assert no two passwords are identical
	// via a single-pass length check.
	require.Equal(t, 100, len(seen))
}

// TestGenerate_no_whitespace_in_output is a defensive check — the charset
// has no whitespace; if it ever did, shells/copy-paste would corrupt the
// password silently.
func TestGenerate_no_whitespace_in_output(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, err := keys.Generate(24)
		require.NoError(t, err)
		require.False(t, strings.ContainsAny(s, " \t\n\r"),
			"iter %d: whitespace in output %q", i, s)
	}
}
