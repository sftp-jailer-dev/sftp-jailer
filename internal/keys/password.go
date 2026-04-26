package keys

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// passwordCharset is the 73-character set used by Generate. Includes
// upper, lower, digits, and the 9 conservative shell-safe symbols
// (!@#$%^&*_-). Excludes characters known to cause copy-paste issues
// in URLs (/, ?, #, &), JSON contexts (\, ", '), or shell quoting (`,
// ;, |, $, (, ), [, ], {, }, <, >).
const passwordCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-"

// Generate returns a length-character password drawn uniformly at random
// from passwordCharset using crypto/rand. Uses big.NewInt + rand.Int to
// avoid modulo bias on the 73-character set. Re-rolls until the output
// contains at least one of upper, lower, digit, symbol — defeats common
// pwquality.conf hardening (minclass=4 — pitfall 7) which otherwise
// silently increases the chpasswd rejection rate on Ubuntu 24.04 boxes
// with hardening profiles applied.
//
// Bounded retries (cap=100) — vanishingly small probability of hitting
// the cap at length=24 (each draw has ~98% chance of containing all
// four classes), but the explicit cap prevents a pathological infinite
// loop on a broken crypto/rand (which cannot happen, but defense in
// depth).
//
// Call-site invariant (T-03-04-06): the caller (M-PASSWORD modal, plan
// 03-07) MUST display the result ONCE via OSC 52 + on-screen render and
// never log it. The keys package itself never logs the output.
func Generate(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("keys.Generate: length must be >= 8, got %d", length)
	}
	setLen := big.NewInt(int64(len(passwordCharset)))
	for attempt := 0; attempt < 100; attempt++ {
		buf := make([]byte, length)
		for i := 0; i < length; i++ {
			n, err := rand.Int(rand.Reader, setLen)
			if err != nil {
				return "", fmt.Errorf("keys.Generate: rand.Int: %w", err)
			}
			buf[i] = passwordCharset[n.Int64()]
		}
		if hasAllClasses(buf) {
			return string(buf), nil
		}
	}
	return "", fmt.Errorf("keys.Generate: 100 attempts failed to produce all four classes — broken RNG?")
}

// hasAllClasses returns true iff b contains at least one upper-case
// letter, one lower-case letter, one digit, and one symbol (anything
// not matching the first three predicates). Mirrors the
// pam_pwquality minclass=4 contract described in pitfall 7.
func hasAllClasses(b []byte) bool {
	var hasU, hasL, hasD, hasS bool
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			hasU = true
		case c >= 'a' && c <= 'z':
			hasL = true
		case c >= '0' && c <= '9':
			hasD = true
		default:
			hasS = true
		}
	}
	return hasU && hasL && hasD && hasS
}
