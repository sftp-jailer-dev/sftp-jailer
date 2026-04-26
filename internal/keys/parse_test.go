// Package keys_test exercises the M-ADD-KEY (D-19/D-20) source-detection
// dispatcher in internal/keys.Parse. The dispatcher decides per line:
//
//	ssh-/ecdsa-/sk- prefix → SourceDirect (validated via ssh.ParseAuthorizedKey)
//	gh:<user>             → SourceGithubAll
//	gh:<user>/<id>        → SourceGithubByID
//	/ or ~/ prefix        → SourceFile (path passed through verbatim)
//	anything else         → ParseErr surfaced to admin via the D-20 review modal
//
// Tests pin the per-line source-detection rules + the SHA256 fingerprint
// format (canonical "SHA256:base64-no-padding" per OpenSSH 6.8+).
package keys_test

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
)

// sampleFingerprint pins the SHA256 fingerprint of testdata/sample.pub
// captured once at fixture-creation time via:
//
//	ssh-keygen -lf internal/keys/testdata/sample.pub
//
// Pinning the literal string ensures keys.Fingerprint stays in lockstep
// with what `ssh-keygen -lf` displays — the same value admins compare
// against the M-ADD-KEY review modal column (D-20).
const sampleFingerprint = "SHA256:tEOJMisUY8XrgbyajGOQ+ZVqOZ06DGYCh/DW22OR+HU"

// sampleKey is the verbatim authorized_keys line from testdata/sample.pub.
// Loaded once for direct-paste tests; tests that need the full file body
// re-read it from disk.
const sampleKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB20MgDa2k54UowTD6LBWWzLRLwc9wMmfGWZvcoRI6d+ test@sftp-jailer-fixture"

// sampleRSAKey is a real RSA key generated alongside the ed25519 fixture
// for multi-algorithm dispatch coverage.
const sampleRSAKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAs+Ym+EqP0EFcoJmi66uFWf16WX+sEFXIbRnK1iGMt6fXjvt2IT/prYxZXg61hMmBe/1d+Pfq/C67AlG74iSAT/nBAurpQ/IdRTrXdwzTBnOYQqTQSi+H42XAP32lpdOGXxAPX9jS87rC0h7CCIXt2lBQmFzn7tZDY2IVaepcq4bp5ocVHhtdWuUA890XhT+TzqDVF2dxm7GkPmkugEfcN4kSlqAgKvIE/GiKKDLyqEE+rsbjil3fF0rdGfXK4ZlcOjrtR1qyiaDAE761/4rCIyoRRUGMXMCVj/c5VLw9P2Jd8pxHQFiJO5awJEmVjP4gdUk/wOwmWAshVyxDn2r7 rsa-test@sftp-jailer-fixture"

// sampleECDSAKey is a real ECDSA-P256 key for direct-paste dispatch coverage.
const sampleECDSAKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF8qDlGX/Rm0sRAtjh82JsFNfklhzlV5jCEoJG24NwmhgfPrjYhwuLrN3mFsF5aA3SmtyyE0p4zFhhNg0wEGo7s= ecdsa-test@sftp-jailer-fixture"

// sampleSKKey is a synthetic sk-ssh-ed25519 (security-key) line. The bytes
// after the algorithm prefix are not a real key — Parse only needs to
// dispatch on the prefix; ssh.ParseAuthorizedKey may reject the body but
// the test scopes to the sk- prefix recognition rule (D-19).
//
// We use a real sk-ssh-ed25519 line shape from openssh's own test suite
// for parser compatibility.
const sampleSKKey = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIIQ8Hd3pUmhULzLP6cF8rJpRMuG0tUq6CT57nh28YfUdAAAABHNzaDo= sk-test@sftp-jailer-fixture"

// TestParse_direct_paste_ssh_ed25519 is the single-line ed25519 dispatch
// happy path. ssh.ParseAuthorizedKey validates; Algorithm/Fingerprint/
// Comment/ByteSize get filled.
func TestParse_direct_paste_ssh_ed25519(t *testing.T) {
	parsed, errs := keys.Parse(sampleKey + "\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)

	k := parsed[0]
	require.Equal(t, keys.SourceDirect, k.Source)
	require.Equal(t, "ssh-ed25519", k.Algorithm)
	require.Equal(t, sampleFingerprint, k.Fingerprint)
	require.Equal(t, "test@sftp-jailer-fixture", k.Comment)
	require.Greater(t, k.ByteSize, 0)
	require.Equal(t, 1, k.Line)
}

// TestParse_direct_paste_ssh_rsa_and_ecdsa_recognized covers the other
// two algorithm prefixes the dispatcher must recognize as direct-paste.
func TestParse_direct_paste_ssh_rsa_and_ecdsa_recognized(t *testing.T) {
	input := sampleRSAKey + "\n" + sampleECDSAKey + "\n"
	parsed, errs := keys.Parse(input)
	require.Empty(t, errs)
	require.Len(t, parsed, 2)

	require.Equal(t, keys.SourceDirect, parsed[0].Source)
	require.Equal(t, "ssh-rsa", parsed[0].Algorithm)

	require.Equal(t, keys.SourceDirect, parsed[1].Source)
	require.Equal(t, "ecdsa-sha2-nistp256", parsed[1].Algorithm)
}

// TestParse_sk_prefix_recognized_as_direct verifies the sk-ssh-ed25519
// security-key prefix routes through the direct-paste path (D-19 includes
// sk-* algorithms).
func TestParse_sk_prefix_recognized_as_direct(t *testing.T) {
	parsed, errs := keys.Parse(sampleSKKey + "\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)
	require.Equal(t, keys.SourceDirect, parsed[0].Source)
	require.Equal(t, "sk-ssh-ed25519@openssh.com", parsed[0].Algorithm)
}

// TestParse_gh_user_marker_no_slash covers the bare gh:<user> form.
// No FetchGitHub call yet — Parse returns the marker; the caller resolves.
func TestParse_gh_user_marker_no_slash(t *testing.T) {
	parsed, errs := keys.Parse("gh:alice\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)

	k := parsed[0]
	require.Equal(t, keys.SourceGithubAll, k.Source)
	require.Equal(t, "alice", k.GithubUser)
	require.Equal(t, 0, k.GithubKeyID)
	require.Empty(t, k.Algorithm)
	require.Empty(t, k.Fingerprint)
}

// TestParse_gh_user_with_id covers the gh:<user>/<id> selective-fetch form.
func TestParse_gh_user_with_id(t *testing.T) {
	parsed, errs := keys.Parse("gh:alice/12345\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)

	k := parsed[0]
	require.Equal(t, keys.SourceGithubByID, k.Source)
	require.Equal(t, "alice", k.GithubUser)
	require.Equal(t, 12345, k.GithubKeyID)
}

// TestParse_path_absolute covers the absolute-path source. Parser doesn't
// read the file — that's the caller's job.
func TestParse_path_absolute(t *testing.T) {
	parsed, errs := keys.Parse("/etc/keys/alice.pub\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)
	require.Equal(t, keys.SourceFile, parsed[0].Source)
	require.Equal(t, "/etc/keys/alice.pub", parsed[0].FilePath)
}

// TestParse_path_tilde covers the ~-relative path source. Parser does NOT
// expand ~ — that's the file-load caller's job.
func TestParse_path_tilde(t *testing.T) {
	parsed, errs := keys.Parse("~/keys/alice.pub\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)
	require.Equal(t, keys.SourceFile, parsed[0].Source)
	require.Equal(t, "~/keys/alice.pub", parsed[0].FilePath)
}

// TestParse_malformed_line_returns_parseErr_keeps_other_lines verifies the
// partial-batch contract: garbage lines become ParseErrs but valid lines
// before/after are still parsed and returned. Critical for the D-20 review
// modal which surfaces both successful keys + per-line errors.
func TestParse_malformed_line_returns_parseErr_keeps_other_lines(t *testing.T) {
	input := sampleKey + "\ngarbage line that does not parse\ngh:alice\n"
	parsed, errs := keys.Parse(input)
	require.Len(t, parsed, 2, "valid ed25519 + gh:alice both kept")
	require.Len(t, errs, 1, "garbage line surfaces as one ParseErr")

	require.Equal(t, 2, errs[0].Line, "ParseErr pins the 1-based line number")
	require.NotNil(t, errs[0].Err)
}

// TestParse_blank_lines_skipped verifies blank lines (leading, trailing,
// between entries) are silently skipped — no spurious ParseErrs.
func TestParse_blank_lines_skipped(t *testing.T) {
	input := "\n\n" + sampleKey + "\n\n\ngh:alice\n\n"
	parsed, errs := keys.Parse(input)
	require.Empty(t, errs)
	require.Len(t, parsed, 2)
}

// TestParse_comment_lines_skipped verifies # comment lines are silently
// skipped — no spurious ParseErrs.
func TestParse_comment_lines_skipped(t *testing.T) {
	input := "# this is a comment\n" + sampleKey + "\n# another comment\n"
	parsed, errs := keys.Parse(input)
	require.Empty(t, errs)
	require.Len(t, parsed, 1)
	require.Equal(t, keys.SourceDirect, parsed[0].Source)
}

// TestParse_multiline_fixture_file exercises the on-disk fixture with the
// exact mix the M-ADD-KEY review modal will see in the wild: 1 ed25519 +
// 1 garbage + 1 blank + 1 gh:alice + 1 ssh-rsa.
func TestParse_multiline_fixture_file(t *testing.T) {
	//nolint:gosec // G304: hardcoded fixture filename
	body, err := os.ReadFile("testdata/multi-line.txt")
	require.NoError(t, err)

	parsed, errs := keys.Parse(string(body))
	require.Len(t, parsed, 3, "ed25519 + gh:alice + ssh-rsa")
	require.Len(t, errs, 1, "garbage line is one ParseErr")

	require.Equal(t, keys.SourceDirect, parsed[0].Source)
	require.Equal(t, "ssh-ed25519", parsed[0].Algorithm)
	require.Equal(t, keys.SourceGithubAll, parsed[1].Source)
	require.Equal(t, "alice", parsed[1].GithubUser)
	require.Equal(t, keys.SourceDirect, parsed[2].Source)
	require.Equal(t, "ssh-rsa", parsed[2].Algorithm)
}

// TestFingerprint_sha256_format_matches_ssh_keygen pins the canonical
// OpenSSH 6.8+ fingerprint format ("SHA256:" + 43-char base64-no-padding)
// and compares verbatim against `ssh-keygen -lf testdata/sample.pub`
// captured at fixture-creation time.
func TestFingerprint_sha256_format_matches_ssh_keygen(t *testing.T) {
	parsed, errs := keys.Parse(sampleKey + "\n")
	require.Empty(t, errs)
	require.Len(t, parsed, 1)

	fp := parsed[0].Fingerprint
	require.True(t, regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(fp),
		"got %q — should match canonical OpenSSH SHA256 form", fp)
	require.Equal(t, sampleFingerprint, fp,
		"fingerprint must match `ssh-keygen -lf testdata/sample.pub`")
}

// TestParse_gh_empty_user_returns_parseErr verifies the "gh:" with no
// username form is a ParseErr — defensive coverage for malformed input.
func TestParse_gh_empty_user_returns_parseErr(t *testing.T) {
	_, errs := keys.Parse("gh:\n")
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Err.Error(), "gh:")
}

// TestParse_gh_invalid_id_returns_parseErr verifies non-numeric IDs and
// zero/negative IDs are ParseErrs.
func TestParse_gh_invalid_id_returns_parseErr(t *testing.T) {
	for _, in := range []string{"gh:alice/notanumber\n", "gh:alice/0\n", "gh:alice/-1\n", "gh:alice/\n", "gh:/123\n"} {
		_, errs := keys.Parse(in)
		require.NotEmpty(t, errs, "input %q should produce a ParseErr", in)
	}
}
