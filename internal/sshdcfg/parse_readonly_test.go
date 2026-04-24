package sshdcfg_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
)

// TestParseDropIn_canonical loads the canonical drop-in fixture and asserts
// that the read-side parser recognises the chroot Match block and its inner
// ForceCommand / ChrootDirectory directives.
func TestParseDropIn_canonical(t *testing.T) {
	b, err := os.ReadFile("../../testdata/sshd_config/50-sftp-jailer-canonical.conf")
	require.NoError(t, err)

	d, err := sshdcfg.ParseDropIn(b)
	require.NoError(t, err)

	require.True(t, d.HasMatchGroup("sftp-jailer"))
	require.Len(t, d.Matches, 1)

	body := d.Matches[0].Body
	findDir := func(kw string) (sshdcfg.Directive, bool) {
		for _, dir := range body {
			if dir.Keyword == kw {
				return dir, true
			}
		}
		return sshdcfg.Directive{}, false
	}

	fc, ok := findDir("forcecommand")
	require.True(t, ok, "canonical drop-in must have a ForceCommand inside the Match body")
	require.Equal(t, "internal-sftp -f AUTHPRIV -l INFO", fc.Value)

	cd, ok := findDir("chrootdirectory")
	require.True(t, ok, "canonical drop-in must have a ChrootDirectory inside the Match body")
	require.Equal(t, "%h", cd.Value)

	// Three more directives per the canonical fixture.
	for _, kw := range []string{"allowtcpforwarding", "x11forwarding", "permittunnel"} {
		d, ok := findDir(kw)
		require.True(t, ok, "canonical drop-in must include %q", kw)
		require.Equal(t, "no", d.Value)
	}
}

// TestParseDropIn_empty: zero-length input returns a zero-value DropIn with
// no error.
func TestParseDropIn_empty(t *testing.T) {
	d, err := sshdcfg.ParseDropIn(nil)
	require.NoError(t, err)
	require.Equal(t, 0, d.Size)
	require.Empty(t, d.Directives)
	require.Empty(t, d.Matches)
}

// TestParseDropIn_comments_and_blanks: comment + blank lines are ignored,
// but the relative order of real directives is preserved.
func TestParseDropIn_comments_and_blanks(t *testing.T) {
	input := []byte(`# header comment

Port 22

# another comment
PermitRootLogin no
`)
	d, err := sshdcfg.ParseDropIn(input)
	require.NoError(t, err)
	require.Empty(t, d.Matches, "no Match block in this input")
	require.Len(t, d.Directives, 2, "two real directives, comments and blanks excluded")
	require.Equal(t, "port", d.Directives[0].Keyword)
	require.Equal(t, "22", d.Directives[0].Value)
	require.Equal(t, "permitrootlogin", d.Directives[1].Keyword)
	require.Equal(t, "no", d.Directives[1].Value)
}

// TestParseDropIn_unknown_directive: unknown directives are preserved as
// pass-through directives, not errored — the read-side parser is lenient.
func TestParseDropIn_unknown_directive(t *testing.T) {
	input := []byte("FooBar baz quux\n")
	d, err := sshdcfg.ParseDropIn(input)
	require.NoError(t, err)
	require.Len(t, d.Directives, 1)
	require.Equal(t, "foobar", d.Directives[0].Keyword)
	require.Equal(t, "baz quux", d.Directives[0].Value)
	require.Equal(t, "FooBar baz quux", d.Directives[0].RawLine)
}

// TestHasMatchGroup_keyword_case_insensitive: the "Match" and "Group" keywords
// match case-insensitively, but the group-name value must match exactly
// (unix group names are case-sensitive).
func TestHasMatchGroup_keyword_case_insensitive(t *testing.T) {
	input := []byte("MATCH group sftp-jailer\n    ChrootDirectory %h\n")
	d, err := sshdcfg.ParseDropIn(input)
	require.NoError(t, err)
	require.True(t, d.HasMatchGroup("sftp-jailer"),
		"Match/Group keyword case-folding should not prevent group detection")
	require.False(t, d.HasMatchGroup("Sftp-Jailer"),
		"group name comparison is case-sensitive — unix groups are case-sensitive")
}

// TestHasMatchGroup_no_match: a Match block on a different condition (User)
// does not trigger HasMatchGroup.
func TestHasMatchGroup_no_match(t *testing.T) {
	d, err := sshdcfg.ParseDropIn([]byte("Port 22\nMatch User alice\n    ChrootDirectory /home\n"))
	require.NoError(t, err)
	require.False(t, d.HasMatchGroup("sftp-jailer"))
}

// TestParseDropIn_Match_block_endless: a Match block without a subsequent
// Match or EOF-terminator includes all remaining directives in its Body.
func TestParseDropIn_Match_block_endless(t *testing.T) {
	input := []byte(`Match Group sftp-jailer
    ChrootDirectory %h
    ForceCommand internal-sftp
    AllowTcpForwarding no
`)
	d, err := sshdcfg.ParseDropIn(input)
	require.NoError(t, err)
	require.Len(t, d.Matches, 1)
	require.NotEmpty(t, d.Matches[0].Body,
		"unclosed Match block must still capture its body up to EOF")
	require.Equal(t, 3, len(d.Matches[0].Body))
}

// TestGetDirective: top-level GetDirective returns the first matching
// directive case-insensitively and false when absent.
func TestGetDirective(t *testing.T) {
	d, err := sshdcfg.ParseDropIn([]byte("Port 22\nPermitRootLogin no\n"))
	require.NoError(t, err)

	got, ok := d.GetDirective("Port")
	require.True(t, ok)
	require.Equal(t, "22", got.Value)

	_, ok = d.GetDirective("NotThere")
	require.False(t, ok)
}

// TestParseDropIn_main_with_include: a realistic main sshd_config excerpt
// parses cleanly and exposes the Include + Subsystem directives.
func TestParseDropIn_main_with_include(t *testing.T) {
	b, err := os.ReadFile("../../testdata/sshd_config/main-with-include.conf")
	require.NoError(t, err)
	d, err := sshdcfg.ParseDropIn(b)
	require.NoError(t, err)

	inc, ok := d.GetDirective("include")
	require.True(t, ok)
	require.Equal(t, "/etc/ssh/sshd_config.d/*.conf", inc.Value)

	sub, ok := d.GetDirective("subsystem")
	require.True(t, ok)
	require.Equal(t, "sftp /usr/lib/openssh/sftp-server", sub.Value)
}
