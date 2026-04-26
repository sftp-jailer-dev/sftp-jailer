package sshdcfg_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
)

// readGolden loads a fixture from internal/sshdcfg/testdata/.
//
// gosec G304: name is a fixture filename hardcoded by the calling test —
// not an attacker-controlled path. Same precedent as
// internal/users/enumerate_test.go's loadFixture helper.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: hardcoded fixture filename
	require.NoError(t, err)
	return b
}

// TestCanonicalDropIn_pins_byte_identity_at_frozen_timestamp pins the exact
// D-07 canonical drop-in bytes for chrootRoot=/srv/sftp-jailer at a frozen
// 2026-04-26T12:00:00Z timestamp.
func TestCanonicalDropIn_pins_byte_identity_at_frozen_timestamp(t *testing.T) {
	got := sshdcfg.CanonicalDropIn(
		"/srv/sftp-jailer",
		time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	)
	want := readGolden(t, "canonical-drop-in.golden")
	if !bytes.Equal(got, want) {
		t.Errorf("CanonicalDropIn mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			string(got), string(want))
	}
}

// TestCanonicalDropIn_chrootRoot_no_trailing_slash_is_canonical asserts the
// renderer canonicalizes trailing slashes on chrootRoot so the output never
// contains a double slash before %u.
func TestCanonicalDropIn_chrootRoot_no_trailing_slash_is_canonical(t *testing.T) {
	frozen := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	noSlash := sshdcfg.CanonicalDropIn("/srv/sftp-jailer", frozen)
	require.Contains(t, string(noSlash), "ChrootDirectory /srv/sftp-jailer/%u\n")

	withSlash := sshdcfg.CanonicalDropIn("/srv/sftp-jailer/", frozen)
	require.Equal(t, noSlash, withSlash,
		"trailing-slash chrootRoot must produce identical output to no-trailing-slash form")
}

// TestCanonicalDropIn_uses_literal_path_not_percent_h pins the D-07/D-08
// invariant: ChrootDirectory uses the literal chrootRoot path, never %h.
func TestCanonicalDropIn_uses_literal_path_not_percent_h(t *testing.T) {
	got := sshdcfg.CanonicalDropIn(
		"/srv/sftp-jailer",
		time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	)
	s := string(got)
	require.Contains(t, s, "ChrootDirectory /srv/sftp-jailer/%u")
	require.NotContains(t, s, "%h",
		"D-08 invariant: canonical drop-in must use literal chrootRoot path, not %%h")
}

// TestRender_byte_identity_for_unmodified_RawLines round-trips a hand-crafted
// drop-in (every Directive carries RawLine after Parse) and asserts Render
// produces byte-equal output to the .golden fixture.
//
// The fixture deliberately omits comments and blank lines because the Phase 1
// parser discards both — they never reach Render. This is documented in the
// SUMMARY as a known property of the round-trip contract (Render is the
// inverse of Parse for non-comment, non-blank content only).
func TestRender_byte_identity_for_unmodified_RawLines(t *testing.T) {
	in := readGolden(t, "round-trip-existing.input")
	want := readGolden(t, "round-trip-existing.golden")

	d, err := sshdcfg.ParseDropIn(in)
	require.NoError(t, err)

	got := sshdcfg.Render(d)
	if !bytes.Equal(got, want) {
		t.Errorf("Render mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			string(got), string(want))
	}
}

// TestRender_emits_top_level_directives_before_match_blocks pins pitfall A3
// (D-16): top-level directives MUST emit before any Match block, otherwise
// they get scoped to the Match block per sshd_config(5) semantics.
func TestRender_emits_top_level_directives_before_match_blocks(t *testing.T) {
	d := sshdcfg.DropIn{
		Directives: []sshdcfg.Directive{
			{Keyword: "PasswordAuthentication", Value: "no"},
		},
		Matches: []sshdcfg.MatchBlock{
			{
				Condition: "Group sftp-jailer",
				Body: []sshdcfg.Directive{
					{Keyword: "ChrootDirectory", Value: "/srv/sftp-jailer/%u"},
				},
			},
		},
	}

	got := string(sshdcfg.Render(d))
	want := "PasswordAuthentication no\n" +
		"Match Group sftp-jailer\n" +
		"    ChrootDirectory /srv/sftp-jailer/%u\n"
	require.Equal(t, want, got)
}

// TestRender_new_directive_in_match_block_has_4space_indent pins the OpenSSH
// convention: new directives (RawLine == "") inside a Match block emit with
// exactly four leading spaces.
func TestRender_new_directive_in_match_block_has_4space_indent(t *testing.T) {
	d := sshdcfg.DropIn{
		Matches: []sshdcfg.MatchBlock{
			{
				Condition: "Group sftp-jailer",
				Body: []sshdcfg.Directive{
					{Keyword: "AllowTcpForwarding", Value: "no"},
				},
			},
		},
	}

	got := string(sshdcfg.Render(d))
	// The body line is the second line; assert exactly four leading spaces.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 2)
	require.True(t, strings.HasPrefix(lines[1], "    "),
		"new directive inside Match block must have 4-space indent, got %q", lines[1])
	require.False(t, strings.HasPrefix(lines[1], "     "),
		"new directive inside Match block must have EXACTLY 4-space indent, got %q", lines[1])
}

// TestRender_new_top_level_directive_has_no_indent pins the convention:
// new top-level directives (RawLine == "") emit with no leading whitespace.
func TestRender_new_top_level_directive_has_no_indent(t *testing.T) {
	d := sshdcfg.DropIn{
		Directives: []sshdcfg.Directive{
			{Keyword: "PasswordAuthentication", Value: "no"},
		},
	}

	got := string(sshdcfg.Render(d))
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	require.NotEmpty(t, lines)
	require.False(t, strings.HasPrefix(lines[0], " "),
		"new top-level directive must have no leading whitespace, got %q", lines[0])
	require.False(t, strings.HasPrefix(lines[0], "\t"),
		"new top-level directive must have no leading whitespace, got %q", lines[0])
	require.Equal(t, "PasswordAuthentication no", lines[0])
}

// TestParseRender_round_trip_property asserts Parse(Render(Parse(b))) ≡
// Parse(b) — the parser is the inverse of the writer for byte-clean inputs.
// Equivalence is by reflect.DeepEqual on the DropIn struct (Directives slice,
// Matches slice, Size).
func TestParseRender_round_trip_property(t *testing.T) {
	cases := []string{
		"round-trip-existing.input",
		"match-header-multispace.input",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			in := readGolden(t, name)

			first, err := sshdcfg.ParseDropIn(in)
			require.NoError(t, err)

			rendered := sshdcfg.Render(first)

			second, err := sshdcfg.ParseDropIn(rendered)
			require.NoError(t, err)

			// Size differs (rendered bytes != input bytes when the input had
			// comments or whitespace canonicalization), so compare the
			// structural slices only.
			if !reflect.DeepEqual(first.Directives, second.Directives) {
				t.Errorf("Directives mismatch after round-trip:\n--- first ---\n%#v\n--- second ---\n%#v",
					first.Directives, second.Directives)
			}
			if !reflect.DeepEqual(first.Matches, second.Matches) {
				t.Errorf("Matches mismatch after round-trip:\n--- first ---\n%#v\n--- second ---\n%#v",
					first.Matches, second.Matches)
			}
		})
	}
}

// TestRender_match_header_canonicalizes_multiple_spaces_to_single_space pins
// the N-03 normalization: the Match block header is always emitted as
// `Match <Condition>` with a single space, regardless of how the source file
// was authored.
//
// Existing drop-ins authored with multiple-space Match separators will see a
// one-character cosmetic diff on first apply via M-APPLY-SETUP. The SUMMARY
// documents this as an acceptable trade — adding a RawHeader field to
// MatchBlock for byte-identity preservation is deferred as future polish
// (low value vs cost; admins rarely use multi-space).
func TestRender_match_header_canonicalizes_multiple_spaces_to_single_space(t *testing.T) {
	in := readGolden(t, "match-header-multispace.input")
	want := readGolden(t, "match-header-multispace.golden")

	d, err := sshdcfg.ParseDropIn(in)
	require.NoError(t, err)

	got := sshdcfg.Render(d)
	if !bytes.Equal(got, want) {
		t.Errorf("Match header canonicalization mismatch:\n--- got ---\n%q\n--- want ---\n%q",
			string(got), string(want))
	}
	// Belt-and-suspenders: assert the exact form of the Match line.
	require.Contains(t, string(got), "Match Group developers\n")
	require.NotContains(t, string(got), "Match  Group developers")
}
