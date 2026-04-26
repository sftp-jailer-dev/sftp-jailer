// Package keys parses SSH public keys from authorized_keys-format text,
// fetches keys from github.com/<user>.keys, and generates strong random
// passwords. All three capabilities share the same domain (SSH key
// material + auth secrets) and consume the same SystemOps-free seam.
//
// Phase 3 callers:
//   - M-ADD-KEY (plan 03-08): Parse → FetchGitHub for gh: lines → review table → commit
//   - M-PASSWORD (plan 03-07): Generate for the auto-generated password mode (D-13)
//   - S-USER-DETAIL (plan 03-08): Parse on read for the keys list display
//
// Design note: this package contains zero subprocess callers, zero
// filesystem mutations, and zero dependencies on internal/sysops. Tests
// drive Parse/Generate as pure helpers and stub HTTP for FetchGitHub via
// the testseam.go SetGithubBaseURLForTest helpers.
package keys

import (
	"bufio"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Source identifies how a parsed line should be resolved into actual
// key bytes downstream. The M-ADD-KEY review modal (D-20) only commits
// SourceDirect entries; the other sources are markers that the caller
// must resolve (FetchGitHub for gh:, os.ReadFile + recursive Parse for
// SourceFile) before populating the review table.
type Source int

const (
	// SourceDirect indicates the input line is itself an authorized_keys-
	// format key; ssh.ParseAuthorizedKey has already validated it and
	// Algorithm/Fingerprint/Comment/ByteSize are populated.
	SourceDirect Source = iota
	// SourceGithubAll indicates a "gh:<user>" marker — caller should
	// invoke FetchGitHub(ctx, GithubUser) to retrieve all keys for the
	// user and re-parse the result for the review modal.
	SourceGithubAll
	// SourceGithubByID indicates a "gh:<user>/<id>" marker — caller
	// should invoke FetchGitHubByID(ctx, GithubUser, GithubKeyID).
	SourceGithubByID
	// SourceFile indicates a "/" or "~/" prefix — caller should
	// os.ReadFile the FilePath (after expanding ~ if needed) and
	// recursively Parse the contents.
	SourceFile
)

// ParsedKey is the result of parsing one line of M-ADD-KEY textarea
// input. For SourceDirect, Algorithm/Fingerprint/Comment/Bytes are
// populated by ssh.ParseAuthorizedKey at parse time. For other sources,
// those fields are filled by the caller AFTER the source is resolved
// (FetchGitHub returns raw bytes, which the caller re-parses).
type ParsedKey struct {
	// Line is the 1-based line number in the original textarea input.
	// Surfaces in the D-20 review modal so admins can locate a specific
	// entry in their pasted text.
	Line int
	// Source identifies the resolution path (see Source constants).
	Source Source
	// Raw is the verbatim line bytes (without trailing newline).
	Raw []byte

	// Algorithm is the ssh-keytype string (ssh-ed25519, ssh-rsa,
	// ecdsa-sha2-nistp256, sk-ssh-ed25519@openssh.com, …). Filled
	// only when Source == SourceDirect.
	Algorithm string
	// Fingerprint is the canonical "SHA256:<base64-no-padding>" form
	// per OpenSSH 6.8+. Matches what `ssh-keygen -lf <file>` displays.
	// Filled only when Source == SourceDirect.
	Fingerprint string
	// Comment is the trailing free-text on the authorized_keys line.
	// Filled only when Source == SourceDirect.
	Comment string
	// ByteSize is len(pubkey.Marshal()) — the wire-format byte length
	// admins see in the D-20 "bytes" column. Filled only when
	// Source == SourceDirect.
	ByteSize int

	// GithubUser is the user component of the "gh:<user>" or
	// "gh:<user>/<id>" marker. Filled only when Source is one of the
	// two SourceGithub variants.
	GithubUser string
	// GithubKeyID is the numeric id from "gh:<user>/<id>". Zero when
	// Source == SourceGithubAll.
	GithubKeyID int

	// FilePath is the verbatim path string from the input line. The
	// keys package does NOT expand ~ — that's the file-load caller's
	// job. Filled only when Source == SourceFile.
	FilePath string
}

// ParseErr describes one line of input that did not match any source
// rule. The D-20 review modal surfaces these verbatim alongside the
// successfully-parsed keys, so the admin can see "line 3 was rejected
// because <reason>" without losing the valid lines around it.
type ParseErr struct {
	// Line is the 1-based line number in the original textarea input.
	Line int
	// Raw is the verbatim line bytes (without trailing newline) — what
	// the admin actually typed/pasted.
	Raw string
	// Err is the underlying error (typically wrapping
	// ssh.ParseAuthorizedKey for direct-paste lines or a typed message
	// for malformed gh: markers).
	Err error
}

// Error formats the line number + underlying error for log/debug
// surfaces. The D-20 review modal renders Line/Raw/Err separately for
// richer presentation, but Error() is the io-friendly fallback.
func (e ParseErr) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

// Parse splits the input by newline and dispatches each non-blank,
// non-comment line to the appropriate source detector. Lines that
// don't match any source rule become ParseErrs (caller surfaces them
// verbatim in the M-ADD-KEY review modal per D-20).
//
// Direct-paste lines are validated immediately via ssh.ParseAuthorizedKey;
// a ParseAuthorizedKey error becomes a ParseErr. gh: and SourceFile
// lines are returned as markers — the caller resolves them via
// FetchGitHub / os.ReadFile + Parse-recursion.
//
// Partial-batch contract: a single malformed line does NOT abort the
// whole parse. A 5-line input with one garbage line returns 4
// ParsedKeys + 1 ParseErr; the admin sees both in the review modal.
func Parse(textarea string) ([]ParsedKey, []ParseErr) {
	var parsed []ParsedKey
	var errs []ParseErr

	sc := bufio.NewScanner(strings.NewReader(textarea))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "gh:"):
			k, err := parseGithubMarker(trimmed[len("gh:"):], lineNo, raw)
			if err != nil {
				errs = append(errs, ParseErr{Line: lineNo, Raw: raw, Err: err})
			} else {
				parsed = append(parsed, k)
			}
		case strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "~/"):
			parsed = append(parsed, ParsedKey{
				Line:     lineNo,
				Source:   SourceFile,
				Raw:      []byte(raw),
				FilePath: trimmed,
			})
		default:
			k, err := parseDirectPaste(raw, lineNo)
			if err != nil {
				errs = append(errs, ParseErr{Line: lineNo, Raw: raw, Err: err})
			} else {
				parsed = append(parsed, k)
			}
		}
	}
	return parsed, errs
}

// parseGithubMarker handles the post-"gh:" portion of a marker line.
// Returns a typed ParseErr-eligible error for malformed forms; the
// caller wraps in ParseErr.
func parseGithubMarker(rest string, lineNo int, raw string) (ParsedKey, error) {
	if rest == "" {
		return ParsedKey{}, fmt.Errorf("gh: requires a username (e.g. gh:alice)")
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return ParsedKey{
			Line: lineNo, Source: SourceGithubAll, Raw: []byte(raw), GithubUser: rest,
		}, nil
	}
	user := rest[:slash]
	idStr := rest[slash+1:]
	if user == "" || idStr == "" {
		return ParsedKey{}, fmt.Errorf("gh: malformed user/id pair: %q", rest)
	}
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil || id <= 0 {
		return ParsedKey{}, fmt.Errorf("gh: key id must be positive integer, got %q", idStr)
	}
	// Reject trailing garbage after the integer (e.g. "gh:alice/12abc"
	// where Sscanf greedily consumes "12" and silently leaves "abc").
	check := fmt.Sprintf("%d", id)
	if check != idStr {
		return ParsedKey{}, fmt.Errorf("gh: key id must be positive integer, got %q", idStr)
	}
	return ParsedKey{
		Line: lineNo, Source: SourceGithubByID, Raw: []byte(raw),
		GithubUser: user, GithubKeyID: id,
	}, nil
}

// parseDirectPaste validates a single line via ssh.ParseAuthorizedKey
// and extracts Algorithm/Fingerprint/Comment/ByteSize for the D-20
// review modal columns. The library handles all OpenSSH-recognized key
// types (RSA, ed25519, ecdsa, sk-*) plus options syntax — far better
// than a hand-rolled base64-+-OID extractor.
func parseDirectPaste(raw string, lineNo int) (ParsedKey, error) {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return ParsedKey{}, fmt.Errorf("ssh.ParseAuthorizedKey: %w", err)
	}
	return ParsedKey{
		Line:        lineNo,
		Source:      SourceDirect,
		Raw:         []byte(raw),
		Algorithm:   pk.Type(),
		Fingerprint: ssh.FingerprintSHA256(pk),
		Comment:     comment,
		ByteSize:    len(pk.Marshal()),
	}, nil
}

// Fingerprint returns the canonical OpenSSH SHA256 fingerprint for a
// public key already obtained via ssh.ParseAuthorizedKey. Thin wrapper
// over ssh.FingerprintSHA256 — kept here so the keys package is the
// single dependency surface for the SSH library.
func Fingerprint(pk ssh.PublicKey) string { return ssh.FingerprintSHA256(pk) }
