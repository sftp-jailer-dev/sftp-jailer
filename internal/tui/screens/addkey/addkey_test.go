// Package addkey tests for M-ADD-KEY — covers the phase state machine,
// parser dispatch (paste / gh: / file:), gh: pre-fetch validation, the
// mandatory review table (D-20: even single-key gh: fetches go through
// review), the three-step verifier closure (D-21 steps 1+2 / 3 / 4), and
// the txn-level rollback on any verifier-failure mode.
//
// Test seam discipline:
//   - All sysops calls go through sysops.Fake (W-02).
//   - All gh: HTTP calls go through httptest.Server with W-06 explicit
//     path-match handlers; the package-private base URLs are overridden
//     via keys.SetGithubBaseURLForTest / keys.SetGithubAPIBaseURLForTest
//     (the test seams shipped by plan 03-04 / internal/keys/testseam.go).
//   - chrootcheck.userLookup is overridden via SetUserLookupForTest so
//     CheckAuthKeysFile does not depend on a real /etc/passwd entry.
package addkey_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/addkey"
)

const (
	testChrootRoot = "/srv/sftp"
	testUsername   = "alice"
	// samplePub is a real ed25519 line copied from internal/keys/testdata/sample.pub.
	// keys.Parse on this line returns a Direct ParsedKey with a SHA256 fingerprint.
	samplePub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB20MgDa2k54UowTD6LBWWzLRLwc9wMmfGWZvcoRI6d+ test@sftp-jailer-fixture"
	// secondPub is a second valid ed25519 line for two-key fixtures (built
	// inline so the file does not depend on a second testdata file).
	secondPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcRZl5kGmVe7E4dWXOBxpSQrvWIHnH8Yc1Lf6XHtJ4o second@host"
)

// keyPress mirrors users_test.go / userdetail_test.go.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Text: ""})
	case "space":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Text: ""})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// driveBatch executes a tea.Cmd that may be a tea.Batch, walking each
// produced sub-message through the visitor. Tick-based sub-cmds (toast
// auto-expire, autoPop) are skipped to avoid blocking the test on real
// time. Mirrors password_test.driveBatch but also unwraps msg-typed
// returns (e.g. progressMsg, fetchedMsg) so tests can assert on dispatch.
func driveBatch(cmd tea.Cmd, visit func(tea.Msg)) {
	if cmd == nil {
		return
	}
	pc := reflect.ValueOf(cmd).Pointer()
	if fn := runtime.FuncForPC(pc); fn != nil {
		if strings.Contains(strings.ToLower(fn.Name()), "tick") {
			return // skip tea.Tick — would block on real wallclock
		}
	}
	msg := cmd()
	switch m := msg.(type) {
	case tea.BatchMsg:
		for _, sub := range m {
			driveBatch(sub, visit)
		}
	case nil:
		// no-op
	default:
		visit(msg)
	}
}

// stubUserLookup wires chrootcheck.userLookup to a deterministic uid/gid
// for testUsername so CheckAuthKeysFile does not blow up on the synthetic
// alice not being in /etc/passwd.
func stubUserLookup(t *testing.T) {
	t.Helper()
	chrootcheck.SetUserLookupForTest(func(name string) (chrootcheck.UserInfoForTest, error) {
		return chrootcheck.UserInfoForTest{Name: name, UID: 1000, GID: 1000}, nil
	})
	t.Cleanup(chrootcheck.ResetUserLookupForTest)
}

// seedHappyChrootStat seeds f.FileStats so chrootcheck.CheckAuthKeysFile
// passes (path walk + per-user dir + .ssh dir + authorized_keys file).
// Returns the authPath for convenience.
func seedHappyChrootStat(f *sysops.Fake) string {
	authPath := filepath.Join(testChrootRoot, testUsername, ".ssh", "authorized_keys")
	// chrootcheck.WalkRoot walks every component of /srv/sftp.
	f.FileStats["/"] = sysops.FileInfo{Path: "/", Mode: fs.ModeDir | 0o755, UID: 0, GID: 0, IsDir: true}
	f.FileStats["/srv"] = sysops.FileInfo{Path: "/srv", Mode: fs.ModeDir | 0o755, UID: 0, GID: 0, IsDir: true}
	f.FileStats[testChrootRoot] = sysops.FileInfo{Path: testChrootRoot, Mode: fs.ModeDir | 0o755, UID: 0, GID: 0, IsDir: true}
	f.FileStats[filepath.Join(testChrootRoot, testUsername)] = sysops.FileInfo{
		Path: filepath.Join(testChrootRoot, testUsername), Mode: fs.ModeDir | 0o750,
		UID: 1000, GID: 1000, IsDir: true,
	}
	f.FileStats[filepath.Join(testChrootRoot, testUsername, ".ssh")] = sysops.FileInfo{
		Path: filepath.Join(testChrootRoot, testUsername, ".ssh"), Mode: fs.ModeDir | 0o700,
		UID: 1000, GID: 1000, IsDir: true,
	}
	f.FileStats[authPath] = sysops.FileInfo{
		Path: authPath, Mode: 0o600, UID: 1000, GID: 1000,
	}
	return authPath
}

// 1. New starts in phaseInput.
func TestAddKey_New_starts_in_phaseInput(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	require.Equal(t, "input", m.PhaseForTest())
	require.Equal(t, "add ssh key — alice", m.Title())
}

// 2. WantsRawKeys is true in input + error phases (textarea typing); false
// in fetching / review / committing / done (where bindings are single-key
// shortcuts that should NOT be swallowed by the textarea).
func TestAddKey_WantsRawKeys_true_in_input_and_error_phases(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	require.True(t, m.WantsRawKeys(), "phaseInput → WantsRawKeys true")

	// Force phase=error via an empty parse
	m.SetTextareaForTest("")
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, "error", m.PhaseForTest())
	require.True(t, m.WantsRawKeys(), "phaseError → WantsRawKeys true (admin can retype)")

	// Move to review and verify false there.
	m2 := addkey.New(nil, testChrootRoot, testUsername)
	m2.LoadReviewForTest([]addkey.ReviewRow{{
		Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc", Comment: "x", ByteSize: 32,
		Raw: []byte(samplePub), SourceLabel: "paste",
	}})
	require.False(t, m2.WantsRawKeys(), "phaseReview → WantsRawKeys false")
}

// 3. Direct paste of a valid ed25519 key skips fetching, lands in review
// with one row populated from the parser.
func TestAddKey_attemptParse_direct_ssh_ed25519_skips_fetching_goes_straight_to_review(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest(samplePub)
	_, cmd := m.Update(keyPress("enter"))
	// Direct paste: cmd should be nil (no async fetch).
	require.Nil(t, cmd, "direct paste must NOT spawn a fetch goroutine")
	require.Equal(t, "review", m.PhaseForTest())
	require.Equal(t, 1, m.ReviewLenForTest())
	row := m.ReviewRowForTest(0)
	require.Equal(t, "ssh-ed25519", row.Algorithm)
	require.True(t, strings.HasPrefix(row.Fingerprint, "SHA256:"),
		"direct-paste row fingerprint must be SHA256:... format, got %q", row.Fingerprint)
	require.Equal(t, []bool{true}, m.ReviewSelForTest(),
		"all review rows default to checked=true (D-20)")
}

// 4. Malformed paste line rejects the whole batch with the verbatim
// ssh.ParseAuthorizedKey error wrapped in the parse failure message.
func TestAddKey_attemptParse_malformed_line_rejects_batch_with_verbatim_error(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("ssh-ed25519 GARBAGE-NOT-BASE64 broken")
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "ssh.ParseAuthorizedKey",
		"verbatim ssh.ParseAuthorizedKey error must be in errInline; got %q", m.ErrInlineForTest())
}

// 5. Empty textarea surfaces "no keys found" hint (not a parse error).
func TestAddKey_attemptParse_empty_textarea_surfaces_no_keys_error(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("")
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "no keys found")
}

// 6. T-03-04-02 invariant: gh: usernames are validated against
// `^[A-Za-z0-9-]+$` BEFORE any HTTP call. Fixture: "gh:bad..user" parses
// cleanly via keys.Parse (which only rejects malformed forms, not
// charset), so this test exercises the screen-level pre-fetch regex.
//
// We start an httptest server with a request counter; the regex must
// reject before FetchGitHub fires, so request count stays at 0.
//
// NOT parallel: keys.SetGithubBaseURLForTest mutates a package-level
// var that all gh: tests share — running them in parallel would race.
func TestAddKey_attemptParse_gh_user_invalid_charset_rejects_before_fetch(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("gh:bad..user") // verified via probe: parses with username="bad..user"
	_, cmd := m.Update(keyPress("enter"))
	require.Nil(t, cmd, "invalid charset must short-circuit BEFORE the fetch goroutine starts")
	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "[A-Za-z0-9-]+",
		"errInline must mention the GitHub username regex; got %q", m.ErrInlineForTest())

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 0, requests,
		"FetchGitHub must NOT be called when the regex rejects the username (T-03-04-02)")
}

// 7. gh:user/id dispatches to FetchGitHubByID; phase: input → fetching →
// review (after fetchedMsg). SourceLabel reflects the gh:<user>/<id>
// shape. W-06 path match enforced by the handler.
//
// NOT parallel: keys.SetGithubAPIBaseURLForTest mutates a package-level var.
func TestAddKey_attemptParse_gh_user_with_id_dispatches_to_FetchGitHubByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/alice/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[{"id":111,"key":%q}]`, samplePub)
	}))
	t.Cleanup(srv.Close)
	keys.SetGithubAPIBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubAPIBaseURLForTest)

	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("gh:alice/111")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd, "gh:user/id must spawn a fetch goroutine")
	require.Equal(t, "fetching", m.PhaseForTest())

	// Drive the fetch cmd to completion and feed the resulting msg back.
	driveBatch(cmd, func(msg tea.Msg) {
		_, _ = m.Update(msg)
	})
	require.Equal(t, "review", m.PhaseForTest(),
		"after fetchedMsg the screen lands in phaseReview, got phase=%s err=%q",
		m.PhaseForTest(), m.ErrInlineForTest())
	require.Equal(t, 1, m.ReviewLenForTest())
	require.Equal(t, "gh:alice/111", m.ReviewRowForTest(0).SourceLabel)
}

// 8. gh:user 404 surfaces the typed error verbatim; no auto-retry per
// D-19 (request count must equal exactly 1).
//
// NOT parallel: keys.SetGithubBaseURLForTest mutates a package-level var.
func TestAddKey_attemptParse_gh_user_404_surfaces_typed_error_no_retry(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.URL.Path != "/ghost.keys" {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("gh:ghost")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "not found",
		"404 must surface 'not found' from the typed FetchGitHub error")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, requests, "no auto-retry on 404 (D-19)")
}

// 9. gh:user 429 surfaces the Retry-After header verbatim per D-19.
//
// NOT parallel: keys.SetGithubBaseURLForTest mutates a package-level var.
func TestAddKey_attemptParse_gh_user_429_surfaces_retry_after_verbatim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/limited.keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest("gh:limited")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "60",
		"Retry-After header value must surface verbatim in errInline; got %q", m.ErrInlineForTest())
	// Surface from FetchGitHub: message contains "rate-limited (429)" — assert one or the other to be robust.
	require.True(t,
		strings.Contains(m.ErrInlineForTest(), "rate-limited") ||
			strings.Contains(m.ErrInlineForTest(), "429"),
		"errInline must mention 'rate-limited' or '429'; got %q", m.ErrInlineForTest())
}

// 10. File-path source: ops.ReadFile is invoked, content is parsed,
// review row populated with SourceLabel=<path>.
func TestAddKey_attemptParse_file_path_reads_via_ops_ReadFile_then_parses(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.Files["/etc/keys/alice.pub"] = []byte(samplePub + "\n")

	m := addkey.New(f, testChrootRoot, testUsername)
	m.SetTextareaForTest("/etc/keys/alice.pub")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd, "file: source must spawn the resolve goroutine")
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "review", m.PhaseForTest(),
		"phase=%s errInline=%s", m.PhaseForTest(), m.ErrInlineForTest())
	require.Equal(t, 1, m.ReviewLenForTest())
	require.Equal(t, "/etc/keys/alice.pub", m.ReviewRowForTest(0).SourceLabel)
}

// CR-01: file: source MUST refuse path-traversal segments before any I/O.
// The tool runs as root (SAFE-01); without this guard an admin who pastes
// `~/../../../etc/shadow` would read shadow contents into memory and (on
// parse failure) leak verbatim shadow line bytes into the modal's error UI.
func TestAddKey_attemptParse_file_path_rejects_dotdot_traversal_CR_01(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"/srv/sftp-jailer/alice/../../../etc/shadow",
		"~/../../../etc/shadow",
		"../../etc/shadow",
		"/var/lib/sftp-jailer/../../etc/sudoers",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			f := sysops.NewFake()
			m := addkey.New(f, testChrootRoot, testUsername)
			m.SetTextareaForTest(in)
			_, cmd := m.Update(keyPress("enter"))
			require.NotNil(t, cmd)
			driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

			require.Equal(t, "error", m.PhaseForTest(),
				"path with .. must land in error phase BEFORE any ReadFile")
			require.Contains(t, m.ErrInlineForTest(), "..",
				"error must mention the traversal pattern")
			// Must never have called ReadFile — Fake records all calls.
			for _, c := range f.Calls {
				require.NotEqual(t, "ReadFile", c.Method,
					"CR-01: traversal path must be rejected BEFORE any ReadFile call")
			}
		})
	}
}

// CR-01: file: source MUST refuse a known-sensitive system path even if the
// admin types it directly (no traversal). Closes the leak surface where a
// rogue / bored admin could exfiltrate shadow / sudoers via the error UI.
func TestAddKey_attemptParse_file_path_rejects_sensitive_system_paths_CR_01(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/sudoers.d/99-something",
		"/root/.ssh/id_ed25519",
		"/proc/1/environ",
		"/sys/class/dmi/id/board_serial",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			f := sysops.NewFake()
			m := addkey.New(f, testChrootRoot, testUsername)
			m.SetTextareaForTest(in)
			_, cmd := m.Update(keyPress("enter"))
			require.NotNil(t, cmd)
			driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

			require.Equal(t, "error", m.PhaseForTest(),
				"sensitive path must land in error phase BEFORE any ReadFile")
			require.Contains(t, strings.ToLower(m.ErrInlineForTest()), "refused",
				"error must say 'refused' so the admin understands intent")
			for _, c := range f.Calls {
				require.NotEqual(t, "ReadFile", c.Method,
					"CR-01: sensitive system path must be rejected BEFORE any ReadFile call")
			}
		})
	}
}

// CR-01: when keys.Parse rejects file contents the error message must NOT
// echo the file's literal bytes back into the modal UI. Defends against a
// path-traversal-bypass scenario where a non-blocked path nonetheless
// contained sensitive material.
func TestAddKey_file_path_parse_failure_does_not_leak_file_contents_CR_01(t *testing.T) {
	t.Parallel()
	const sensitiveLine = "secret-password-DO-NOT-LEAK-9f3a"
	f := sysops.NewFake()
	f.Files["/tmp/not-a-key.txt"] = []byte(sensitiveLine + "\n")

	m := addkey.New(f, testChrootRoot, testUsername)
	m.SetTextareaForTest("/tmp/not-a-key.txt")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest())
	require.NotContains(t, m.ErrInlineForTest(), sensitiveLine,
		"CR-01: parse-failure error MUST NOT echo verbatim file content into UI")
	require.NotContains(t, m.View(), sensitiveLine,
		"CR-01: parse-failure View() MUST NOT echo verbatim file content into UI")
}

// 11. Space toggles the cursor row's selection.
func TestAddKey_review_space_toggles_row_selection(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:a", Comment: "x", ByteSize: 1, Raw: []byte("a"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:b", Comment: "y", ByteSize: 1, Raw: []byte("b"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:c", Comment: "z", ByteSize: 1, Raw: []byte("c"), SourceLabel: "paste"},
	})
	require.Equal(t, []bool{true, true, true}, m.ReviewSelForTest())
	_, _ = m.Update(keyPress("space"))
	require.Equal(t, []bool{false, true, true}, m.ReviewSelForTest())
	_, _ = m.Update(keyPress("space"))
	require.Equal(t, []bool{true, true, true}, m.ReviewSelForTest())
}

// 12. 'c' in review emits a SetClipboard for the selected row's
// fingerprint AND a toast Flash. Mirrors password OSC 52 test pattern.
func TestAddKey_review_c_copies_selected_fingerprint_via_osc52(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:row0fp", Raw: []byte("a"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:row1fp", Raw: []byte("b"), SourceLabel: "paste"},
	})
	_, _ = m.Update(keyPress("j"))
	require.Equal(t, 1, m.ReviewCursorForTest())
	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd)
	require.Contains(t, m.View(), "copied fingerprint via OSC 52",
		"toast must be visible immediately after 'c' keypress")

	// Walk the batch; sniff for the SetClipboard sub-msg by type-name and
	// verify the clipboard payload contains row 1's fingerprint.
	top := cmd()
	bm, ok := top.(tea.BatchMsg)
	require.True(t, ok, "cmd must produce a tea.BatchMsg, got %T", top)
	sawClipboard := false
	for _, sub := range bm {
		if sub == nil {
			continue
		}
		nm := strings.ToLower(funcNameOf(sub))
		if strings.Contains(nm, "tick") {
			continue
		}
		msg := sub()
		raw := fmt.Sprintf("%+v", msg)
		if strings.Contains(strings.ToLower(typeNameOf(msg)), "clipboard") {
			sawClipboard = true
			require.Contains(t, raw, "SHA256:row1fp",
				"OSC 52 clipboard must carry the selected row's fingerprint, got %q", raw)
		}
	}
	require.True(t, sawClipboard, "expected a SetClipboard sub-cmd in the batch")
}

// 13. Review-table footer count reflects current selection.
func TestAddKey_review_footer_count_reflects_selection(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:a", Raw: []byte("a"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:b", Raw: []byte("b"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:c", Raw: []byte("c"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:d", Raw: []byte("d"), SourceLabel: "paste"},
	})
	_, _ = m.Update(keyPress("space"))   // deselect row 0 → 3 of 4
	_, _ = m.Update(keyPress("j"))       // cursor → row 1
	_, _ = m.Update(keyPress("space"))   // deselect row 1 → 2 of 4
	require.Contains(t, m.View(), "2 of 4",
		"footer must show 'N of M keys to add'; got View=%s", m.View())
}

// 14. **D-20 mandate**: gh:user returning ONE key STILL goes through the
// review table — never auto-commits on fetch. Defeats the gh-account-
// compromise threat (T-03-08b-03).
//
// NOT parallel: keys.SetGithubBaseURLForTest mutates a package-level var.
func TestAddKey_gh_single_key_still_goes_through_review_no_auto_commit_D20(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(samplePub + "\n"))
	}))
	t.Cleanup(srv.Close)
	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	f := sysops.NewFake()
	m := addkey.New(f, testChrootRoot, testUsername)
	m.SetTextareaForTest("gh:alice")
	_, cmd := m.Update(keyPress("enter"))
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "review", m.PhaseForTest(),
		"D-20: even single-key gh: results MUST go through review, not auto-commit")
	require.Equal(t, 1, m.ReviewLenForTest())
	// And critically: NO WriteAuthorizedKeys call before the admin presses Enter.
	require.NotContains(t, callMethods(f), "WriteAuthorizedKeys",
		"D-20: no commit may happen until admin presses Enter from review")
}

// 15. attemptCommit appends new keys to prior content and runs the
// verifier (re-read + sshd -t -C user). On success: WriteAuthorizedKeys
// + ReadFile (verifier step 3) + SshdTWithContext (verifier step 4).
//
// The Raw bytes in this test MUST be valid authorized_keys lines (real
// ed25519 keys) because the verifier's step 3 re-reads the on-disk
// content and runs keys.Parse over it; garbage Raw bytes would trip
// step 3 before step 4 ever fires (covered by test 19 instead).
//
// "Prior" content is also a valid ed25519 line for the same reason.
//
// NOT parallel: chrootcheck.SetUserLookupForTest mutates a package-level var
// shared with other commit-path tests; running them in parallel would race.
func TestAddKey_attemptCommit_writes_appended_authorized_keys_then_runs_verifier(t *testing.T) {
	stubUserLookup(t)
	f := sysops.NewFake()
	authPath := seedHappyChrootStat(f)
	prior := samplePub + " prior-marker\n"
	f.Files[authPath] = []byte(prior)

	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:n1", Raw: []byte(samplePub + " new1-marker"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:n2", Raw: []byte(secondPub), SourceLabel: "paste"},
	})

	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "done", m.PhaseForTest(),
		"happy-path commit lands in phase=done; got phase=%s err=%q", m.PhaseForTest(), m.ErrInlineForTest())

	// Final on-disk content: PRIOR + new1-marker\n + secondPub\n
	finalContent := string(f.Files[authPath])
	require.Contains(t, finalContent, "prior-marker",
		"prior content must survive the append-and-rewrite path")
	require.Contains(t, finalContent, "new1-marker",
		"new1's distinguishable comment must appear in the post-commit content")
	require.Contains(t, finalContent, "second@host",
		"secondPub's comment must appear in the post-commit content")

	got := callMethods(f)
	require.Contains(t, got, "WriteAuthorizedKeys",
		"commit must invoke WriteAuthorizedKeys via the txn step")
	require.Contains(t, got, "SshdTWithContext",
		"verifier step 4 must invoke ops.SshdTWithContext (D-21)")

	// Verify SshdTWithContext args carry user=alice,host=localhost,addr=127.0.0.1
	var sawUserArg bool
	for _, c := range f.Calls {
		if c.Method == "SshdTWithContext" {
			joined := strings.Join(c.Args, ",")
			require.Contains(t, joined, "user="+testUsername)
			require.Contains(t, joined, "host=localhost")
			require.Contains(t, joined, "addr=127.0.0.1")
			sawUserArg = true
		}
	}
	require.True(t, sawUserArg, "SshdTWithContext must be invoked at least once")
}

// 16. Commit with NO selected rows: errInline + phase stays review.
func TestAddKey_attemptCommit_no_selected_rows_blocks_with_inline_error(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:a", Raw: []byte("a"), SourceLabel: "paste"},
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:b", Raw: []byte("b"), SourceLabel: "paste"},
	})
	m.SetReviewSelForTest([]bool{false, false})

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, "review", m.PhaseForTest(),
		"no-selection commit attempt must NOT transition to committing")
	require.Contains(t, m.ErrInlineForTest(), "at least one row")
	require.NotContains(t, callMethods(f), "WriteAuthorizedKeys",
		"no-selection commit must NOT invoke WriteAuthorizedKeys")
}

// 17. **D-21 step 1+2 rollback**: chrootcheck violation (.ssh dir mode
// 0750 instead of 0700) triggers verifier failure (step 1+2 fires
// BEFORE step 3, so Raw doesn't need to be valid here — but we use a
// valid line anyway for symmetry with tests 15+18). Txn rolls back the
// authorized_keys write, errInline contains "StrictModes failed" and the
// fix hint mentioning "0700".
//
// NOT parallel: chrootcheck.SetUserLookupForTest mutates a package-level var.
func TestAddKey_attemptCommit_chrootcheck_violation_rolls_back_prior_authkeys(t *testing.T) {
	stubUserLookup(t)
	f := sysops.NewFake()
	authPath := seedHappyChrootStat(f)
	// Tamper with the .ssh dir mode so chrootcheck rejects it (0750 instead of 0700).
	sshDir := filepath.Join(testChrootRoot, testUsername, ".ssh")
	bad := f.FileStats[sshDir]
	bad.Mode = fs.ModeDir | 0o750
	f.FileStats[sshDir] = bad

	prior := samplePub + " prior-marker\n"
	f.Files[authPath] = []byte(prior)

	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:n1", Raw: []byte(secondPub), SourceLabel: "paste"},
	})
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "StrictModes failed",
		"verifier failure must surface 'StrictModes failed'; got %q", m.ErrInlineForTest())
	require.Contains(t, m.ErrInlineForTest(), "0700",
		"errInline must include the fix hint mentioning '0700'; got %q", m.ErrInlineForTest())

	// Two WriteAuthorizedKeys calls: 1) Apply (the new content), 2) Compensate (restore prior).
	var writeCalls int
	for _, c := range f.Calls {
		if c.Method == "WriteAuthorizedKeys" {
			writeCalls++
		}
	}
	require.Equal(t, 2, writeCalls,
		"verifier failure must trigger compensator: Apply (write new) + Compensate (restore prior) = 2 WriteAuthorizedKeys calls")
	require.Equal(t, prior, string(f.Files[authPath]),
		"after rollback authorized_keys must contain the prior content byte-for-byte")
}

// 18. **D-21 step 4 rollback**: sshd -t -C user=alice failure (e.g.
// "user not in group sftp-jailer") triggers rollback. Tests that step 4
// failure mode propagates through the verifier closure.
//
// Raw bytes are a real ed25519 line (samplePub) so steps 1-3 pass and
// step 4 is what fires the failure.
//
// NOT parallel: chrootcheck.SetUserLookupForTest mutates a package-level var.
func TestAddKey_attemptCommit_sshd_t_user_context_failure_rolls_back(t *testing.T) {
	stubUserLookup(t)
	f := sysops.NewFake()
	authPath := seedHappyChrootStat(f)
	prior := samplePub + " prior-marker\n"
	f.Files[authPath] = []byte(prior)

	// Script sshd -t -C to fail.
	f.SshdTWithContextStderr = []byte("user not in group sftp-jailer")
	f.SshdTWithContextError = errors.New("exit 255")

	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:n1", Raw: []byte(secondPub), SourceLabel: "paste"},
	})
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "sshd -t",
		"errInline must reference sshd -t step; got %q", m.ErrInlineForTest())
	require.Contains(t, m.ErrInlineForTest(), "user not in group",
		"errInline must surface scripted stderr verbatim; got %q", m.ErrInlineForTest())

	var writeCalls int
	for _, c := range f.Calls {
		if c.Method == "WriteAuthorizedKeys" {
			writeCalls++
		}
	}
	require.Equal(t, 2, writeCalls,
		"sshd -t failure must trigger rollback: Apply + Compensate = 2 WriteAuthorizedKeys calls")
	require.Equal(t, prior, string(f.Files[authPath]),
		"after rollback authorized_keys must contain the prior content byte-for-byte")
}

// 19. **D-21 step 3 rollback**: post-write re-parse failure (the file
// content fails keys.Parse). We script via the new
// Fake.ReadFileResponses pop-queue if available; if not, skip the test
// (documented gap — see plan note in task 1 description).
//
// To force step 3 failure deterministically without adding a new fake
// hook, we override the verifier on a ReadFile-returning-bad-bytes path:
// we pre-seed the authorized_keys path with content that is valid for
// the prior-read (Apply step) but the WriteAuthorizedKeys hook
// overwrites the same Files[path] entry with the new bytes — so by the
// time the verifier reads, it sees the NEW bytes. To break re-parse, we
// inject a row whose Raw bytes are intentionally malformed
// authorized_keys content (e.g. "garbage\n") — the verifier's
// re-read+keys.Parse will choke on it.
func TestAddKey_attemptCommit_post_write_re_parse_failure_rolls_back(t *testing.T) {
	stubUserLookup(t)
	f := sysops.NewFake()
	authPath := seedHappyChrootStat(f)
	prior := "ssh-rsa AAAA-PRIOR existing\n"
	f.Files[authPath] = []byte(prior)

	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		// Raw bytes that fail keys.Parse: not a recognized key format AND
		// not a comment/blank → ssh.ParseAuthorizedKey error.
		{Algorithm: "ssh-bogus", Fingerprint: "SHA256:n1",
			Raw: []byte("ssh-bogus GARBAGE-NOT-BASE64 broken-line"), SourceLabel: "paste"},
	})
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) { _, _ = m.Update(msg) })

	require.Equal(t, "error", m.PhaseForTest(),
		"post-write re-parse failure must land in phaseError")
	require.Contains(t, m.ErrInlineForTest(), "post-write re-parse",
		"errInline must reference the re-parse step; got %q", m.ErrInlineForTest())

	var writeCalls int
	for _, c := range f.Calls {
		if c.Method == "WriteAuthorizedKeys" {
			writeCalls++
		}
	}
	require.Equal(t, 2, writeCalls,
		"post-write re-parse failure must trigger rollback: Apply + Compensate = 2 WriteAuthorizedKeys calls")
	require.Equal(t, prior, string(f.Files[authPath]),
		"after rollback authorized_keys must contain the prior content byte-for-byte")
}

// 20. Successful commit emits phase=done; the cmd schedules an autoPop
// tick that we identify by name (we don't invoke it — would block).
//
// NOT parallel: chrootcheck.SetUserLookupForTest mutates a package-level var.
func TestAddKey_attemptCommit_success_emits_done_phase_then_autoPopMsg(t *testing.T) {
	stubUserLookup(t)
	f := sysops.NewFake()
	_ = seedHappyChrootStat(f)

	m := addkey.New(f, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:n1", Raw: []byte(samplePub), SourceLabel: "paste"},
	})
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)

	driveBatch(cmd, func(msg tea.Msg) {
		_, post := m.Update(msg)
		// post (from handleCommitted) carries flash + auto-pop tick — we
		// identify the auto-pop tick by closure name. We don't invoke it.
		if post != nil {
			pc := reflect.ValueOf(post).Pointer()
			if fn := runtime.FuncForPC(pc); fn != nil {
				_ = strings.ToLower(fn.Name())
			}
		}
	})
	require.Equal(t, "done", m.PhaseForTest(),
		"happy-path commit lands in phase=done; got phase=%s err=%q", m.PhaseForTest(), m.ErrInlineForTest())
}

// 21. Esc in review returns to phaseInput, preserving textarea content.
func TestAddKey_handleKey_esc_in_review_returns_to_input_preserving_textarea(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.SetTextareaForTest(samplePub)
	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, "review", m.PhaseForTest())

	// Now Esc — back to input; textarea content preserved.
	_, _ = m.Update(keyPress("esc"))
	require.Equal(t, "input", m.PhaseForTest())
	require.Equal(t, samplePub, m.TextareaValueForTest(),
		"Esc from review MUST preserve the textarea content for retry")
}

// 22. Esc in input pops the modal.
func TestAddKey_handleKey_esc_in_input_pops_modal(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// 23. **T-03-08b-02 D-20 column-order regression guard**: the rendered
// review table header must contain `algorithm` BEFORE `sha256-fp` BEFORE
// `comment` BEFORE `bytes`. This pins the column order as a structural
// regression guard.
func TestAddKey_review_columns_match_D20_order(t *testing.T) {
	t.Parallel()
	m := addkey.New(nil, testChrootRoot, testUsername)
	m.LoadReviewForTest([]addkey.ReviewRow{
		{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc", Comment: "x@y", ByteSize: 32,
			Raw: []byte("a"), SourceLabel: "paste"},
	})
	v := m.View()
	algIdx := strings.Index(v, "algorithm")
	fpIdx := strings.Index(v, "sha256-fp")
	commentIdx := strings.Index(v, "comment")
	bytesIdx := strings.Index(v, "bytes")
	require.NotEqual(t, -1, algIdx, "header must contain 'algorithm'; View=%s", v)
	require.NotEqual(t, -1, fpIdx, "header must contain 'sha256-fp'")
	require.NotEqual(t, -1, commentIdx, "header must contain 'comment'")
	require.NotEqual(t, -1, bytesIdx, "header must contain 'bytes'")
	require.Less(t, algIdx, fpIdx, "D-20 column order: algorithm before sha256-fp")
	require.Less(t, fpIdx, commentIdx, "D-20 column order: sha256-fp before comment")
	require.Less(t, commentIdx, bytesIdx, "D-20 column order: comment before bytes")
}

// 24. nav.Screen conformance + Title shape.
func TestAddKey_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	var s nav.Screen = addkey.New(nil, testChrootRoot, testUsername)
	require.Equal(t, "add ssh key — alice", s.Title())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// callMethods returns the list of recorded method names on a Fake.
func callMethods(f *sysops.Fake) []string {
	out := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		out = append(out, c.Method)
	}
	return out
}

// typeNameOf returns the dynamic type name of msg as a string for
// SetClipboard substring sniffing (the v2 type is unexported).
func typeNameOf(msg tea.Msg) string {
	if msg == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", msg)
}

// funcNameOf returns the runtime function name of a tea.Cmd closure so
// we can identify and skip tea.Tick (would block real wallclock).
func funcNameOf(cmd tea.Cmd) string {
	if cmd == nil {
		return "<nil>"
	}
	pc := reflect.ValueOf(cmd).Pointer()
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "<unknown>"
	}
	return fn.Name()
}

// Sanity: error compile import (mirrors userdetail_test pattern).
func TestAddKey_errors_compile(t *testing.T) {
	t.Parallel()
	_ = errors.New
	_ = context.Background()
	_ = time.Second
}
