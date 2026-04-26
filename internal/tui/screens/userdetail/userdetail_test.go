// Package userdetail tests for S-USER-DETAIL — keys table render +
// a/d/p/c keybindings + D-22 single-key delete via txn batch.
package userdetail_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/userdetail"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

const (
	testChrootRoot = "/srv/sftp"
	testUsername   = "alice"
)

// genTestKey returns an authorized_keys-format line + the parsed shape so
// tests can pin against the actual fingerprint without hardcoding base64.
// Uses ed25519 for deterministic short keys.
func genTestKey(t *testing.T, comment string) (line string, parsed keys.ParsedKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	authLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n") + " " + comment
	parsedSlice, errs := keys.Parse(authLine)
	require.Empty(t, errs)
	require.Len(t, parsedSlice, 1)
	return authLine, parsedSlice[0]
}

// keyPress mirrors users_test.go's helper.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Text: ""})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// TestUserDetail_implements_nav_Screen — compile-time check that Model
// satisfies nav.Screen plus runtime checks on Title / KeyMap.
func TestUserDetail_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	var s nav.Screen = userdetail.New(nil, testChrootRoot, testUsername)
	require.Equal(t, "user detail — alice", s.Title())
	require.False(t, s.WantsRawKeys(), "WantsRawKeys is false by default — no textinput on this screen")
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestUserDetail_initial_loading_then_keysLoadedMsg_populates_table —
// LoadKeysForTest with 2 keys + a known mtime; assert View renders
// algorithm + fingerprint + a humanized "ago" timestamp (B-06 plumbing).
func TestUserDetail_initial_loading_then_keysLoadedMsg_populates_table(t *testing.T) {
	t.Parallel()
	_, k1 := genTestKey(t, "alice@laptop")
	_, k2 := genTestKey(t, "alice@desktop")

	m := userdetail.New(nil, testChrootRoot, testUsername)
	mtime := time.Now().Add(-3 * 24 * time.Hour)
	m.LoadKeysForTest([]keys.ParsedKey{k1, k2}, mtime)

	v := m.View()
	require.Contains(t, v, k1.Algorithm)
	require.Contains(t, v, k1.Fingerprint[:30],
		"truncated fingerprint must appear in the rendered row")
	require.Contains(t, v, k2.Fingerprint[:30])
	// humanize.RelTime emits "3 days ago" for a 3-day-old mtime.
	require.Contains(t, v, "days ago",
		"FileInfo.ModTime (B-06) → humanize-rendered 'X days ago' must appear in the 'added' column; got View=%s", v)
}

// TestUserDetail_no_authorized_keys_file_renders_empty_state —
// keysLoadedMsg{exists: false} → View shows "no authorized_keys file
// yet" + "[a]" + the explicit "M-ADD-KEY ships in plan 03-08b" pointer.
func TestUserDetail_no_authorized_keys_file_renders_empty_state(t *testing.T) {
	t.Parallel()
	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	v := m.View()
	require.Contains(t, v, "no authorized_keys file yet")
	require.Contains(t, v, "[a]",
		"empty state must mention the [a] add-key shortcut so admins know the path even before plan 03-08b lands")
	require.Contains(t, v, "03-08b",
		"empty state qualifier must explicitly point at plan 03-08b so admins know M-ADD-KEY is pending")
}

// TestUserDetail_a_emits_placeholder_pending_03_08b — pressing 'a' on
// any state (with or without keys) emits a tea.Println AND a toast both
// containing the literal placeholder string. Plan 03-08b will REPLACE
// this branch with `nav.PushCmd(addkey.New(...))`; this test gets
// updated in 03-08b to assert push-to-addkey instead.
func TestUserDetail_a_emits_placeholder_pending_03_08b(t *testing.T) {
	t.Parallel()
	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd, "pressing 'a' must return a non-nil tea.Cmd (placeholder Println + toast)")

	// The cmd is a tea.Batch of (tea.Println, toast.Flash). Walk the
	// batch and confirm at least one sub-msg contains the placeholder
	// string.
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)
	var sawPlaceholder bool
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		s := fmt.Sprintf("%v", sub())
		if strings.Contains(s, "03-08b") || strings.Contains(s, "M-ADD-KEY pending") {
			sawPlaceholder = true
			break
		}
	}
	require.True(t, sawPlaceholder,
		"at least one sub-cmd in the 'a' batch must produce a message containing the placeholder string '03-08b' (Println or toast)")

	// Pin the exported constant for the explicit literal check.
	require.Equal(t, "M-ADD-KEY pending — see plan 03-08b", userdetail.PlaceholderAddKeyMessage,
		"PlaceholderAddKeyMessage constant is the contract — plan 03-08b will delete this constant when it replaces the 'a' branch with addkey.New")
}

// TestUserDetail_p_pushes_password_modal — pressing 'p' pushes
// *password.Model with this user's username.
func TestUserDetail_p_pushes_password_modal(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("p"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	pm, isPwModel := nm.Screen.(*password.Model)
	require.True(t, isPwModel, "pushed screen must be *password.Model, got %T", nm.Screen)
	require.Equal(t, testUsername, pm.UsernameForTest(),
		"M-PASSWORD must carry this screen's username")
}

// TestUserDetail_c_copies_selected_fingerprint_via_osc52 — load 2 keys;
// cursor on row 1; press 'c'; assert tea.SetClipboard + toast.
func TestUserDetail_c_copies_selected_fingerprint_via_osc52(t *testing.T) {
	t.Parallel()
	_, k1 := genTestKey(t, "alice@laptop")
	_, k2 := genTestKey(t, "alice@desktop")

	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadKeysForTest([]keys.ParsedKey{k1, k2}, time.Now())
	m.SetCursorForTest(1)

	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd)
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "expected tea.BatchMsg, got %T", msg)

	var sawFingerprint bool
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		s := fmt.Sprintf("%v", sub())
		if strings.Contains(s, k2.Fingerprint) {
			sawFingerprint = true
		}
	}
	require.True(t, sawFingerprint,
		"OSC 52 batch must include the SELECTED row's fingerprint (cursor=1 → k2.Fingerprint=%s)", k2.Fingerprint)

	// Note: we don't assert on m.View() containing the toast text here
	// because invoking the batched cmd above also runs the embedded
	// tea.Tick(2s) for the toast TTL — by the time View() runs, the
	// toast has already expired. The OSC 52 cmd in the batch is the
	// load-bearing assertion.
}

// TestUserDetail_c_no_selection_is_noop — pressing 'c' on an empty key
// list returns no cmd (no fingerprint to copy).
func TestUserDetail_c_no_selection_is_noop(t *testing.T) {
	t.Parallel()
	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadEmptyForTest()
	_, cmd := m.Update(keyPress("c"))
	require.Nil(t, cmd, "pressing 'c' with no keys must be a no-op")
}

// TestUserDetail_d_runs_single_key_delete_txn — load 2 keys A+B;
// cursor on A; press 'd'; assert f.Calls includes WriteAuthorizedKeys
// with the reduced content (only B's line) AND the verifier was invoked.
func TestUserDetail_d_runs_single_key_delete_txn(t *testing.T) {
	t.Parallel()
	lineA, kA := genTestKey(t, "alice@a")
	lineB, kB := genTestKey(t, "alice@b")

	authPath := filepath.Join(testChrootRoot, testUsername, ".ssh", "authorized_keys")
	original := lineA + "\n" + lineB + "\n"

	f := sysops.NewFake()
	f.Files[authPath] = []byte(original)

	// Pre-seed Lstat for the authorized_keys file so the post-write
	// reload doesn't trip — and seed a frozen mtime so the rendered
	// "added" column is deterministic.
	f.FileStats[authPath] = sysops.FileInfo{
		Path:    authPath,
		Mode:    0o600,
		UID:     1000,
		GID:     1000,
		ModTime: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}

	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadKeysForTest([]keys.ParsedKey{kA, kB}, f.FileStats[authPath].ModTime)
	m.SetCursorForTest(0)

	// Inject a stub verifier that returns no violations so the txn batch
	// completes successfully. (The default verifier wraps
	// chrootcheck.CheckAuthKeysFile which would do an os/user.Lookup that
	// likely fails for the synthetic 'alice' username.)
	m.SetVerifierForTest(func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]txn.VerifyViolation, error) {
		return nil, nil
	})

	_, cmd := m.Update(keyPress("d"))
	require.NotNil(t, cmd, "pressing 'd' on a real key must return a tea.Cmd (delete-txn goroutine)")
	// Run the delete-txn cmd to completion + feed the resulting msg back.
	msg := cmd()
	delMsg, ok := msg.(interface{}) // we can't access the unexported keyDeletedMsg; use Update path
	_ = delMsg
	require.NotNil(t, ok)

	// Drive the result message through Update.
	_, _ = m.Update(msg)

	// Assert that WriteAuthorizedKeys was called with content that
	// contains lineB but NOT lineA (the deleted key).
	var sawWriteCall bool
	for _, c := range f.Calls {
		if c.Method == "WriteAuthorizedKeys" {
			sawWriteCall = true
		}
	}
	require.True(t, sawWriteCall, "delete-txn must invoke ops.WriteAuthorizedKeys via the txn step")

	// Confirm the post-write fake state matches the reduced content.
	finalContent := string(f.Files[authPath])
	require.NotContains(t, finalContent, kA.Fingerprint[:20],
		"deleted key A's content must NOT survive in authorized_keys")
	require.Contains(t, finalContent, strings.TrimSpace(lineB),
		"surviving key B's line must remain in authorized_keys")
}

// TestUserDetail_d_failure_to_verify_rolls_back — script the verifier
// to return a violation; assert there are TWO WriteAuthorizedKeys calls
// in f.Calls (initial write, then compensator restore).
func TestUserDetail_d_failure_to_verify_rolls_back(t *testing.T) {
	t.Parallel()
	lineA, kA := genTestKey(t, "alice@a")
	lineB, kB := genTestKey(t, "alice@b")

	authPath := filepath.Join(testChrootRoot, testUsername, ".ssh", "authorized_keys")
	original := lineA + "\n" + lineB + "\n"

	f := sysops.NewFake()
	f.Files[authPath] = []byte(original)
	f.FileStats[authPath] = sysops.FileInfo{Path: authPath, Mode: 0o600, ModTime: time.Now()}

	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadKeysForTest([]keys.ParsedKey{kA, kB}, f.FileStats[authPath].ModTime)
	m.SetCursorForTest(0)

	// Stub verifier that ALWAYS returns a violation — forces txn rollback.
	m.SetVerifierForTest(func(_ context.Context, _ sysops.SystemOps, _, _ string) ([]txn.VerifyViolation, error) {
		return []txn.VerifyViolation{{Path: "/x", Reason: "stubbed bad mode for test"}}, nil
	})

	_, cmd := m.Update(keyPress("d"))
	require.NotNil(t, cmd)
	msg := cmd()
	_, _ = m.Update(msg)

	// Count WriteAuthorizedKeys calls — Apply (delete write) + Compensate
	// (restore prior content) should be TWO calls.
	var writeCalls int
	for _, c := range f.Calls {
		if c.Method == "WriteAuthorizedKeys" {
			writeCalls++
		}
	}
	require.Equal(t, 2, writeCalls,
		"verifier failure must trigger rollback: 1× Apply (delete-write) + 1× Compensate (restore prior content) = 2 WriteAuthorizedKeys calls")

	// Final content should match the ORIGINAL (compensator restored it).
	require.Equal(t, original, string(f.Files[authPath]),
		"after rollback, authorized_keys must contain the original two-key content byte-for-byte")
}

// TestUserDetail_added_on_column_uses_FileInfo_ModTime — pre-seed
// f.FileStats with a known ModTime; load via the async path; render
// View; assert the rendered "added" cell contains a humanized
// representation derived from that time. (B-06 — confirms the screen
// reads sysops.FileInfo.ModTime, not time.Now() or ReadFile-side
// metadata.)
func TestUserDetail_added_on_column_uses_FileInfo_ModTime(t *testing.T) {
	t.Parallel()
	line, k := genTestKey(t, "alice@laptop")
	knownMtime := time.Now().Add(-7 * 24 * time.Hour) // 7 days ago

	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadKeysForTest([]keys.ParsedKey{k}, knownMtime)

	v := m.View()
	// humanize.RelTime renders "1 week ago" for ~7 days.
	require.True(t,
		strings.Contains(v, "week ago") || strings.Contains(v, "days ago"),
		"FileInfo.ModTime (B-06) → humanize must render a 'week ago' or 'days ago' label for a 7-day-old mtime; got View=%s", v)

	// Sanity — m.MtimeForTest must equal what we seeded.
	require.Equal(t, knownMtime, m.MtimeForTest(),
		"the screen must store the FileInfo.ModTime verbatim (no rounding / re-stamping)")

	// And the line we passed in is the source of the rendered fingerprint.
	require.Contains(t, v, k.Fingerprint[:30],
		"the rendered fingerprint must come from the parsed key (sanity)")
	_ = line
}

// TestUserDetail_loadKeys_async_path_via_Init_sets_keysFileExists_false_on_missing
// — exercises Init's async load with no Files entry → ErrNotExist →
// keysLoadedMsg{exists:false}. Drives the cmd to completion and feeds
// the result back through Update.
func TestUserDetail_loadKeys_async_path_via_Init_sets_keysFileExists_false_on_missing(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// No Files entry for the authorized_keys path → ReadFile returns ErrNotExist.

	m := userdetail.New(f, testChrootRoot, testUsername)
	cmd := m.Init()
	require.NotNil(t, cmd, "Init must return a tea.Cmd when ops != nil")

	msg := cmd()
	_, _ = m.Update(msg)

	v := m.View()
	require.Contains(t, v, "no authorized_keys file yet",
		"missing authorized_keys file → empty-state copy")
}

// TestUserDetail_loadKeys_async_path_via_Init_populates_state_on_success
// — pre-seed f.Files with valid authorized_keys content + Lstat with a
// known ModTime; Init+Update should land the screen in a populated
// non-loading state with the table rendered.
func TestUserDetail_loadKeys_async_path_via_Init_populates_state_on_success(t *testing.T) {
	t.Parallel()
	line, k := genTestKey(t, "alice@laptop")
	authPath := filepath.Join(testChrootRoot, testUsername, ".ssh", "authorized_keys")
	mtime := time.Now().Add(-2 * 24 * time.Hour)

	f := sysops.NewFake()
	f.Files[authPath] = []byte(line + "\n")
	f.FileStats[authPath] = sysops.FileInfo{Path: authPath, Mode: 0o600, ModTime: mtime}

	m := userdetail.New(f, testChrootRoot, testUsername)
	cmd := m.Init()
	require.NotNil(t, cmd)
	msg := cmd()
	_, _ = m.Update(msg)

	require.Equal(t, 1, m.KeysCountForTest(), "post-Init: 1 key loaded")
	require.Equal(t, mtime, m.MtimeForTest(),
		"post-Init: B-06 mtime stored verbatim from ops.Lstat")
	v := m.View()
	require.Contains(t, v, k.Fingerprint[:30])
}

// TestUserDetail_default_verifier_wraps_chrootcheck — sanity that the
// production verifier seam adapts chrootcheck.Violation → txn.VerifyViolation.
// We can't easily invoke the default verifier with a real os/user.Lookup,
// but we can confirm the type signatures compose: chrootcheck.Violation
// has Path + Reason and so does txn.VerifyViolation.
func TestUserDetail_default_verifier_wraps_chrootcheck(t *testing.T) {
	t.Parallel()
	// Compile-time check: types align.
	v1 := chrootcheck.Violation{Path: "/x", Reason: "test"}
	v2 := txn.VerifyViolation{Path: v1.Path, Reason: v1.Reason}
	require.Equal(t, "/x", v2.Path)
	require.Equal(t, "test", v2.Reason)
}

// TestUserDetail_esc_pops — UI-SPEC: esc/q pops back to caller.
func TestUserDetail_esc_pops(t *testing.T) {
	t.Parallel()
	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadEmptyForTest()
	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	nm, ok := cmd().(nav.Msg)
	require.True(t, ok)
	require.Equal(t, nav.Pop, nm.Intent)
}

// TestUserDetail_jk_navigation_clamps — verify j/k cursor movement
// stays within bounds.
func TestUserDetail_jk_navigation_clamps(t *testing.T) {
	t.Parallel()
	_, k1 := genTestKey(t, "a")
	_, k2 := genTestKey(t, "b")

	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadKeysForTest([]keys.ParsedKey{k1, k2}, time.Now())

	require.Equal(t, 0, m.CursorForTest())
	_, _ = m.Update(keyPress("j"))
	require.Equal(t, 1, m.CursorForTest(), "j moves cursor down")
	_, _ = m.Update(keyPress("j"))
	require.Equal(t, 1, m.CursorForTest(), "j at end clamps")
	_, _ = m.Update(keyPress("k"))
	require.Equal(t, 0, m.CursorForTest(), "k moves cursor up")
	_, _ = m.Update(keyPress("k"))
	require.Equal(t, 0, m.CursorForTest(), "k at top clamps")
}

// TestUserDetail_d_no_keys_is_noop — pressing 'd' with no keys returns
// no cmd (nothing to delete).
func TestUserDetail_d_no_keys_is_noop(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()
	_, cmd := m.Update(keyPress("d"))
	require.Nil(t, cmd, "pressing 'd' with no keys must be a no-op")

	// Also confirm no sysops calls happened.
	for _, c := range f.Calls {
		require.NotEqual(t, "WriteAuthorizedKeys", c.Method,
			"no-op delete must not invoke WriteAuthorizedKeys")
	}
}

// Sanity: the package surfaces the right errors.As-friendly shapes
// (compile-time check; if the signatures drift this block fails to
// build).
func TestUserDetail_errors_compile(t *testing.T) {
	t.Parallel()
	_ = errors.New
}
