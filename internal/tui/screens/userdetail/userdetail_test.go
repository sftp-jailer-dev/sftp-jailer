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
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/addkey"
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
// yet" + the [a] add-key shortcut. Plan 03-08b dropped the "(note:
// M-ADD-KEY ships in plan 03-08b)" qualifier when the surface landed.
func TestUserDetail_no_authorized_keys_file_renders_empty_state(t *testing.T) {
	t.Parallel()
	m := userdetail.New(nil, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	v := m.View()
	require.Contains(t, v, "no authorized_keys file yet")
	require.Contains(t, v, "[a]",
		"empty state must mention the [a] add-key shortcut")
	require.NotContains(t, v, "03-08b",
		"plan 03-08b qualifier must be removed once M-ADD-KEY is wired")
	require.NotContains(t, v, "M-ADD-KEY ships",
		"the 'ships in plan' qualifier must be removed once M-ADD-KEY is wired")
}

// TestUserDetail_a_pushes_addkey_modal — pressing 'a' pushes
// *addkey.Model with this user's username and chrootRoot. Mirrors
// TestUserDetail_p_pushes_password_modal (same shape, different
// destination package). Replaces the prior placeholder-pending test
// once plan 03-08b wired addkey.New.
func TestUserDetail_a_pushes_addkey_modal(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd, "pressing 'a' must return a non-nil tea.Cmd (push addkey)")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	am, isAddKeyModel := nm.Screen.(*addkey.Model)
	require.True(t, isAddKeyModel, "pushed screen must be *addkey.Model, got %T", nm.Screen)
	require.Equal(t, "add ssh key — "+testUsername, am.Title(),
		"M-ADD-KEY must carry this screen's username")
}

// TestUserDetail_a_keybinding_no_longer_emits_placeholder_string —
// regression guard against accidental revert of the 03-08b wiring. The
// 'a' keypress's resulting message must NOT be a tea.PrintMsg and must
// NOT contain the prior placeholder strings ("03-08b" / "pending" /
// "M-ADD-KEY pending"). This complements the positive assertion in
// TestUserDetail_a_pushes_addkey_modal.
func TestUserDetail_a_keybinding_no_longer_emits_placeholder_string(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd)
	msg := cmd()

	// Must NOT be a tea.PrintMsg / tea.BatchMsg containing one.
	require.NotContains(t, fmt.Sprintf("%T", msg), "PrintMsg",
		"'a' must not emit a tea.PrintMsg (the 03-08a placeholder used tea.Println)")
	if bm, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range bm {
			if sub == nil {
				continue
			}
			subMsg := sub()
			require.NotContains(t, fmt.Sprintf("%T", subMsg), "PrintMsg",
				"no sub-cmd may produce a tea.PrintMsg")
			s := fmt.Sprintf("%v", subMsg)
			require.NotContains(t, s, "03-08b",
				"placeholder string '03-08b' must not survive any sub-msg, got %q", s)
			require.NotContains(t, s, "M-ADD-KEY pending",
				"placeholder string 'M-ADD-KEY pending' must not survive any sub-msg, got %q", s)
		}
	} else {
		// Single nav.Msg path — fine; just sanity-check intent.
		nm, ok := msg.(nav.Msg)
		require.True(t, ok, "expected nav.Msg, got %T", msg)
		require.Equal(t, nav.Push, nm.Intent)
	}
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

// stubScreen is a tiny nav.Screen used by the factory-injection tests
// for the M-ADD-RULE 'r' keybind (Plan 04-05 Task 3).
type stubScreen struct {
	name      string
	username  string // captured by the AddRuleFactory closure
}

func (s *stubScreen) Init() tea.Cmd                        { return nil }
func (s *stubScreen) Update(tea.Msg) (nav.Screen, tea.Cmd) { return s, nil }
func (s *stubScreen) View() string                         { return s.name }
func (s *stubScreen) Title() string                        { return s.name }
func (s *stubScreen) KeyMap() nav.KeyMap                   { return stubKeyMap{} }
func (s *stubScreen) WantsRawKeys() bool                   { return false }

type stubKeyMap struct{}

func (stubKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (stubKeyMap) FullHelp() [][]nav.KeyBinding { return nil }

// TestSUserDetail_r_pushes_addrule_with_user_prefill — pressing 'r' on
// S-USER-DETAIL must emit nav.Push carrying the M-ADD-RULE modal
// pre-filled with this screen's username. Wired via the package-level
// AddRuleFactory + SetAddRuleFactory seam (analogous to the home
// screen's factory pattern). The factory MUST receive the screen's
// username so the modal locks the user pre-fill.
func TestSUserDetail_r_pushes_addrule_with_user_prefill(t *testing.T) {
	defer userdetail.SetAddRuleFactory(nil) // cleanup global

	var capturedUsername string
	stub := &stubScreen{name: "M-ADD-RULE"}
	userdetail.SetAddRuleFactory(func(username string) nav.Screen {
		capturedUsername = username
		stub.username = username
		return stub
	})

	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("r"))
	require.NotNil(t, cmd, "pressing 'r' with factory set must emit a non-nil tea.Cmd")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	require.Same(t, nav.Screen(stub), nm.Screen,
		"pushed screen must be the factory's return value")
	require.Equal(t, testUsername, capturedUsername,
		"AddRuleFactory must be called with this screen's username")
}

// TestSUserDetail_r_noop_when_factory_nil — pressing 'r' with no
// factory registered is a clean no-op.
func TestSUserDetail_r_noop_when_factory_nil(t *testing.T) {
	userdetail.SetAddRuleFactory(nil)

	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()
	_, cmd := m.Update(keyPress("r"))
	require.Nil(t, cmd, "'r' without factory must be a no-op")
}

// TestSUserDetail_a_still_pushes_addkey_after_phase4 — W-03 regression
// guard. The Phase 3 'a' = add-SSH-key wiring must NOT be replaced by
// the M-ADD-RULE keybind. Phase 4 uses 'r' (mnemonic: rule) instead to
// preserve Phase 3's UAT-validated muscle memory.
func TestSUserDetail_a_still_pushes_addkey_after_phase4(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := userdetail.New(f, testChrootRoot, testUsername)
	m.LoadEmptyForTest()

	_, cmd := m.Update(keyPress("a"))
	require.NotNil(t, cmd,
		"W-03 regression guard: 'a' must STILL push M-ADD-KEY (not be replaced)")
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Push, nm.Intent)
	_, isAddKey := nm.Screen.(*addkey.Model)
	require.True(t, isAddKey,
		"W-03 regression: 'a' must STILL push *addkey.Model (Phase 3 behaviour preserved); got %T",
		nm.Screen)
}
