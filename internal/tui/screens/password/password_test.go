// Package password tests for M-PASSWORD — covers the auto-gen + explicit
// flows, OSC 52 copy + Toast.Flash, pam_pwquality stderr surfacing,
// force-change checkbox + lockout warning, and (security invariant) the
// "password literal NEVER reaches FakeCall.Args" assertion.
package password_test

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
)

// keyPress is the standard bubbletea v2 KeyPressMsg builder helper used
// across the project's screen tests.
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
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// callMethods returns a flat list of method names recorded by the Fake.
func callMethods(f *sysops.Fake) []string {
	out := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		out = append(out, c.Method)
	}
	return out
}

// driveBatch executes a tea.Cmd that may be a tea.Batch and feeds each
// produced message into the visitor. Used to introspect the post-submit
// nav.Push + toast flash combo.
func driveBatch(cmd tea.Cmd, visit func(tea.Msg)) {
	if cmd == nil {
		return
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

// 1. Auto-gen mode lands in phaseShowing with a non-empty password.
func TestPassword_autogen_mode_initial_phase_shows_password(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("DETERMINISTIC-test-pw-24c!")
	require.Equal(t, password.PhaseShowingForTest, m.PhaseForTest())
	require.NotEmpty(t, m.PasswordForTest())
}

// 2. 'c' emits a tea.SetClipboard cmd + a toast Flash.
//
// We capture View BEFORE invoking cmd — Flash schedules a 2s tea.Tick
// that we don't want to block on. The toast text is set synchronously
// inside Update so View() shows it immediately.
//
// For the SetClipboard half: cmd() returns a tea.BatchMsg containing the
// SetClipboard sub-cmd + the toast Tick. We unpack the BatchMsg and call
// each sub-cmd — the SetClipboard cmd returns immediately with its
// (unexported in v2) setClipboardMsg, which we sniff via "%T". The
// toast Tick is the only one that would block; we identify it by its
// message type and skip without invoking.
func TestPassword_copy_via_osc52_emits_setClipboard_and_toast(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("test-pw-deterministic-24!")
	_, cmd := m.Update(keyPress("c"))
	require.NotNil(t, cmd)
	require.Contains(t, m.View(), "copied password via OSC 52",
		"toast must be visible immediately after the OSC 52 keypress")
	// Unpack the top-level BatchMsg without invoking the toast Tick.
	top := cmd()
	bm, ok := top.(tea.BatchMsg)
	require.True(t, ok, "top-level cmd must produce a tea.BatchMsg, got %T", top)
	sawClipboard := false
	for _, sub := range bm {
		if sub == nil {
			continue
		}
		// Identify cmds by their func pointer name. tea.Tick returns a
		// closure whose name contains "Tick"; tea.SetClipboard returns a
		// closure whose name contains "SetClipboard". We invoke only the
		// non-Tick sub-cmds so the test does not block.
		nm := strings.ToLower(funcNameOf(sub))
		if strings.Contains(nm, "tick") {
			continue
		}
		msg := sub()
		if strings.Contains(strings.ToLower(typeNameOf(msg)), "clipboard") {
			sawClipboard = true
		}
	}
	require.True(t, sawClipboard, "expected a SetClipboard sub-cmd in the batch")
}

// 3. 'r' regenerates — m.PasswordForTest() returns a different value.
func TestPassword_regenerate_replaces_pw_value(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	// Use a counter-based stub so each regenerate returns a distinct value.
	count := 0
	m.SetGenFnForTest(func(int) (string, error) {
		count++
		return fmt.Sprintf("pw-attempt-%d", count), nil
	})
	first := m.PasswordForTest()
	require.NotEmpty(t, first)
	_, _ = m.Update(keyPress("r"))
	second := m.PasswordForTest()
	require.NotEmpty(t, second)
	require.NotEqual(t, first, second, "regenerate must produce a distinct password value")
}

// 4. Force-change checkbox defaults OFF (D-13 / pitfall 2 mitigation).
func TestPassword_force_change_default_off(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("any-pw")
	require.False(t, m.ForceChangeForTest(),
		"force-change-next-login MUST default OFF — chrooted SFTP users have no shell to host the change-password prompt")
}

// 5. Space toggles the checkbox.
func TestPassword_force_change_toggle_via_space(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("any-pw")
	require.False(t, m.ForceChangeForTest())
	_, _ = m.Update(keyPress("space"))
	require.True(t, m.ForceChangeForTest(), "space must flip the force-change checkbox")
}

// 6. Submit with force-change OFF: only Chpasswd called (no Chage).
func TestPassword_submit_calls_chpasswd_only_when_force_off(t *testing.T) {
	f := sysops.NewFake()
	m := password.New(f, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("strong-pw-12345!")
	// Drive the submit cmd so the txn closure runs against the Fake.
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	require.Contains(t, got, "Chpasswd")
	require.NotContains(t, got, "Chage", "force-change OFF must NOT call Chage")
}

// 7. Submit with force-change ON: Chpasswd then Chage.
func TestPassword_submit_calls_chpasswd_then_chage_when_force_on(t *testing.T) {
	f := sysops.NewFake()
	m := password.New(f, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("strong-pw-12345!")
	_, _ = m.Update(keyPress("space")) // toggle force-change ON
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	require.Equal(t, []string{"Chpasswd", "Chage"}, got,
		"force-change ON must call Chpasswd then Chage in order")
}

// 8. pam_pwquality rejection: stderr surfaces inline as Critical errInline.
func TestPassword_submit_pamPwquality_rejection_surfaces_stderr_inline(t *testing.T) {
	f := sysops.NewFake()
	f.ChpasswdError = errors.New("exit status 1")
	f.ChpasswdStderr = []byte("BAD PASSWORD: too short")
	m := password.New(f, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("weak")
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(msg tea.Msg) {
		// Feed the submit-done back through Update so phaseError lands.
		_, _ = m.Update(msg)
	})
	require.Equal(t, password.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "BAD PASSWORD",
		"pam_pwquality stderr must be surfaced inline (B5) — got %q", m.ErrInlineForTest())
	require.Contains(t, m.ErrInlineForTest(), "pam_pwquality")
}

// 9. View includes the chrooted-SFTP lockout warning when force-change
// is checked (pitfall 2 / RH solution 24758).
func TestPassword_view_includes_chrootSFTP_lockout_warning_when_force_change_checked(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("any-pw")
	_, _ = m.Update(keyPress("space"))
	v := m.View()
	require.Contains(t, v, "lock them out", "lockout warning must mention 'lock them out'")
	require.Contains(t, v, "OOB reset", "lockout warning must mention 'OOB reset' workflow")
}

// 10. Hygiene: m.pw cleared after successful submit.
func TestPassword_pw_cleared_after_successful_submit(t *testing.T) {
	m := password.New(nil, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest("strong-pw-12345!")
	require.NotEmpty(t, m.PasswordForTest())
	_, _ = m.FeedSubmitDoneForTest(nil)
	require.Empty(t, m.PasswordForTest(),
		"password literal MUST be cleared from m.pw after successful submit (T-03-07-02)")
}

// 11. Explicit mode: validates match BEFORE submit; mismatch keeps the
// model in phaseExplicit with errInline; NO Chpasswd call.
func TestPassword_explicit_mode_validates_match_before_submit(t *testing.T) {
	f := sysops.NewFake()
	m := password.New(f, "alice", password.ExplicitMode)
	require.Equal(t, password.PhaseExplicitForTest, m.PhaseForTest())
	// Type "abc12345" into the password textinput.
	for _, r := range "abc12345" {
		_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
	}
	// Tab to confirm field, type a different value.
	_, _ = m.Update(keyPress("tab"))
	for _, r := range "abc12399" {
		_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
	}
	// Submit — should be blocked by the validation gate.
	_, _ = m.Update(keyPress("enter"))
	require.Contains(t, m.ErrInlineForTest(), "do not match")
	require.Equal(t, password.PhaseExplicitForTest, m.PhaseForTest(),
		"mismatch must keep the model in phaseExplicit (no transition to submitting)")
	require.NotContains(t, callMethods(f), "Chpasswd",
		"mismatch must NOT trigger any Chpasswd call")
}

// 12. SECURITY INVARIANT: password literal NEVER appears in any
// FakeCall.Args entry. Plan 03-01's Fake.Chpasswd records "len=N" only.
func TestPassword_NEVER_records_password_literal_in_FakeCalls(t *testing.T) {
	f := sysops.NewFake()
	pwLiteral := "testSecret123!"
	m := password.New(f, "alice", password.AutoGenerateMode)
	m.LoadPasswordForTest(pwLiteral)
	_, cmd := m.Update(keyPress("enter"))
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	for _, c := range f.Calls {
		for _, arg := range c.Args {
			require.NotContains(t, arg, pwLiteral,
				"password literal must NEVER appear in FakeCall.Args (T-03-01 / E3 / T-03-07-01) — found in %s args=%v",
				c.Method, c.Args)
		}
	}
	// Sanity: the Chpasswd call DID happen — not a vacuous-pass via "no
	// calls were made".
	require.Contains(t, callMethods(f), "Chpasswd",
		"sanity: Chpasswd MUST have been called for the security invariant to be meaningful")
}

// nav.Screen compile-time conformance.
func TestPassword_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = password.New(nil, "alice", password.AutoGenerateMode)
	require.Equal(t, "set password — alice", s.Title())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// typeNameOf returns the dynamic type name of msg as a string for the
// SetClipboard substring check (the tea.SetClipboard message type is
// unexported in bubbletea v2).
func typeNameOf(msg tea.Msg) string {
	if msg == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", msg)
}

// funcNameOf returns the runtime function name of a tea.Cmd closure so we
// can identify tea.Tick (would block 2s) vs tea.SetClipboard (returns
// immediately). The runtime exposes the underlying closure source via
// reflect+runtime.FuncForPC; closures created inside tea.Tick / tea.Batch
// /etc. have predictable name segments ("Tick", "SetClipboard").
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
