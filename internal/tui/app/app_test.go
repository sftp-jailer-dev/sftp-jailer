package app_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/tuitest"
)

// testScreen is a minimal nav.Screen used to drive the App under test.
// It records the last message seen and optionally panics on next Update.
type testScreen struct {
	name         string
	wantsRawKeys bool
	lastMsg      tea.Msg
	msgCount     int
	lastSize     tea.WindowSizeMsg
	panicOnNext  bool
	// emitOnInit is an optional tea.Cmd returned from Init(); useful for
	// driving nav intents into the App from a test screen.
	emitOnInit tea.Cmd
}

func (s *testScreen) Init() tea.Cmd { return s.emitOnInit }
func (s *testScreen) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	if s.panicOnNext {
		s.panicOnNext = false
		panic("boom")
	}
	s.msgCount++
	s.lastMsg = msg
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		s.lastSize = ws
	}
	return s, nil
}
func (s *testScreen) View() string      { return "test:" + s.name }
func (s *testScreen) Title() string     { return s.name }
func (s *testScreen) KeyMap() nav.KeyMap { return emptyKeyMap{} }
func (s *testScreen) WantsRawKeys() bool { return s.wantsRawKeys }

type emptyKeyMap struct{}

func (emptyKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKeyMap) FullHelp() [][]nav.KeyBinding { return [][]nav.KeyBinding{{{Keys: []string{"q"}, Help: "quit"}}} }

// keyPress constructs a tea.KeyPressMsg for a simple printable rune.
func keyPress(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)})
}

// ctrlC constructs the ctrl+c keypress.
func ctrlC() tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})
}

func TestApp_NavPushPop(t *testing.T) {
	tuitest.ResetResolvers(t)
	first := &testScreen{name: "first"}
	a := app.New("v", "u", first)
	require.Equal(t, 1, a.StackLen())

	// Emit Push
	_, _ = a.Update(nav.Msg{Intent: nav.Push, Screen: &testScreen{name: "second"}})
	require.Equal(t, 2, a.StackLen())
	require.Equal(t, "second", a.TopTitle())

	// Emit Pop
	_, _ = a.Update(nav.Msg{Intent: nav.Pop})
	require.Equal(t, 1, a.StackLen())
	require.Equal(t, "first", a.TopTitle())

	// Pop on single-element stack is safe (goes to 0).
	_, _ = a.Update(nav.Msg{Intent: nav.Pop})
	require.Equal(t, 0, a.StackLen())

	// Pop on empty stack is safe (stays 0).
	_, _ = a.Update(nav.Msg{Intent: nav.Pop})
	require.Equal(t, 0, a.StackLen())
}

func TestApp_NavReplaceOnEmpty(t *testing.T) {
	tuitest.ResetResolvers(t)
	a := app.New("v", "u")
	require.Equal(t, 0, a.StackLen())
	_, _ = a.Update(nav.Msg{Intent: nav.Replace, Screen: &testScreen{name: "only"}})
	require.Equal(t, 1, a.StackLen())
	require.Equal(t, "only", a.TopTitle())
}

func TestApp_NavReplaceMsgFactoryResolution(t *testing.T) {
	tuitest.ResetResolvers(t)
	a := app.New("v", "u", &testScreen{name: "first"})
	called := 0
	replacement := &testScreen{name: "factory-made"}
	_, _ = a.Update(nav.ReplaceMsg{Factory: func() nav.Screen {
		called++
		return replacement
	}})
	require.Equal(t, 1, called, "factory must be called exactly once")
	require.Equal(t, 1, a.StackLen())
	require.Equal(t, "factory-made", a.TopTitle())
}

func TestApp_PlaceholderResolverFires(t *testing.T) {
	tuitest.ResetResolvers(t)
	resolvedFor := &testScreen{name: "resolved"}
	app.RegisterPlaceholderResolver(func(s nav.Screen) nav.Screen {
		if s != nil && s.Title() == "placeholder" {
			return resolvedFor
		}
		return nil
	})
	a := app.New("v", "u", &testScreen{name: "first"})
	_, _ = a.Update(nav.ReplaceMsg{Factory: func() nav.Screen {
		return &testScreen{name: "placeholder"}
	}})
	require.Equal(t, "resolved", a.TopTitle())
}

func TestApp_ResizeBroadcastsToAllScreens(t *testing.T) {
	tuitest.ResetResolvers(t)
	a, b := &testScreen{name: "a"}, &testScreen{name: "b"}
	m := app.New("v", "u", a, b)
	_, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	require.Equal(t, 80, a.lastSize.Width)
	require.Equal(t, 24, a.lastSize.Height)
	require.Equal(t, 80, b.lastSize.Width)
	require.Equal(t, 24, b.lastSize.Height)
}

func TestApp_QuitOnQ_whenNotRawKeys(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "s", wantsRawKeys: false}
	a := app.New("v", "u", s)
	_, cmd := a.Update(keyPress('q'))
	require.NotNil(t, cmd, "expected tea.Quit cmd when wantsRawKeys=false")
	// Execute the cmd to confirm it's tea.Quit (returns tea.QuitMsg).
	require.IsType(t, tea.QuitMsg{}, cmd())
}

func TestApp_QForwardedWhenRawKeys(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "s", wantsRawKeys: true}
	a := app.New("v", "u", s)
	before := s.msgCount
	_, cmd := a.Update(keyPress('q'))
	require.Nil(t, cmd, "expected no tea.Quit cmd when wantsRawKeys=true")
	require.Greater(t, s.msgCount, before, "message must be forwarded to the screen")
}

func TestApp_CtrlCAlwaysQuits(t *testing.T) {
	tuitest.ResetResolvers(t)
	// Even with wantsRawKeys=true, ctrl+c must quit.
	s := &testScreen{name: "s", wantsRawKeys: true}
	a := app.New("v", "u", s)
	_, cmd := a.Update(ctrlC())
	require.NotNil(t, cmd)
	require.IsType(t, tea.QuitMsg{}, cmd())
}

func TestApp_HelpTogglesOnQuestionMark(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "s"}
	a := app.New("v", "u", s)
	require.False(t, a.ShowHelp())
	_, _ = a.Update(keyPress('?'))
	require.True(t, a.ShowHelp())
	_, _ = a.Update(keyPress('?'))
	require.False(t, a.ShowHelp())
}

// TestApp_mouse_wheel_no_panic is the H6 fix locking: MouseWheelMsg must
// not panic the root program.
func TestApp_mouse_wheel_no_panic(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "s"}
	a := app.New("v", "u", s)
	require.NotPanics(t, func() {
		_, _ = a.Update(tea.MouseWheelMsg{})
	})
	require.Equal(t, 1, s.msgCount, "mouse-wheel must be forwarded to the top screen")
}

// TestOSC52_clipboard_cmd_nonNil is the H6 fix locking: tea.SetClipboard
// returns a non-nil tea.Cmd (proves v2 clipboard API is linked).
func TestOSC52_clipboard_cmd_nonNil(t *testing.T) {
	cmd := tea.SetClipboard("hello")
	require.NotNil(t, cmd, "tea.SetClipboard must return a non-nil tea.Cmd")
}

// TestApp_teatest_quits_cleanly drives the App through teatest to prove it
// integrates with the real program loop (catches broken Model interface
// impls that unit tests miss).
func TestApp_teatest_quits_cleanly(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "s"}
	a := app.New("v", "u", s)
	tm := teatest.NewTestModel(t, a, teatest.WithInitialTermSize(80, 24))
	tm.Send(keyPress('q'))
	// Drain the output so the program can exit; assert it finishes.
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	_, _ = io.Copy(io.Discard, out)
}

func TestApp_teatest_renders_screen_view(t *testing.T) {
	tuitest.ResetResolvers(t)
	s := &testScreen{name: "home"}
	a := app.New("v", "u", s)
	tm := teatest.NewTestModel(t, a, teatest.WithInitialTermSize(80, 24))
	// Let the first frame render, then quit.
	time.Sleep(50 * time.Millisecond)
	tm.Send(keyPress('q'))
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	buf := &bytes.Buffer{}
	_, _ = io.Copy(buf, out)
	require.True(t, strings.Contains(buf.String(), "test:home"),
		"rendered frame must contain the screen's View output; got:\n%s", buf.String())
}

// -----------------------------------------------------------------------------
// WriteRecoveryScript tests live in this package for proximity — they
// exercise the tui package whose terminal.go is the companion to app.
// -----------------------------------------------------------------------------

func TestWriteRecoveryScript_creates_executable_script(t *testing.T) {
	// Use a unique-ish PID (won't collide with anything live on the system).
	pid := 99990 + (int(time.Now().UnixNano()) % 10)
	path, err := tuitest.WriteRecoveryScript(pid)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	info, err := os.Stat(path)
	require.NoError(t, err)
	// L4 fix: assert user-rwx bits are all set regardless of umask.
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm()&0o700,
		"user-rwx bits must all be set regardless of umask, got %v", info.Mode().Perm())

	b, err := os.ReadFile(path) //nolint:gosec // G304: test-only, path is the file we just wrote
	require.NoError(t, err)
	require.Contains(t, string(b), "stty sane")
	// The script stores escape sequences as shell-escaped literals (`\033`
	// as four characters followed by `[?1049l`) rather than as the raw
	// 0x1b byte — `printf` interprets them at script-run time. The plan's
	// original assertion used the raw byte form; we assert the literal
	// form since that's what's actually on disk.
	require.Contains(t, string(b), `\033[?1049l`)
}
