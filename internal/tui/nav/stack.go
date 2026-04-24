// Package nav defines the screen-stack navigation intents and the Screen
// interface every TUI screen implements. Screens emit nav.Msg / nav.ReplaceMsg
// via tea.Cmd; the root App consumes them and mutates the stack.
//
// The ReplaceMsg carrier with a factory closure is the DI seam that lets
// splash request "replace me with home" without importing the home package
// (which would create a cycle: splash <- about <- home).
package nav

import (
	tea "charm.land/bubbletea/v2"
)

// Intent identifies what the root App should do to the screen stack.
type Intent int

const (
	// None is the zero value; not emitted by real code paths.
	None Intent = iota
	// Push adds Screen to the top of the stack.
	Push
	// Pop removes the top of the stack; no-op on an empty stack.
	Pop
	// Replace swaps the top of the stack; on an empty stack, behaves like Push.
	Replace
	// Quit terminates the whole program (maps to tea.Quit).
	Quit
)

// Msg is the imperative nav intent emitted by screens.
type Msg struct {
	Intent Intent
	Screen Screen
}

// ReplaceMsg is the DI seam for cross-package replace without import cycles.
// The sender supplies a factory closure; the App resolves it on the way
// through Update. Used by splash → home (splash cannot import home because
// About re-pushes splash-as-modal, which would create a cycle).
type ReplaceMsg struct {
	Factory func() Screen
}

// KeyBinding is the shared shape for declaring keybindings at the nav layer.
// Screens translate their own bindings into this shape for the help overlay.
type KeyBinding struct {
	Keys []string
	Help string
}

// KeyMap is what every Screen exposes for help-overlay rendering.
type KeyMap interface {
	ShortHelp() []KeyBinding
	FullHelp() [][]KeyBinding
}

// Screen is the uniform interface for every TUI screen — splash, home,
// doctor, users, firewall, logs, etc. It deliberately does NOT embed
// tea.Model because Update has a Screen-typed return (not tea.Model), which
// keeps the stack homogeneous.
type Screen interface {
	Init() tea.Cmd
	Update(tea.Msg) (Screen, tea.Cmd)
	View() string
	Title() string
	KeyMap() KeyMap
	// WantsRawKeys returns true when a textinput (or similar) on the screen
	// is focused — the root App suppresses its own global 'q' handler so the
	// letter gets typed into the input rather than quitting the program.
	WantsRawKeys() bool
}

// PushCmd returns a tea.Cmd that asks the root App to push s.
func PushCmd(s Screen) tea.Cmd { return func() tea.Msg { return Msg{Intent: Push, Screen: s} } }

// PopCmd returns a tea.Cmd that asks the root App to pop the top screen.
func PopCmd() tea.Cmd { return func() tea.Msg { return Msg{Intent: Pop} } }

// ReplaceCmd returns a tea.Cmd that asks the root App to replace the top
// screen with s.
func ReplaceCmd(s Screen) tea.Cmd { return func() tea.Msg { return Msg{Intent: Replace, Screen: s} } }

// ReplaceWithFactoryCmd returns a tea.Cmd that carries a factory the App
// resolves when it processes the message. This lets a package (e.g. splash)
// request a replacement with a screen it cannot import directly.
func ReplaceWithFactoryCmd(f func() Screen) tea.Cmd {
	return func() tea.Msg { return ReplaceMsg{Factory: f} }
}

// QuitCmd returns a tea.Cmd that asks the root App to quit the program.
func QuitCmd() tea.Cmd { return func() tea.Msg { return Msg{Intent: Quit} } }
