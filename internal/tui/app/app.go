// Package app is the root Bubble Tea model. It owns the screen stack, the
// global key bindings (q / ctrl+c / ?), and the resize broadcast down the
// stack. Exactly one App is constructed per process (pitfall E1).
//
// App does NOT implement nav.Screen — it implements tea.Model. Screens are
// added and removed via the nav.Msg / nav.ReplaceMsg tea.Cmd producers in
// internal/tui/nav, which every screen can emit without coupling to the App.
package app

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
)

// PlaceholderResolver is the seam that lets a screen ship a marker type
// through nav.ReplaceMsg and have the App construct the real screen on
// receipt. The splash screen uses this so it can request "replace me with
// home" without importing the home package (which would create a cycle:
// home → about → splash → home).
//
// Register resolvers with RegisterPlaceholderResolver before calling New.
// The resolver is called with the factory-produced Screen; if it returns a
// non-nil Screen, that replaces the one the factory produced. Otherwise the
// factory's output is used as-is. See internal/tui/screens/splash for the
// canonical consumer.
type PlaceholderResolver func(nav.Screen) nav.Screen

var placeholderResolvers []PlaceholderResolver

// RegisterPlaceholderResolver adds a resolver invoked on every nav.ReplaceMsg
// factory output. Resolvers are tried in registration order; the first one
// to return a non-nil Screen wins. Call this at process startup (before
// program.Run); it is NOT safe to call concurrently with Update.
func RegisterPlaceholderResolver(r PlaceholderResolver) {
	placeholderResolvers = append(placeholderResolvers, r)
}

// App is the root Bubble Tea model.
type App struct {
	stack      []nav.Screen
	width      int
	height     int
	help       widgets.HelpOverlay
	toast      widgets.Toast
	modebar    widgets.ModeBar // Phase 4 plan 04-09 — global MODE+countdown banner
	showHelp   bool
	version    string
	projectURL string
}

// New constructs an App with the given initial screen stack. If
// initialStack is empty, the App starts with no screens and the first View
// returns an empty tea.View — main is expected to supply at least a splash.
//
// The modebar is constructed with a nil watcher reference; production
// callers must call SetWatcher after the *revert.Watcher is built (see
// main.go::runTUI Phase 4 bootstrap). Until SetWatcher is called the
// modebar renders MODE state but never the REVERTING branch.
func New(version, projectURL string, initialStack ...nav.Screen) *App {
	a := &App{
		version:    version,
		projectURL: projectURL,
		help:       widgets.NewHelpOverlay(),
		modebar:    widgets.NewModeBar(nil),
	}
	a.stack = append(a.stack, initialStack...)
	return a
}

// SetWatcher binds the App's modebar to a revert.Watcher so the REVERTING
// countdown branch fires when a SAFE-04 timer is armed (D-L0809-03 +
// D-S04-03). Idempotent — pass nil to detach (tests). Called from
// main.go::runTUI after the Watcher singleton is constructed.
func (a *App) SetWatcher(w *revert.Watcher) {
	a.modebar = widgets.NewModeBar(w)
}

// SetMode forwards to the modebar widget. Called by callers that mutate
// firewall state (S-FIREWALL post-mutation, S-LOCKDOWN post-commit, app
// bootstrap after the first firewall.Enumerate) to keep the global strip
// in sync with the ufw rule set.
func (a *App) SetMode(mode firewall.Mode, ruleCount, userCount int) {
	a.modebar = a.modebar.SetMode(mode, ruleCount, userCount)
}

// Version returns the version string the App was constructed with. Screens
// that need it (splash, about) are passed it directly; this accessor exists
// mainly so tests and future screens can look it up through the App.
func (a *App) Version() string { return a.version }

// ProjectURL returns the project URL the App was constructed with.
func (a *App) ProjectURL() string { return a.projectURL }

// Init returns the batched Init cmds of every screen currently on the
// stack plus the modebar TickCmd that drives the 1s countdown re-render.
// Even with an empty stack the modebar tick fires so the global strip
// updates during splash → home transitions.
func (a *App) Init() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(a.stack)+1)
	// Phase 4 plan 04-09 — start the periodic modebar re-render so the
	// REVERTING countdown text updates every second.
	cmds = append(cmds, widgets.TickCmd())
	for i := range a.stack {
		if c := a.stack[i].Init(); c != nil {
			cmds = append(cmds, c)
		}
	}
	return tea.Batch(cmds...)
}

// Update handles global messages (resize, global keys, nav intents) and
// routes everything else to the top screen.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		// Broadcast resize to every screen on the stack — including those
		// currently hidden under a modal — so they render correctly when
		// popped back to. (TUI-05.)
		var cmds []tea.Cmd
		for i := range a.stack {
			var cmd tea.Cmd
			a.stack[i], cmd = a.stack[i].Update(m)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return a, tea.Batch(cmds...)

	case tea.KeyPressMsg:
		// ctrl+c ALWAYS quits regardless of textinput focus (safety).
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}
		// `q` quits only if the top screen doesn't want raw keys. This is
		// the textinput-safety gate — screens with a focused input flip
		// WantsRawKeys() true so the letter types instead of quitting.
		if m.String() == "q" {
			if len(a.stack) == 0 || !a.stack[len(a.stack)-1].WantsRawKeys() {
				return a, tea.Quit
			}
			// fall through: route to the top screen so the letter types
		}
		// `?` toggles the help overlay. Doesn't fall through.
		if m.String() == "?" {
			a.showHelp = !a.showHelp
			return a, nil
		}

	case nav.Msg:
		return a.handleNav(m)

	case widgets.ModeBarTickMsg:
		// Phase 4 plan 04-09 — route the periodic countdown tick to the
		// modebar widget and re-arm the next tick. View() reads the
		// armed-revert state from the bound Watcher on each render so the
		// modebar update itself is a no-op; what matters here is keeping
		// the cycle alive so the countdown text refreshes every second.
		a.modebar = a.modebar.Update(m)
		return a, widgets.TickCmd()

	case nav.ReplaceMsg:
		var replacement nav.Screen
		if m.Factory != nil {
			replacement = m.Factory()
		}
		// Run through any registered placeholder resolvers so screens can
		// ship marker types (e.g. splash.HomePlaceholder) and have the
		// App construct the real screen.
		for _, r := range placeholderResolvers {
			if out := r(replacement); out != nil {
				replacement = out
				break
			}
		}
		if replacement == nil {
			return a, nil
		}
		if len(a.stack) == 0 {
			a.stack = append(a.stack, replacement)
		} else {
			a.stack[len(a.stack)-1] = replacement
		}
		// Broadcast the last known size so the new screen renders at the
		// right dimensions on first draw.
		var sizeCmd tea.Cmd
		if a.width > 0 && a.height > 0 {
			replacement, sizeCmd = replacement.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
			a.stack[len(a.stack)-1] = replacement
		}
		return a, tea.Batch(replacement.Init(), sizeCmd)
	}

	// Toast messages pass through the toast first (it consumes its expire msg).
	a.toast = a.toast.Update(msg)

	// Default: route to the top of the stack.
	if len(a.stack) == 0 {
		return a, nil
	}
	idx := len(a.stack) - 1
	var cmd tea.Cmd
	a.stack[idx], cmd = a.stack[idx].Update(msg)
	return a, cmd
}

// handleNav mutates the stack per the Intent.
func (a *App) handleNav(m nav.Msg) (tea.Model, tea.Cmd) {
	switch m.Intent {
	case nav.Push:
		if m.Screen == nil {
			return a, nil
		}
		a.stack = append(a.stack, m.Screen)
		var sizeCmd tea.Cmd
		if a.width > 0 && a.height > 0 {
			a.stack[len(a.stack)-1], sizeCmd = m.Screen.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		}
		return a, tea.Batch(m.Screen.Init(), sizeCmd)

	case nav.Pop:
		if len(a.stack) > 0 {
			a.stack = a.stack[:len(a.stack)-1]
		}
		return a, nil

	case nav.Replace:
		if m.Screen == nil {
			return a, nil
		}
		if len(a.stack) == 0 {
			a.stack = append(a.stack, m.Screen)
		} else {
			a.stack[len(a.stack)-1] = m.Screen
		}
		var sizeCmd tea.Cmd
		if a.width > 0 && a.height > 0 {
			a.stack[len(a.stack)-1], sizeCmd = m.Screen.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		}
		return a, tea.Batch(m.Screen.Init(), sizeCmd)

	case nav.Quit:
		return a, tea.Quit
	}
	return a, nil
}

// View composes the global modebar strip + the stack's top view + an
// optional help overlay + an optional toast.
//
// Phase 4 plan 04-09 — the modebar is rendered ABOVE the active screen
// body on every screen (D-L0809-03 + D-S04-03). When a SAFE-04 revert is
// armed the modebar replaces the MODE words with the REVERTING countdown
// (Critical-red); admins always see the live timer regardless of which
// screen they're on.
//
// MouseMode is set to MouseModeCellMotion so clicks, drags, and wheel
// events are delivered to the root as mouse messages (TUI-04). AltScreen
// is set to true so we own the full terminal.
func (a *App) View() tea.View {
	modebar := a.modebar.View()
	if len(a.stack) == 0 {
		v := tea.NewView(modebar)
		v.AltScreen = true
		v.MouseMode = tea.MouseModeCellMotion
		return v
	}
	top := a.stack[len(a.stack)-1]
	body := top.View()
	// Phase 4 plan 04-09 — global MODE+countdown banner above the active
	// screen. The blank line between modebar and body lets the screen
	// content visually breathe under the strip.
	body = modebar + "\n\n" + body
	if a.showHelp {
		body = a.help.Overlay(body, top.KeyMap().FullHelp())
	}
	if ts := a.toast.View(); ts != "" {
		body += "\n" + ts
	}
	v := tea.NewView(body)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// StackLen returns the current stack depth. Exported for tests.
func (a *App) StackLen() int { return len(a.stack) }

// TopTitle returns the Title of the top screen, or "" if empty.
// Exported for tests.
func (a *App) TopTitle() string {
	if len(a.stack) == 0 {
		return ""
	}
	return a.stack[len(a.stack)-1].Title()
}

// FlashToast is exported so screens (and tests) can trigger a toast via the
// App. It returns the tea.Cmd the caller must route back through Update.
// Usage pattern for callers that hold a pointer to App:
//
//	cmd := a.FlashToast("copied")
func (a *App) FlashToast(text string) tea.Cmd {
	t, cmd := a.toast.Flash(text)
	a.toast = t
	return cmd
}

// ShowHelp reports whether the help overlay is currently visible.
// Exported for tests.
func (a *App) ShowHelp() bool { return a.showHelp }
