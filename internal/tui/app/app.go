// Package app is the root Bubble Tea model. It owns the screen stack, the
// global key bindings (q / ctrl+c / ?), and the resize broadcast down the
// stack. Exactly one App is constructed per process (pitfall E1).
//
// App does NOT implement nav.Screen - it implements tea.Model. Screens are
// added and removed via the nav.Msg / nav.ReplaceMsg tea.Cmd producers in
// internal/tui/nav, which every screen can emit without coupling to the App.
package app

import (
	"context"
	"fmt"
	"time"

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

// RevertCanceller is the injection seam for the SAFE-04 [C]onfirm key
// (debug session safe04-confirm-view-keys). Wrap a single-step txn
// dispatch of txn.NewCancelRevertStep here in main.go so the App stays
// decoupled from sysops/txn:
//
//	a.SetRevertCanceller(func(ctx context.Context, unitName string) error {
//	    return txn.New(ops).Apply(ctx, []txn.Step{
//	        txn.NewCancelRevertStep(unitName, revertWatcher),
//	    })
//	})
//
// nil is valid (tests + pre-bootstrap construction); the C key becomes a
// silent no-op when no canceller is bound.
type RevertCanceller func(ctx context.Context, unitName string) error

// revertConfirmedMsg is delivered back to App.Update after the canceller
// goroutine returns. err is nil on success.
type revertConfirmedMsg struct {
	unitName string
	err      error
}

// App is the root Bubble Tea model.
type App struct {
	stack      []nav.Screen
	width      int
	height     int
	help       widgets.HelpOverlay
	toast      widgets.Toast
	modebar    widgets.ModeBar // Phase 4 plan 04-09 - global MODE+countdown banner
	showHelp   bool
	version    string
	projectURL string

	// SAFE-04 [C]onfirm / [V]iew countdown wiring (debug session
	// safe04-confirm-view-keys). watcher mirrors the modebar's bound
	// watcher so App.Update can Get() the armed state without poking the
	// modebar's internals. revertCanceller is the injected dispatcher
	// (see RevertCanceller doc).
	watcher         *revert.Watcher
	revertCanceller RevertCanceller
	// modeDetector is the injected closure App calls on Init and after
	// every revertConfirmedMsg success to refresh the modebar firewall
	// state. nil = no-op (tests, pre-bootstrap).
	modeDetector ModeDetector
}

// New constructs an App with the given initial screen stack. If
// initialStack is empty, the App starts with no screens and the first View
// returns an empty tea.View - main is expected to supply at least a splash.
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
// D-S04-03). Idempotent - pass nil to detach (tests). Called from
// main.go::runTUI after the Watcher singleton is constructed.
//
// Also stores the watcher on the App so Update can read armed state for
// the [C]onfirm / [V]iew countdown key handlers (debug session
// safe04-confirm-view-keys).
func (a *App) SetWatcher(w *revert.Watcher) {
	a.watcher = w
	a.modebar = widgets.NewModeBar(w)
}

// SetRevertCanceller injects the [C]onfirm key dispatcher. Pass nil to
// detach (tests, pre-bootstrap). See RevertCanceller doc for the wrapper
// shape and main.go::runTUI for the production wiring.
func (a *App) SetRevertCanceller(c RevertCanceller) {
	a.revertCanceller = c
}

// ModeDetector returns the current firewall mode + rule + user counts
// for the modebar. The closure shape decouples App from firewall +
// sysops (similar to RevertCanceller). main.go wires a closure that
// calls firewall.Enumerate + DetectMode + counts users.
//
// Without an injected detector, the modebar stays on its default
// ModeUnknown value forever (a UAT regression on 2026-05-03 - the
// SetMode method has existed since v1.0 but no production callsite
// invoked it). The App calls the detector on Init (startup) and on
// every revertConfirmedMsg success (post-mutation).
type ModeDetector func() (mode firewall.Mode, ruleCount int, userCount int)

// SetModeDetector injects the modebar refresh closure. Pass nil to
// detach (tests, pre-bootstrap). Calling it after Init has no immediate
// effect - the next refreshMode() call (Init + revertConfirmedMsg)
// will pick up the new detector.
func (a *App) SetModeDetector(d ModeDetector) {
	a.modeDetector = d
}

// refreshMode invokes the injected ModeDetector and pushes the result
// into the modebar. No-op when no detector is bound.
func (a *App) refreshMode() {
	if a.modeDetector == nil {
		return
	}
	mode, ruleCount, userCount := a.modeDetector()
	a.modebar = a.modebar.SetMode(mode, ruleCount, userCount)
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
	// Refresh the firewall mode at startup so the modebar reflects the
	// real state instead of the default ModeUnknown. UAT round 3 caught
	// the prior behavior - modebar was stuck on UNKNOWN forever because
	// no production callsite ever invoked SetMode.
	a.refreshMode()
	// Phase 4 plan 04-09 - start the periodic modebar re-render so the
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
		// Broadcast resize to every screen on the stack - including those
		// currently hidden under a modal - so they render correctly when
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
		// the textinput-safety gate - screens with a focused input flip
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
		// SAFE-04 global hotkeys (debug session safe04-confirm-view-keys):
		// [C]onfirm cancels the armed revert + persists the apply;
		// [V]iew countdown surfaces a brief deadline + reverse-cmd-count
		// toast. Both are gated by WantsRawKeys (textinput safety mirror
		// of the `q` gate) and by an actually-armed watcher.Get() - they
		// fall through to the top screen otherwise so they don't shadow
		// per-screen `c`/`v` bindings (e.g. a future textinput).
		if k := m.String(); k == "c" || k == "C" || k == "v" || k == "V" {
			if len(a.stack) > 0 && a.stack[len(a.stack)-1].WantsRawKeys() {
				// fall through to screen routing below
			} else if cmd := a.handleSafe04Hotkey(k); cmd != nil {
				return a, cmd
			} else if a.armedState() != nil {
				// Armed but the handler chose to swallow (e.g. C without
				// a canceller bound, or any other defensive no-op):
				// stop here so the keystroke does not leak to the screen.
				return a, nil
			}
			// Not armed: fall through so screens still see plain c/v.
		}

	case nav.Msg:
		return a.handleNav(m)

	case widgets.ModeBarTickMsg:
		// Phase 4 plan 04-09 - route the periodic countdown tick to the
		// modebar widget and re-arm the next tick. View() reads the
		// armed-revert state from the bound Watcher on each render so the
		// modebar update itself is a no-op; what matters here is keeping
		// the cycle alive so the countdown text refreshes every second.
		a.modebar = a.modebar.Update(m)
		return a, widgets.TickCmd()

	case revertConfirmedMsg:
		// SAFE-04 [C]onfirm result (debug session safe04-confirm-view-keys).
		// Watcher.Clear has already run inside CancelRevertStep on success
		// so the modebar will auto-revert to MODE on the next View().
		if m.err != nil {
			return a, a.FlashToast(fmt.Sprintf("Revert cancel failed: %v", m.err))
		}
		// Refresh the firewall mode now that the SAFE-04 timer is gone -
		// the just-applied mutation should be reflected in the modebar
		// (e.g. lockdown commit + confirm should flip the modebar from
		// REVERTING -> FIREWALL MODE: LOCKED, not back to the stale
		// pre-mutation mode).
		a.refreshMode()
		return a, a.FlashToast("Apply confirmed - revert disarmed")

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

// armedState returns the currently armed revert state or nil. Mirrors the
// modebar's lookup so View and Update agree on when the SAFE-04 banner is
// live.
func (a *App) armedState() *revert.State {
	if a.watcher == nil {
		return nil
	}
	return a.watcher.Get()
}

// handleSafe04Hotkey returns a tea.Cmd for the c/C/v/V key when a revert
// is armed, or nil when no revert is armed (caller falls through to
// screen routing). Returning a non-nil cmd commits the hotkey - caller
// short-circuits screen routing.
//
// C/c: dispatch the canceller in a goroutine; the result returns as a
// revertConfirmedMsg. Without a bound canceller, returns nil so caller
// can decide whether to swallow or pass through (caller swallows when
// armed - no point letting a stale c keystroke fall through to a screen
// that has its own c binding).
//
// V/v: flash an immediate toast describing the live deadline + queued
// reverse-command count. No async work.
func (a *App) handleSafe04Hotkey(key string) tea.Cmd {
	armed := a.armedState()
	if armed == nil {
		return nil // caller falls through to screen routing
	}
	switch key {
	case "c", "C":
		if a.revertCanceller == nil {
			return nil // no canceller bound; armed: caller swallows
		}
		canceller := a.revertCanceller
		unitName := armed.UnitName
		return func() tea.Msg {
			// Bounded context so a hung systemctl can't pin the goroutine
			// forever. 30s is generous - SystemctlStop on .timer/.service
			// completes in <1s on a healthy system.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := canceller(ctx, unitName)
			return revertConfirmedMsg{unitName: unitName, err: err}
		}
	case "v", "V":
		remaining := time.Until(time.Unix(0, armed.DeadlineUnixNs)).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		var cmdCount int
		if a.watcher != nil {
			cmdCount = len(a.watcher.ReverseCommands())
		}
		return a.FlashToast(fmt.Sprintf(
			"Revert: %s remaining, %d rollback cmd(s) queued (press C to confirm)",
			remaining, cmdCount))
	}
	return nil
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
// Phase 4 plan 04-09 - the modebar is rendered ABOVE the active screen
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
	// Phase 4 plan 04-09 - global MODE+countdown banner above the active
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

// ToastText returns the currently displayed toast text (or "" when no
// toast is active). Exported for tests that need to assert toast content
// without rendering View. Mirrors widgets.Toast.View()'s rendered output
// minus the leading checkmark glyph.
func (a *App) ToastText() string { return a.toast.View() }

// ShowHelp reports whether the help overlay is currently visible.
// Exported for tests.
func (a *App) ShowHelp() bool { return a.showHelp }
