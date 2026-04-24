package app

import "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"

// GlobalKeyMap is the always-on key surface owned by the root App. Every
// screen's own KeyMap should include these (help them discoverable in the
// overlay) — concrete wiring is done per-screen in Phase 1 because Go has no
// mixin; for Phase 2 we may promote this to a nav.KeyMap interface.
type GlobalKeyMap struct {
	Quit nav.KeyBinding
	Help nav.KeyBinding
}

// DefaultGlobalKeyMap returns the canonical global bindings.
func DefaultGlobalKeyMap() GlobalKeyMap {
	return GlobalKeyMap{
		Quit: nav.KeyBinding{Keys: []string{"q", "ctrl+c"}, Help: "quit"},
		Help: nav.KeyBinding{Keys: []string{"?"}, Help: "help"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k GlobalKeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Help, k.Quit}
}

// FullHelp implements nav.KeyMap.
func (k GlobalKeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Help, k.Quit}}
}
