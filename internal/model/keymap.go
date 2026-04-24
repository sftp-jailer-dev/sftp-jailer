package model

// KeyBinding is a shared type used by both the nav Screen interface
// (plan 02) and the help overlay (plan 02). Keep it tiny.
type KeyBinding struct {
	Keys []string
	Help string
}
