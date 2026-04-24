// Package tuitest provides small test helpers shared across the TUI packages.
// It is an internal test-support package: not imported by production code.
package tuitest

import (
	"testing"

	apppkg "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	tui "github.com/sftp-jailer-dev/sftp-jailer/internal/tui"
)

// ResetResolvers clears any placeholder resolvers registered by previous
// tests or init paths. Call at the top of every test that constructs an
// app.App so tests don't leak resolvers into each other.
func ResetResolvers(t *testing.T) {
	t.Helper()
	apppkg.ResetPlaceholderResolversForTest()
}

// WriteRecoveryScript re-exports tui.WriteRecoveryScript so tests in the
// app package can exercise it without an import cycle. (tui has no test
// deps; widgets and app both depend on tui; this shim lives in tuitest
// which is the join point.)
func WriteRecoveryScript(pid int) (string, error) {
	return tui.WriteRecoveryScript(pid)
}
