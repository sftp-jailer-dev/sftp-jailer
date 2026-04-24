// Package about is the TUI About overlay reached from the home screen's
// 'a' binding. It re-uses the splash renderer via splash.NewModal so the
// logo-picker + color-profile logic lives in one place.
package about

import (
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
)

// New returns a nav.Screen that shows the splash content in modal mode
// (no auto-dismiss; any key pops). TUI-08 re-openable About.
func New(version, projectURL string) nav.Screen {
	return splash.NewModal(version, projectURL)
}
