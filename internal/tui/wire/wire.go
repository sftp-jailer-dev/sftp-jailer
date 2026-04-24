// Package wire is the single place that imports both splash and home to
// register the placeholder resolver that swaps splash.HomePlaceholder for
// home.New(version, url). This keeps splash and home decoupled (C4 fix):
// splash does not import home, home does not import splash, and wire is
// the one package that sees both.
//
// main.go calls wire.Register() once at startup; tests call it in their
// setup before constructing an app.App.
package wire

import (
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
)

// Register installs the splash.HomePlaceholder -> home.New resolver.
// Idempotent across calls within a single process.
func Register() {
	app.RegisterPlaceholderResolver(func(s nav.Screen) nav.Screen {
		if ph, ok := s.(*splash.HomePlaceholder); ok {
			return home.New(ph.Version, ph.ProjectURL)
		}
		return nil
	})
}
