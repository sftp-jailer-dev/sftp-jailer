// Package wire is the single place that imports splash, home, AND the
// doctor screen so the post-splash placeholder can be resolved into a
// startup-doctor gate that lazy-builds home only when the diagnostic
// is healthy. This keeps splash, home, and doctorscreen decoupled
// (C4 fix): none of them import each other; wire is the one package
// that sees all three.
//
// main.go calls wire.Register(doctorSvc) once at startup; tests call
// it (with a Fake-backed service) in their setup before constructing
// an app.App.
package wire

import (
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
)

// Register installs the splash.HomePlaceholder -> startup-doctor gate
// resolver. The gate auto-advances to home.New when the diagnostic is
// healthy (no [FAIL] rows) and otherwise stays visible so the operator
// can resolve the failure before continuing.
//
// doctorSvc may be nil in tests that do not exercise the gate path;
// in that case the resolver falls back to constructing home directly,
// preserving the legacy splash -> home behavior.
//
// Idempotent across calls within a single process.
func Register(doctorSvc *doctor.Service) {
	app.RegisterPlaceholderResolver(func(s nav.Screen) nav.Screen {
		ph, ok := s.(*splash.HomePlaceholder)
		if !ok {
			return nil
		}
		if doctorSvc == nil {
			return home.New(ph.Version, ph.ProjectURL)
		}
		return doctorscreen.NewStartupGate(doctorSvc, func() nav.Screen {
			return home.New(ph.Version, ph.ProjectURL)
		})
	})
}
