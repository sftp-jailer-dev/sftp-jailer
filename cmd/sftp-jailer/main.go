package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/wire"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/version"
)

// ldflag-injected at build time. Defaults are dev-friendly.
var (
	buildVersion    = "dev"
	buildProjectURL = "https://github.com/sftp-jailer-dev/sftp-jailer"
)

// geteuid is a test seam; production uses os.Geteuid.
var geteuid = os.Geteuid

func main() {
	// Sync ldflag vars into the version package so any code that imports
	// internal/version sees the build-time values (About overlay in plan 02).
	version.Version = buildVersion
	version.ProjectURL = buildProjectURL

	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sftp-jailer",
		Short: "Chrooted SFTP administration TUI for Ubuntu 24.04",
		// Root cobra runs the TUI by default (plan 02 wires it).
		RunE: runTUI,
		// SAFE-01 gate: refuse on ANY subcommand unless running as root.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Exception: `version` is read-only metadata, allow non-root.
			if cmd.Name() == "version" {
				return nil
			}
			msg, shouldExit := rootCheckMessage(os.Args[1:], geteuid())
			if shouldExit {
				fmt.Fprint(os.Stderr, msg)
				os.Exit(1)
			}
			return nil
		},
	}
	root.AddCommand(versionCmd())
	root.AddCommand(doctorCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("sftp-jailer %s — %s\n", version.Version, version.ProjectURL)
			return nil
		},
	}
}

// doctorCmd runs the six read-only diagnostic detectors and prints a
// human-readable report (default) or the JSON-serialized model.DoctorReport
// (when --json is passed). The SAFE-01 gate on rootCmd runs before this
// handler, so we can assume euid=0 here.
func doctorCmd() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Read-only diagnostic of the box's SFTP posture",
		RunE: func(cmd *cobra.Command, args []string) error {
			// T-04-05: bound the detector chain at 30 s so a hung sshd -T
			// (or any other system call) cannot block indefinitely.
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			svc := doctor.New(sysops.NewReal())
			rep, err := svc.Run(ctx)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			fmt.Fprint(cmd.OutOrStdout(), doctor.RenderText(rep))
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of the text report")
	return c
}

// runTUI constructs the single Bubble Tea program for the session (pitfall
// E1: exactly one program instance) and runs it until the user quits. Before
// the program starts, a recovery script is written to /tmp and its path
// printed to stderr (pitfall E2) so if the terminal is wedged by a SIGKILL
// or OOM, the admin sees the recovery invocation in scrollback.
func runTUI(cmd *cobra.Command, args []string) error {
	// Pitfall E2: recovery script for unclean exits. Path printed to stderr
	// BEFORE program.Run() so it's in scrollback even on a SIGKILL.
	recoveryPath, err := tui.WriteRecoveryScript(os.Getpid())
	if err != nil {
		return fmt.Errorf("write recovery script: %w", err)
	}
	defer os.Remove(recoveryPath)

	fmt.Fprintf(os.Stderr,
		"sftp-jailer: if the terminal is wedged after a crash, run: %s\n",
		recoveryPath)

	// Register the splash.HomePlaceholder -> home.New resolver (C4 seam).
	wire.Register()

	// C2 wiring (plan 01-04): build the SystemOps handle + doctor service
	// once here and inject a factory closure into the home screen. Home's
	// `d` binding will construct a fresh doctor screen per push; the service
	// itself is reused across pushes.
	ops := sysops.NewReal()
	doctorSvc := doctor.New(ops)
	home.SetDoctorFactory(func() nav.Screen {
		return doctorscreen.New(doctorSvc)
	})

	// Construct the App with the splash as the initial screen. The splash
	// will auto-dismiss after 1s and ReplaceMsg itself with a home screen
	// via the wire resolver.
	a := app.New(version.Version, version.ProjectURL,
		splash.New(version.Version, version.ProjectURL),
	)

	// Exactly ONE program constructor per process (pitfall E1).
	// Bubble Tea v2 notes:
	//   - tea.WithAltScreen is not a ProgramOption in v2; alt-screen is set
	//     via v.AltScreen = true in the root View() (see internal/tui/app).
	//   - Panic catching is default in v2; there is no WithCatchPanics.
	//     To disable it use tea.WithoutCatchPanics() — we want the default.
	p := tea.NewProgram(a)
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
