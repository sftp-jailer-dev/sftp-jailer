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
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/wire"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
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
	root.AddCommand(observeRunCmd()) // Phase 2 plan 02-02
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
			_, _ = fmt.Fprint(cmd.OutOrStdout(), doctor.RenderText(rep))
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of the text report")
	return c
}

// observationsDBPath is the canonical on-disk SQLite path for the
// observation pipeline (OBS-* / D-08). Variable (not const) so tests and
// future work can override; production callers always read it as-is.
var observationsDBPath = "/var/lib/sftp-jailer/observations.db"

// runTUI constructs the single Bubble Tea program for the session (pitfall
// E1: exactly one program instance) and runs it until the user quits. Before
// the program starts, a recovery script is written to /tmp and its path
// printed to stderr (pitfall E2) so if the terminal is wedged by a SIGKILL
// or OOM, the admin sees the recovery invocation in scrollback.
//
// Bootstrap ownership (plan 02-04): this function constructs the full
// production graph that wave-3+ feature plans extend by adding ONE
// `home.SetXFactory(...)` line each — they do NOT modify the bootstrap.
//   - 02-05 adds home.SetFirewallFactory(...)
//   - 02-06 adds home.SetLogsFactory(...)    (also captures `p` for goroutine Send)
//   - 02-07 adds home.SetSettingsFactory(...)
//   - 02-08 wires logsscreen.SetObserveRunFactory(...) (different shape)
func runTUI(cmd *cobra.Command, args []string) error {
	// Pitfall E2: recovery script for unclean exits. Path printed to stderr
	// BEFORE program.Run() so it's in scrollback even on a SIGKILL.
	recoveryPath, err := tui.WriteRecoveryScript(os.Getpid())
	if err != nil {
		return fmt.Errorf("write recovery script: %w", err)
	}
	defer func() { _ = os.Remove(recoveryPath) }()

	fmt.Fprintf(os.Stderr,
		"sftp-jailer: if the terminal is wedged after a crash, run: %s\n",
		recoveryPath)

	// Register the splash.HomePlaceholder -> home.New resolver (C4 seam).
	wire.Register()

	// --- Production bootstrap (plan 02-04) -------------------------------
	// SystemOps is the single seam for /etc reads + subprocess execution
	// (enforced by scripts/check-no-exec-outside-sysops.sh). All downstream
	// data-layer constructors take this handle.
	ops := sysops.NewReal()

	// Open the observation DB (read pool + single-conn writer split). The
	// DB file may not yet exist on a fresh install; sqlite auto-creates it
	// and Migrate brings the schema up to ExpectedSchemaVersion. A nonzero
	// open error is fatal — without the DB the users / logs / firewall
	// screens cannot enrich rows from observations.
	st, err := store.Open(observationsDBPath)
	if err != nil {
		return fmt.Errorf("runTUI store.Open(%s): %w", observationsDBPath, err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(cmd.Context()); err != nil {
		return fmt.Errorf("runTUI store.Migrate: %w", err)
	}
	queries := store.NewQueries(st)

	// Per-screen enrichers / services. usersEnum is shared across pushes
	// (the Enumerator is stateless beyond its handles) so we build it once.
	// usersEnum is consumed by the usersscreen factory wired in this plan's
	// Task 2 commit (which adds the import + the home.SetUsersFactory call).
	usersEnum := users.New(ops, queries)
	_ = usersEnum // silence unused until Task 2 wires usersscreen.New(usersEnum)

	// C2 wiring (plan 01-04): doctor service.
	doctorSvc := doctor.New(ops)

	// Factory injections — sorted alphabetically by screen name so future
	// wave plans can insert their own line without merge conflict noise.
	home.SetDoctorFactory(func() nav.Screen { return doctorscreen.New(doctorSvc) })
	// home.SetUsersFactory    wired by plan 02-04 Task 2 (this plan).
	// home.SetFirewallFactory wired by plan 02-05 (firewall.Enumerate consumer).
	// home.SetLogsFactory     wired by plan 02-06 (queries + sysops live-tail consumer).
	// home.SetSettingsFactory wired by plan 02-07 (config.Load/Save consumer).

	// Construct the App with the splash as the initial screen. The splash
	// will auto-dismiss after 2s and ReplaceMsg itself with a home screen
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
