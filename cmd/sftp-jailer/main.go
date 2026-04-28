package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/app"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
	firewallscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/firewallrule"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/home"
	lockdownscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/lockdown"
	logsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/logs"
	observerunscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/observerun"
	settingsscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/settings"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/splash"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/userdetail"
	usersscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/users"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/wire"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/version"
)

// defaultChrootRoot is the fallback when sshd_config.d drop-ins do not
// declare a ChrootDirectory we recognise. Same default M-APPLY-SETUP uses
// (plan 03-06) so the canonical-config path stays consistent.
const defaultChrootRoot = "/srv/sftp-jailer"

// defaultSFTPPort is the literal that M-ADD-RULE renders into the
// proposed `ufw insert 1 allow proto tcp from <src> to any port <port>`
// command. Phase 4 v1 hard-codes "22" — sftp-jailer assumes the standard
// OpenSSH port. Future phases (D-FW-PORT) may parse Port from
// sshd_config.d/*.conf, at which point this becomes a fallback.
const defaultSFTPPort = "22"

// resolveChrootRoot scans /etc/ssh/sshd_config.d/*.conf for a Match-block
// ChrootDirectory directive, strips the per-user expansion suffix
// (`/%u` / `/%h`), and returns the literal path. Falls back to
// defaultChrootRoot on any read/parse failure or absent directive.
//
// Phase 3 plan 03-07 wiring: passed into usersscreen.NewWithConfig so the
// M-NEW-USER + Enter-on-INFO-orphan flows can pre-fill the home path
// against whatever chroot root is actually deployed (admins occasionally
// move it from /srv/sftp-jailer to /var/sftp-jailer or similar).
func resolveChrootRoot(ctx context.Context, ops sysops.SystemOps) string {
	paths, _ := ops.Glob(ctx, "/etc/ssh/sshd_config.d/*.conf")
	for _, p := range paths {
		b, err := ops.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		d, _ := sshdcfg.ParseDropIn(b)
		for _, m := range d.Matches {
			for _, dir := range m.Body {
				if dir.Keyword == "chrootdirectory" {
					v := strings.TrimSpace(dir.Value)
					v = strings.TrimSuffix(v, "/%u")
					v = strings.TrimSuffix(v, "/%h")
					if v = strings.TrimRight(v, "/"); v != "" {
						return v
					}
				}
			}
		}
	}
	return defaultChrootRoot
}

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

// configFilePath is the canonical on-disk YAML path for sftp-jailer's own
// settings (D-07 / OBS-05). The S-SETTINGS screen reads + atomically
// rewrites this file; observe-run reads it via config.Load. Variable (not
// const) for symmetry with observationsDBPath — tests can override if a
// future test seam needs it. Same path is also hardcoded in
// cmd/sftp-jailer/observe.go's --config flag default; both must stay in
// sync.
var configFilePath = "/etc/sftp-jailer/config.yaml"

// observerCursorPath is the canonical journalctl cursor file consumed by
// observe-run. Mirrors the default of cmd/sftp-jailer/observe.go's
// --cursor flag. Variable (not const) for test-overrides.
var observerCursorPath = "/var/lib/sftp-jailer/observer.cursor"

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
//   - 04-05 adds firewallscreen.SetAddRuleFactory(...) and
//     userdetail.SetAddRuleFactory(...) — both inject an M-ADD-RULE
//     constructor that captures the per-process *revert.Watcher (D-S04-04
//     singleton: exactly one Watcher per TUI process so the 3-min revert
//     state is shared across modals).
//   - 04-06 adds firewallscreen.SetDeleteRuleFactory(...) and
//     usersscreen.SetDeleteUserFwRulesFactory(...) — both inject an
//     M-DELETE-RULE constructor sharing the same *revert.Watcher
//     singleton. The firewallscreen factory dispatches by mode
//     (ModeByID for 'd', ModeBySource for 's'); the usersscreen
//     factory always builds ModeByUser scoped to the selected user
//     (W1 keybind deviation: uppercase 'D' on S-USERS reserves
//     lowercase 'd' for Phase 3 03-08a M-DELETE-USER).
//   - 04-08 adds home.SetLockdownFactory(...) — injects an
//     S-LOCKDOWN constructor that captures the live ops, the
//     per-process *revert.Watcher singleton, a freshly-built
//     lockdown.Generator (reads the observation DB through the
//     queries handle), the same usersEnum used by S-USERS, the
//     defaultSFTPPort literal, and the koanf-loaded
//     LockdownProposalWindowDays. Pressing capital `L` on home
//     opens the flagship S-LOCKDOWN screen.
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
	usersEnum := users.New(ops, queries)

	// Load the persisted config once at startup so the S-USERS screen's
	// password-age legend + threshold buckets reflect what the admin set.
	// A missing file yields config.Defaults() (180 / 365), so first launch
	// renders sensible buckets without requiring the admin to write the
	// file first. A genuine read/parse error is surfaced upstream — at
	// that point the TUI can still launch with Defaults() to keep the
	// degradation graceful.
	usersCfg := config.Defaults()
	if loaded, err := config.Load(cmd.Context(), ops, configFilePath); err == nil {
		usersCfg = loaded
	} else {
		fmt.Fprintf(os.Stderr,
			"sftp-jailer: warning: could not load %s (%v); falling back to defaults for the S-USERS legend\n",
			configFilePath, err)
	}

	// C2 wiring (plan 01-04): doctor service.
	doctorSvc := doctor.New(ops)

	// Phase 3 plan 03-07: resolve the chroot root once at startup so the
	// usersscreen factory can hand it to M-NEW-USER pushes without each
	// modal having to re-parse sshd_config.d/*.conf.
	chrootRoot := resolveChrootRoot(cmd.Context(), ops)

	// Phase 4 plan 04-04 + 04-05: SAFE-04 revert state is owned by exactly
	// ONE *revert.Watcher per TUI process so the 3-min revert window is
	// shared across all FW-mutation modals (M-ADD-RULE today; M-DELETE-RULE
	// in 04-06; S-LOCKDOWN commit in 04-08). The watcher's on-disk pointer
	// at /var/lib/sftp-jailer/revert.active survives crashes — the Restore
	// flow on next launch reloads pending revert state.
	revertWatcher := revert.New(ops)

	// Plan 04-09 carryover: reconcile any in-flight SAFE-04 revert window
	// from a prior TUI session before constructing the App. Restore reads
	// the on-disk pointer at /var/lib/sftp-jailer/revert.active and:
	//   - missing             → clean state, modebar renders MODE words.
	//   - present + active    → in-process state restored; modebar will
	//     immediately switch to the REVERTING countdown on first render.
	//   - present + inactive  → unit fired (timer expired or killed
	//     externally); pointer auto-cleared and a stderr line surfaced
	//     so the admin sees the recovery on launch.
	//   - present + corrupt   → orphan pointer; best-effort clear with
	//     a stderr warning so the box state is surfaced even if Restore
	//     can't fully reconcile.
	// Bound the call by 5s so a hung systemctl on a degraded box does
	// not block TUI startup indefinitely.
	{
		restoreCtx, restoreCancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		switch fired, err := revertWatcher.Restore(restoreCtx); {
		case err != nil && fired:
			fmt.Fprintf(os.Stderr,
				"sftp-jailer: warning: orphan revert pointer cleared on startup: %v\n", err)
		case err != nil:
			fmt.Fprintf(os.Stderr,
				"sftp-jailer: warning: revert.Restore failed: %v (continuing without revert state)\n", err)
		case fired:
			fmt.Fprintf(os.Stderr,
				"sftp-jailer: prior revert window fired before this launch — pre-change ufw rules were restored by the systemd unit\n")
		}
		restoreCancel()
	}

	// Factory injections — sorted alphabetically by screen name so future
	// wave plans can insert their own line without merge conflict noise.
	firewallscreen.SetAddRuleFactory(func() nav.Screen {
		m := firewallrule.New(ops, revertWatcher, defaultSFTPPort, "")
		m.SetStore(queries)
		return m
	})
	// Plan 04-06: M-DELETE-RULE factory dispatches by mode. ModeByID
	// receives the firewall.Rule selected on S-FIREWALL; ModeBySource
	// receives the source-CIDR string ("" in v1 — modal renders the
	// no-matches state). ModeByUser is reachable via the per-user
	// factory below (usersscreen.SetDeleteUserFwRulesFactory).
	firewallscreen.SetDeleteRuleFactory(func(mode firewallrule.DeleteMode, payload interface{}) nav.Screen {
		var m *firewallrule.DeleteModel
		switch mode {
		case firewallrule.ModeByID:
			rule, _ := payload.(firewall.Rule)
			m = firewallrule.NewDeleteByID(ops, revertWatcher, rule)
		case firewallrule.ModeBySource:
			source, _ := payload.(string)
			m = firewallrule.NewDeleteBySource(ops, revertWatcher, source)
		case firewallrule.ModeByUser:
			username, _ := payload.(string)
			m = firewallrule.NewDeleteByUser(ops, revertWatcher, username)
		default:
			return nil
		}
		m.SetStore(queries)
		return m
	})
	home.SetDoctorFactory(func() nav.Screen { return doctorscreen.New(doctorSvc) })
	home.SetFirewallFactory(func() nav.Screen { return firewallscreen.New(ops) })
	// Plan 04-08: capital `L` on home opens S-LOCKDOWN. The factory
	// closure constructs a fresh model per push so each navigation
	// re-reads the observation DB + firewall state. Captures:
	//   - ops             — sysops.SystemOps for `who`, ufw, systemctl, ip
	//   - revertWatcher   — per-process SAFE-04 singleton (D-S04-04)
	//   - lockdown.NewGenerator(queries) — proposal generator (LOCK-02)
	//     constructed inside the closure so each push gets a fresh
	//     instance; the Generator is stateless beyond its queries
	//     handle, so this is cheap.
	//   - usersEnum       — sftp-jailer-managed user enumerator (shared
	//     with S-USERS, S-SETTINGS, etc.)
	//   - defaultSFTPPort — Phase 4 v1 hard-coded "22"
	//   - usersCfg.LockdownProposalWindowDays — koanf-loaded window
	//     (D-L0204-01); defaults to 90 if config absent (config.Defaults).
	// SetStore registers the *store.Queries handle for FW-08 mirror
	// rebuild post-commit (W2 best-effort).
	home.SetLockdownFactory(func() nav.Screen {
		m := lockdownscreen.New(
			ops,
			revertWatcher,
			lockdown.NewGenerator(queries),
			usersEnum,
			defaultSFTPPort,
			usersCfg.LockdownProposalWindowDays,
		)
		m.SetStore(queries)
		return m
	})
	home.SetLogsFactory(func() nav.Screen { return logsscreen.New(queries, ops) })
	home.SetSettingsFactory(func() nav.Screen { return settingsscreen.New(ops, configFilePath, usersEnum, chrootRoot) })
	home.SetUsersFactory(func() nav.Screen { return usersscreen.NewWithConfig(usersEnum, &usersCfg, ops, chrootRoot) })
	userdetail.SetAddRuleFactory(func(username string) nav.Screen {
		m := firewallrule.New(ops, revertWatcher, defaultSFTPPort, username)
		m.SetStore(queries)
		return m
	})
	// Plan 04-06: S-USERS 'D' (uppercase) → M-DELETE-RULE in
	// ModeByUser scoped to the selected user. W1 keybind deviation
	// preserves Phase 3 03-08a's lowercase 'd' = delete user account.
	usersscreen.SetDeleteUserFwRulesFactory(func(username string) nav.Screen {
		m := firewallrule.NewDeleteByUser(ops, revertWatcher, username)
		m.SetStore(queries)
		return m
	})

	// Construct the App with the splash as the initial screen. The splash
	// will auto-dismiss after 2s and ReplaceMsg itself with a home screen
	// via the wire resolver.
	a := app.New(version.Version, version.ProjectURL,
		splash.New(version.Version, version.ProjectURL),
	)
	// Plan 04-09: bind the SAFE-04 watcher to the App's modebar so the
	// REVERTING countdown branch fires when the timer is armed across
	// any screen (D-L0809-03 + D-S04-03). If revert.Restore above
	// repopulated the in-process State, the very first View() after
	// program.Run will already render the countdown.
	a.SetWatcher(revertWatcher)

	// Exactly ONE program constructor per process (pitfall E1).
	// Bubble Tea v2 notes:
	//   - tea.WithAltScreen is not a ProgramOption in v2; alt-screen is set
	//     via v.AltScreen = true in the root View() (see internal/tui/app).
	//   - Panic catching is default in v2; there is no WithCatchPanics.
	//     To disable it use tea.WithoutCatchPanics() — we want the default.
	p := tea.NewProgram(a)

	// M-OBSERVE wiring (plan 02-08): the observerun modal needs the
	// *tea.Program reference for the goroutine-Send pattern (RESEARCH
	// Pattern 4). Captured here AFTER the program is constructed above
	// and BEFORE p.Run. This is structurally different from the
	// home.SetXFactory wiring above because the dependency graph is
	// asymmetric — only M-OBSERVE needs to push events back into the
	// program from a goroutine.
	observeRunOpts := sysops.ObserveRunSubprocessOpts{
		// SelfPath empty → ObserveRunStream resolves os.Executable() at runtime.
		CursorFile: observerCursorPath,
		DBPath:     observationsDBPath,
		ConfigPath: configFilePath,
	}
	logsscreen.SetObserveRunFactory(func() nav.Screen {
		return observerunscreen.New(p, ops, observeRunOpts)
	})

	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
