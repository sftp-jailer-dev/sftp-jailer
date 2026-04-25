// Package main (observe.go): the `sftp-jailer observe-run` Cobra subcommand.
//
// This is the headless ingestion entry point invoked by:
//   - the systemd timer (Phase 2 plan 02-09 ships the unit), and
//   - the M-OBSERVE TUI modal (Phase 2 plan 02-08 streams its stdout).
//
// SAFE-01 root gate is inherited via rootCmd.PersistentPreRunE — every
// observe-run invocation is non-root-blocked before this RunE runs.
//
// OBS-04 schema-drift gate runs BEFORE store.Open / store.Migrate via the
// testable schemaCheck() helper. On drift the cmd writes a clear message
// to stderr and os.Exit(2) (distinct exit code per RESEARCH §540-548).
//
// OBS-05 retention values flow from config.Load (or config.Defaults() if
// the file is missing or unreadable) — this is the loop that closes the
// config-driven retention story end-to-end.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/observe"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// observeRunLockPath is the hardcoded flock(2) path for OBS-02 race
// protection. Lives in /var/lib/sftp-jailer (writable by root, persists
// across boots) — NOT /run, because we want the lock to survive a brief
// race where two concurrent invocations both attempt to start before
// either has called AcquireRunLock.
const observeRunLockPath = "/var/lib/sftp-jailer/observe-run.lock"

// observeRunTimeout caps the total run at 10 minutes so a hung journalctl
// stream cannot block the systemd timer indefinitely.
const observeRunTimeout = 10 * time.Minute

// observeRunCmd builds the `observe-run` Cobra command.
//
// Flag defaults are the production paths shipped by the .deb package
// (Phase 2 plan 02-09). Tests can override every default explicitly.
func observeRunCmd() *cobra.Command {
	var cursorPath, dbPath, configPath, since string
	var quiet bool

	c := &cobra.Command{
		Use:   "observe-run",
		Short: "Ingest sshd events from journald into the observation DB",
		Long: `observe-run drains new sshd events from the journal cursor file,
classifies them into the four-tier model, batched-INSERTs them into the
SQLite observations table, and runs end-of-run compaction + size-cap pruning.

Emits NDJSON progress events on stdout (per phase) and a final 'done' event
with the run summary. Use --quiet to suppress everything except 'done'.

Exit codes:
  0  success (or skipped: another run in progress)
  1  generic failure
  2  schema drift (DB written by a newer binary)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), observeRunTimeout)
			defer cancel()

			ops := sysops.NewReal()

			// OBS-04 / D-14 schema-drift gate — BEFORE store.Open + Migrate.
			drift, current, err := schemaCheck(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("peek schema: %w", err)
			}
			if drift {
				_, _ = fmt.Fprint(cmd.ErrOrStderr(), schemaDriftMessage(current, store.ExpectedSchemaVersion))
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				osExit(2) // testable seam (see var osExit below)
				return nil
			}

			// Open store + apply migrations.
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("store.Open: %w", err)
			}
			defer func() { _ = st.Close() }()
			if err := st.Migrate(ctx); err != nil {
				return fmt.Errorf("store.Migrate: %w", err)
			}

			// Load config — Defaults on file-missing; warn-and-default on parse error.
			cfg, cerr := config.Load(ctx, ops, configPath)
			if cerr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"sftp-jailer: warn: config %s unreadable (%v); using defaults\n",
					configPath, cerr)
				cfg = config.Defaults()
			}

			opts := observe.RunOpts{
				CursorFile:          cursorPath,
				DetailRetentionDays: cfg.DetailRetentionDays,
				DBMaxSizeMB:         cfg.DBMaxSizeMB,
				CompactAfterDays:    cfg.CompactAfterDays,
				Since:               since,
				Quiet:               quiet,
			}

			// OBS-02: flock-based race protection. Second concurrent invocation
			// gets ErrLockHeld → emit `skipped` JSON line and exit 0 (no error).
			release, lerr := ops.AcquireRunLock(ctx, observeRunLockPath)
			if lerr != nil {
				if errors.Is(lerr, sysops.ErrLockHeld) {
					return observe.EmitSkipped(cmd.OutOrStdout(), "another run in progress")
				}
				return fmt.Errorf("AcquireRunLock: %w", lerr)
			}
			defer release()

			return observe.NewRunner(ops, st).Run(ctx, opts, cmd.OutOrStdout())
		},
	}
	c.Flags().StringVar(&cursorPath, "cursor", "/var/lib/sftp-jailer/observer.cursor", "journalctl cursor file path")
	c.Flags().StringVar(&dbPath, "db", "/var/lib/sftp-jailer/observations.db", "SQLite DB path")
	c.Flags().StringVar(&configPath, "config", "/etc/sftp-jailer/config.yaml", "settings file path")
	c.Flags().StringVar(&since, "since", "", "test-only: override the time window (e.g. '7 days ago')")
	c.Flags().BoolVar(&quiet, "quiet", false, "suppress per-line JSON; emit only the final summary line")
	return c
}

// osExit is a test seam so TestObserveRunCmd_OBS04_… can verify the gate
// is invoked without actually killing the test process. Production code
// uses os.Exit; tests can override.
var osExit = os.Exit

// schemaCheck reads PRAGMA user_version from path WITHOUT triggering any
// migration. Returns drift=true when the on-disk version exceeds the
// binary's ExpectedSchemaVersion. Used by the OBS-04 gate.
//
// Mirrors store.PeekUserVersion's contract but is duplicated here so the
// observe-run cmd can act on the bool decision without importing the full
// store package's PRAGMA shape (keeps the gate testable in isolation).
func schemaCheck(ctx context.Context, dbPath string) (drift bool, current int, err error) {
	current, err = store.PeekUserVersion(ctx, dbPath)
	if err != nil {
		return false, 0, err
	}
	return current > store.ExpectedSchemaVersion, current, nil
}

// schemaDriftMessage formats the OBS-04 stderr message. Kept as a separate
// helper so the text contract is unit-testable.
func schemaDriftMessage(current, expected int) string {
	return fmt.Sprintf(
		"sftp-jailer: DB schema v%d newer than this binary expects (v%d). Run 'apt upgrade sftp-jailer'.\n",
		current, expected)
}

// keep modernc.org/sqlite reachable from this file's import graph for the
// schemaCheck → store.PeekUserVersion path. The store package already
// blank-imports it; this is a defensive sentinel only.
var _ = sql.ErrNoRows
