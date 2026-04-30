// Package main (init_db.go): the hidden `sftp-jailer init-db` Cobra subcommand
// invoked by the .deb postinst script to initialize the observation DB at
// the current schema version IMMEDIATELY at install time — closing the
// gap from 05-VERIFICATION.md where the DB was previously created lazily
// by the first timer-triggered observe-run instead.
//
// CONTEXT.md / ROADMAP.md decisions implemented:
//   - DIST-04 / ROADMAP Phase 5 SC3: postinst initializes
//     /var/lib/sftp-jailer/observations.db at the current schema version
//     during `apt install`. Strict reading of the success criterion: the
//     DB MUST exist at install time, not after the first timer fire.
//   - Hidden:true: the subcommand is invoked only by the .deb postinst.
//     cobra/doc.GenManTree (Phase 5 plan 05-02) skips Hidden subcommands,
//     so no man page is generated; --help excludes it.
//   - SAFE-01 root gate inherited via rootCmd.PersistentPreRunE
//     (already wired in cmd/sftp-jailer/main.go::safeRootGate).
//
// Schema-drift gate (mirrors cmd/sftp-jailer/observe.go::schemaCheck):
//
//	BEFORE store.Open + Migrate, this subcommand calls
//	store.PeekUserVersion to read PRAGMA user_version WITHOUT applying
//	any migration. If the on-disk version > ExpectedSchemaVersion,
//	this is a downgrade-install scenario (admin installed a newer .deb
//	then is now installing an older one). The subcommand refuses with
//	a clear stderr message and exit code 2 (same exit code as the
//	OBS-04 gate in observe-run). postinst's `set -e` propagates the
//	failure; dpkg marks the configure step failed; the admin sees
//	the failure and rolls back. This is the SAFE-by-default behavior.
//
// Idempotent on re-invocation:
//
//	store.Migrate is documented as idempotent
//	(internal/store/store_test.go::TestMigrate_advances_to_expected_version).
//	On a fresh install, sqlite auto-creates the file via store.Open's
//	DSN, Migrate advances user_version 0 -> ExpectedSchemaVersion.
//	On `apt upgrade`, the existing DB at the prior version is opened,
//	Migrate is forward-only, no destructive operation occurs. CRITICAL
//	anti-parity with WR-01: this subcommand NEVER truncates or
//	overwrites state — unlike the existing `: > observer.cursor`
//	postinst line which does (a known WR-01 issue out of scope here).
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

// initDBTimeout caps the postinst subcommand at 30 seconds so a hung
// sqlite connection cannot stall an apt install. Mirrors purgeSshdCleanupTimeout.
const initDBTimeout = 30 * time.Second

// initDBPath is a package-var test seam for observationsDBPath. Production
// reads observationsDBPath (cmd/sftp-jailer/main.go L184); tests override
// initDBPath to point at t.TempDir(). The two-variable split exists because
// observationsDBPath is shared with the TUI bootstrap and observe-run; this
// subcommand wants its own override surface for test isolation without
// affecting the global.
var initDBPath = func() string { return observationsDBPath }

// initDBOsExit is a testable seam for os.Exit. Tests override it to record
// the exit code without terminating the test binary. Mirrors purgeOsExit.
var initDBOsExit = os.Exit

// initDBCmd builds the hidden `init-db` Cobra command.
//
// Exit codes:
//
//	0  success — DB exists at ExpectedSchemaVersion (fresh create OR idempotent re-run)
//	1  generic failure (sqlite open / migrate error) — RunE returns the error
//	2  schema drift — on-disk user_version > ExpectedSchemaVersion (downgrade install)
//
// postinst invokes this without `|| true` so set -e propagates a non-zero
// exit and dpkg marks the configure step failed — admin sees the failure.
func initDBCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "init-db",
		Short:  "Internal: invoked by .deb postinst to initialize observations.db (hidden)",
		Hidden: true,
		Long: `init-db is invoked by the .deb postinst script during 'apt install
sftp-jailer' to initialize /var/lib/sftp-jailer/observations.db at the
current schema version. It opens the store (which auto-creates the file),
runs PRAGMA user_version against the on-disk file BEFORE applying any
migration (the OBS-04 schema-drift gate), and on no-drift dispatches
Store.Migrate to advance user_version to ExpectedSchemaVersion.

This subcommand is idempotent — running it on an already-migrated DB is
a no-op (Store.Migrate's documented contract). On a downgrade-install
scenario where the on-disk DB has a higher schema version than this
binary expects, init-db refuses with exit code 2.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), initDBTimeout)
			defer cancel()

			dbPath := initDBPath()

			// OBS-04 schema-drift gate — BEFORE store.Open + Migrate.
			// Mirrors cmd/sftp-jailer/observe.go::schemaCheck.
			current, err := store.PeekUserVersion(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("init-db peek schema: %w", err)
			}
			if current > store.ExpectedSchemaVersion {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"sftp-jailer: DB schema v%d newer than this binary expects (v%d). Run 'apt upgrade sftp-jailer'.\n",
					current, store.ExpectedSchemaVersion)
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				initDBOsExit(2)
				return nil // unreachable in production; testable seam
			}

			// Open store + apply migrations (forward-only, idempotent).
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("init-db store.Open(%s): %w", dbPath, err)
			}
			defer func() { _ = st.Close() }()
			if err := st.Migrate(ctx); err != nil {
				return fmt.Errorf("init-db store.Migrate: %w", err)
			}
			return nil
		},
	}
}
