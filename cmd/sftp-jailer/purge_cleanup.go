// Package main (purge_cleanup.go): the hidden `sftp-jailer purge-sshd-cleanup`
// Cobra subcommand invoked by the .deb prerm script.
//
// CONTEXT.md decisions implemented:
//   - D-MS-01: prerm invokes this subcommand while /usr/bin/sftp-jailer is
//     still on disk; it builds an internal/txn batch that backs up + removes
//     the canonical drop-in, runs `sshd -t`, then dispatches a SAFE-06
//     reload of ssh.service. On any step failure, the txn rolls back via
//     the compensators (drop-in restored from backup; reload re-issued).
//   - D-MS-04: subcommand is Hidden:true (not in --help, not in generated
//     man pages). SAFE-01 root gate inherited via rootCmd.PersistentPreRunE.
//     Idempotent: returns 0 if drop-in already absent. No --no-revert flag
//     needed because the SAFE-04 3-min revert wrapper is NOT used here -
//     dpkg's prerm context is non-interactive; there is no admin to confirm
//     during a 3-minute window.
//
// SAFE-06 dispatcher choice (CONTEXT.md D-MS-01 + Phase 3 D-09):
//
//	Dropping a drop-in cannot affect Port/ListenAddress/AddressFamily
//	directives - the canonical writer never put those in the drop-in (Phase
//	3 D-08; the file holds Subsystem + Match Group sftp-jailer + chroot/
//	ForceCommand). Therefore ReloadService is the correct dispatch (NOT
//	RestartSocket). This matches the apply path's own dispatch for the
//	same reason.
//
// Drop-in path source (CONTEXT.md "Claude's Discretion" option (b)):
//
//	internal/tui/screens/applysetup.DropInPath - refactor-resistant. If
//	Phase 3 ever moves the constant, this code follows automatically.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/applysetup"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// purgeSshdCleanupTimeout caps the prerm subcommand at 30 seconds so a
// hung systemctl/sshd cannot stall an apt purge.
const purgeSshdCleanupTimeout = 30 * time.Second

// purgeBackupDir is the backup directory for the removed drop-in. Lives
// OUTSIDE /var/lib/sftp-jailer so postrm's `rm -rf /var/lib/sftp-jailer`
// (Phase 5 plan 05-04) does NOT delete it - admins can recover the last
// drop-in's bytes from this directory after a purge.
const purgeBackupDir = "/var/backups/sftp-jailer"

// purgeStepsFn returns the txn step slice for purge-sshd-cleanup. Exposed
// as a package var so tests can assert step composition without invoking
// the real subsystems. Production callers use the default value.
//
// Step order (must not change without re-verifying SAFE-06 invariants):
//  1. RemoveSshdDropIn - backup-then-remove; Compensate restores from backup.
//  2. SshdValidate     - `sshd -t` against the resulting config; no compensator.
//  3. SystemctlReload  - `systemctl reload ssh.service` (ReloadService default
//     - drop-in removal cannot touch socket directives).
var purgeStepsFn = func(dropInPath, backupDir string, now func() time.Time) []txn.Step {
	return []txn.Step{
		txn.NewRemoveSshdDropInStep(dropInPath, backupDir, 0o644, now),
		txn.NewSshdValidateStep(),
		txn.NewSystemctlReloadStep(txn.ReloadService),
	}
}

// purgeSshdCleanupCmd builds the hidden `purge-sshd-cleanup` Cobra command.
//
// Exit codes (printed via os.Exit since this is a leaf subcommand):
//
//	0  success (apply ran and committed) OR idempotent skip (drop-in absent)
//	1  generic failure - the txn rolled back via compensators (drop-in restored)
//	2  rollback failed - drop-in MAY be in inconsistent state; ops-page-able
func purgeSshdCleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "purge-sshd-cleanup",
		Short:  "Internal: invoked by .deb prerm to remove the sshd drop-in (hidden)",
		Hidden: true,
		Long: `purge-sshd-cleanup is invoked by the .deb prerm script during
'apt purge sftp-jailer'. It atomically removes /etc/ssh/sshd_config.d/50-sftp-jailer.conf,
runs 'sshd -t' against the resulting config, and dispatches a SAFE-06 reload
of ssh.service. On any failure the drop-in is restored from backup.

This subcommand is idempotent - running it when the drop-in is already
absent is a no-op that exits 0.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), purgeSshdCleanupTimeout)
			defer cancel()

			ops := sysops.NewReal()

			// Idempotent skip - if drop-in already absent, exit 0 (D-MS-04 step 2).
			if _, err := ops.ReadFile(ctx, applysetup.DropInPath); errors.Is(err, fs.ErrNotExist) {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "drop-in already absent, skipping")
				return nil
			} else if err != nil {
				// Genuine read error (permission etc.) - bail out without changes.
				return fmt.Errorf("read drop-in %s: %w", applysetup.DropInPath, err)
			}

			steps := purgeStepsFn(applysetup.DropInPath, purgeBackupDir, time.Now)
			if err := txn.New(ops).Apply(ctx, steps); err != nil {
				// The txn already ran compensators in reverse order. The wrapped
				// error chain may include a compensator error if any compensator
				// itself failed - in that case exit 2 (ops-page-able).
				if isCompensateFailure(err) {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "purge-sshd-cleanup: ROLLBACK FAILED: %v\n", err)
					purgeOsExit(2)
					return nil // unreachable in production; testable seam
				}
				return fmt.Errorf("purge-sshd-cleanup: %w", err)
			}
			return nil
		},
	}
}

// isCompensateFailure inspects a txn.Apply error chain for a compensator
// failure marker. The internal/txn package wraps compensate errors via
// fmt.Errorf("compensate %s: %w", stepName, err) and then joins them
// into the returned error via errors.Join. The substring "compensate"
// (lowercase) is the reliable discriminant - it appears in every
// compensate-error path in txn.rollback.
//
// T-05-03-07 mitigation: this predicate always over-classifies (returns
// true when in doubt → exit 2 rather than 1). Over-classification is
// the safe direction: the admin sees "ROLLBACK FAILED" and investigates,
// rather than silently swallowing a genuinely failed compensator. A future
// tightening can replace this with errors.Is(err, txn.ErrCompensateFailed)
// once the txn package exposes a typed sentinel.
func isCompensateFailure(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "compensate")
}

// purgeOsExit is a testable seam for os.Exit. Tests override it to record
// the exit code without terminating the test binary.
var purgeOsExit = os.Exit
