// Package rootcmd factors the cobra command tree out of cmd/sftp-jailer
// (package main) so it can be imported by cmd/gen-manpage and by tests.
//
// Both cmd/sftp-jailer/main.go and cmd/gen-manpage/main.go consume Build
// to obtain a *cobra.Command pre-wired with all visible subcommands. Hidden
// subcommands (e.g. purge-sshd-cleanup from plan 05-03 and init-db from
// plan 05-07) are included - cobra/doc.GenManTree skips them automatically.
//
// Build does NOT include the runtime TUI hook (runTUI) or the SAFE-01
// PersistentPreRunE - those are wired by cmd/sftp-jailer/main.go after
// calling Build. This split keeps gen-manpage purely declarative (no
// process-state side effects when invoked from `go generate`).
package rootcmd

import "github.com/spf13/cobra"

// Opts captures hooks the production binary must inject. cmd/gen-manpage
// passes a zero-value Opts (no hooks needed for man-page generation).
type Opts struct {
	// RunTUI is the root command's RunE. cmd/sftp-jailer wires runTUI here;
	// cmd/gen-manpage leaves it nil (no man page generated for the implicit
	// RunE; cobra still emits a top-level page from the Use/Short fields).
	RunTUI func(cmd *cobra.Command, args []string) error

	// PersistentPreRunE is the SAFE-01 root gate. cmd/sftp-jailer wires the
	// existing closure; cmd/gen-manpage leaves it nil.
	PersistentPreRunE func(cmd *cobra.Command, args []string) error

	// Subcommands is the slice of subcommand factories to AddCommand onto
	// the root. Both consumers pass the same set:
	//   versionCmd, doctorCmd, observeRunCmd, purgeSshdCleanupCmd (added by 05-03),
	//   initDBCmd (added by 05-07, Hidden:true)
	Subcommands []*cobra.Command
}

// Build returns the root *cobra.Command with metadata + subcommands wired.
// Use, Short, and the project description are static.
func Build(o Opts) *cobra.Command {
	root := &cobra.Command{
		Use:   "sftp-jailer",
		Short: "Chrooted SFTP administration TUI for Ubuntu 24.04",
		Long: `sftp-jailer is an interactive TUI for Linux sysadmins managing
chrooted SFTP on Ubuntu 24.04. It turns sshd_config edits, filesystem
permissions, user accounts, firewall rules, and log-grepping into a single
TUI for setting up a hardened, IP-locked-down SFTP server.

See https://sftp-jailer.com for documentation.`,
		RunE:              o.RunTUI,
		PersistentPreRunE: o.PersistentPreRunE,
	}
	for _, sub := range o.Subcommands {
		root.AddCommand(sub)
	}
	return root
}
