package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

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

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Read-only diagnostic of the box's SFTP posture",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("doctor subcommand not yet wired — see plan 04")
			return nil
		},
	}
}

func runTUI(cmd *cobra.Command, args []string) error {
	fmt.Println("TUI not yet wired — see plan 02")
	return nil
}
