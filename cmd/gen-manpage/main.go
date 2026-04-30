// Package main: cmd/gen-manpage drives cobra/doc.GenManTree against the
// sftp-jailer cobra root. Output lands in docs/man/ as one .1 file per
// visible subcommand. Hidden subcommands (e.g. purge-sshd-cleanup added
// by plan 05-03) are skipped automatically by GenManTree.
//
// Invocation:
//
//	go run ./cmd/gen-manpage           # writes to docs/man/
//	go run ./cmd/gen-manpage --output /tmp/foo  # writes elsewhere (CI guard uses this)
//
// The "before:" hook in packaging/goreleaser.yml (plan 05-01) invokes this
// at release time as a belt-and-suspenders so a stale docs/man/ commit
// cannot ship in a release artifact.
//
// CI guard scripts/check-manpage-fresh.sh runs this against a tmpdir and
// diffs against the committed docs/man/.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/rootcmd"
)

func main() {
	output := flag.String("output", "docs/man", "output directory for generated .1 files")
	flag.Parse()

	if err := os.MkdirAll(*output, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "gen-manpage: mkdir %s: %v\n", *output, err)
		os.Exit(1)
	}

	// Build the cobra tree with the SAME subcommand list as the production
	// binary. Hidden subcommands (added by 05-03) are included here too -
	// GenManTree filters them out by inspecting the Hidden field.
	root := rootcmd.Build(rootcmd.Opts{
		// No RunTUI / PersistentPreRunE - generator is declarative-only.
		Subcommands: gatherSubcommands(),
	})

	// Pin the date so generated output is deterministic across runs.
	// (The CI guard scripts/check-manpage-fresh.sh diffs the output;
	// a moving date would make every CI run fail.)
	fixedDate := time.Date(2026, time.April, 29, 0, 0, 0, 0, time.UTC)

	header := &doc.GenManHeader{
		Title:   "SFTP-JAILER",
		Section: "1",
		Source:  fmt.Sprintf("sftp-jailer %s", versionString()),
		Manual:  "User Commands",
		Date:    &fixedDate,
	}

	if err := doc.GenManTree(root, header, *output); err != nil {
		fmt.Fprintf(os.Stderr, "gen-manpage: GenManTree: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("gen-manpage: wrote .1 pages to %s\n", *output)
}

// versionString returns the project version. We do NOT depend on
// internal/version (which is ldflag-injected at production build time and
// would carry a "dev" string in this generator's process). For man-page
// purposes the static "1" is sufficient - DIST-03's lintian gate doesn't
// check the version string in the .TH header. If a future maintainer wants
// the man page to carry a version string from git describe, factor that
// here.
func versionString() string {
	return "1"
}

// gatherSubcommands returns the same factory-product slice that cmd/sftp-jailer's
// rootCmd() passes to rootcmd.Build. We re-construct the factory list here
// rather than importing cmd/sftp-jailer (which is package main).
//
// CRITICAL: keep this list in lockstep with cmd/sftp-jailer/main.go's
// rootCmd(). The CI guard scripts/check-manpage-fresh.sh fails on drift,
// surfacing any divergence at PR time.
//
// The factories here re-construct minimal cobra.Command shapes - they need
// not contain the production RunE bodies (man-page generation only reads
// Use/Short/Long/Flags). Stub bodies are simpler than re-importing the
// production factories' types.
func gatherSubcommands() []*cobra.Command {
	return []*cobra.Command{
		stubCmd("version", "Print version and exit"),
		stubDoctorCmd(),
		stubObserveRunCmd(),
		// 05-03 appends: stubPurgeSshdCleanupCmd() - but that command will
		// have Hidden:true so GenManTree skips it. (We add it here anyway
		// so the rootcmd.Build subcommand list matches production exactly,
		// and the Hidden filter does its job.)
	}
}

// stubCmd is the minimal shape - Use + Short + a no-op RunE.
func stubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE:  func(*cobra.Command, []string) error { return nil },
	}
}

// stubDoctorCmd mirrors cmd/sftp-jailer/main.go::doctorCmd() Use/Short/flags.
// Body is a stub - only the man-page-relevant metadata matters.
func stubDoctorCmd() *cobra.Command {
	c := stubCmd("doctor", "Read-only diagnostic of the box's SFTP posture")
	c.Flags().Bool("json", false, "emit JSON instead of the text report")
	return c
}

// stubObserveRunCmd mirrors cmd/sftp-jailer/observe.go::observeRunCmd()
// Use/Short/Long/flags exactly. Production body is the journalctl ingestion
// loop; for man pages, we only need the flag declarations.
func stubObserveRunCmd() *cobra.Command {
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
		RunE: func(*cobra.Command, []string) error { return nil },
	}
	c.Flags().String("cursor", "/var/lib/sftp-jailer/observer.cursor", "journalctl cursor file path")
	c.Flags().String("db", "/var/lib/sftp-jailer/observations.db", "SQLite DB path")
	c.Flags().String("config", "/etc/sftp-jailer/config.yaml", "settings file path")
	c.Flags().String("since", "", "test-only: override the time window (e.g. '7 days ago')")
	c.Flags().Bool("quiet", false, "suppress per-line JSON; emit only the final summary line")
	return c
}
