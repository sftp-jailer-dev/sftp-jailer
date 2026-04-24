// Package version exposes build-time version metadata as package variables
// so that the About overlay (plan 02) and the version subcommand can read
// them without a back-reference to main.
//
// Values are overwritten at startup by cmd/sftp-jailer/main.go from
// ldflag-injected variables, so ldflags can remain rooted in the main
// package (the standard Go packaging convention).
package version

// Version is the build-time version string. "dev" in unreleased builds.
var Version = "dev"

// ProjectURL is the canonical upstream URL shown in the About overlay and
// the version subcommand output.
var ProjectURL = "https://github.com/sftp-jailer-dev/sftp-jailer"
