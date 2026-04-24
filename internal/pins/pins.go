// Package pins keeps module pins alive across task boundaries.
//
// Plan 01-01 commits pins for the full Phase 1 direct-dep set in Task 1,
// but Tasks 2 and 3 only import a subset. Without this file, `go mod tidy`
// would strip charm.land/bubbletea, charm.land/bubbles, charm.land/lipgloss,
// sahilm/fuzzy, and modernc.org/sqlite from go.mod until plans 02, 04, and
// 05 bring in source that uses them.
//
// The blank imports here pin those modules in go.mod without affecting the
// final binary — the Go compiler discards unused imported packages.
// Delete entries from this file only when the corresponding real import
// has landed in production source.
package pins

import (
	// TUI framework (plan 02).
	_ "charm.land/bubbles/v2"
	_ "charm.land/bubbletea/v2"
	_ "charm.land/lipgloss/v2"

	// CLI subcommand framework (Task 3 wires this into cmd/sftp-jailer).
	_ "github.com/spf13/cobra"

	// Fuzzy-search (plan 02 — `/` slash-search on list screens).
	_ "github.com/sahilm/fuzzy"

	// Observation DB driver (plan 05+).
	_ "modernc.org/sqlite"
)
