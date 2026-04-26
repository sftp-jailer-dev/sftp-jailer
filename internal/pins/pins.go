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
//
// Shrinkage log:
//   - 01-05: removed `_ "modernc.org/sqlite"` — internal/store imports it.
//   - 01-02: removed the four TUI pin-keepers — internal/tui/* now imports
//     bubbletea/v2, bubbles/v2, lipgloss/v2, and sahilm/fuzzy directly.
//     This file is now empty; kept in place as documentation of the
//     pattern so future plans know where to park future pre-import pins.
//   - 03-04: NO change required — `golang.org/x/crypto` was added as a
//     real production import via `internal/keys` (ssh.ParseAuthorizedKey
//     + ssh.FingerprintSHA256). New direct deps that have a real
//     consumer landing in the same plan never need a pin-keeper entry.
//   - 03-06 Task 1: ADDED `_ "github.com/aymanbagabas/go-udiff"` —
//     bridge between Task 1 (dep promotion + script bump) and Task 2
//     (the new applysetup package becomes the real consumer).
//   - 03-06 Task 2: REMOVED the go-udiff pin-keeper above — the real
//     production import landed in
//     internal/tui/screens/applysetup/applysetup.go for the SAFE-05
//     unified-diff renderer. Pin-keeper retired per the contract above.
package pins
