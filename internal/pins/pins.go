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
//   - 03-06 Task 1: ADD `_ "github.com/aymanbagabas/go-udiff"` — the dep
//     is promoted from indirect to direct in this task (M-APPLY-SETUP
//     SAFE-05 unified-diff renderer requires it), but the real production
//     import lands in Task 2 (the new applysetup package). Pin-keeper
//     bridges the two atomic commits so the `// indirect` marker
//     disappears immediately and `scripts/check-go-mod-pins.sh` can count
//     the new direct entry. Task 2 removes this entry when the real
//     applysetup import lands.
package pins

// Phase 3 plan 03-06 Task 1 → Task 2 bridge. See package doc shrinkage log
// entry "03-06 Task 1" for removal cadence.
import _ "github.com/aymanbagabas/go-udiff"
