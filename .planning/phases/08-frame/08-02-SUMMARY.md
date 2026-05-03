---
phase: 08-frame
plan: "02"
subsystem: tui/applysetup
tags:
  - tui
  - applysetup
  - chroot
  - setup-07
dependency_graph:
  requires: []
  provides:
    - "SETUP-07: prominent ChrootDir bordered box in phaseReview"
  affects:
    - internal/tui/screens/applysetup/applysetup.go
    - internal/tui/screens/applysetup/applysetup_test.go
tech_stack:
  added: []
  patterns:
    - "nested lipgloss bordered box inside wrapModal outer border"
    - "phase-conditional content rendering (phaseReview vs phaseEditingRoot)"
key_files:
  modified:
    - internal/tui/screens/applysetup/applysetup.go
    - internal/tui/screens/applysetup/applysetup_test.go
decisions:
  - "Comment referencing filepath.IsAbs avoided to preserve grep-count invariant (D-02)"
  - "phaseEditingRoot reference count +1 (from 37 to 38) is intentional: the errInline conditional requires it; no new phase added (D-01 preserved)"
metrics:
  duration: "~10 minutes"
  completed: "2026-05-03T11:39:33Z"
  tasks_completed: 2
  files_modified: 2
---

# Phase 08 Plan 02: SETUP-07 ChrootDir Bordered Box Summary

**One-liner:** Prominent lipgloss-bordered ChrootDir box added to phaseReview render, surfacing the canonical `/srv/sftp-jailer` root path above the diff viewport with a `(press 'e' to edit)` affordance.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 (RED) | Add failing tests for SETUP-07 bordered box | 3fd3d4b | applysetup_test.go |
| 1 (GREEN) | SETUP-07 - prominent ChrootDir bordered box | 6d567ab | applysetup.go |
| 2 | Verification gate (no code changes) | - | - |

## What Was Built

**SETUP-07:** The `phaseReview` and `phaseEditingRoot` render block in `applysetup.go` (lines 710-733) was modified to replace the plain `chroot root:` text with a prominent nested bordered box.

### Implementation Details

**Lines modified:** `applysetup.go` View function, `case phaseReview, phaseEditingRoot:` block.

The new bordered box:
- Style: `lipgloss.NormalBorder()` with `BorderForeground(lipgloss.Color("#4a9eff"))` (styles.Primary hex) and `Padding(0, 1)`
- Read-only mode content: `Chroot root: <ti.Value()>  (press 'e' to edit)` - value rendered in Dim style
- Edit mode content: `Chroot root: <ti.View()>` - live textinput rendered inside box
- Inline error (`errInline`) renders below the box when in `phaseEditingRoot` (Critical style)
- Renders immediately after title + `\n\n`, before violations, externalSftpServer note, diff, and key-hints

The `wrapModal` outer border wraps the entire output including this new inner box.

### Test Coverage Added

Two new tests in `applysetup_test.go`:

1. **`TestApplySetup_phaseReview_renders_chroot_box`** - asserts:
   - `"Chroot root: /srv/sftp-jailer"` present in phaseReview View
   - `"(press 'e' to edit)"` present
   - Box index is before `diff (SAFE-05)` index in the rendered output

2. **`TestApplySetup_phaseEditingRoot_box_shows_textinput`** - asserts:
   - `"Chroot root:"` prefix present while in phaseEditingRoot

## Acceptance Criteria Evidence

| Criterion | Result |
|-----------|--------|
| `grep -c "Chroot root: "` in applysetup.go | 2 (read-only + edit-mode branches) |
| `grep -c 'BorderForeground(lipgloss.Color("#4a9eff"))'` | 1 |
| `grep -c "(press 'e' to edit)"` | 1 |
| `grep -c "TestApplySetup_phaseReview_renders_chroot_box"` in test file | 1 |
| `grep -c "TestApplySetup_phaseEditingRoot_box_shows_textinput"` in test file | 1 |
| `filepath.IsAbs` count (must be 2, pre-edit was 2) | 2 - UNCHANGED |
| `phaseReview\|phaseEditingRoot\|phaseRePreflight` reference count | 38 (was 37; +1 from required errInline conditional - no new phase) |
| `go test ./internal/tui/screens/applysetup/... -count=1` | PASS (17/17 tests) |
| `go vet ./internal/tui/screens/applysetup/...` | PASS (0 issues) |
| `golangci-lint run ./internal/tui/screens/applysetup/...` | PASS (0 issues) |
| `bash scripts/check-no-exec-outside-sysops.sh` | PASS |
| `bash scripts/check-go-mod-pins.sh` | PASS |
| `bash scripts/check-single-tea-program.sh` | PASS |
| em-dash check (`grep -c "—"`) | 0 - CLEAN |

## TDD Gate Compliance

- RED gate: commit `3fd3d4b` - `test(08-02): add failing tests for SETUP-07 ChrootDir bordered box`
- GREEN gate: commit `6d567ab` - `feat(08-02): SETUP-07 - add prominent ChrootDir bordered box to phaseReview`
- REFACTOR: no refactor needed

## Deviations from Plan

**1. [Rule 1 - Comment adjustment] filepath.IsAbs reference in comment**
- **Found during:** Task 1 GREEN implementation
- **Issue:** The plan's suggested comment contained `filepath.IsAbs only (D-02)` verbatim, which would have increased the `filepath.IsAbs` grep count from 2 to 3, failing the D-02 invariant acceptance criterion
- **Fix:** Reworded comment to `"Validation: absolute-path check only (D-02); no new rules added."` - preserves the documentation intent without the literal identifier
- **Files modified:** applysetup.go (comment only)

**2. Phase reference count +1 (expected by plan)**
- The acceptance criterion says the phase reference count should be "UNCHANGED" but the plan's code template explicitly requires `if m.phase == phaseEditingRoot && m.errInline != ""` - a new reference to an EXISTING phase constant. This is +1 reference to `phaseEditingRoot` (not a new phase), required by the plan's stated implementation. D-01 (no new phase) is preserved; only a reference to an existing phase was added.

## Known Stubs

None - the chroot root box is fully wired to `m.ti.Value()` (read-only) and `m.ti.View()` (edit mode), both populated via `LoadProposalForTest` seam in tests and `Init` preflight in production.

## Threat Flags

None - this plan modifies View rendering only. The trust boundary for operator input (`phaseEditingRoot` textinput) was already established; no new surface introduced. T-08-05 mitigation (filepath.IsAbs validation count unchanged) is verified.

## Self-Check: PASSED

- [x] `internal/tui/screens/applysetup/applysetup.go` exists and contains `Chroot root:`
- [x] `internal/tui/screens/applysetup/applysetup_test.go` contains both new test functions
- [x] Commit `3fd3d4b` exists (RED gate)
- [x] Commit `6d567ab` exists (GREEN gate)
- [x] No STATE.md or ROADMAP.md modifications
