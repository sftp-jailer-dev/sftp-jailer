---
phase: 05-packaging-install-purge-automated-release
plan: "02"
subsystem: packaging/manpage
tags:
  - manpage
  - cobra
  - codegen
  - ci-guard
dependency_graph:
  requires:
    - 05-01 (goreleaser.yml with before: hook placeholder)
  provides:
    - docs/man/*.1 (committed groff artifacts for nfpm contents)
    - cmd/gen-manpage (cobra/doc driver)
    - internal/rootcmd (shared cobra tree factory)
    - scripts/check-manpage-fresh.sh (CI guard)
  affects:
    - 05-03 (adds purgeSshdCleanupCmd to both main.go and gen-manpage stubs)
    - 05-05 (release.yml invokes check-manpage-fresh.sh)
tech_stack:
  added:
    - github.com/spf13/cobra/doc (subpackage of existing cobra v1.10.2 dep; adds go-md2man + blackfriday as indirect)
  patterns:
    - cobra/doc.GenManTree fixed-date determinism
    - rootcmd.Build(Opts) factory pattern for shared cobra tree
    - CI guard script shape matching check-go-mod-pins.sh
key_files:
  created:
    - internal/rootcmd/rootcmd.go
    - cmd/gen-manpage/main.go
    - cmd/gen-manpage/main_test.go
    - docs/man/sftp-jailer.1
    - docs/man/sftp-jailer-doctor.1
    - docs/man/sftp-jailer-observe-run.1
    - docs/man/sftp-jailer-version.1
    - scripts/check-manpage-fresh.sh
    - cmd/sftp-jailer/main_test.go
  modified:
    - cmd/sftp-jailer/main.go (rootCmd refactored to use rootcmd.Build; safeRootGate extracted)
    - .github/workflows/ci.yml (invariants job: added setup-go@v5 + Manpages fresh step)
    - go.mod / go.sum (cobra/doc transitive deps: go-md2man v2.0.6, blackfriday v2.1.0)
decisions:
  - "D-MP-01: cobra/doc.GenManTree chosen as man-page driver (zero net-new code, free from cobra dep already present)"
  - "Option (a) factoring chosen: rootcmd.Build in internal/rootcmd vs option (b) parallel reconstruction — refactor-resistant single source of truth"
  - "Fixed-date trick in GenManHeader.Date (2026-04-29) for deterministic generator output"
  - "Stub-factory approach in gatherSubcommands: minimal cobra.Command shapes in gen-manpage matching production Use/Short/Long/Flags"
metrics:
  duration_seconds: 361
  tasks_completed: 4
  files_changed: 11
  completed_date: "2026-04-29"
---

# Phase 05 Plan 02: Manpage Generator Summary

**One-liner:** cobra/doc.GenManTree driver in cmd/gen-manpage with fixed-date determinism, internal/rootcmd shared tree factory, and CI freshness guard — silences lintian no-manual-page.

## What Was Done

- Refactored `cmd/sftp-jailer/main.go`: extracted `rootCmd()` cobra tree into new `internal/rootcmd` package exposing `Build(Opts)`. Factored inline `PersistentPreRunE` closure into named `safeRootGate` function. Behavior is byte-identical to prior inline closure.
- Created `cmd/gen-manpage/main.go`: single-file ~120-line generator invoking `cobra/doc.GenManTree` against a rootcmd-built cobra tree. Stub subcommand factories (Use/Short/Long/Flags only — no production RunE bodies).
- Committed 4 generated `.1` pages under `docs/man/`: `sftp-jailer.1`, `sftp-jailer-doctor.1`, `sftp-jailer-observe-run.1`, `sftp-jailer-version.1`.
- Created `scripts/check-manpage-fresh.sh`: re-runs generator into tmpdir, diffs against committed `docs/man/`, exits 1 with `FAIL:` prefix + remediation hint on drift.
- Wired `check-manpage-fresh.sh` into `.github/workflows/ci.yml` invariants job (new `actions/setup-go@v5` setup step required — invariants job previously had no Go available).
- Added `cmd/gen-manpage/main_test.go`: `TestGatherSubcommands_HasExpectedNames` smoke test (TDD RED commit 985fcad, GREEN commit 0aab1fd).
- Added `cmd/sftp-jailer/main_test.go`: `TestRootCmd_BuildsExpectedTree` and `TestSafeRootGate_VersionExempt`.

## Decisions Implemented

**D-MP-01: cobra/doc.GenManTree driver**
- Zero net-new Go code for the man-page format: `GenManTree` is part of cobra's existing dep already in go.mod. Only transitive additions needed: `go-md2man/v2` and `blackfriday/v2` (both indirect in go.mod).
- CI guard pattern directly mirrors `scripts/check-go-mod-pins.sh`: same `set -euo pipefail`, same `FAIL:` stderr prefix, same `exit 1` on drift, same `OK:` success line.

**"Claude's Discretion" option (a) chosen: rootcmd factoring**
- `internal/rootcmd.Build(Opts)` is the single source of truth for the cobra tree structure. Both `cmd/sftp-jailer/main.go` and `cmd/gen-manpage/main.go` call it — no duplication of `Use/Short/Long` metadata.
- Option (b) (parallel reconstruction in gen-manpage without a shared package) was rejected: it drifts silently on root-command metadata changes and requires manual lockstep maintenance beyond what the CI guard catches.

## Determinism Guarantee

`GenManHeader.Date` is hardcoded to `time.Date(2026, time.April, 29, 0, 0, 0, 0, time.UTC)`. Without this, `cobra/doc.GenManTree` embeds the current date in each `.TH` header line, producing different output on every `go run ./cmd/gen-manpage` invocation. The CI guard (`check-manpage-fresh.sh`) diffs the generator output against committed `docs/man/`; a moving date would fail every CI run. The fixed-date approach is the standard cobra/doc convention for committed-output projects.

## Hidden-Subcommand Exclusion

`cobra/doc.GenManTree` automatically skips subcommands with `Hidden: true` (verified via cobra source inspection). Plan 05-03 will add `purgeSshdCleanupCmd()` with `Hidden: true`. The `gatherSubcommands()` stub list in `cmd/gen-manpage/main.go` must include that stub (to keep the cobra tree in lockstep with production), but no `.1` file will be generated for it. Post-05-03 verification: confirm `docs/man/sftp-jailer-purge-sshd-cleanup.1` does not exist after adding the hidden stub.

## Stub-Factory Drift Risk

`gatherSubcommands()` in `cmd/gen-manpage/main.go` reconstructs minimal stubs (Use/Short/Long/Flags) for each production subcommand. The CI guard catches drift at PR time — if a future maintainer adds a new subcommand to `cmd/sftp-jailer` without updating `cmd/gen-manpage`, `check-manpage-fresh.sh` will fail because the generated `.1` file count changes. **Any new subcommand in cmd/sftp-jailer must be mirrored in gatherSubcommands() with its Use/Short/Long/Flags.**

## Downstream Consumers

- **05-03** adds `purgeSshdCleanupCmd()` to `cmd/sftp-jailer/main.go` rootCmd() and must add a corresponding `stubPurgeSshdCleanupCmd()` (with `Hidden: true`) to `gatherSubcommands()` in `cmd/gen-manpage/main.go`. GenManTree skips it automatically — no new `.1` file produced.
- **05-01** goreleaser.yml `before:` hook should invoke `go run ./cmd/gen-manpage` as belt-and-suspenders at release time (belt = committed docs/man/, suspenders = regenerated at release).
- **05-05** release.yml should run `bash scripts/check-manpage-fresh.sh` in its invariants block (same as ci.yml).

## Deviations from Plan

**1. [Rule 3 - Blocking] Added cobra/doc transitive dependencies to go.mod**
- **Found during:** Task 2 (GREEN phase — `go test ./cmd/gen-manpage/...` failed with "missing go.sum entry for module providing package github.com/cpuguy83/go-md2man/v2/md2man")
- **Fix:** `go get github.com/spf13/cobra/doc@v1.10.2` — added `github.com/cpuguy83/go-md2man/v2 v2.0.6` and `github.com/russross/blackfriday/v2 v2.1.0` as indirect deps. `check-go-mod-pins.sh` still passes (guards only direct deps).
- **Files modified:** `go.mod`, `go.sum`
- **Commit:** 0aab1fd

## Verification Commands Run

```bash
go build ./...                                           # exits 0
go test -count=1 ./cmd/gen-manpage/... ./internal/rootcmd/... ./cmd/sftp-jailer/...  # exits 0
go run ./cmd/gen-manpage --output docs/man               # writes 4 .1 files
bash scripts/check-manpage-fresh.sh                      # exits 0 (OK: ...)
grep -q 'check-manpage-fresh.sh' .github/workflows/ci.yml  # exits 0
go run ./cmd/gen-manpage --output /tmp/manpage-smoke && diff -ru docs/man/ /tmp/manpage-smoke/  # exits 0 (deterministic)
```

## TDD Gate Compliance

- RED gate commit: `985fcad test(05-02): RED — gatherSubcommands test for cmd/gen-manpage`
- GREEN gate commit: `0aab1fd feat(05-02): add cmd/gen-manpage and commit generated docs/man/*.1 pages`
- No REFACTOR phase needed (code was clean).

## Self-Check

### Files Created/Modified
- `test -f internal/rootcmd/rootcmd.go` — FOUND
- `test -f cmd/gen-manpage/main.go` — FOUND
- `test -f docs/man/sftp-jailer.1` — FOUND
- `test -f docs/man/sftp-jailer-doctor.1` — FOUND
- `test -f docs/man/sftp-jailer-observe-run.1` — FOUND
- `test -f docs/man/sftp-jailer-version.1` — FOUND
- `test -f scripts/check-manpage-fresh.sh` — FOUND
- `grep -q 'check-manpage-fresh.sh' .github/workflows/ci.yml` — FOUND

### Commits
- `62dab2c` refactor(05-02): extract rootcmd.Build — FOUND
- `985fcad` test(05-02): RED — FOUND
- `0aab1fd` feat(05-02): add cmd/gen-manpage — FOUND
- `1be72aa` feat(05-02): add scripts/check-manpage-fresh.sh — FOUND

## Self-Check: PASSED
