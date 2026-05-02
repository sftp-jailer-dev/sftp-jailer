---
phase: 05-packaging-install-purge-automated-release
plan: "03"
subsystem: purge-subcommand
tags:
  - cobra
  - subcommand
  - sshd-reload
  - txn
  - safe-06
  - dpkg-prerm
dependency_graph:
  requires:
    - 05-02  # man-page generator (Hidden:true verified no man page emitted)
  provides:
    - purge-sshd-cleanup cobra subcommand (invoked by 05-04 prerm)
    - NewRemoveSshdDropInStep txn step (general-purpose drop-in removal)
  affects:
    - 05-04  # debian maintainer scripts: prerm calls this subcommand
    - 05-06  # empirical UAT runbook: exercises prerm -> subcommand -> reload path
tech_stack:
  added: []
  patterns:
    - txn.Step backup-then-remove (mirrors NewWriteSshdDropInStep)
    - Hidden cobra subcommand (dpkg prerm integration)
    - testable seam via package-var purgeStepsFn + purgeOsExit
key_files:
  created:
    - cmd/sftp-jailer/purge_cleanup.go
    - cmd/sftp-jailer/purge_cleanup_test.go
  modified:
    - internal/txn/steps.go
    - internal/txn/steps_test.go
    - cmd/sftp-jailer/main.go
decisions:
  - "D-MS-01: purge sshd reload runs via Go subcommand (single source of truth for SAFE-06; no shell port)"
  - "D-MS-04: Hidden subcommand, idempotent on absent drop-in, no --no-revert flag (dpkg context is non-interactive)"
  - "CONTEXT.md option (b): DropInPath referenced via applysetup.DropInPath (refactor-resistant)"
  - "SAFE-06 dispatcher: ReloadService (NOT RestartSocket) — drop-in removal cannot touch socket directives"
  - "purgeBackupDir = /var/backups/sftp-jailer (outside /var/lib — survives postrm rm -rf)"
metrics:
  duration: "6m 17s"
  completed: "2026-04-29T21:36:26Z"
  tasks_completed: 3
  tasks_total: 3
  files_created: 2
  files_modified: 3
---

# Phase 5 Plan 03: Purge sshd Cleanup Subcommand Summary

One-liner: Hidden cobra subcommand `purge-sshd-cleanup` wired into rootCmd, backed by new `NewRemoveSshdDropInStep` in internal/txn, exercising the same SAFE-06 reload path as the canonical apply flow.

## What Was Done

- Added `NewRemoveSshdDropInStep` + 5 tests to `internal/txn/steps.go` — mirrors `NewWriteSshdDropInStep` contract verbatim (backup-then-remove on Apply; restore-from-backup on Compensate).
- Created `cmd/sftp-jailer/purge_cleanup.go`: Hidden cobra subcommand `purge-sshd-cleanup` that composes `[RemoveSshdDropIn, SshdValidate, SystemctlReload(ReloadService)]` and runs it through `txn.New(ops).Apply`.
- Wired into `rootCmd` via one-line addition to `main.go`'s `rootcmd.Opts.Subcommands` slice — `purgeSshdCleanupCmd()` passed alongside `versionCmd`, `doctorCmd`, `observeRunCmd`.
- Tests cover: Hidden flag, root-cmd registration, `--help` exclusion, step composition order, backup-dir-outside-/var/lib invariant.

## Decisions Implemented

- **D-MS-01** — prerm invokes `/usr/bin/sftp-jailer purge-sshd-cleanup` while the binary is still on disk; all SAFE-06 logic stays in Go (single source of truth, no drift risk vs. the apply path).
- **D-MS-04** — subcommand is `Hidden:true` (not in `--help`, not in generated man pages). SAFE-01 root gate inherited via `rootCmd.PersistentPreRunE`. Idempotent: exits 0 when drop-in already absent. No `--no-revert` flag needed (dpkg prerm is non-interactive).
- **CONTEXT.md "Claude's Discretion" option (b)** — `DropInPath` constant referenced via `applysetup.DropInPath` (refactor-resistant; compile-time drift detected automatically).
- **SAFE-06 dispatcher choice** — `ReloadService` (NOT `RestartSocket`). Drop-in removal cannot touch `Port`/`ListenAddress`/`AddressFamily` because the canonical writer (Phase 3 D-08) never wrote those directives into the drop-in. This matches the apply path's own dispatch for the same reason.

## Load-Bearing Invariant — Backup Dir Outside `/var/lib/sftp-jailer`

`purgeBackupDir = "/var/backups/sftp-jailer"` — deliberately outside `/var/lib/sftp-jailer`.

- 05-04's `postrm` runs `rm -rf /var/lib/sftp-jailer` on `apt purge`. A backup under `/var/lib` would be destroyed during the very operation it is meant to survive.
- Admins can recover the last sshd drop-in's bytes after `apt purge` by reading `/var/backups/sftp-jailer/<ts>-50-sftp-jailer.conf.bak`.
- Test `TestPurgeBackupDir_OutsideVarLib` pins this invariant in CI — a future maintainer moving the backup dir under `/var/lib` will trip the test at PR time.
- The backup directory is root:root, mode 0600 on the backup file itself (matching `NewWriteSshdDropInStep`'s convention).

## Compensator Chain on `sshd -t` Failure

`txn.New(ops).Apply` runs compensators in REVERSE on any step error:

1. `RemoveSshdDropIn.Apply` succeeds → drop-in backed up + removed.
2. `SshdValidate.Apply` fails → rollback begins.
3. `RemoveSshdDropIn.Compensate` runs → restores drop-in from `/var/backups/sftp-jailer/<ts>-50-sftp-jailer.conf.bak`.
4. `SystemctlReload` never ran → no reload compensation needed.

Net effect: if `sshd -t` fails, the drop-in is restored and sshd continues running its prior config (since the reload never fired). The subcommand exits with code 1.

If a compensator itself fails, `isCompensateFailure` detects the "compensate" substring in the joined error string and exits with code 2 (ops-page-able; "ROLLBACK FAILED" printed to stderr).

## Downstream Consumers

- **05-04** prerm script invokes `/usr/bin/sftp-jailer purge-sshd-cleanup` while binary is still on disk (D-MS-01 decision implemented here).
- **05-02** CI guard (`scripts/check-manpage-fresh.sh`) verifies no `docs/man/sftp-jailer-purge-sshd-cleanup.1` is generated (`Hidden:true` filter is respected by `cobra/doc.GenManTree`).
- **05-06** UAT runbook exercises the full `prerm → purge-sshd-cleanup → reload` path on the lab host.

## Verification Commands Run

```
go build ./...                                              # exit 0
go test -count=1 ./internal/txn/...                        # exit 0 (all tests pass)
go test -count=1 ./cmd/sftp-jailer/...                     # exit 0 (all tests pass)
bash scripts/check-no-exec-outside-sysops.sh               # OK
bash scripts/check-go-mod-pins.sh                          # OK (no new deps)
grep -q 'func NewRemoveSshdDropInStep' internal/txn/steps.go   # PASS
grep -q 'Hidden: true' cmd/sftp-jailer/purge_cleanup.go        # PASS
grep -q 'purgeSshdCleanupCmd()' cmd/sftp-jailer/main.go        # PASS
```

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written, with one minor adaptation:

**[Rule 2 - Test Quality] Adjusted `readErrorFake` adapter for `TestRemoveSshdDropIn_Apply_ReadErrorOtherThanNotExist`**

- **Found during:** Task 1 test implementation
- **Issue:** `sysops.Fake` only returns `fs.ErrNotExist` for absent `ReadFile` keys — no per-path error injection map. The plan's test skeleton used `f.ReadFileErrors` (which doesn't exist on the Fake).
- **Fix:** Implemented a minimal `readErrorFake` struct embedding `*sysops.Fake` that overrides `ReadFile` for the specific path under test — consistent with the Go interface discipline used throughout the test suite.
- **Files modified:** `internal/txn/steps_test.go`
- **Commit:** 736669f

**[Rule 2 - Test Quality] Simplified `TestRemoveSshdDropIn_Apply_BackupWriteFailure`**

- **Found during:** Task 1 test implementation
- **Issue:** The plan's skeleton used `f.AtomicWriteFileErrors = map[string]error{...}` (per-path map, doesn't exist). The Fake uses a single `f.AtomicWriteError` field.
- **Fix:** Set `f.AtomicWriteError = errors.New("disk full")` — sufficient because the first `AtomicWriteFile` call in `Apply` is the backup write (the exact call we want to fail). This is the correct sysops.Fake idiom.
- **Files modified:** `internal/txn/steps_test.go`
- **Commit:** 736669f

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The subcommand operates on a compile-time-constant file path (`applysetup.DropInPath`) via existing `sysops.SystemOps` typed wrappers — no new trust boundary surface.

All T-05-03-0x threats from the plan's threat register are addressed:
- T-05-03-01: DropInPath is a Go const (compile-time, no runtime override).
- T-05-03-03: `purgeSshdCleanupTimeout = 30s` bounds the entire txn.
- T-05-03-07: `isCompensateFailure` substring is documented as conservative (over-classifies toward exit 2 — safe direction). Code comment calls out the future tightening path (`errors.Is(err, txn.ErrCompensateFailed)`).

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| cmd/sftp-jailer/purge_cleanup.go exists | FOUND |
| cmd/sftp-jailer/purge_cleanup_test.go exists | FOUND |
| internal/txn/steps.go exists | FOUND |
| 05-03-SUMMARY.md exists | FOUND |
| Commit 736669f (Task 1) exists | FOUND |
| Commit 948ae5c (Task 2) exists | FOUND |
| SUMMARY references D-MS-01, D-MS-04, option (b), SAFE-06, ReloadService | PASS |
| SUMMARY documents backup-dir-outside-/var/lib invariant | PASS |
| SUMMARY names 05-04 and 05-06 as downstream consumers | PASS |
