---
gsd_state_version: 1.0
milestone: v1.2
milestone_name: Packaging & Release
status: verifying
last_updated: "2026-04-30T22:46:24.581Z"
last_activity: 2026-04-30 -- Plan 05-07 (postinst-init-db) executed; 6 commits on main, all tests green
progress:
  total_phases: 1
  completed_phases: 1
  total_plans: 7
  completed_plans: 7
  percent: 100
---

# STATE: sftp-jailer

**Updated:** 2026-04-30 - Phase 5 plan 05-07 (gap-closure for DIST-04 SC3) executed. Hidden `sftp-jailer init-db` cobra subcommand added; postinst now invokes it between `install -d` and observer.cursor pre-create (guarded `[ -x /usr/bin/sftp-jailer ]`, `set -e` propagates failure). UAT runbooks gained step 2.4 (Ubuntu 24.04) / D.2.4 (Debian 13) verifying observations.db exists at install time with `PRAGMA user_version >= 1`. Full `go test ./...` green; `bash scripts/check-no-exec-outside-sysops.sh` green. Truth #3 in 05-VERIFICATION.md remains `partial` until empirical re-UAT on real hosts captures the new step 2.4/D.2.4 evidence.

## Project Reference

See `.planning/PROJECT.md` (updated 2026-04-29 - v1.2 Current Milestone block + DIST-08 added).

**What this is:** Interactive TUI for Linux sysadmins managing a chrooted SFTP server on Ubuntu 24.04 - one supervised flow from "fresh box" to "per-user IP-locked-down SFTP" with observation-driven intel.
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" - safely, interactively, with observable traffic intel driving every decision.
**Current focus:** Phase 05 - packaging-install-purge-automated-release (code complete, re-UAT pending)

## Current Position

Phase: 05 (packaging-install-purge-automated-release) - CODE COMPLETE, RE-UAT PENDING
Plan: 7 of 7 complete (05-01..05-07 SUMMARY.md on disk, committed)
Status: Phase 05 code shipped; empirical re-UAT against Ubuntu 24.04 + Debian 13 (192.168.1.170) is the final gate before VERIFICATION truth #3 moves from `partial` to `verified`.
Last activity: 2026-04-30 -- Plan 05-07 (postinst-init-db) executed; 6 commits on main, all tests green
Resume file: --resume-file

## Accumulated Context

**Validated decisions (frozen at v1.1):** Single Go-binary cgo-free; Bubble Tea v2 at `charm.land/bubbletea/v2`; hand-rolled `sshd_config` parser; drop-in at `/etc/ssh/sshd_config.d/50-sftp-jailer.conf`; firewall-only per-user IP enforcement with `sftpj:v=1:user=<name>` versioned comments; `systemd-run --on-active=3min` for SAFE-04 auto-revert; all subprocess invocations through `internal/sysops` package + CI guard; reload dispatcher per Launchpad #2069041; empirical UAT on real Ubuntu 24.04 box as load-bearing acceptance gate.

**Open carry-over from v1.1 (close opportunistically in v1.2):** BUG-04-B dual-family + v6-only edge; `PasswordAgingDays`/`PasswordStaleDays` in S-SETTINGS UI; per-user log-detail modal; detached `context.Background()` in 4 resolveAsync paths; missing `validation_md` for Phases 1, 2, 3 (Phase 4 already Nyquist-compliant).

**Planned Phase:** 5 (packaging-install-purge-automated-release) - 7 plans - 2026-04-30T12:54:26.626Z
