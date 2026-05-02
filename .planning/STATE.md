---
gsd_state_version: 1.0
milestone: v1.2
milestone_name: Packaging & Release
status: shipped
last_updated: "2026-05-02T18:00:00Z"
last_activity: 2026-05-02 - Milestone v1.2 closed via /gsd:complete-milestone. Archives written (milestones/v1.2-ROADMAP.md, milestones/v1.2-REQUIREMENTS.md, milestones/v1.2-MILESTONE-AUDIT.md), MILESTONES.md entry appended, PROJECT.md evolved (v1.2 reqs moved to Validated, v1.2.x close-out + 9 carry-over tech-debt items moved to Active for v1.3 review, Key Decisions extended with v1.2 D-MP-02/D-LC-02/D-14/D-16/D-07-08/Phase-7-doc-only verdict), ROADMAP.md collapsed (Phases 5-7 in details block), REQUIREMENTS.md removed via git rm, phase dirs archived to milestones/v1.2-phases/, RETROSPECTIVE.md created with v1.1 + v1.2 sections, git tag v1.2 created. v1.2.0 release tag push remains a separate operator action gated on RELEASE-CHECKLIST sign-offs.
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 16
  completed_plans: 16
  percent: 100
---

# STATE: sftp-jailer

**Updated:** 2026-05-02 - Milestone v1.2 archived. Run `/gsd:new-milestone` to scope v1.3 (carry-over candidates documented in PROJECT.md Active section + `milestones/v1.2-MILESTONE-AUDIT.md` tech-debt inventory).

## Project Reference

See `.planning/PROJECT.md` (updated 2026-05-02 - v1.2 close-out: shipped reqs moved to Validated, Active section refreshed for v1.3 scoping).

**What this is:** Interactive TUI for Linux sysadmins managing a chrooted SFTP server on Ubuntu 24.04 - one supervised flow from "fresh box" to "per-user IP-locked-down SFTP" with observation-driven intel.
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" - safely, interactively, with observable traffic intel driving every decision.
**Current focus:** Between milestones. Run `/gsd:new-milestone` to scope v1.3.

## Current Position

Milestone: v1.2 (Packaging & Release) — SHIPPED 2026-05-02. All 3 phases complete (Phases 5, 6, 7). 12/12 reqs satisfied. Audit passed.
Status: Between milestones — no active scope. v1.2.0 release tag push is an operator action gated on RELEASE-CHECKLIST sign-offs (separate from milestone close).
Next gate: scope v1.3 via `/gsd:new-milestone`, OR push `v1.2.0` after operator UAT sign-offs.

## Accumulated Context

**Validated decisions (frozen at v1.2):** All v1.1 frozen decisions, plus — `goreleaser` v2 + `nfpm` declarative pipeline; `Depends: ufw` (not Recommends, D-MP-02); `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` excluded from dpkg contents (D-LC-02, runtime-owned); tag-push-only release surface (no nightly/workflow_dispatch/main-push); FW-09 family-agnostic by construction with zero production lines changed (D-14); `cmd.WaitDelay = 2s` SIGKILL fallback for cancellable subprocesses (D-07/D-08); Phase 7 documentation-only verdict (no `07-VALIDATION.md`).

**Open at v1.2 close (operator-gated, not v1.3 scope):** v1.2.0 tag push (gated on 7 RELEASE-CHECKLIST operator sign-offs); FW-09 empirical IPv6 VM UAT (pre-agreed deferral per Phase 6 D-16, flips checkbox in v1.2.x point release).

**Carry-over for v1.3 review (9 tech-debt items):** WR-02 S-SETTINGS in-process refresh; WR-01 postinst observer.cursor preservation on apt upgrade; WR-04 unused NewBackupDefaultUfwStep; IN-01 userlog goroutine cancel on modal pop; IN-03 rows.Err() ordering; addkey fetch-fallback copy refresh; deleteuser errFatal alignment; WR-03 lintian-overrides comment cleanup; `git rm docs/man/.gitkeep`. See `milestones/v1.2-MILESTONE-AUDIT.md` Tech Debt Inventory.

### Quick Tasks Completed (v1.2)

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260502-3tf | RELEASE-CHECKLIST.md Build+Test pre-flight + lintian on Debian 13 lab (initial 13/17, GREEN 17/17 after lga) | 2026-05-02 | (no commit — verification only, commit_docs=false) | [260502-3tf-run-release-checklist-md-pre-flight-buil](./quick/260502-3tf-run-release-checklist-md-pre-flight-buil/) |
| 260502-jv2 | govulncheck pre-flight item 4 closed: Go 1.25.9 + govulncheck v1.3.0 on Debian 13 lab; exit 0 / zero vulns against origin/main HEAD 96db0bd6 | 2026-05-02 | (no commit — verification only, commit_docs=false) | [260502-jv2-install-govulncheck-on-linux-host-and-re](./quick/260502-jv2-install-govulncheck-on-linux-host-and-re/) |
| 260502-j5x | lintian --pedantic cleanup: 5E+4W+1 unused override eliminated (goreleaser.yml /usr/lib paths + xz + gzip -n; lintian-overrides re-pin; changelog wrap; .gz regen) | 2026-05-02 | 55cbd6a | [260502-j5x-fix-lintian-pedantic-findings-16-17-from](./quick/260502-j5x-fix-lintian-pedantic-findings-16-17-from/) |
| 260502-kr0 | Pre-flight items 3, 16, 17 re-run on Debian 13 lab against origin/main 96db0bd6 (later determined to be unfixed-baseline artifact: kr0 lab built before j5x merge) | 2026-05-02 | (no commit - verification only, commit_docs=false) | [260502-kr0-re-run-pre-flight-items-3-16-17-against-](./quick/260502-kr0-re-run-pre-flight-items-3-16-17-against-/) |
| 260502-lga | Lintian regression follow-up: Decision A — no source edits; pushed origin main 96db0bd→55cbd6a; fresh-clone + goreleaser snapshot + lintian = 0E+0W+0U on both archs; 17/17 GREEN | 2026-05-02 | (push only — no source-config commits per Decision A; commit_docs=false) | [260502-lga-fix-lintian-regressions-on-rebuilt-deb-a](./quick/260502-lga-fix-lintian-regressions-on-rebuilt-deb-a/) |
