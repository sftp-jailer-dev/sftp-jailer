---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: - First-Run + Daily-Driver UX
status: executing
last_updated: "2026-05-04T00:25:00.000Z"
last_activity: 2026-05-04 -- Phase 09 Wave 1 complete (09-01, 09-02)
progress:
  total_phases: 9
  completed_phases: 1
  total_plans: 7
  completed_plans: 6
  percent: 86
---

# STATE: sftp-jailer

**Updated:** 2026-05-04 - Phase 09 Wave 1 complete: 09-01 (FW-10 ufwcomment v=1 discriminated union) and 09-02 (LOG-10 migration 004 + WithProgress hook) both merged green. Wave 2 (09-03 dedup queries) ready.

## Project Reference

See `.planning/PROJECT.md` (updated 2026-05-03 - v1.3 Current Milestone block + Active refreshed with 8 target-feature buckets).

**What this is:** Interactive TUI for Linux sysadmins managing a chrooted SFTP server on Ubuntu 24.04 - one supervised flow from "fresh box" to "per-user IP-locked-down SFTP" with observation-driven intel.
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" - safely, interactively, with observable traffic intel driving every decision.
**Current focus:** Phase 09 - data-layer

## Current Position

Phase: 09 (data-layer) - EXECUTING
Plan: Wave 1 complete (2/3); Wave 2 ready (09-03)
Status: Executing Phase 09
Last activity: 2026-05-04 -- Phase 09 Wave 1 merged green

## Accumulated Context

**Validated decisions (frozen at v1.2):** All v1.1 frozen decisions, plus - `goreleaser` v2 + `nfpm` declarative pipeline; `Depends: ufw` (not Recommends, D-MP-02); `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` excluded from dpkg contents (D-LC-02, runtime-owned); tag-push-only release surface (no nightly/workflow_dispatch/main-push); FW-09 family-agnostic by construction with zero production lines changed (D-14); `cmd.WaitDelay = 2s` SIGKILL fallback for cancellable subprocesses (D-07/D-08); Phase 7 documentation-only verdict (no `07-VALIDATION.md`).

**v1.3 architectural commitments locked at roadmap time:**

- Stay on `ufwcomment` Version=1; extend to discriminated union (`user=` vs `scope=subnet:reason=`) - architecture researcher verdict over stack researcher's v=2 proposal because v=2 self-DoSes forward-compat for the dominant user-rule case (verified against `firewall/mode_test.go:65-66`).
- `ufw enable` exits the SAFE-04 contract (P3-A: compensator `ufw disable` leaves rules-but-no-enforcement, a state that didn't exist before the mutation). Confirm-only path with pre-flight allow-rule check + remote-SSH session detection + "type YES" gate.
- Console REPLACES `home` as post-launch landing target; `home` stays in tree as fallback (zero cost, second escape hatch). S-USERS and S-FIREWALL retired from the screen registry per CONSOLE-05; S-LOGS and S-LOCKDOWN remain as drill-downs.
- Build order is 8 -> 9 -> 10 -> 11 -> 13 -> 12 -> 14 (NOT phase-number order). Phase 12 (launch state machine) lands AFTER Phase 13 (console) because the console is the routing target.
- Subnet whitelist aggregation over success-tier IPs ONLY (excludes targeted/noise/unmatched per P5-C); public-tier IPs NEVER auto-aggregated (P5-A threat-model regression: hosting-provider /24 spans many tenants).
- Migration via 3 explicit modes (LINK / REUSE_IN_PLACE / MOVE-with-rsync); never raw `mv`; never symlinks in chroot path; refuse UID < 1000 at compile-time const + runtime guard per P7-A and Phase 3 invariant.
- Zero new third-party dependencies for v1.3; all features ride existing `go.mod` (Go 1.25, Bubble Tea v2.0.6, Bubbles v2.1.0, Lip Gloss v2.0.3, modernc.org/sqlite v1.49.1) plus stdlib `net/netip`. Single static cgo-free 6.7 MB binary envelope holds.

**Open at v1.2 close (operator-gated, not v1.3 scope):** v1.2.0 tag push (gated on 7 RELEASE-CHECKLIST operator sign-offs; resolved 2026-05-02); FW-09 empirical IPv6 VM UAT (pre-agreed deferral per Phase 6 D-16, flips checkbox in v1.2.x point release).

**Carry-over folded into v1.3:** WR-02 (S-SETTINGS in-process refresh) -> TUI-15 in Phase 14; WR-01 (postinst observer.cursor preservation on apt upgrade) -> OBS-08 in Phase 12; WR-04 (unused NewBackupDefaultUfwStep), IN-01 (userlog goroutine cancel on modal pop), IN-03 (rows.Err() ordering), addkey fetch-fallback copy, deleteuser errFatal alignment, WR-03 (lintian-overrides comment cleanup), `docs/man/.gitkeep` removal -> all rolled into DEBT-01 in Phase 14. See `milestones/v1.2-MILESTONE-AUDIT.md` Tech Debt Inventory.

**Empirical UAT acceptance gates (v1.1-established load-bearing safety pattern):** 9 pitfalls require lab-host runs:

- P1-D real-terminal narrow-band rendering (Phase 13 console at 80/100/120 col bands)
- P2-B / P2-D real-DB query plan + migration latency (Phase 9 dedup query on lab observation DB)
- P3-A / P3-B remote-SSH session-cut semantics + SAFE-04 revert end-state (Phase 8 ufw-enable)
- P4-A timer-vs-launch race window (Phase 12 launch within 5s of scheduled timer fire)
- P5-A / P5-B operator perception of subnet over-aggregation (Phase 11 subnet proposal against actual lab observation DB)
- P6-A slow-VM keystroke-vs-timer race (Phase 12 Esc at t=1990ms)
- P7-A chroot path-walk + filesystem ownership real-world (Phase 10 migration on lab host)
- P9-A / P9-B rapid add+delete cycle (Phase 13 console refresh contract)

Lab convention per memory: connect as `jnuyens` + sudo, not root; aliases `ubuntu-wifi` (192.168.1.187 Ubuntu 24.04, tier-1) and `debian13` (192.168.1.170 Debian 13, install/runtime parity only - not tier-1).

### Quick Tasks Completed (v1.2)

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260502-3tf | RELEASE-CHECKLIST.md Build+Test pre-flight + lintian on Debian 13 lab (initial 13/17, GREEN 17/17 after lga) | 2026-05-02 | (no commit - verification only, commit_docs=false) | [260502-3tf-run-release-checklist-md-pre-flight-buil](./quick/260502-3tf-run-release-checklist-md-pre-flight-buil/) |
| 260502-jv2 | govulncheck pre-flight item 4 closed: Go 1.25.9 + govulncheck v1.3.0 on Debian 13 lab; exit 0 / zero vulns against origin/main HEAD 96db0bd6 | 2026-05-02 | (no commit - verification only, commit_docs=false) | [260502-jv2-install-govulncheck-on-linux-host-and-re](./quick/260502-jv2-install-govulncheck-on-linux-host-and-re/) |
| 260502-j5x | lintian --pedantic cleanup: 5E+4W+1 unused override eliminated (goreleaser.yml /usr/lib paths + xz + gzip -n; lintian-overrides re-pin; changelog wrap; .gz regen) | 2026-05-02 | 55cbd6a | [260502-j5x-fix-lintian-pedantic-findings-16-17-from](./quick/260502-j5x-fix-lintian-pedantic-findings-16-17-from/) |
| 260502-kr0 | Pre-flight items 3, 16, 17 re-run on Debian 13 lab against origin/main 96db0bd6 (later determined to be unfixed-baseline artifact: kr0 lab built before j5x merge) | 2026-05-02 | (no commit - verification only, commit_docs=false) | [260502-kr0-re-run-pre-flight-items-3-16-17-against-](./quick/260502-kr0-re-run-pre-flight-items-3-16-17-against-/) |
| 260502-lga | Lintian regression follow-up: Decision A - no source edits; pushed origin main 96db0bd to 55cbd6a; fresh-clone + goreleaser snapshot + lintian = 0E+0W+0U on both archs; 17/17 GREEN | 2026-05-02 | (push only - no source-config commits per Decision A; commit_docs=false) | [260502-lga-fix-lintian-regressions-on-rebuilt-deb-a](./quick/260502-lga-fix-lintian-regressions-on-rebuilt-deb-a/) |
| 260502-wc2 | v1.2.1 first-run UX polish: 3 atomic commits - fd02081 fix(rootcmd): wire --version flag on root cobra command (byte-identical output to `version` subcommand) + cd87b99 chore(ux): rename "canonical config" to "SFTP jail configuration" in user-facing strings (8 files; internal Go symbols + docs/uat/*.md preserved) + 3e68e74 fix(doctor): respect Match Group sftp-jailer ForceCommand override on subsystem check (false-positive fix; 3 new tests; suppresses [A] when override resolves only failing detector). Plus follow-up f9fa6f3 fix(rootcmd): check fmt.Fprintf return in version test (errcheck) - lint regression caught by release pipeline run 25262610672 after first v1.2.1 tag push; tag deleted + recreated at f9fa6f3; pipeline run 25263088194 GREEN; release published. | 2026-05-03 | fd02081, cd87b99, 3e68e74, f9fa6f3 | [260502-wc2-v1-2-1-first-run-ux-polish-version-flag-](./quick/260502-wc2-v1-2-1-first-run-ux-polish-version-flag-/) |
| 260503-0tn | v1.2.2 doctor + empty-state correctness fixes: 2 atomic commits - 13fe5a4 fix(doctor): detect inactive ufw and surface [FAIL] + [A] Enable ufw label (closes the false-negative where doctor reported all-OK while S-FIREWALL showed "ufw status reports inactive"; label-only, mutation handler deferred to v1.3 with SAFE-04 timer coverage; 4 new doctor tests + 3 new render tests) + 0eeb32d chore(ux): rewrite S-USERS empty-state copy (drops "Phase 3" jargon, surfaces [n] Add a user). go test PASS, golangci-lint 0 issues, all 5 architectural CI guards PASS. Targeting v1.2.2 patch tag (operator pushes manually). | 2026-05-03 | 13fe5a4, 0eeb32d | [260503-0tn-v1-2-2-doctor-empty-state-correctness-fi](./quick/260503-0tn-v1-2-2-doctor-empty-state-correctness-fi/) |

**Planned Phase:** 08 (Frame) — 4 plans — 2026-05-03T11:30:18.473Z
