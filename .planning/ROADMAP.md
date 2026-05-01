# Roadmap: sftp-jailer

**Created:** 2026-04-24
**Last reorganized:** 2026-04-29 — v1.2 milestone opened (Phases 5–7 added)
**Granularity:** coarse
**Parallelization:** enabled
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" — safely, interactively, with observable traffic intel driving every decision.

## Milestones

- ✅ **v1.1 — Hardened Chrooted SFTP** — Phases 1–4 (shipped 2026-04-29) — see [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- 📋 **v1.2 — Packaging & Release** — Phases 5–7 (planned)

## Phases

<details>
<summary>✅ v1.1 Hardened Chrooted SFTP (Phases 1–4) — SHIPPED 2026-04-29</summary>

- [x] Phase 1: Foundation, Diagnostic & TUI Shell (5/5 plans) — completed 2026-04-24
- [x] Phase 2: Observation Pipeline & Read-Only Feature Screens (12/12 plans) — completed 2026-04-26
- [x] Phase 3: Canonical sshd/Chroot Config & User+Key Mutations (10/10 plans) — completed 2026-04-27
- [x] Phase 4: Firewall Mutations & Progressive Lockdown Flagship (13/13 plans, incl. 3 BUG-04-A/C/D gap closures) — completed 2026-04-29

Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md). 67/67 in-scope requirements satisfied. Audit: PASSED.
Phase working dirs archived to `.planning/milestones/v1.1/phases/`.

</details>

### 📋 v1.2 Packaging & Release (Planned)

- [ ] **Phase 5**: Packaging, Install/Purge & Automated Release (DIST-02/03/04/05/08/09/10 — 7 reqs)
- [ ] **Phase 6**: v1.1 Carry-over Closure — Firewall edge + TUI polish (FW-09, TUI-09/10/11 — 4 reqs)
- [ ] **Phase 7**: Retroactive Nyquist Validation Authoring (NYQ-01 — 1 req)

## Phase Details (Active)

### Phase 5: Packaging, Install/Purge & Automated Release

**Goal:** `apt install ./sftp-jailer_*.deb` on a fresh Ubuntu 24.04 box produces a working, lintian-clean installation, and `git tag vX.Y.Z && git push --tags` triggers a GitHub Actions workflow that publishes signed-checksum `.deb` artifacts to the GitHub Release with no manual steps. The same `.deb` also runs the full thesis flow on Debian 13 (lab host 192.168.1.170) — surfacing any apt/systemd/ufw/journald portability deltas before release. Every future v1.x / v2.x release inherits this contract.

**Depends on:** v1.1 milestone (full feature surface). Specifically Phase 3 (`apt purge` reuses the SAFE-06 socket-vs-service sshd reload dispatcher) and Phase 1 (DIST-06 `CGO_ENABLED=0` invariant + `check-go-mod-pins` CI guard already in place).

**Requirements (7):** DIST-02, DIST-03, DIST-04, DIST-05, DIST-08, DIST-09, DIST-10.

**Success criteria** (what must be TRUE):

1. **Local build produces installable artifacts.** `goreleaser release --snapshot --clean` on a developer machine produces `.deb` artifacts for `amd64` and `arm64`. `apt install ./sftp-jailer_<ver>_<arch>.deb` on a fresh Ubuntu 24.04 VM lands `/usr/bin/sftp-jailer`, both systemd unit files, `/var/lib/sftp-jailer/`, and `/usr/share/man/man1/sftp-jailer.1.gz`. The binary is a single static cgo-free executable. *(DIST-02)*
2. **Lintian gate is zero-tolerance.** `lintian --pedantic <deb>` returns zero errors and zero warnings on both architectures. CI fails the release build if either artifact fails the gate. *(DIST-03)*
3. **postinst/prerm round-trips cleanly.** After `apt install`, `postinst` has created the `sftp-jailer` group (idempotent), enabled and started `sftp-jailer-observer.timer`, and initialized `/var/lib/sftp-jailer/observations.db` at the current schema version. `systemctl is-active sftp-jailer-observer.timer` returns `active`. *(DIST-04 / closes deferred half of OBS-01)*
4. **`apt purge` is complete and sshd-aware.** `apt purge sftp-jailer` removes the binary, both systemd units, `/var/lib/sftp-jailer/` (including the observation DB), and `/etc/ssh/sshd_config.d/50-sftp-jailer.conf`. The correct sshd reload is dispatched (per the SAFE-06 socket-vs-service dispatcher), the host's sshd remains running, and existing SSH sessions are not killed. *(DIST-05)*
5. **Automated tag-push release pipeline lands `.deb`s on GitHub Releases.** A GitHub Actions workflow triggered on `vX.Y.Z` tag push runs `goreleaser release`, runs the `lintian --pedantic` gate, attaches the `.deb`s for `amd64` + `arm64` plus `SHA256SUMS.txt` to the GitHub Release, and exits non-zero if any step fails. Every future tagged release inherits this without manual steps. The trigger surface is tag push only (no nightly, no `workflow_dispatch`, no `main`-push builds). *(DIST-08)*
6. **Brownfield purge preserves admin-edited main `sshd_config`.** UAT on a VM where the admin has manually added a non-tool directive to `/etc/ssh/sshd_config`: after `apt install` followed by `apt purge`, only `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` is removed; the admin's main `sshd_config` and any unrelated drop-ins are untouched, byte-identical to pre-install. *(DIST-09)*
7. **Debian 13 thesis flow passes empirical UAT.** On the lab host at `192.168.1.170` (Debian 13), the same `.deb` from criterion 1 installs, the diagnostic posture report renders, the canonical sshd drop-in applies under the `sshd -t` gate, per-user CRUD with passwords + SSH keys works, the observation timer fires and ingests `journalctl --output=json`, and the lockdown commit/rollback cycle completes under the SAFE-04 3-minute revert window. Any apt/systemd/ufw/journald portability delta is filed as a finding; deltas that prevent the thesis flow from completing block the phase. Debian 13 is **not** committed as a tier-1 platform — install/runtime parity is the v1.2 acceptance gate only. *(DIST-10)*

**Empirical UAT acceptance gate:** Two real hosts are the load-bearing acceptance gate for criteria 1, 3, 4, 6, and 7 — matching the v1.1 Phase 4 / Plan 04-10 standard:
- **Ubuntu 24.04 VM** (clean install + brownfield variant) — gates criteria 1, 3, 4, 6
- **Debian 13 host at 192.168.1.170** — gates criterion 7

CI exercises criteria 2 and 5.

**Parallelization hints:** `goreleaser.yaml` + `nfpm.yaml`, `postinst`/`prerm` scripts, man-page authoring, lintian-cleanup pass, and the GitHub Actions workflow yaml are independent workstreams once the v1.1 feature set is frozen (it is). DIST-08 (the GitHub Actions workflow) depends on DIST-02/03/04 working locally — schedule it as the last sub-plan in this phase.

**Plans:** 6 plans (waves 1-5):
- [ ] 05-01-PLAN.md — goreleaser/nfpm declarative pipeline (DIST-02/03)
- [ ] 05-02-PLAN.md — cobra-driven man-page generator + CI freshness gate (DIST-02/03)
- [ ] 05-03-PLAN.md — hidden `purge-sshd-cleanup` cobra subcommand + RemoveSshdDropIn txn step (DIST-04/05/09)
- [ ] 05-04-PLAN.md — Debian maintainer scripts (postinst/prerm/postrm) + brownfield safety (DIST-04/05/09)
- [ ] 05-05-PLAN.md — tag-push GitHub Actions release workflow + lintian gate (DIST-08/03)
- [ ] 05-06-PLAN.md — empirical UAT runbooks (Ubuntu 24.04 + Debian 13) + cmd/uat-05 helper (DIST-04/05/09/10)

---

### Phase 6: v1.1 Carry-over Closure — Firewall edge + TUI polish

**Goal:** Close the v1.1 carry-over tech debt that was opportunistically deferred from Phase 4 — one firewall correctness bug, two UX polish items, and one code-quality cleanup. Independent workstream from packaging; can ship before, after, or in parallel with Phase 5.

**Depends on:** v1.1 milestone (specifically Phase 4 firewall mutation infrastructure and Phase 3 `resolveAsync` paths). No dependency on Phase 5.

**Requirements (4):** FW-09, TUI-09, TUI-10, TUI-11.

**Success criteria:**

1. **BUG-04-B closure on dual-family + v6-only hosts.** `S-LOCKDOWN` commit on a host with a dual-family (IPv4 + IPv6) ufw policy correctly enumerates and atomically deletes both the v4 and v6 catch-all rules in a single pass; on a v6-only host, the same flow operates exclusively against the v6 ruleset. The position-independent enumerate-based deletion (already landed for IPv4 in plans 04-12/13) is extended; the `sftpj:v=1:user=<name>` comment-schema parser is exercised against both families. Empirical UAT on an IPv6-enabled VM is the acceptance gate. *(FW-09)*
2. **`S-SETTINGS` exposes password-aging knobs.** `PasswordAgingDays` and `PasswordStaleDays` are editable from the TUI via textinput modals with positive-integer validation (max 3650), persist via the existing settings writer, and round-trip on TUI restart. Admins no longer need to edit `config.yaml` directly. *(TUI-09)*
3. **Per-user log-detail modal.** Selecting a user in `S-USERS` and pressing the existing detail keybind opens a modal showing that user's last 90 days of login attempts: tier counts (success / targeted / noise / unmatched) plus the last 20 raw entries with timestamps + source IPs. *(TUI-10)*
4. **Cancellable `resolveAsync` paths.** Pressing `Esc` during `addkey`, `deleteuser`, `applysetup`, or `pwauthdisable` sends `SIGTERM` (then `SIGKILL` after a 2s grace) to the in-flight subprocess and only closes the modal after the subprocess exits. Replaces the four detached `context.Background()` sites with cancellable contexts threaded through the `internal/sysops` typed wrappers. *(TUI-11)*

**Empirical UAT acceptance gate:** Criterion 1 requires a real IPv6-enabled Ubuntu 24.04 VM. Criteria 2–4 are TUI-tested via `teatest/v2` golden-file flows + manual smoke on the same VM.

**Parallelization hints:** All four requirements are independent — schedule as parallel plans within the phase.

**Plans:** 4 plans (wave 1, all parallel per D-18):
- [x] 06-01-PLAN.md - FW-09 close BUG-04-B (dual-family + v6-only test fixtures + UAT runbook)
- [x] 06-02-PLAN.md - TUI-09 expose password_aging_days/password_stale_days in S-SETTINGS
- [x] 06-03-PLAN.md - TUI-10 per-user log-detail modal (M-USER-LOG) on uppercase L
- [x] 06-04-PLAN.md - TUI-11 cancellable resolveAsync paths in 4 modals (SIGTERM + 2s SIGKILL grace)

---

### Phase 7: Retroactive Nyquist Validation Authoring

**Goal:** Author `validation_md` for v1.1 Phases 1, 2, and 3 so milestone-level audits have uniform Nyquist coverage across the project. Phase 4 already shipped with `validation_md`; this phase backfills the earlier phases.

**Depends on:** Phases 5 and 6 (so the Nyquist coverage author has the latest behavioral surface to reference). No code is changed in this phase — pure documentation.

**Requirements (1):** NYQ-01.

**Success criteria:**

1. **`validation_md` exists and passes for Phases 1, 2, and 3.** Each phase's `validation_md` (located under the archived `.planning/milestones/v1.1/phases/<phase>/`) enumerates the requirement → test/UAT-evidence map produced retroactively from the existing phase artifacts (PLAN.md, REVIEW.md, VERIFICATION.md, SUMMARY.md). `/gsd:validate-phase 1`, `/gsd:validate-phase 2`, and `/gsd:validate-phase 3` all return PASS.
2. **Milestone-level audit re-runs cleanly.** `/gsd:audit-milestone v1.1` re-run with the new `validation_md` files in place returns PASS with full Nyquist coverage reported (no "missing validation_md" warnings).

**Empirical UAT acceptance gate:** Not applicable — this is documentation work. Validity is verified by the GSD validate-phase / audit-milestone toolchain.

**Parallelization hints:** Phases 1, 2, 3 `validation_md` files can be authored in parallel by separate plans.

**Plans:** TBD — break down via `/gsd:discuss-phase 7` → `/gsd:plan-phase 7`.

---

## Progress

| Milestone | Phase | Plans Complete | Status | Completed |
|-----------|-------|----------------|--------|-----------|
| v1.1 | 1. Foundation, Diagnostic & TUI Shell | 5/5 | ✅ Complete | 2026-04-24 |
| v1.1 | 2. Observation Pipeline & Read-Only Feature Screens | 12/12 | ✅ Complete | 2026-04-26 |
| v1.1 | 3. Canonical sshd/Chroot Config & User+Key Mutations | 10/10 | ✅ Complete | 2026-04-27 |
| v1.1 | 4. Firewall Mutations & Progressive Lockdown Flagship | 13/13 | ✅ Complete | 2026-04-29 |
| v1.2 | 5. Packaging, Install/Purge & Automated Release | 0/6 | 📋 Planned | — |
| v1.2 | 6. v1.1 Carry-over Closure — Firewall edge + TUI polish | 0/4 | 📋 Planned | — |
| v1.2 | 7. Retroactive Nyquist Validation Authoring | 0/TBD | 📋 Planned | — |

## Cross-Phase Notes (v1.2)

**Recommended execution order:** Phase 5 → Phase 6 (or Phase 5 ∥ Phase 6 if a parallel workstream is desired) → Phase 7. Phase 7 explicitly depends on Phases 5 and 6 for accurate Nyquist mapping.

**Tech-debt that will NOT be touched in v1.2** (logged here so it isn't accidentally scoped in):
- Phase 2 informational REVIEW findings (WR-02..05, S-SETTINGS knob exposure beyond TUI-09)
- Phase 3 informational REVIEW findings (the 6 Warning + 8 Info items from `03-REVIEW.md`)
- Phase 4 `portMatchesCatchAllPort` duplication and `cmd/uat-04` Phase 3 redundancy
- Multi-distro / non-Ubuntu portability (locked Out of Scope)

**Deferred beyond v1.2 (per REQUIREMENTS.md Future Requirements):** DIST-v2-01 (cosign-signed reproducible builds), DIST-v2-02 (SLSA L3 provenance), DIST-v2-03 (`linux/arm/v7`), DIST-v3-01 (`.rpm` via nfpm). Not on the v1.x roadmap.

**Empirical UAT remains the load-bearing safety gate** for any phase that touches packaging, runtime behavior, or firewall state — established in v1.1 Phase 4 (Plan 04-10) after BUG-04-A/C/D were caught by it before milestone close.

---

*Roadmap created: 2026-04-24. Last reorganized: 2026-04-29 — v1.2 Phases 5–7 added, v1.1 Phase 5 stub replaced with full v1.2 phase set.*
