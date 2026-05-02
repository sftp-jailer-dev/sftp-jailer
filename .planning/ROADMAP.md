# Roadmap: sftp-jailer

**Created:** 2026-04-24
**Last reorganized:** 2026-05-02 — v1.2 milestone closed (Phases 5–7 archived)
**Granularity:** coarse
**Parallelization:** enabled
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" — safely, interactively, with observable traffic intel driving every decision.

## Milestones

- ✅ **v1.1 — Hardened Chrooted SFTP** — Phases 1–4 (shipped 2026-04-29) — see [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- ✅ **v1.2 — Packaging & Release** — Phases 5–7 (shipped 2026-05-02) — see [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)
- 📋 **v1.3 — TBD** — not yet scoped (run `/gsd:new-milestone`)

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

<details>
<summary>✅ v1.2 Packaging & Release (Phases 5–7) — SHIPPED 2026-05-02</summary>

- [x] Phase 5: Packaging, Install/Purge & Automated Release (7/7 plans, incl. 05-07 DIST-04 gap closure) — completed 2026-04-30
- [x] Phase 6: v1.1 Carry-over Closure — Firewall edge + TUI polish (5/5 plans, incl. 06-05 TUI-11 gap closure) — completed 2026-05-01
- [x] Phase 7: Retroactive Nyquist Validation Authoring (4/4 plans) — completed 2026-05-02

Full archive: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md). 12/12 requirements satisfied (FW-09 with pre-agreed `verified-code, UAT-pending` posture per Phase 6 D-16). Audit (re-run 2026-05-02): [`milestones/v1.2-MILESTONE-AUDIT.md`](milestones/v1.2-MILESTONE-AUDIT.md) — passed. Phase working dirs archived to `.planning/milestones/v1.2-phases/`. v1.2.0 release tag remains gated on operator UAT sign-offs per `.planning/RELEASE-CHECKLIST.md`.

</details>

### 📋 v1.3 (Not yet scoped)

Run `/gsd:new-milestone` to scope v1.3. Carry-over candidates: 9 tech-debt items from v1.2 close (see `milestones/v1.2-MILESTONE-AUDIT.md`), DIST-v2-01 cosign signing, DIST-v2-02 SLSA L3 provenance, DIST-v2-03 `linux/arm/v7`, formal Codeberg mirror + Debian 13 tier-1 commitment.

## Progress

| Milestone | Phase | Plans Complete | Status | Completed |
|-----------|-------|----------------|--------|-----------|
| v1.1 | 1. Foundation, Diagnostic & TUI Shell | 5/5 | ✅ Complete | 2026-04-24 |
| v1.1 | 2. Observation Pipeline & Read-Only Feature Screens | 12/12 | ✅ Complete | 2026-04-26 |
| v1.1 | 3. Canonical sshd/Chroot Config & User+Key Mutations | 10/10 | ✅ Complete | 2026-04-27 |
| v1.1 | 4. Firewall Mutations & Progressive Lockdown Flagship | 13/13 | ✅ Complete | 2026-04-29 |
| v1.2 | 5. Packaging, Install/Purge & Automated Release | 7/7 | ✅ Complete | 2026-04-30 |
| v1.2 | 6. v1.1 Carry-over Closure — Firewall edge + TUI polish | 5/5 | ✅ Complete | 2026-05-01 |
| v1.2 | 7. Retroactive Nyquist Validation Authoring | 4/4 | ✅ Complete | 2026-05-02 |

---

*Roadmap created: 2026-04-24. Last reorganized: 2026-05-02 — v1.2 milestone closed; Phases 5–7 collapsed into archive details block; v1.3 placeholder added.*
