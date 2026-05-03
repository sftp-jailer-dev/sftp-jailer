# Roadmap: sftp-jailer

**Created:** 2026-04-24
**Last reorganized:** 2026-05-03 - v1.3 milestone opened (Phases 8-14 added)
**Granularity:** coarse
**Parallelization:** enabled
**Core value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" - safely, interactively, with observable traffic intel driving every decision.

## Milestones

- ✅ **v1.1 - Hardened Chrooted SFTP** - Phases 1-4 (shipped 2026-04-29) - see [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- ✅ **v1.2 - Packaging & Release** - Phases 5-7 (shipped 2026-05-02) - see [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)
- 🚧 **v1.3 - First-Run + Daily-Driver UX** - Phases 8-14 (defining; 38 requirements scoped 2026-05-03)

## Phases

<details>
<summary>✅ v1.1 Hardened Chrooted SFTP (Phases 1-4) - SHIPPED 2026-04-29</summary>

- [x] Phase 1: Foundation, Diagnostic & TUI Shell (5/5 plans) - completed 2026-04-24
- [x] Phase 2: Observation Pipeline & Read-Only Feature Screens (12/12 plans) - completed 2026-04-26
- [x] Phase 3: Canonical sshd/Chroot Config & User+Key Mutations (10/10 plans) - completed 2026-04-27
- [x] Phase 4: Firewall Mutations & Progressive Lockdown Flagship (13/13 plans, incl. 3 BUG-04-A/C/D gap closures) - completed 2026-04-29

Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md). 67/67 in-scope requirements satisfied. Audit: PASSED.
Phase working dirs archived to `.planning/milestones/v1.1/phases/`.

</details>

<details>
<summary>✅ v1.2 Packaging & Release (Phases 5-7) - SHIPPED 2026-05-02</summary>

- [x] Phase 5: Packaging, Install/Purge & Automated Release (7/7 plans, incl. 05-07 DIST-04 gap closure) - completed 2026-04-30
- [x] Phase 6: v1.1 Carry-over Closure - Firewall edge + TUI polish (5/5 plans, incl. 06-05 TUI-11 gap closure) - completed 2026-05-01
- [x] Phase 7: Retroactive Nyquist Validation Authoring (4/4 plans) - completed 2026-05-02

Full archive: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md). 12/12 requirements satisfied (FW-09 with pre-agreed `verified-code, UAT-pending` posture per Phase 6 D-16). Audit (re-run 2026-05-02): [`milestones/v1.2-MILESTONE-AUDIT.md`](milestones/v1.2-MILESTONE-AUDIT.md) - passed. Phase working dirs archived to `.planning/milestones/v1.2-phases/`. v1.2.0 release tag remains gated on operator UAT sign-offs per `.planning/RELEASE-CHECKLIST.md`.

</details>

### 🚧 v1.3 First-Run + Daily-Driver UX (Phases 8-14)

- [ ] **Phase 8: Frame** - Cross-cutting prerequisites: ufw-enable mutation handler, B4 deletion, ChrootDir confirm-or-edit, doctor wording fix
- [ ] **Phase 9: Data Layer** - ufwcomment v=1 discriminated union + log dedup query + migration `004` covering index
- [ ] **Phase 10: Migrate** - System-user migration screen with 3 modes (LINK / REUSE_IN_PLACE / MOVE-with-rsync) + UID >= 1000 invariant
- [ ] **Phase 11: Subnet** - Pre-lockdown subnet whitelist (RFC1918/RFC4193/link-local longest-prefix detection) with operator-tunable thresholds
- [ ] **Phase 13: Console (flagship)** - Unified per-user management overview replacing S-USERS + S-FIREWALL; landing-screen target after launch green-gate
- [ ] **Phase 12: Launch** - Auto-doctor + auto-route + auto-observer launch state machine (lands AFTER Phase 13 because console is the routing target)
- [ ] **Phase 14: Footer + Friendliness + Tech Debt** - Per-screen `KeyHints()` nav-footer + friendliness rename pass + 9 v1.2 carry-over items + Node 24 GH Actions + cosign signing

## Phase Details

### Phase 8: Frame

**Goal**: Cross-cutting prerequisites land first so the unified console + launch state machine can build on stable surfaces. Operator-visible value early via `[A] Enable ufw` mutation closing the v1.2.2 label-only deferral.

**Depends on**: Nothing (first v1.3 phase)

**Requirements**: SETUP-07, SETUP-08, FW-11, TUI-12 (4 requirements)

**Plans**: 4 plans

**Success Criteria** (what must be TRUE):
  1. Operator running new-user flow no longer sees the B4 `/etc/shells` pre-flight; the chroot-chain walk pre-flight stays in place and still catches root-owned-with-no-group-write violations.
  2. Operator running the SFTP jail apply flow is shown the canonical default ChrootDirectory `/srv/sftp-jailer/%u` with a confirm-or-edit step before the drop-in is written.
  3. Operator pressing `[A]` on the doctor "ufw inactive" row triggers a confirm-only mutation (NOT SAFE-04: `ufw disable` would leave a strictly-worse state per P3-A) that runs `ufw --force enable` after a "type YES" gate plus pre-flight allow-rule check plus remote-SSH-session detection; post-enable doctor re-check confirms ufw status reports active.
  4. Doctor "ufw inactive" row copy includes the inline `systemctl is-active` vs `ufw status` divergence note (operator-locked at v1.2.2 close).

**UAT gate**: Empirical UAT REQUIRED on lab hosts ubuntu-wifi (192.168.1.187) + debian13 (192.168.1.170). P3-A and P3-B (SAFE-04 boundary; remote-SSH session-cut semantics) cannot be caught by CI - operator must run `[A] Enable ufw` from a real SSH session and confirm pre-flight blocks correctly. Architectural Key Decision logged in PROJECT.md: "SAFE-04 boundary - non-self-revertable mutations use confirm-only."

**Plans**:
- [ ] 08-01-PLAN.md — SETUP-08 (B4 deletion) + TUI-12 (doctor copy update); Wave 1 parallel-safe
- [ ] 08-02-PLAN.md — SETUP-07 (ChrootDir confirm-or-edit in apply flow); Wave 1 parallel-safe
- [ ] 08-03-PLAN.md — FW-11 foundations: sysops EnableUFW + ShowUFWAdded, firewall pending parser + SSHAllowPresent, doctor.NeedsUfwEnable, addrule AutoRevert flag; Wave 1 parallel-safe
- [ ] 08-04-PLAN.md — FW-11 composition: ufwenable modal + doctor [a] precedence dispatch + > marker + footer hint + lab-host UAT; Wave 2 (depends on 08-01 + 08-03)

---

### Phase 9: Data Layer

**Goal**: Pure data-layer additions (ufwcomment grammar extension + new dedup index migration + new typed query) that Phase 11 (subnet whitelist) and Phase 13 (console) both depend on. Schema bumps from `user_version=3` to `user_version=4`.

**Depends on**: Phase 8 (CI green; non-blocking but ordered for ufwcomment audit)

**Requirements**: FW-10, LOG-07, LOG-08, LOG-09, LOG-10 (5 requirements)

**Plans**: ~2-3 plans hint

**Success Criteria** (what must be TRUE):
  1. `internal/ufwcomment` decodes both `sftpj:v=1:user=<name>` (existing) and `sftpj:v=1:scope=subnet:reason=<rfc1918|rfc4193|link-local|operator>` (new) shapes; v1.2.x binaries continue to safely treat the new shape as foreign per the `ErrBadVersion` forward-compat contract pinned in `firewall/mode_test.go`.
  2. S-LOGS default mode renders one row per `(source_ip, username)` pair with humanized last-seen, count, and tier classification; tier-colored rows (success=green, targeted=red, noise=gray, unmatched=yellow).
  3. Operator pressing Enter on a deduplicated row drills down to full per-`(source_ip, username)` event history reading the underlying `observations` table; every connection remains accessible.
  4. Migration `004_add_dedup_index.sql` ships covering index `observation_runs(source_ip, username, ts_unix_ns DESC)`; `EXPLAIN QUERY PLAN` regression test asserts `USING COVERING INDEX`; `user_version` bumps to 4.

**UAT gate**: Empirical UAT REQUIRED for P2-B (real-DB query plan on lab observation DB) + P2-D (migration latency on lab host with 6 months of attack noise). Synthetic 100k-row benchmark in CI; lab-host measurement to confirm <100ms first-paint and acceptable migration UX (block-on-launch with progress label vs lazy-with-warning is a plan-check decision).

**Plans**: TBD

---

### Phase 10: Migrate

**Goal**: Brownfield-safe bulk migration of existing system users into the `sftp-jailer` group with three operator-selected modes and full M-DRY-RUN preview. Closes the "fresh apt install + I already have SFTP users" friction. CRITICAL P7-A safety design lives here.

**Depends on**: Nothing in v1.3 (parallel-safe with Phases 8, 9)

**Requirements**: USER-15, USER-16, USER-17, USER-18 (4 requirements)

**Plans**: ~2-3 plans hint

**Success Criteria** (what must be TRUE):
  1. Operator opens the migration screen and sees a multi-select toggle list of candidates discovered as the union of (a) users owning a directory under the configured chroot root NOT in `sftp-jailer` group AND (b) members of any `sftp*` group NOT in `sftp-jailer` group; each row shows username, UID, group memberships, chroot-dir match status, home-dir path.
  2. Per-user migration mode is one of three: LINK (symlink chroot-side to existing home), REUSE_IN_PLACE (chown existing chroot-dir, no file movement), MOVE-with-rsync (relocate $HOME contents to chroot root then chown). NEVER raw `mv`. NEVER symlinks in the chroot path.
  3. Migration refuses UID < 1000 candidates at both compile-time const and runtime guard (operator-locked Phase 3 invariant: SFTP users stay regular users with real home dirs and authorized_keys, not service accounts).
  4. M-DRY-RUN modal previews all selected migrations together (one diff per user with mode, source, destination, chown plan); on confirm, migrations commit as a single batch through `internal/txn`; per-user backups land under `.pre-migrate-<timestamp>` and are retained 30 days.

**UAT gate**: Empirical UAT REQUIRED for P7-A (migrate-user data loss / unreadable files / chroot path-walk + filesystem ownership real-world). Operator runs migration on lab host against a non-jnuyens fixture user across all 3 modes; asserts primary GID preserved, supplementary groups extended (not replaced), `~/.ssh/authorized_keys` byte-identical pre/post, and `.pre-migrate-<timestamp>` backup recoverable.

**Plans**: TBD

---

### Phase 11: Subnet

**Goal**: Pre-lockdown subnet whitelist detector recognizes RFC1918 / RFC4193 / link-local clusters in observed success-tier IPs and offers operator-tunable longest-matching-prefix proposals before falling through to per-IP enumeration. CRITICAL P5-A safety design lives here.

**Depends on**: Phase 9 (ufwcomment v=1 discriminated union; new `scope=subnet:reason=...` payload writer)

**Requirements**: LOCK-10, LOCK-11, LOCK-12, LOCK-13 (4 requirements)

**Plans**: ~2-3 plans hint

**Success Criteria** (what must be TRUE):
  1. Pre-lockdown subnet detector runs longest-matching-prefix scan over success-tier IPs ONLY (excludes targeted, noise, unmatched); public-tier IPs are NEVER auto-aggregated (threat-model regression: hosting-provider /24 spans many tenants).
  2. Cluster recognition limited to RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC4193 (`fc00::/7`), and link-local (`169.254.0.0/16`, `fe80::/10`) ranges via stdlib `net/netip.Addr.IsPrivate` + `IsLinkLocalUnicast`.
  3. Operator confirming a subnet proposal sees the M-DRY-RUN modal extended with the proposed subnet rule alongside the explicit list of covered IPs (so they can audit "you're allowing 10.0.0.0/24, which covers 10.0.0.5, 10.0.0.7, 10.0.0.12 from observed connections plus any future 10.0.0.x").
  4. Operator-tunable thresholds in S-SETTINGS with defaults 60% in /24, 75% in /16, 90% in /8 (deeper prefix = stricter bar); subnet detection is suppressed when the cluster does not meet the threshold; lockdown falls back to per-IP enumeration.

**UAT gate**: Empirical UAT REQUIRED for P5-A (operator perception of subnet over-aggregation; the math being right is necessary but not sufficient) + P5-B (mixed RFC1918 false grouping). Operator runs subnet proposal against the actual lab-host observation DB and confirms longest-prefix matches expectations across mixed-RFC1918, single-/24, and public+private-mix topologies.

**Plans**: TBD

---

### Phase 13: Console (flagship)

**Goal**: Single management overview replacing `home` as default landing target and retiring S-USERS + S-FIREWALL screens. One row per SFTP user with cross-lane data join (user state + firewall posture + observation tier counts). Per-row keybinds dispatch to existing modal factories (no new modals). The v1.3 flagship.

**Depends on**: Phase 8 (B4 + ufw-enable + ChrootDir confirm), Phase 9 (ufwcomment grammar + dedup query / index), Phase 10 (migration drill-down available from empty-state), Phase 11 (subnet rule rendering in firewall column)

**Requirements**: CONSOLE-01, CONSOLE-02, CONSOLE-03, CONSOLE-04, CONSOLE-05, CONSOLE-06, CONSOLE-07 (7 requirements)

**Plans**: ~3-4 plans hint

**Success Criteria** (what must be TRUE):
  1. Operator launching post-green-gate lands on a single management overview screen replacing `home` as default landing target; one row per SFTP user with columns username, UID, group memberships, password aging state (days until force-change), SSH key count, firewall rule count + lockdown coverage indicator, last-seen IP, observation tier counts (success / targeted / noise / unmatched).
  2. Per-row keybinds work as documented (lowercase mutates current row, uppercase navigates or destructive): `a`/`k` add SSH key, `p` set/reset password, `r`/`f` add/edit firewall rule, `D` delete user firewall rules, `d` delete user, `L` open per-user log detail; cursor navigation (`j`/`k`/`g`/`G`), sort cycle, fuzzy `/` search, OSC52 yank-row preserved from existing S-USERS conventions.
  3. S-USERS and S-FIREWALL screens are retired from the screen registry (their per-screen Go files removed); S-LOGS (drill-down via `L` or `l`) and S-LOCKDOWN (drill-down via top-bar action) remain reachable from the console as drill-down screens.
  4. Console renders correctly at 80, 100, 120 column terminal widths with column-priority truncation (drop low-priority columns first; never collapse cursor or username); golden-file tests cover all three width bands with no broken ANSI escape sequences mid-line.
  5. Adding or deleting a user from a console drill-down modal reflects in the table on modal-pop without manual refresh (single `UnifiedConsoleRefreshMsg` contract; optimistic UI with debounce-during-interaction).

**Plans**: TBD
**UI hint**: yes

**UAT gate**: Empirical UAT REQUIRED for P1-D (real-terminal narrow-band rendering at 80 / 100 / 120 col bands; golden files alone insufficient for human-perception of "where did the column go?") + P9-A / P9-B (rapid add+delete cycle for stale data and ghost rows).

---

### Phase 12: Launch

**Goal**: Auto-doctor on TUI launch with green-gate countdown and Esc-to-stay; auto-route to landing target (Phase 13's console if green, doctor screen if not); fire `observe-run` async after green-gate so log data is fresh on first interaction; close v1.2 WR-01 (postinst observer.cursor truncation). Lands AFTER Phase 13 because the console is the routing target.

**Depends on**: Phase 13 (console is the post-green-gate landing target). Also touches Phase 8's doctor wording and Phase 9's observer pipeline.

**Requirements**: LAUNCH-01, LAUNCH-02, LAUNCH-03, LAUNCH-04, LAUNCH-05, OBS-07, OBS-08 (7 requirements)

**Plans**: ~3 plans hint

**Success Criteria** (what must be TRUE):
  1. TUI launch runs doctor automatically before showing any interactive screen; doctor scan results are presented as the launch screen content; when all 6 sections return `[OK]`, the launch screen counts down 2 seconds and auto-continues; ANY keystroke (not just Esc) pauses the countdown indefinitely; resize is treated as an interaction and pauses the countdown.
  2. After green-gate auto-continue, TUI routes to the unified management console (Phase 13's CONSOLE-01); non-green doctor pins on the doctor screen until operator dispatches an `[A]` action and doctor re-runs green.
  3. TUI launch fires `observe-run` async (goroutine via `tea.Cmd` + `*tea.Program.Send`) after the green-gate; `flock` single-flight on `/var/lib/sftp-jailer/observer.lock` protects against concurrent timer fire; skip if an observer run completed within the configured recent-run window (default 5 minutes; tunable in S-SETTINGS).
  4. Splash logo is enlarged to fill more of the terminal; auto-dismiss timeout is extended by 1 second over the v1.2.x value.
  5. postinst no longer truncates `observer.cursor` unconditionally on `apt upgrade`; the cursor is preserved across upgrades; re-ingestion of the last 7 days only triggers when the cursor is missing or invalid (closes v1.2 WR-01).

**Plans**: TBD
**UI hint**: yes

**UAT gate**: Empirical UAT REQUIRED for P4-A (timer-vs-launch race window: launch TUI within 5s of scheduled timer fire on lab host; assert single run, no duplicate rows) + P6-A (slow-VM keystroke-vs-timer race: Esc at t=1990ms must reliably stop auto-route).

---

### Phase 14: Footer + Friendliness + Tech Debt

**Goal**: Cross-cutting refactor that touches every screen (per-screen `KeyHints() []Hint` migration to new nav-footer widget); friendliness rename pass with centralized strings.go + stable IDs to preserve audit trail; close 9 v1.2 carry-over tech debt items; Node 24 GitHub Actions migration ahead of 2026-06-02 forced deadline; cosign-keyless-signed reproducible releases.

**Depends on**: All other v1.3 phases (touches every screen migrated in Phases 8-13; do last to avoid churn during flagship development)

**Requirements**: TUI-13, TUI-14, TUI-15, DEBT-01, DIST-11, DIST-12 (6 requirements)

**Plans**: ~3-4 plans hint

**Success Criteria** (what must be TRUE):
  1. Every screen renders a multi-line nav-footer using a per-screen `KeyHints() []Hint` (or richer struct) interface; colors match the SFTP-JAILER logo palette (centralized in `internal/tui/widgets/palette.go`); footer degrades gracefully on terminals narrower than 80 columns (truncate or wrap keys; never blank); ANSI reset codes appended unconditionally at every line end.
  2. User-facing strings centralized with stable string IDs (e.g., `LBL_APPLY_DROPIN_TITLE`); friendliness pass scans all user-facing strings for remaining dev-jargon (continuation of v1.2.1 "canonical config" rename); addkey fetch-fallback copy refreshed; `docs/uat/*.md` historical sign-offs preserved (audit trail invariant).
  3. S-SETTINGS save propagates password-aging values to in-process `usersCfg` without requiring TUI restart (closes v1.2 WR-02 carry-over).
  4. Six v1.2 carry-over tech-debt items closed: dead `NewBackupDefaultUfwStep` removed; userlog read-only goroutines cancel on modal pop; `rows.Err()` ordering fixed in queries.go; `deleteuser.Model` aligned with `errFatal` field; lintian-overrides WHY block comment cleaned up; `docs/man/.gitkeep` removed.
  5. GitHub Actions release + CI workflows migrated off Node 20 ahead of the 2026-06-02 forced-Node-24 deadline; cosign-keyless-signed reproducible releases (`cosign sign-blob` over each `.deb` + `SHA256SUMS.txt` + goreleaser manifest); verification instructions added to README and verified on a clean machine via `cosign verify-blob`.

**Plans**: TBD
**UI hint**: yes

**UAT gate**: P8 family (footer overflow / broken ANSI mid-line / palette drift) covered by golden-file tests at 80/100/160/200 cols + cross-screen palette-consistency unit test; P10 family (rename scope discipline) covered by pre-rename inventory in plan doc + optional CI guard against `docs/uat/*.md` mutation outside an explicit "uat" change-classification commit.

## Progress

| Milestone | Phase | Plans Complete | Status | Completed |
|-----------|-------|----------------|--------|-----------|
| v1.1 | 1. Foundation, Diagnostic & TUI Shell | 5/5 | ✅ Complete | 2026-04-24 |
| v1.1 | 2. Observation Pipeline & Read-Only Feature Screens | 12/12 | ✅ Complete | 2026-04-26 |
| v1.1 | 3. Canonical sshd/Chroot Config & User+Key Mutations | 10/10 | ✅ Complete | 2026-04-27 |
| v1.1 | 4. Firewall Mutations & Progressive Lockdown Flagship | 13/13 | ✅ Complete | 2026-04-29 |
| v1.2 | 5. Packaging, Install/Purge & Automated Release | 7/7 | ✅ Complete | 2026-04-30 |
| v1.2 | 6. v1.1 Carry-over Closure - Firewall edge + TUI polish | 5/5 | ✅ Complete | 2026-05-01 |
| v1.2 | 7. Retroactive Nyquist Validation Authoring | 4/4 | ✅ Complete | 2026-05-02 |
| v1.3 | 8. Frame | 0/4 | Planned | - |
| v1.3 | 9. Data Layer | 0/? | Not started | - |
| v1.3 | 10. Migrate | 0/? | Not started | - |
| v1.3 | 11. Subnet | 0/? | Not started | - |
| v1.3 | 13. Console (flagship) | 0/? | Not started | - |
| v1.3 | 12. Launch | 0/? | Not started | - |
| v1.3 | 14. Footer + Friendliness + Tech Debt | 0/? | Not started | - |

---

## Backlog

### Phase 999.1: Unified home with users + firewall integration + always-visible LOCKED/UNLOCKED indicator (BACKLOG)

**Goal:** [Captured for future planning - candidate v1.4 flagship]
**Requirements:** TBD
**Plans:** 0 plans

Plans:
- [ ] TBD (promote with /gsd:review-backlog when ready)

**Captured 2026-05-03 from Phase 8 lab UAT.** Operator articulated this redesign while validating the v1.3 ufwenable modal: the 3-way separation between home / users / firewall feels scattered when every firewall rule is conceptually owned by a user (per the ufwcomment grammar `sftpj:v=1:user=<u>`).

**Operator-stated direction (refined 2026-05-03 UAT rounds 2-4):**

**Overarching metaphor:** Midnight-Commander-style full-screen terminal with a full system overview always visible. No vestigial menu home screen.

- Home screen IS the users screen (users list with per-user rule rows embedded). Operator lands on this directly after splash → doctor.
- Firewall rules are integrated into the user view, not a separate top-level.
- Firewall mode renders as **"FIREWALL MODE"** (not "MODE:") and lives in the **right-hand side** of the chrome as a **visual switch widget** (orange = not locked, green = LOCKED).
- The state color wraps the entire UI frame: top line + left border + right border all painted in the current state color (orange = unlocked, green = LOCKED). A glance at any pixel of the chrome tells the operator whether the system is protected.
- The command bar (currently a per-screen footer hint) moves to **the bottom two lines of the terminal** with **light background colors borrowed from the splash screen palette**. This is a global element, not per-screen.

**Always-visible overview strip (replaces the v1.x home `SSH: ? · Users: ? · Rules: ?` placeholders that were never wired):**
- **SSH:** count of active SSH sessions (parsed from `who` output - same source as the FW-11 SSH-detection fallback)
- **Users:** count of sftp-jailer users (from the FW-08 mirror or live `users.Enumerator`)
- **Rules:** count of firewall rules with the `sftpj:v=1:user=` comment (from `ufw status numbered` parse, filtered)
- Render as a header strip on every screen (like the modebar today) - operator never has to navigate to see system state.

**Lockdown toggle (L key):**
- `L` from anywhere toggles between LOCKED and UNLOCKED based on current firewall mode.
- If UNLOCKED → opens lockdown commit wizard (current S-LOCKDOWN flow).
- If LOCKED → invokes the rollback-to-OPEN flow directly (currently buried inside S-LOCKDOWN behind the `R` key).
- Eliminates the discoverability problem operators hit in v1.x: once locked, the path back to OPEN is hidden inside a screen they have to navigate to.

**Affected surfaces (initial scan):**
- `internal/tui/screens/home/home.go` (becomes user-list-rooted)
- `internal/tui/screens/users/users.go` (likely merges into home)
- `internal/tui/screens/firewall/firewall.go` (likely deprecates as a separate top-level)
- `internal/tui/widgets/modebar.go` (LOCKED/UNLOCKED becomes prominent header, not subtle banner)
- KeyMap rebinds (`f` may free up; `u` may become no-op since users IS home)
- Help overlay structure
- Any screen that depends on the current 3-way separation

**Open questions for the v1.4 discuss-phase:**
- Does the doctor screen stay as a separate `d` jump, or fold into home as a status strip?
- Does the lockdown screen stay separate or merge?
- How do per-user rule rows render when users have many rules (truncation / drill-down)?
- How does the always-visible LOCKED/UNLOCKED interact with REVERTING (SAFE-04 banner)? Precedence?
- Adjacent: doctor screen needs auto-run on app startup (separate but related UX request from same UAT session).

**Suggested milestone:** v1.4 (after v1.3 Phase 8-14 ships). Plan via `/gsd:new-milestone v1.4` with this backlog item as the seed PROJECT.md update.

---

### Phase 999.2: Settings allow changing chroot jail directory post-setup (BACKLOG)

**Goal:** [Captured for future planning]
**Requirements:** TBD
**Plans:** 0 plans

Plans:
- [ ] TBD (promote with /gsd:review-backlog when ready)

**Captured 2026-05-03 from Phase 8 lab UAT.**

The chroot directory is currently locked in once at apply-setup time (the SETUP-07 bordered box added in Phase 8 / 08-02 lets the operator confirm or edit it before the first apply, but afterwards there is no UI path to change it). The settings screen stores `chrootRoot` only to pass it through to the `pwauthdisable` modal for path validation - it does NOT expose an "edit chroot" affordance.

**Operator-stated direction:** The settings screen should let the operator change the chroot jail directory post-initial-setup.

**Open questions for the discuss-phase:**
- What happens to existing per-user home directories under the old chroot? Move (rsync), symlink, or require manual relocation?
- Does this trigger a re-run of M-APPLY-SETUP (rewrite `sshd_config.d/50-sftp-jailer.conf` with the new `ChrootDirectory` path) and `sshd -t` validation?
- Does it lock-out current SSH sessions while the move runs? Does it use SAFE-04?
- Overlap with Phase 10 (Migrate) which already handles user-home relocation in 3 modes (LINK / REUSE_IN_PLACE / MOVE-with-rsync) - does this become a settings entry-point that pushes the migrate flow?
- Permission semantics: is the new chroot path validated for `root:root + 0755 all the way down` like the existing chain check?

**Affected surfaces (initial scan):**
- `internal/tui/screens/settings/settings.go` - new dispatch row + handler
- New mutation modal (or reuse the M-APPLY-SETUP entry point with a different prefilled root)
- `internal/sshdcfg/` - rewrite drop-in with new path
- `internal/chrootcheck/` - validate new path before write
- Possibly Phase 10's migrate flow - relocate user homes

**Suggested milestone:** v1.4 or v1.5 depending on whether it lands as a standalone phase or folds into the v1.4 unified-home redesign.

---

*Roadmap created: 2026-04-24. Last reorganized: 2026-05-03 - v1.3 First-Run + Daily-Driver UX scoped (38 requirements across 7 phases; phase numbers 8-14 continue from v1.2's Phase 7; build order is 8 -> 9 -> 10 -> 11 -> 13 -> 12 -> 14 with Phase 12 landing AFTER Phase 13 because the console is the post-green-gate routing target).*
