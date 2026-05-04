# sftp-jailer

## What This Is

`sftp-jailer` is an interactive, colorful terminal UI for Linux sysadmins who run a chrooted SFTP server on Ubuntu 24.04. It turns a scattered pile of `sshd_config` edits, filesystem permissions, user accounts, firewall rules, and log-grepping into a single TUI where you set up the chroot, manage users + passwords + SSH keys, browse SFTP transaction logs, and progressively tighten access from "open to the world" into per-user IP-allowlisted lockdown. Distributed as a single Go binary, GPL-3.0, aimed at the gap left by SFTP *clients* (termscp, lssh) — there's no equivalent admin tool for managing the server side.

## Core Value

**One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" — safely, interactively, with observable traffic intel driving every decision.** If everything else fails, this flow must work.

## Current State

**Shipped:** v1.2 (2026-05-02) - Phases 5-7, 16 plans, 12 of 12 requirements satisfied. v1.2.0/v1.2.1/v1.2.2 published to GitHub Releases on 2026-05-02 / 2026-05-03 / 2026-05-03 with full `RELEASE-CHECKLIST.md` operator sign-off (all 7 sign-offs ticked 2026-05-02; pre-flight 17/17 GREEN; lintian --pedantic 0E + 0W + 0U on both archs against post-push origin/main). v1.2.x patches `.deb` smoke-tested on lab hosts ubuntu-wifi (192.168.1.187 Ubuntu 24.04) and debian13 (192.168.1.170 Debian 13). Full record: [`MILESTONES.md`](MILESTONES.md) and [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md). Audit (re-run 2026-05-02): [`milestones/v1.2-MILESTONE-AUDIT.md`](milestones/v1.2-MILESTONE-AUDIT.md) - passed.

**Cumulative:** v1.1 + v1.2 = 56 plans across 7 phases; 79 of 79 in-scope requirements satisfied. v1.1 archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md).

The core thesis flow works end-to-end on a real Ubuntu 24.04 box and on a Debian 13 lab host (install/runtime parity only, not tier-1 supported), starting from `apt install ./sftp-jailer_*.deb`: diagnostic posture report → canonical sshd drop-in apply with `sshd -t` gate → per-user CRUD with passwords + SSH keys → weekly observation timer ingesting sshd logs into a 4-tier-classified SQLite store → progressive lockdown with per-user IP allowlist proposal seeded from observed successful connections → commit/rollback under a 3-minute `systemd-run` auto-revert window that survives a TUI crash. `apt purge` round-trips cleanly with brownfield-safe sshd_config preservation. `git tag vX.Y.Z && git push --tags` triggers a goreleaser+lintian+SHA256SUMS GitHub Actions workflow with no manual steps.

## Current Milestone: v1.3 First-Run + Daily-Driver UX

**Goal:** Take the journey from "fresh `apt install`" to "lockdown committed" from "works if you read the code" to "obvious to a sysadmin who has never opened the codebase". Tighten the daily-driver experience by collapsing the four feature screens (users, firewall, logs, lockdown) into one coherent management console.

**Target features:**

- **Launch flow:** larger splash with +1s timeout; auto-doctor on TUI launch; if all green, auto-continue after 2s with Esc-to-stay; auto-route to landing screen; auto-run `observe-run` async after green-gate so log data is fresh on first interaction.
- **Unified management console:** single overview replacing or fronting S-USERS / S-FIREWALL / S-LOGS / S-LOCKDOWN. One row per SFTP user with their firewall rules, last-seen IP, observation tier counts, password aging state, and one-key actions (add key, set password, edit rules, delete user). Drill-down modals for per-user detail. Likely the v1.3 flagship.
- **Logs view dedup:** one row per `(source_ip, username)` with last-seen + count + tier; drill-down to full event history; underlying audit DB schema unchanged (every event still persisted). Likely needs covering index `observation_runs(source_ip, username, ts)`.
- **Pre-lockdown subnet whitelist:** detect IP clusters in RFC1918 / private ranges, offer whole-subnet whitelist instead of per-IP enumeration; comment-schema extension `sftpj:v=1:scope=subnet:reason=...`.
- **Nav-footer on every screen:** multi-line, colored to match the SFTP-JAILER logo palette, with a clear "next action" cue (not just key hints). Consistent `KeyHints()` contract across screens.
- **User flows:** S-USERS empty-state adds `[m] Migrate existing system user` action (UID >= 1000 stays); ChrootDirectory default `/srv/sftp-jailer/%u` surfaced in apply flow with confirm-or-edit; B4 `/etc/shells` pre-flight DELETED (solving non-problem; keep chroot-chain walk).
- **Diagnostics + remediation:** doctor "ufw inactive" copy clarifies the systemctl-active vs ufw-status-inactive divergence inline; `[A] Enable ufw` mutation handler wired through `internal/txn` apply+compensate with SAFE-04 timer coverage (currently label-only in v1.2.2).
- **Friendliness pass:** continuation of v1.2.1 wording rename across user-create, password-reset, lockdown commit modals.

**Plus carry-over from v1.2 milestone close:**

- 9 tech-debt items from `milestones/v1.2-MILESTONE-AUDIT.md` (postinst observer.cursor preservation on apt upgrade, S-SETTINGS in-process refresh, dead `NewBackupDefaultUfwStep`, userlog goroutine cancel on modal pop, addkey fetch-fallback copy refresh, etc.)
- DIST-v2-01 cosign signing
- DIST-v2-02 SLSA L3 provenance
- DIST-v2-03 `linux/arm/v7`
- Node 20 GitHub Actions deprecation (forced Node 24 from 2026-06-02; Node 20 removed 2026-09-16; release pipeline blocker)

**Operator-locked decisions baked in (from notes/2026-05-03-v1.3-first-run-ux.md):**

- SFTP users stay regular users (UID >= 1000), NOT system users; no `useradd -r` switch. Phase 3 invariant stays.
- B4 `/etc/shells` pre-flight: delete entirely (not auto-fix). The check is solving a non-problem; `useradd` does not consult `/etc/shells`.
- `docs/uat/*.md` historical sign-offs preserved (audit trail).
- Internal Go symbols preserved (`CanonicalDropIn`, `WriteCanonicalSshdDropInStep`, etc.); v1.2.1 user-facing rename pattern continues for any new dev-jargon found.
- `commit_docs=false` stays; `.planning/` remains gitignored with curated force-adds for milestone artifacts.
- Operator expects mid-milestone scope additions for genuine bugs surfaced by validation; do not lock requirements too tightly.

## Open at v1.2 close (single remaining operator-gated item)

- **FW-09 empirical IPv6 VM UAT** - pre-agreed deferral per Phase 6 D-16; flips checkbox in v1.2.x point release after operator runs `docs/uat/06-fw09-uat.md` against dual-family + v6-only Ubuntu 24.04 VMs. Production code is family-agnostic by construction; this is operator UAT only, not a code gap. Not a v1.3 dependency.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

#### v1.2.x patch releases (shipped 2026-05-02 / 2026-05-03)

- ✓ v1.2.0 GA released 2026-05-02 with full RELEASE-CHECKLIST sign-off (7/7 ticked: pre-flight + lintian + Variant A + Variant B brownfield + Debian 13 UAT + tag pipeline + GitHub Release artifacts) - v1.2 (post-milestone close)
- ✓ v1.2.1 first-run UX polish (3 atomic commits + 1 lint follow-up): `--version` flag wired on root cobra, "canonical config" -> "SFTP jail configuration" rename across user-facing strings (8 files; internal Go symbols preserved), doctor subsystem false-positive fix (respects `Match Group sftp-jailer ForceCommand internal-sftp` override). Released 2026-05-03 - v1.2 (quick task 260502-wc2)
- ✓ v1.2.2 doctor + empty-state correctness fixes: doctor detects inactive ufw and surfaces `[FAIL] + [A] Enable ufw` label (mutation handler deferred to v1.3 with SAFE-04 timer coverage); S-USERS empty-state copy refreshed (drops "Phase 3" jargon, surfaces `[n] Add a user`). Released 2026-05-03 - v1.2 (quick task 260503-0tn)

#### v1.2 (shipped 2026-05-02) — Phases 5–7

- ✓ `goreleaser` + `nfpm` produce lintian-clean `.deb` for `amd64` and `arm64` with man page, both systemd units, `/var/lib/sftp-jailer/`; `CGO_ENABLED=0 -trimpath` (DIST-02) — v1.2 (Phase 5)
- ✓ `lintian --pedantic` returns zero errors and zero warnings on both `.deb` artifacts; CI release workflow refuses to publish if lintian fails (DIST-03) — v1.2 (Phase 5; empirically GREEN per quick task 260502-lga)
- ✓ `postinst` creates `sftp-jailer` group (idempotent), enables and starts `sftp-jailer-observer.timer`, and initializes `observations.db` at `user_version=3` via hidden `sftp-jailer init-db` cobra subcommand (DIST-04) — v1.2 (Phase 5 plans 05-04, 05-07)
- ✓ `apt purge sftp-jailer` removes binary, both units, `/var/lib/sftp-jailer/`, and `/etc/ssh/sshd_config.d/50-sftp-jailer.conf`; correct sshd reload dispatched per SAFE-06; sshd remains running, sessions preserved (DIST-05) — v1.2 (Phase 5)
- ✓ Automated tag-push release pipeline via GitHub Actions: `goreleaser release` + `lintian --pedantic` gate + SHA256SUMS.txt upload on every `vX.Y.Z` tag push; trigger surface narrowed to tag push only (DIST-08) — v1.2 (Phase 5 plan 05-05)
- ✓ Brownfield `apt purge` byte-identical to pre-install on admin-edited main `sshd_config` (sha256 597db2fa…, empirically confirmed) (DIST-09) — v1.2 (Phase 5; Variant B UAT signed)
- ✓ Debian 13 thesis flow PASS on lab host 192.168.1.170 (install/runtime parity gate; not tier-1 support) (DIST-10) — v1.2 (Phase 5 plan 05-06; operator-signed 2026-04-30)
- ✓ BUG-04-B closure: family-agnostic catch-all delete on dual-family + v6-only hosts via `stripV6Suffix` parser; zero production lines changed (FW-09) — v1.2 (Phase 6 plan 06-01; empirical IPv6 VM UAT pre-agreed deferred to v1.2.x per D-16)
- ✓ `S-SETTINGS` exposes `PasswordAgingDays` / `PasswordStaleDays` editable with positive-integer validation max=3650 + round-trip on TUI restart (TUI-09) — v1.2 (Phase 6 plan 06-02)
- ✓ Per-user log-detail modal (`M-USER-LOG`) on uppercase `L`: 90-day tier counts (success/targeted/noise/unmatched) + last 20 raw entries (TUI-10) — v1.2 (Phase 6 plan 06-03)
- ✓ Cancellable `resolveAsync` paths in 4 mutation modals (addkey, deleteuser, applysetup, pwauthdisable): SIGTERM via context cancel + `cmd.WaitDelay = 2s` SIGKILL fallback; D-08 hang diagnostic with live PID + path + PID=0 fallback (TUI-11) — v1.2 (Phase 6 plans 06-04, 06-05)
- ✓ v1.1 Phases 1–3 backfilled with `validation_md`; v1.1 milestone audit re-runs at 4/4 `nyquist_compliant` (NYQ-01) — v1.2 (Phase 7)

#### v1.1 (shipped 2026-04-29) — Phases 1–4

- ✓ Single static Go binary, Bubble Tea v2 + Bubbles + Lip Gloss, cgo-free via `modernc.org/sqlite` — v1.1 (6.7 MB, CGO_ENABLED=0)
- ✓ Refuses to start without root/sudo (SAFE-01) — v1.1 (Phase 1)
- ✓ Read-only six-item diagnostic: sshd drop-ins, chroot ownership, ufw IPV6, AppArmor sshd enforce, Docker/Tailscale nft, sftp subsystem (SETUP-01) — v1.1 (Phase 1; pitfalls A2/A5/A6/C4/C5 retired)
- ✓ TUI shell: nav stack, resize-safe, mouse, OSC 52 clipboard, panic-safe `/tmp` recovery script, ANSI splash (TUI-01..08) — v1.1 (Phase 1)
- ✓ Green CI: `go test`, `golangci-lint v2.11`, `govulncheck`, 3 architectural-invariant guards (DIST-01/06/07) — v1.1 (Phase 1)
- ✓ Public GitHub repo with README, LICENSE (GPL-3.0), install stub, Dependabot — v1.1 (Phase 1)
- ✓ Weekly systemd-timer observation pipeline parsing `journalctl --output=json` into WAL-mode SQLite with 4-tier classification (success/targeted/noise/unmatched) (OBS-02..06, LOG-05) — v1.1 (Phase 2)
- ✓ Read-only TUI screens: S-USERS unified overview (USER-01/02), S-FIREWALL with `sftpj:v=1:user=<name>` comment parsing (FW-01/04), S-LOGS split-pane with live tail via `journalctl -u ssh -f` (LOG-01..06) — v1.1 (Phase 2)
- ✓ `internal/txn` apply+compensate framework with rolling backups + mandatory `sshd -t` gate (SAFE-02/03/05/06) — v1.1 (Phase 3; Launchpad #2069041 confirmed live three times)
- ✓ Canonical sshd drop-in writer at `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` with `Match Group sftp-jailer` + `internal-sftp -f AUTHPRIV -l INFO` (SETUP-02..06) — v1.1 (Phase 3, empirically UAT-confirmed on Ubuntu 24.04)
- ✓ Chroot path-walk validator (root:root + no-group-write `/` → chroot root) (SETUP-04) — v1.1 (Phase 3)
- ✓ Full user lifecycle: create from scratch + create from orphan dir with B-03 GID preservation + delete with archive-or-permanent (USER-03/04/11/12, SETUP-05) — v1.1 (Phase 3, empirically UAT-confirmed: orphan UID:GID 6308:6308 preserved byte-for-byte)
- ✓ Password set/reset via stdin-piped `chpasswd` (NEVER on argv) + auto-generate strong + force change on next login (USER-05/06/07) — v1.1 (Phase 3, empirically confirmed via yescrypt hash in `/etc/shadow`)
- ✓ SSH key management: list with SHA256 fingerprint + paste / file / `gh:<user>` import + delete with atomic write + StrictModes verifier with rollback (USER-08/09/10/14) — v1.1 (Phase 3, USER-14 verifier rollback empirically PROVED — restored authorized_keys to 186 bytes byte-identical after malformed key)
- ✓ `PasswordAuthentication` global disable with pre-flight users-without-keys block (USER-13) — v1.1 (Phase 3, DISABLE/RE-ENABLE both empirically confirmed)
- ✓ Per-user firewall CRUD with `sftpj:v=1:user=<name>` versioned comments + 3-minute `systemd-run --on-active=3min` auto-revert on every mutation (SAFE-04, FW-02/03/05/07) — v1.1 (Phase 4)
- ✓ `internal/revert.Watcher` singleton + on-disk JSON pointer for SAFE-04 restart recovery (SAFE-07) — v1.1 (Phase 4)
- ✓ FW-06 `/etc/default/ufw IPV6=no` hard-block + M-FW-IPV6-FIX remediation modal — v1.1 (Phase 4)
- ✓ S-LOCKDOWN flagship: observation-driven per-user IP allowlist proposal (90-day window, configurable) + admin-IP guard + M-DRY-RUN preview + commit/rollback (LOCK-02..06, LOCK-08, LOCK-09) — v1.1 (Phase 4)
- ✓ `MODE: OPEN | STAGING | LOCKED` global modebar (LOCK-01, LOCK-07) — v1.1 (Phase 4)
- ✓ FW-08 `user_ips` SQLite mirror rebuilt from firewall comments (belt-and-suspenders, never authority) — v1.1 (Phase 4)

### Active

<!-- v1.3 First-Run + Daily-Driver UX scope. Building toward these. -->

#### Launch flow

- [ ] Splash screen: increase size + bump timeout by 1s
- [ ] Auto-doctor on TUI launch; if all green, auto-continue after 2s with Esc-to-stay
- [ ] Auto-route to landing screen (likely the unified console) after green-doctor gate
- [ ] Auto-run `observe-run` async after green-gate so log data is fresh on first interaction (do not block launch)

#### Unified management console (likely flagship)

- [ ] Single overview screen showing per-user: username, UID, group, password aging, firewall rules with `sftpj:v=1:user=<name>` comments, last-seen IP, observation tier counts, password aging state
- [ ] One-key per-user actions: add key, set password, edit rules, delete user
- [ ] Drill-down modals for per-user detail
- [ ] S-USERS / S-FIREWALL / S-LOGS / S-LOCKDOWN consolidation strategy (front, retire, or keep as drill-downs - decide in discuss-phase)

#### Logs view dedup

- [ ] One row per `(source_ip, username)` with last-seen + count + tier in default view
- [ ] Drill-down to full per-(IP, user) event history
- [ ] Underlying audit DB schema unchanged (every event still persisted)
- [ ] Covering index `observation_runs(source_ip, username, ts)` if profiling shows need

#### Pre-lockdown subnet whitelist

- [ ] Detect IP clusters in RFC1918 + RFC4193 + link-local ranges from observed connections
- [ ] Offer whole-subnet whitelist before falling through to per-IP proposal
- [ ] Comment-schema extension `sftpj:v=1:scope=subnet:reason=<rfc1918|operator>` for non-user-tied subnet rules
- [ ] Threshold heuristic decision (operator-tunable in S-SETTINGS or per-lockdown prompt)

#### Frame: nav-footer on every screen

- [ ] Multi-line footer on every screen with key hints + "next action" cue
- [ ] Colored to match SFTP-JAILER logo palette
- [ ] Consistent `KeyHints() []string` (or richer) per-screen contract
- [ ] Forward-compat with the unified-console drill-down flows

#### User flows

- [ ] S-USERS empty-state: add `[m] Migrate existing system user into the sftp-jailer group` action (UID >= 1000 stays; no system-user switch)
- [ ] ChrootDirectory default `/srv/sftp-jailer/%u` surfaced in apply flow with confirm-or-edit step
- [ ] Delete B4 `/etc/shells` pre-flight entirely (the check is solving a non-problem; `useradd` does not consult `/etc/shells`); keep the chroot-chain walk
- [ ] Friendliness pass: continuation of v1.2.1 wording rename across user-create, password-reset, lockdown commit modals; hunt remaining dev-jargon

#### Diagnostics + remediation

- [ ] Doctor "ufw inactive" copy: keep the word "inactive" but add a clarifying note about systemctl-active vs ufw-status-inactive divergence inline
- [ ] `[A] Enable ufw` mutation handler: wire through `internal/txn` apply+compensate per Phase 4 SAFE-04 conventions (currently label-only in v1.2.2)

#### v1.2 carry-over tech debt (9 items - see `milestones/v1.2-MILESTONE-AUDIT.md`)

- [ ] Phase 6 WR-02: propagate S-SETTINGS password-aging save to in-process `usersCfg` without TUI restart
- [ ] Phase 5 WR-01: postinst should not unconditionally truncate `observer.cursor` on `apt upgrade` (re-ingests last 7 days)
- [ ] Phase 5 WR-04: remove latent unused `NewBackupDefaultUfwStep`
- [ ] Phase 6 IN-01: cancel userlog read-only goroutines on modal pop (up to 30s wasted SQLite query time)
- [ ] Phase 6 IN-03: `rows.Err()` ordering after `rows.Close()` in queries.go (stylistic)
- [ ] Phase 6 post-06-05 IN-01: refresh addkey fetch-fallback copy ("modal stays open until request returns")
- [ ] Phase 6 post-06-05 IN-02: align `deleteuser.Model` with `errFatal` field carried by other 3 modals
- [ ] Phase 5 WR-03: clean up misleading lintian-overrides WHY block comment
- [ ] `git rm docs/man/.gitkeep` - `scripts/check-manpage-fresh.sh` reports `Only in docs/man: .gitkeep`

#### Distribution + supply chain (deferred from v1.1/v1.2)

- [ ] DIST-v2-01: cosign-keyless-signed reproducible releases (`cosign sign-blob` over `.deb`s + `SHA256SUMS.txt` + manifest)
- [ ] DIST-v2-02: SLSA Level 3 provenance via `slsa-github-generator`
- [ ] DIST-v2-03: `linux/arm/v7` (32-bit) `.deb` for Raspberry-Pi-class hardware
- [ ] Node 20 GitHub Actions deprecation: pin or upgrade `actions/checkout`, `actions/setup-go`, `goreleaser/goreleaser-action` ahead of 2026-06-02 forced Node 24 / 2026-09-16 Node 20 removal

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- **Multi-server orchestration** — v1 runs against localhost only. Remote management via SSH-out or agent architecture is a much bigger design and dilutes the focused "box I'm on" experience.
- **RHEL / Fedora / Arch / older-Ubuntu** — dnf/pacman, firewalld, rsyslog, mismatched systemd versions multiply the test surface. Shipping v1 on one hard-supported family first is better than a half-working matrix.
- **Debian 13 — partial (v1.2 confirmed).** Empirical UAT acceptance gate at v1.2 (192.168.1.170 lab host; install/runtime parity confirmed PASS 2026-04-30). Debian 13 is **not** a tier-1 supported platform — install/runtime parity is the v1.2 acceptance gate; full tier-1 support (CI matrix, README, .deb metadata) would be a separate milestone.
- **Web UI / REST API** — the whole point is a fast, colorful TUI experience. An HTTP surface is a different product.
- **Email / Slack / webhook notifications** — attack intel is visible in-TUI only in v1. Alerting is its own product category.
- **fail2ban-style automatic blocking** — the tool observes and classifies, but the admin decides what to do with the intel. Automated response is a separate trust domain.
- **File transfer operations** — sftp-jailer manages SFTP access; it isn't itself an SFTP client. No in-TUI file browsing of user directories; use a client for that.
- **sshd `Match User` per-user restrictions** — rejected in favor of firewall-only enforcement (simpler, no sshd reloads on IP edits, comments survive, admin sees one truth).

## Context

**The gap this fills.** The OSS landscape has plenty of SFTP *clients* (termscp, lssh, muon-ssh) but no equivalent admin tool for the server side of a chrooted SFTP deployment. The usual experience is a blog-post dance: edit `sshd_config`, chown the chroot root, set sticky bits, manually add users, manually set passwords, grep `/var/log/auth.log`, write firewall rules by hand. sftp-jailer collapses that into one supervised flow.

**Codebase as of v1.2 (2026-05-02):** v1.1 baseline + ~+8,040 / -1,668 lines across 180 files for v1.2 packaging + carry-over closure + Nyquist backfill (excluding `.planning/`); 112 commits across 4 calendar days. Single static cgo-free binary still under the v1.1 6.7 MB envelope. All tests green; 3 architectural-invariant CI guards passing (`check-no-exec-outside-sysops`, `check-go-mod-pins`, `check-single-tea-program`); a 4th CI guard (`check-manpage-fresh.sh`) added in Phase 5 plan 05-02. SAFE-04 / SAFE-06 / USER-14 still empirically confirmed; brownfield purge byte-identical sshd_config (sha256 597db2fa…) added as a v1.2 empirical confirmation. Tag-push GitHub Actions release pipeline live; lintian sub-gate `0E + 0W + 0U` on Debian 13 lab against post-push origin/main.

**Codebase as of v1.1 (2026-04-29):** ~40,514 LOC of Go across 147 files / 37 packages, single 6.7 MB cgo-free static binary, 153 commits over 5 calendar days. All tests green; 3 architectural-invariant CI guards passing. SAFE-04 (`systemd-run` 3-min auto-revert), SAFE-06 (socket-vs-service reload dispatcher per Launchpad #2069041), and USER-14 (`authorized_keys` verifier with rollback) all empirically confirmed live on a real Ubuntu 24.04 box during phase UAT runs. Three production P0 bugs (BUG-04-A position-shift, BUG-04-C dual-family, BUG-04-D timer-vs-service stop ordering) caught by Plan 04-10's empirical UAT and closed via gap-closure plans before milestone close — establishing empirical UAT as a load-bearing safety gate going forward.

**Why firewall-only for per-user IP enforcement.** Two credible alternatives were considered:
1. `sshd_config Match User X Address Y` blocks — precise but requires an sshd reload on every IP edit, fragile parsing of the config, and a second surface to keep consistent with the firewall.
2. Firewall-only with structured comments as the user↔IP mapping — chosen. System state is the single truth. No drift, no sshd reloads, comments survive `ufw reload`, and the "prepare lockdown" transition has a clean data pipeline (observation DB → proposed rules).

The tradeoff is that once an IP is allowed at the firewall, it can *attempt* login as any user — but the tool manages strong auth (password + keys), and in lockdown mode the allowed-IP surface is tiny. Documented as an explicit threat-model decision.

**Target scale.** 20–100 users per server, 1–3 servers per admin. Not designed for 10k-user multi-tenant hosting (UI and observation DB are sized for the smaller number).

**Observation DB lives under `/var/lib/sftp-jailer/observations.db`.** Populated by a weekly systemd timer (installed first-run) — not cron; a `.timer` + `.service` unit pair packaged in the `.deb`. Grows with internet attack volume once exposed; configurable retention is a feature, not an afterthought.

**Ubuntu 24.04 specifics that matter.** Default logging backend is systemd-journald; default firewall is `ufw` (nftables-backed). Default SFTP Subsystem does not log per-file transactions — the tool has to opt in. chroot root directories must be root-owned with no group-write; per-user writable subdirs live below. Ubuntu 24.04 ships Go 1.22 in `apt`, which is too old for Bubble Tea v2 (requires Go 1.25+) — development docs will point at the longsleep PPA or the go.dev tarball. sshd config edits go to a drop-in at `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` rather than the main file, so uninstall/upgrade is clean and the main file stays admin-owned. These assumptions are baked into the auto-config flow.

## Constraints

- **Tech stack**: Go 1.25+ (Bubble Tea v2 requirement), Bubble Tea v2 at `charm.land/bubbletea/v2` (framework), Bubbles (components), Lip Gloss (styling). Single static binary — no runtime dependencies beyond libc.
- **Platform**: Ubuntu 24.04 LTS, hard dependency. `apt`, `systemd` (journald + timers), `ufw` (nftables backend) all assumed present. No cron — scheduled jobs are systemd timer units.
- **Privilege**: must run as root/sudo — tool refuses to start otherwise. Modifies `sshd_config.d/` drop-ins, creates system users, writes firewall rules, reloads services.
- **Config ownership**: tool writes to `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` (a drop-in owned end-to-end by this tool). The main `/etc/ssh/sshd_config` stays admin-owned and is only read.
- **External process surface**: shells out to `useradd`/`userdel`/`gpasswd`/`chpasswd`/`chage`/`chown`/`chmod`/`tar`/`ufw`/`sshd -t`/`systemctl`/`journalctl`. Wrapped in typed Go functions; no raw string concatenation into shell.
- **Persistence**: SQLite via `modernc.org/sqlite` (pure Go — keeps the binary cgo-free) for the observation DB. No user↔IP state: that's in firewall rule comments.
- **Safety posture**: admin-trusted, minimal friction — but `sshd -t` validation before any sshd reload is mandatory (a typo there is self-DoS over SFTP). One rolling backup of any config drop-in on first edit per session, overwritten thereafter.
- **License**: GPL-3.0.
- **Distribution**: single Go binary, `.deb` package built via `nfpm`/`goreleaser`, hosted on GitHub (no Codeberg mirror for v1).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Name: `sftp-jailer` | Ranked ahead of `sftp-manager`, `sftpguard`, `sftp-warden` on discoverability — "sftp jail" is the literal phrase tutorials use for chrooted SFTP | ✓ Good (v1.1) |
| Go 1.25+, Bubble Tea v2 (`charm.land/bubbletea/v2`) | Research flagged v2 as the current stable line and that its new module path differs from training-data defaults; pinning both avoids scaffolding errors | ✓ Good (v1.1) |
| Single static binary, cgo-free | Uses `modernc.org/sqlite` (pure Go) not `mattn/go-sqlite3` — preserves `go build` static-binary goal for `.deb` distribution | ✓ Good (v1.1) |
| Firewall-only per-user IP enforcement, user↔IP in rule comments | Single source of truth, no sshd reloads on IP edits, no drift between two configs. Trade: allowed IPs can attempt any user (mitigated by strong auth + small allow-surface in lockdown) | ✓ Good (v1.1) |
| Observation via weekly systemd timer → SQLite | Installed first-run, collects real traffic before lockdown so the "prepare lockdown" proposal is data-driven. systemd timer (not cron) matches 24.04's native scheduling stack | ✓ Good (v1.1) |
| All sshd changes go to `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` | Keeps the main `sshd_config` admin-owned; upgrade/uninstall is a single-file operation; avoids parsing/writing the monolithic file | ✓ Good (v1.1) |
| Ubuntu 24.04 hard dependency for v1 | Locks to one apt+systemd+ufw+journald stack. Ship v1 that works perfectly > v1 with half-working multi-distro matrix | ✓ Good (v1.1) |
| Passwords + SSH keys in v1 | Modern SFTP is key-first, but password-only deployments still exist. Managing both is the responsible OSS default | ✓ Good (v1.1) |
| Admin-trusted / minimal-friction UX, but `sshd -t` validation mandatory | Workflow is fast (no per-step confirmations) except for the one change that can lock the admin out | ✓ Good (v1.1) |
| GPL-3.0 license | User's explicit choice — copyleft matches the sysadmin-tool ecosystem and ensures downstream forks stay open | ✓ Good (v1.1) |
| GitHub-only hosting for v1 (no Codeberg mirror) | Maximum discovery for a brand-new OSS tool with no audience yet; `goreleaser` → GitHub Releases is the smoothest `.deb` pipeline. Codeberg mirror reconsidered post-v1 | ✓ Good (v1.1) |
| nfpm `Depends: ufw` (not Recommends) | `.deb` cannot install on a host without ufw; trades portability for correctness contract — the lockdown flow has no fallback path if ufw is missing (D-MP-02, Phase 5) | ✓ Good (v1.2) |
| `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` excluded from dpkg contents | Drop-in is written by the tool's apply flow at runtime, not by the `.deb`; keeps the file under runtime ownership and makes brownfield purge byte-identical (D-LC-02, Phase 5) | ✓ Good (v1.2) |
| Tag-push-only release surface | No nightly, no `workflow_dispatch`, no `main`-push builds — keeps the release contract narrow; one-off testing via local `goreleaser build --snapshot` (Phase 5 plan 05-05) | ✓ Good (v1.2) |
| FW-09: family-agnostic by construction, zero production lines changed | `stripV6Suffix` parser exercised on existing `internal/firewall.AddRule` + `ufwcomment.Encode/Decode` grammar; regression net is unit tests + fixtures + UAT runbook (D-14, Phase 6) | ✓ Good (v1.2) |
| FW-09 empirical IPv6 VM UAT pre-agreed deferral to v1.2.x | Production code is family-agnostic per D-14; operator-gated checkbox flip is not a milestone-close blocker (D-16, Phase 6) | — Pending (v1.2.x operator action) |
| Phase 7 documentation-only verdict (no `07-VALIDATION.md`) | Phase 7 authored no runnable code; Nyquist concept not applicable to documentation phases. Step 7b explicitly skipped | ✓ Good (v1.2) |
| `cmd.WaitDelay = 2s` SIGKILL fallback for cancellable subprocesses | TUI Esc sends SIGTERM via context cancel; modal closes only after subprocess exits; 2s grace before SIGKILL keeps responsiveness predictable (D-07/D-08, Phase 6 plan 06-04) | ✓ Good (v1.2) |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-04 - Phase 09 (Data Layer) complete: ufwcomment v=1 discriminated union (FW-10), migration 004 dedup covering index + ANALYZE + schema v4 + WithProgress hook (LOG-10), DedupRows/EventsForPair queries + EQP regression + 100k-row CI benchmark (LOG-07/08/09). Phase 10 (Migrate) is next per locked v1.3 build sequence 8 -> 9 -> 10 -> 11 -> 13 -> 12 -> 14. Lab UATs P2-B (real-DB query plan) and P2-D (migration latency) operator-gated.*
