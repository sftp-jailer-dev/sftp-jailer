# sftp-jailer

## What This Is

`sftp-jailer` is an interactive, colorful terminal UI for Linux sysadmins who run a chrooted SFTP server on Ubuntu 24.04. It turns a scattered pile of `sshd_config` edits, filesystem permissions, user accounts, firewall rules, and log-grepping into a single TUI where you set up the chroot, manage users + passwords + SSH keys, browse SFTP transaction logs, and progressively tighten access from "open to the world" into per-user IP-allowlisted lockdown. Distributed as a single Go binary, GPL-3.0, aimed at the gap left by SFTP *clients* (termscp, lssh) — there's no equivalent admin tool for managing the server side.

## Core Value

**One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" — safely, interactively, with observable traffic intel driving every decision.** If everything else fails, this flow must work.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — ship to validate)

### Active

<!-- Current scope. Building toward these. -->

#### Chroot setup & filesystem

- [ ] Inspect `/etc/ssh/sshd_config` (and any `sshd_config.d/` drop-ins) for a working chrooted SFTP subsystem; report what's missing
- [ ] Interactively propose and apply a canonical chroot configuration if missing or broken (with `sshd -t` validation before any reload)
- [ ] Enforce correct permissions on the chroot root and user directories (root-owned chroot root, sticky bit where appropriate, per-user writable subdirs)
- [ ] Reconfigure `Subsystem sftp` to use `internal-sftp -f AUTHPRIV -l INFO` so per-file transactions appear in logs

#### User & directory reconciliation

- [ ] Enumerate user directories under the configured chroot root
- [ ] Detect "orphan" directories (no backing system user) and offer to create the missing user with matching UID/GID derived from the directory's ownership
- [ ] Present a unified overview table: system user ↔ chroot directory ↔ auth method(s) ↔ last login ↔ current IP allowlist
- [ ] Manage passwords per user from inside the TUI (set / reset / force change on next login)
- [ ] Manage `authorized_keys` per user: list fingerprints, add key (paste or from file), delete key

#### Log observation & intelligence

- [ ] Install a weekly cron job on first run that parses sshd/SFTP logs (journalctl-based on 24.04) into a local SQLite DB
- [ ] Record successful connections (user, source IP, timestamp, session bytes if available)
- [ ] After lockdown is enabled, also record failed attempts + unmatched username attempts
- [ ] Classify each attempt into tiers: `success` (known user from allowed IP), `targeted` (known user from unallowed IP), `noise` (username unknown to the system)
- [ ] Configurable retention / cleanup strategy (e.g. keep N days of detail, compact older `noise` into counters)
- [ ] In-TUI log viewer: global feed, per-user feed, success/failed/noise filters, searchable

#### Firewall & lockdown

- [ ] First-run state: allow all IPv4 + IPv6 to the SFTP port; cron observation collects real traffic
- [ ] Admin can promote to "lockdown" mode: the tool reads the observation DB, proposes a per-user IP allowlist seeded from observed successful connections, and commits the per-user rules to the firewall
- [ ] Per-user IP allowlists are enforced as individual `ufw`/`nftables` allow rules, each tagged with a structured comment (`sftpj:user=<name>`) that the tool parses to rebuild the user↔IP mapping
- [ ] Interactive add/remove of IPs per user (single IP, CIDR, IPv4 or IPv6), with the firewall being the source of truth and the TUI showing the mapping
- [ ] Cross-referenced view: for every firewall rule show which user it belongs to; for every user show their rules

#### Runtime & distribution

- [ ] Single static Go binary built with Bubble Tea + Bubbles + Lip Gloss
- [ ] Refuses to start unless running as root/sudo
- [ ] Installable as a `.deb` package for Ubuntu 24.04 (includes the cron job + state dir under `/var/lib/sftp-jailer/`)
- [ ] GitHub project with README, LICENSE (GPL-3.0), install instructions, screenshots/screencast

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- **Multi-server orchestration** — v1 runs against localhost only. Remote management via SSH-out or agent architecture is a much bigger design and dilutes the focused "box I'm on" experience.
- **Non-Ubuntu 24.04 distros** — Debian/RHEL/Arch/older-Ubuntu compatibility doubles the surface (apt vs dnf, ufw vs firewalld, cron vs systemd-timer, systemd-journal vs rsyslog). Shipping v1 on one hard-supported distro first is better than a half-working matrix.
- **Web UI / REST API** — the whole point is a fast, colorful TUI experience. An HTTP surface is a different product.
- **Email / Slack / webhook notifications** — attack intel is visible in-TUI only in v1. Alerting is its own product category.
- **fail2ban-style automatic blocking** — the tool observes and classifies, but the admin decides what to do with the intel. Automated response is a separate trust domain.
- **File transfer operations** — sftp-jailer manages SFTP access; it isn't itself an SFTP client. No in-TUI file browsing of user directories; use a client for that.
- **sshd `Match User` per-user restrictions** — rejected in favor of firewall-only enforcement (simpler, no sshd reloads on IP edits, comments survive, admin sees one truth).

## Context

**The gap this fills.** The OSS landscape has plenty of SFTP *clients* (termscp, lssh, muon-ssh) but no equivalent admin tool for the server side of a chrooted SFTP deployment. The usual experience is a blog-post dance: edit `sshd_config`, chown the chroot root, set sticky bits, manually add users, manually set passwords, grep `/var/log/auth.log`, write firewall rules by hand. sftp-jailer collapses that into one supervised flow.

**Why firewall-only for per-user IP enforcement.** Two credible alternatives were considered:
1. `sshd_config Match User X Address Y` blocks — precise but requires an sshd reload on every IP edit, fragile parsing of the config, and a second surface to keep consistent with the firewall.
2. Firewall-only with structured comments as the user↔IP mapping — chosen. System state is the single truth. No drift, no sshd reloads, comments survive `ufw reload`, and the "prepare lockdown" transition has a clean data pipeline (observation DB → proposed rules).

The tradeoff is that once an IP is allowed at the firewall, it can *attempt* login as any user — but the tool manages strong auth (password + keys), and in lockdown mode the allowed-IP surface is tiny. Documented as an explicit threat-model decision.

**Target scale.** 20–100 users per server, 1–3 servers per admin. Not designed for 10k-user multi-tenant hosting (UI and observation DB are sized for the smaller number).

**Observation DB lives under `/var/lib/sftp-jailer/observations.db`.** Populated by a weekly cron (installed first-run). Grows with internet attack volume once exposed; configurable retention is a feature, not an afterthought.

**Ubuntu 24.04 specifics that matter.** Default logging backend is systemd-journald; default firewall is `ufw` (nftables-backed). Default SFTP Subsystem does not log per-file transactions — the tool has to opt in. chroot root directories must be root-owned with no group-write; per-user writable subdirs live below. These assumptions are baked into the auto-config flow.

## Constraints

- **Tech stack**: Go 1.22+, Bubble Tea (framework), Bubbles (components), Lip Gloss (styling). Single static binary — no runtime dependencies beyond libc.
- **Platform**: Ubuntu 24.04 LTS, hard dependency. `apt`, `systemd`, `journalctl`, `ufw` (nftables backend), `cron` (vixie-style) all assumed present.
- **Privilege**: must run as root/sudo — tool refuses to start otherwise. Modifies `sshd_config`, creates system users, writes firewall rules, reloads services.
- **External process surface**: shells out to `adduser`/`usermod`/`chpasswd`/`passwd`/`chown`/`chmod`/`ufw`/`sshd -t`/`systemctl`. Wrapped in typed Go functions; no raw string concatenation into shell.
- **Persistence**: SQLite (via modernc.org/sqlite, pure Go — keeps the binary cgo-free) for the observation DB. No user↔IP state: that's in firewall rule comments.
- **Safety posture**: admin-trusted, minimal friction — but `sshd -t` validation before any sshd reload is mandatory (a typo there is self-DoS over SFTP). One rolling backup of `sshd_config` on first edit per session, overwritten thereafter.
- **License**: GPL-3.0.
- **Distribution**: single Go binary, `.deb` package, GitHub release.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Name: `sftp-jailer` | Ranked ahead of `sftp-manager`, `sftpguard`, `sftp-warden` on discoverability — "sftp jail" is the literal phrase tutorials use for chrooted SFTP | — Pending |
| Go + Bubble Tea | Single static binary → easy `.deb` + apt distribution. Huge TUI ecosystem (Bubbles, Lip Gloss). Good system-tooling fit | — Pending |
| Firewall-only per-user IP enforcement, user↔IP in rule comments | Single source of truth, no sshd reloads on IP edits, no drift between two configs. Trade: allowed IPs can attempt any user (mitigated by strong auth + small allow-surface in lockdown) | — Pending |
| Observation via weekly cron → SQLite | Installed first-run, collects real traffic before lockdown so the "prepare lockdown" proposal is data-driven. Configurable retention since port 22 is a noise magnet | — Pending |
| Ubuntu 24.04 hard dependency for v1 | Locks to one apt+systemd+ufw+journald stack. Ship v1 that works perfectly > v1 with half-working multi-distro matrix | — Pending |
| Passwords + SSH keys in v1 | Modern SFTP is key-first, but password-only deployments still exist. Managing both is the responsible OSS default | — Pending |
| Admin-trusted / minimal-friction UX, but `sshd -t` validation mandatory | Workflow is fast (no per-step confirmations) except for the one change that can lock the admin out | — Pending |
| GPL-3.0 license | User's explicit choice — copyleft matches the sysadmin-tool ecosystem and ensures downstream forks stay open | — Pending |

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
*Last updated: 2026-04-24 after initialization*
