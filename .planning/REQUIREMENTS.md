# Requirements: sftp-jailer - Milestone v1.3

**Defined:** 2026-05-03
**Core Value:** One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" - safely, interactively, with observable traffic intel driving every decision.

Milestone v1.3 takes the empirically-shipped binary at v1.2.x and rewrites the first-run + daily-driver UX so the journey from "fresh `apt install`" to "lockdown committed" is obvious to a sysadmin who has never opened the codebase. The flagship is a unified Users + Firewall + Logs + Lockdown management console replacing `home` as the post-launch landing target. Auto-doctor + auto-observer on launch close the "stale data on first interaction" gap. Pre-lockdown subnet-whitelist detection brings the lockdown proposal in line with how operators actually think about internal networks. Bulk-select migration of existing system users into the `sftp-jailer` group closes the "I already have SFTP users, now what" gap. v1.2 carry-over tech debt and Node 20 GH Actions deprecation are folded in.

REQ-ID numbering continues v1.1/v1.2 conventions: existing category prefixes (`SETUP`, `USER`, `OBS`, `FW`, `TUI`, `LOG`, `LOCK`, `DIST`) are reused with new numbers; two new prefixes (`LAUNCH`, `CONSOLE`) are introduced for launch state machine and unified management console; one (`DEBT`) is introduced as a catch-all for v1.2 internal-cleanup items that do not fit a user-facing category.

The full v1.1 + v1.2 requirements sets are archived in `milestones/v1.1-REQUIREMENTS.md` (67/67 in-scope satisfied) and `milestones/v1.2-REQUIREMENTS.md` (12/12 satisfied).

---

## v1.3 Requirements

### Setup (SETUP)

- [ ] **SETUP-07**: ChrootDirectory default `/srv/sftp-jailer/%u` is surfaced in the apply flow with a confirm-or-edit step before the drop-in is written. Operator can accept the default or type an alternate path.
- [ ] **SETUP-08**: B4 `/etc/shells` pre-flight is removed from the new-user flow at `internal/tui/screens/newuser/newuser.go:304-321`. Chroot-chain walk pre-flight (the other half of B4) is preserved. The check is solving a non-problem: `useradd` does not consult `/etc/shells`, and the SFTP login path uses `Match Group sftp-jailer + ForceCommand internal-sftp` which overrides the user shell entirely.

### User flows (USER)

- [ ] **USER-15**: Migrate-existing-system-users bulk-select screen discovers candidates as the union of (a) users owning a directory under the configured chroot root who are NOT in `sftp-jailer` group AND (b) members of any group matching glob `sftp*` who are NOT in `sftp-jailer` group. Each candidate row shows username, UID, group memberships, chroot-dir match status (yes/no with path), home-dir path.
- [ ] **USER-16**: The migration screen is a multi-select toggle list. The operator checks/unchecks candidates and picks a per-user migration mode from three options: LINK (symlink chroot-side to existing home), REUSE_IN_PLACE (chown existing chroot-dir, no file movement), MOVE-with-rsync (relocate $HOME contents to chroot root then chown).
- [ ] **USER-17**: Migration refuses UID < 1000 candidates at both compile-time const and runtime guard. Operator-locked decision: SFTP users stay regular users with real home dirs and authorized_keys; not service accounts.
- [ ] **USER-18**: A single M-DRY-RUN modal previews all selected migrations together (one diff per user with mode, source, destination, chown plan). On confirm, the migrations commit as a single batch through `internal/txn`. Per-user backups land under `.pre-migrate-<timestamp>` and are retained 30 days.

### Observation (OBS)

- [ ] **OBS-07**: Observer single-flight via `flock` applies to both TUI-fired and timer-fired runs. Concurrent invocations exit cleanly without writing duplicate rows. Recent-run skip: if an observer run completed within the configured window, the TUI-fire is a no-op.
- [ ] **OBS-08**: postinst no longer truncates `observer.cursor` unconditionally on `apt upgrade`. The cursor is preserved across upgrades; re-ingestion of the last 7 days only triggers when the cursor is missing or invalid (closes v1.2 WR-01 carry-over).

### Firewall (FW)

- [ ] **FW-10**: `internal/ufwcomment` v=1 grammar is extended to a discriminated union supporting both user-rules (`v=1:user=<name>`) and subnet-rules (`v=1:scope=subnet:reason=<rfc1918|rfc4193|link-local|operator>`). v1.2.x binaries continue to safely treat unknown shapes as foreign per the `ErrBadVersion` forward-compat contract pinned in `firewall/mode_test.go`.
- [x] **FW-11
**: `[A] Enable ufw` mutation handler runs the actual `ufw --force enable` mutation via `internal/txn` confirm-only path (NOT SAFE-04). Pre-flight: allow-rule check (refuses to enable if there is no SSH allow rule) + remote-SSH-session detection ("you appear to be on an SSH session, this could lock you out"). Operator confirms by typing "YES". Post-enable doctor re-check confirms ufw status reports active. Closes the v1.2.2 `[A] Enable ufw` label-only deferral.

### Lockdown (LOCK)

- [ ] **LOCK-10**: Pre-lockdown subnet detector runs longest-matching-prefix scan over success-tier IPs only (excludes targeted, noise, unmatched). Public-tier IPs are NEVER auto-aggregated.
- [ ] **LOCK-11**: Cluster recognition limited to RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC4193 (`fc00::/7`), and link-local (`169.254.0.0/16`, `fe80::/10`) ranges.
- [ ] **LOCK-12**: M-DRY-RUN modal extended to show the proposed subnet rule alongside the explicit list of covered IPs (so the operator can audit "you're allowing 10.0.0.0/24, which covers 10.0.0.5, 10.0.0.7, 10.0.0.12 from observed connections plus any future 10.0.0.x"), before the operator confirms.
- [ ] **LOCK-13**: Operator-tunable subnet thresholds in S-SETTINGS with defaults 60% in /24, 75% in /16, 90% in /8 (deeper prefix = stricter bar). Subnet detection is suppressed when the cluster does not meet the threshold; lockdown falls back to per-IP enumeration.

### TUI: doctor + footer + friendliness (TUI)

- [ ] **TUI-12**: Doctor "ufw inactive" row copy includes an inline note about the `systemctl is-active ufw` returning "active" while `ufw status` returns "inactive" divergence. Wording locked at v1.2.2 close: keep "inactive" (matches `ufw status`) and add "Note: `systemctl is-active ufw` may report 'active' - that 'active (exited)' is the oneshot init service, not rule enforcement. `ufw status` is the source of truth."
- [ ] **TUI-13**: Multi-line nav-footer on every screen using a per-screen `KeyHints() []Hint` (or richer struct) interface. Colors match the SFTP-JAILER logo palette. Degrades gracefully on terminals narrower than 80 columns (truncate or wrap keys; never blank). Replaces ad-hoc inline footer copy on existing screens.
- [ ] **TUI-14**: Friendliness pass: scan all user-facing strings for remaining dev-jargon (continuation of v1.2.1 "canonical config" rename). Centralize user-facing strings with stable string IDs (e.g., `LBL_APPLY_DROPIN_TITLE`) so future renames preserve the docs/uat/*.md audit trail. Includes addkey fetch-fallback copy refresh ("modal stays open until request returns").
- [ ] **TUI-15**: S-SETTINGS save propagates password-aging values to in-process `usersCfg` without requiring TUI restart (closes v1.2 WR-02 carry-over).

### Launch state machine (LAUNCH)

- [ ] **LAUNCH-01**: TUI launch runs doctor automatically before showing any interactive screen. The doctor scan results are presented as the launch screen content.
- [ ] **LAUNCH-02**: When doctor returns all 6 sections `[OK]`, the launch screen counts down 2 seconds and auto-continues. Any keystroke pauses the countdown indefinitely. Esc holds on the doctor view permanently.
- [ ] **LAUNCH-03**: After green-gate auto-continue, the TUI routes to the unified management console (CONSOLE-01). Non-green doctor pins on the doctor screen until the operator dispatches an `[A]` action and the doctor re-runs green.
- [ ] **LAUNCH-04**: TUI launch fires `observe-run` async (goroutine via `tea.Cmd` + `*tea.Program.Send`) after the green-gate. `flock` single-flight protects against concurrent timer fire (OBS-07). Skip if an observer run completed within the configured recent-run window (default 5 minutes; tunable in S-SETTINGS).
- [ ] **LAUNCH-05**: Splash logo is enlarged to fill more of the terminal; auto-dismiss timeout is extended by 1 second over the v1.2.x value.

### Unified management console (CONSOLE)

- [ ] **CONSOLE-01**: A single management overview screen replaces `home` as the default landing target. One row per SFTP user.
- [ ] **CONSOLE-02**: Per-row columns: username, UID, group memberships, password aging state (days until force-change), SSH key count, firewall rule count + lockdown coverage indicator, last-seen IP, observation tier counts (success / targeted / noise / unmatched).
- [ ] **CONSOLE-03**: Per-row keybinds (lowercase mutates current row, uppercase navigates or destructive): `a`/`k` add SSH key, `p` set/reset password, `r`/`f` add/edit firewall rule, `D` delete user firewall rules, `d` delete user, `L` open per-user log detail.
- [ ] **CONSOLE-04**: Cursor navigation (`j`/`k`/`g`/`G`), sort cycle, fuzzy `/` search, OSC52 yank-row preserved from existing S-USERS conventions.
- [ ] **CONSOLE-05**: S-USERS and S-FIREWALL screens are retired from the screen registry. Their functionality is fully delivered by the console; their per-screen Go files are removed.
- [ ] **CONSOLE-06**: S-LOGS (drill-down via `L` or `l`) and S-LOCKDOWN (drill-down via top-bar action) remain reachable from the console as drill-down screens.
- [ ] **CONSOLE-07**: Console renders correctly at 80, 100, 120 column terminal widths with column-priority truncation (drop low-priority columns first; never collapse cursor or username); golden-file tests cover all three width bands.

### Distribution + supply chain (DIST)

- [ ] **DIST-11**: GitHub Actions release + CI workflows migrated off Node 20 ahead of the 2026-06-02 forced-Node-24 deadline / 2026-09-16 Node-20-removal. `actions/checkout`, `actions/setup-go`, `goreleaser/goreleaser-action` (and any other Node-20-flagged action surfaced by GH warnings) pinned or upgraded to Node-24-compatible versions.
- [ ] **DIST-12**: Cosign-keyless-signed reproducible releases: `cosign sign-blob` over each `.deb` + `SHA256SUMS.txt` + goreleaser manifest. Verification instructions added to README. Verified on a clean machine via `cosign verify-blob`.

### Logs view (LOG)

- [ ] **LOG-07**: Observation log view default mode shows one row per `(source_ip, username)` pair with last-seen timestamp, connection count, and tier classification.
- [ ] **LOG-08**: Drill-down (Enter) on a deduplicated row opens the full per-`(IP, user)` event history reading the underlying audit DB rows. Every connection (and future file-transfer event) remains accessible.
- [ ] **LOG-09**: Tier-colored dedup rows: success=green, targeted=red, noise=gray, unmatched=yellow.
- [ ] **LOG-10**: Underlying observation DB schema unchanged (every connection persisted; dedup is presentation-layer only). Covering index `observation_runs(source_ip, username, ts_unix_ns DESC)` added via migration `004_add_dedup_index.sql`; schema bumps to `user_version=4`.

### Tech debt cleanup (DEBT)

- [ ] **DEBT-01**: Close v1.2 carry-over tech-debt items not folded into other requirements: WR-04 remove dead `NewBackupDefaultUfwStep`; IN-01 cancel userlog read-only goroutines on modal pop; IN-03 fix `rows.Err()` ordering after `rows.Close()` in queries.go; post-06-05 IN-02 align `deleteuser.Model` with `errFatal` field carried by other 3 modals; WR-03 clean up misleading lintian-overrides WHY block comment; `git rm docs/man/.gitkeep`.

---

## Future Requirements (deferred from v1.3)

### Distribution v2 (DIST-v2) - already deferred from v1.1/v1.2

- **DIST-v2-02**: SLSA Level 3 provenance via `slsa-github-generator` action. Defer to v1.4.
- **DIST-v2-03**: `linux/arm/v7` (32-bit) `.deb` for Raspberry-Pi-class hardware. Defer to v1.4.

### TUI advanced features

- **Next-action cue (data-driven advisor)**: footer surfaces "3 users have no SSH keys; press `k` on a row to fix" derived from per-screen state. Differentiator beyond reactive key-hints. Defer to v1.4 pending discuss-phase scoping.
- **"Promote IP to lockdown allowlist" cross-screen one-key**: dedup-view -> S-LOCKDOWN one-key flow. Cross-screen state plumbing is L-scope. Defer to v1.4.
- **`home` screen full retirement**: console replaces it as landing; `home` stays in tree as a fallback. Operator may prefer full retirement; that is a v1.4 cleanup decision.
- **Bulk-select primitive generalization**: USER-15/16's multi-select toggle list is the first multi-select primitive in v1.x. If it generalizes well, future screens may adopt it (e.g., bulk delete of firewall rules). Defer pattern-extraction to v1.4.

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| Switching SFTP users to system-UID range during migration | Operator-locked: SFTP users stay regular users (UID >= 1000) with real home dirs and authorized_keys, not service accounts. Phase 3 invariant preserved. |
| Auto-aggregate public-IP `/24` ranges in subnet whitelist | Threat-model regression: hosting-provider /24 spans many tenants. Allow-surface explosion. Subnet aggregation limited to RFC1918 / RFC4193 / link-local. |
| Auto-apply subnet whitelist without confirm | "Surprise allow surface" anti-pattern; M-DRY-RUN gate is mandatory. |
| Cached doctor result skip on launch | State changes between launches; cache is a footgun. Doctor re-runs on every launch. |
| Real-time sub-second refresh of dedup view | sftp-jailer is forensic, not IDS. Refresh is on-demand or periodic. |
| Mouse-clickable footer hints | SSH/jumphost mouse unreliable. Keys only. |
| Vim-like ex-command line for search | `/` fuzzy search is sufficient for sysadmin audience; ex-mode is dev-tool culture. |
| Bumping `ufwcomment` to v=2 | Synthesis verdict: stay on v=1, extend to discriminated union. v=2 self-DoSes the schema's own forward-compat for the dominant user-rule case (v1.2.x binaries reading v=2 user-rules return ErrBadVersion and refuse to act). Discriminated union extends safely without breaking the existing forward-compat test. |
| `ufw enable` under SAFE-04 timer coverage | Operator-locked Key Decision (v1.3): the SAFE-04 compensator (`ufw disable`) leaves the system in a state that did not exist before the mutation (rules but no enforcement). Confirm-only is the correct gate. |

---

## Traceability

Phase mapping validated by gsd-roadmapper 2026-05-03. Phases 8-14 continue from v1.2's Phase 7. **Build order is 8 -> 9 -> 10 -> 11 -> 13 -> 12 -> 14** (NOT phase-number order): Phase 12 (launch state machine) lands AFTER Phase 13 (console) because the unified console is the post-green-gate routing target. Phase 14 (footer + friendliness + tech debt) lands last to avoid churn during flagship development.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SETUP-07 | Phase 8 | Pending |
| SETUP-08 | Phase 8 | Pending |
| FW-11 | Phase 8 | Pending |
| TUI-12 | Phase 8 | Pending |
| FW-10 | Phase 9 | Pending |
| LOG-07 | Phase 9 | Pending |
| LOG-08 | Phase 9 | Pending |
| LOG-09 | Phase 9 | Pending |
| LOG-10 | Phase 9 | Pending |
| USER-15 | Phase 10 | Pending |
| USER-16 | Phase 10 | Pending |
| USER-17 | Phase 10 | Pending |
| USER-18 | Phase 10 | Pending |
| LOCK-10 | Phase 11 | Pending |
| LOCK-11 | Phase 11 | Pending |
| LOCK-12 | Phase 11 | Pending |
| LOCK-13 | Phase 11 | Pending |
| CONSOLE-01 | Phase 13 | Pending |
| CONSOLE-02 | Phase 13 | Pending |
| CONSOLE-03 | Phase 13 | Pending |
| CONSOLE-04 | Phase 13 | Pending |
| CONSOLE-05 | Phase 13 | Pending |
| CONSOLE-06 | Phase 13 | Pending |
| CONSOLE-07 | Phase 13 | Pending |
| LAUNCH-01 | Phase 12 | Pending |
| LAUNCH-02 | Phase 12 | Pending |
| LAUNCH-03 | Phase 12 | Pending |
| LAUNCH-04 | Phase 12 | Pending |
| LAUNCH-05 | Phase 12 | Pending |
| OBS-07 | Phase 12 | Pending |
| OBS-08 | Phase 12 | Pending |
| TUI-13 | Phase 14 | Pending |
| TUI-14 | Phase 14 | Pending |
| TUI-15 | Phase 14 | Pending |
| DEBT-01 | Phase 14 | Pending |
| DIST-11 | Phase 14 | Pending |
| DIST-12 | Phase 14 | Pending |

**Coverage:**
- v1.3 requirements: 37 total (corrected; the original "38" headline at requirements-definition time was an off-by-one count error - the underlying category enumeration and traceability table both contain 37 distinct REQ-IDs)
- Mapped to phases: 37 (100% coverage; roadmap-validated 2026-05-03)
- Unmapped: 0
- Duplicate mappings: 0

**Phase requirement counts:**
- Phase 8 (Frame): 4 (SETUP-07, SETUP-08, FW-11, TUI-12)
- Phase 9 (Data Layer): 5 (FW-10, LOG-07, LOG-08, LOG-09, LOG-10)
- Phase 10 (Migrate): 4 (USER-15, USER-16, USER-17, USER-18)
- Phase 11 (Subnet): 4 (LOCK-10, LOCK-11, LOCK-12, LOCK-13)
- Phase 13 (Console): 7 (CONSOLE-01..07)
- Phase 12 (Launch): 7 (LAUNCH-01..05, OBS-07, OBS-08)
- Phase 14 (Footer + Friendliness + Tech Debt): 6 (TUI-13, TUI-14, TUI-15, DEBT-01, DIST-11, DIST-12)
- Sum: 4 + 5 + 4 + 4 + 7 + 7 + 6 = 37

---

*Requirements defined: 2026-05-03*
*Last updated: 2026-05-03 - milestone v1.3 opened via /gsd:new-milestone; requirements scoped from operator feedback + 4-researcher synthesis; roadmap validated 2026-05-03 (build order 8 -> 9 -> 10 -> 11 -> 13 -> 12 -> 14 with Phase 12 landing AFTER Phase 13). Coverage recount surfaced 37 (not 38) requirements; corrected inline.*
