---
phase: 5
slug: packaging-install-purge-automated-release
status: verified
threats_open: 0
asvs_level: 1
created: 2026-04-30
---

# Phase 5 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
>
> Phase scope: `.deb` build pipeline (DIST-02/03), install/purge round-trip
> (DIST-04/05/09), automated tag-push release (DIST-08), and the Debian 13
> empirical UAT acceptance gate (DIST-10), plus the `init-db` postinst hook
> closing DIST-04 SC3.

---

## Trust Boundaries

Aggregated from the seven plan-level threat models (deduplicated where the
same boundary appears in multiple plans).

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| developer machine → goreleaser | YAML config drives both local snapshot builds and CI release. Schema errors surface as `goreleaser check` / build failures, not at runtime on user systems. | Build manifest (paths, modes, scripts list) |
| nfpm → dpkg | The `nfpms.contents` block declares files and modes; dpkg installs them as root. Any path or mode here is what lands on every user's system. | Package contents (binaries, units, man, overrides, state dir) |
| build artifact → end-user host | The `.deb` is integrity-checked only via `SHA256SUMS.txt` (cosign deferred to DIST-v2-01, SLSA L3 to DIST-v2-02). End-users trust the GitHub Releases TLS chain to verify artifact origin. | `.deb` (binary + scripts + metadata) |
| developer commit → CI guard | A PR may modify the cobra tree (add/rename/hide subcommands). `scripts/check-manpage-fresh.sh` ensures `docs/man/` is regenerated; otherwise the `.deb` ships stale man pages. | Cobra metadata → groff |
| generated groff → /usr/share/man/man1/ | Lintian on the `.deb` requires the man page at the conventional path; missing → `no-manual-page` warning, fails DIST-03 pedantic gate. | Pre-compressed man pages |
| stub factories in cmd/gen-manpage → production factories in cmd/sftp-jailer | Drift produces stale `.1` files. CI guard mitigates. | Cobra command metadata |
| dpkg prerm (root) → /usr/bin/sftp-jailer purge-sshd-cleanup | The prerm runs as root in dpkg's non-interactive context. The subcommand inherits SAFE-01 root gate; EUID is already 0 here. The threat surface is whether the subcommand can be tricked into removing files OTHER than the canonical drop-in. | argv (none — case-arg only); EUID=0 |
| applysetup.DropInPath (compile-time const) → ops.RemoveAll | The path is a Go const, baked into the binary at build time. No env/flag/config-file override. The only way to change the targeted path is to recompile. | Hard-coded path string |
| internal/txn compensator chain → drop-in restore | If `sshd -t` fails after RemoveSshdDropIn succeeded, the compensator restores from `/var/backups/sftp-jailer/`. Tampering window is bounded by 30s ctx timeout; backup dir is mode 0700 root-owned. | Drop-in bytes (no secrets) |
| /var/backups/sftp-jailer survives apt purge | Deliberate trust choice — admins keep the last drop-in's bytes after purge for recovery. Contents readable only to root; no secret material in a sshd drop-in. | Drop-in bytes |
| dpkg (root) → maintainer scripts | dpkg invokes scripts as root in non-interactive context. Scripts use NO variables from external input (`$1` is dpkg's case-arg, validated against a fixed allowlist). | dpkg case-arg (`configure`/`remove`/`purge`/etc.) |
| postinst → /var/lib/sftp-jailer/ | postinst creates this directory mode 0755 and writes observer.cursor mode 0600. `install -d` does NOT change perms on an existing dir — brownfield admin's ownership is preserved. | Directory + cursor file |
| postinst → /usr/bin/sftp-jailer init-db | postinst invokes the package's own binary to initialize observations.db at install time (DIST-04 SC3). Guarded by `[ -x ... ]`. SAFE-01 inherited. | DB path → SQLite migrate |
| prerm → /usr/bin/sftp-jailer purge-sshd-cleanup | Shell script invokes the binary by literal path while the binary is still on disk. dpkg + apt verify the `.deb`'s binary is from this package. | Binary path; argv |
| postrm → rm -rf /var/lib/sftp-jailer | Path is a hardcoded literal. No globbing, no variable substitution. | Path string |
| .deb on disk → end-user host | DIST-v2-01 (cosign) closes this gap in v2.x. SHA256SUMS.txt + GitHub Releases TLS is the v1.2 trust chain. | `.deb` artifact |
| Tag push (developer) → release.yml | The workflow trusts that anyone with push-tag permission is authorized to release. Branch-protection rules out of scope. | Git tag (e.g. `v1.2.0`, `v1.2.0-rc1`) |
| GitHub Actions runner → goreleaser-action | Action pinned to major version (`@v6`); goreleaser binary pinned at `v2.15.4`. | Workflow inputs (config path, args) |
| GITHUB_TOKEN scope | `contents: write` only. NO `id-token: write`, NO `packages: write`, NO `actions: write`. | Auto-provisioned GHA token |
| .deb on dist/ → GitHub Release attachment | Goreleaser uploads the .deb + .tar.gz; release.yml appends SHA256SUMS.txt independently. | Artifact bytes |
| lintian gate → CI failure | If lintian raises a non-overridden warning, the workflow exits non-zero. | Lintian warning set |
| Operator (root on staging VMs) → cmd/uat-05 binary | Operator copies the helper to the VMs and runs as root. Binary built from project source; CGO_ENABLED=0; respects `check-no-exec-outside-sysops.sh`. | Helper binary |
| cmd/uat-05 → /var/log/sftp-jailer-uat-05/ | Receipts written mode 0644 root:root. Contains evidence (file hashes, host info, command excerpts). No secrets. | JSON receipts |
| Brownfield UAT-MARKER write to /etc/ssh/sshd_config | Runbook instructs operator to append a comment line on a STAGING VM dedicated to brownfield variant — never production. | Marker comment line |
| sha256sum baseline → operator → env var | Baseline hash captured, recorded, re-supplied via `UAT_BASELINE_SHA256`. Typo would surface as `DIST-09 VIOLATION` (over-classification — safe direction). | Hash string |
| Debian 13 lab host @192.168.1.170 | Single-purpose UAT host; not tier-1 supported per `lab_host_debian13.md`. | SSH session |
| postinst init-db → SQLite | DSN-based open, forward-only Migrate. PeekUserVersion gate rejects downgrade-install (exit 2). | DB path; PRAGMA user_version |
| Schema-drift gate (init-db / observe-run) | Both invocations check `user_version > ExpectedSchemaVersion` and refuse with same exit code (2). Consistent OBS-04 behavior. | PRAGMA value |
| 0644 observations.db | Pre-existing posture: created mode 0644 root:root (sqlite default). Contents are SFTP transaction metadata; no credentials. | SFTP event metadata |

---

## Threat Register

Plan-by-plan classification of all 56 phase threats. Status reflects the
verification disposition rule: `mitigate` threats CLOSED if the cited
mitigation pattern is present in implementation; `accept` threats CLOSED
once entered into the Accepted Risks Log below.

### 05-01 — goreleaser + nfpm config (6 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-01-01 | Tampering | nfpms.contents file paths | mitigate | All `src:`/`dst:` entries in `packaging/goreleaser.yml` are hardcoded literals (e.g. `packaging/systemd/sftp-jailer-observer.service` → `/lib/systemd/system/sftp-jailer-observer.service`). No template expansion of user-supplied values. | closed |
| T-05-01-02 | Tampering | nfpms.scripts maintainer-script paths | mitigate | `packaging/goreleaser.yml` L124-L127 references scripts by literal repo path (`packaging/debian/postinst`, `prerm`, `postrm`). | closed |
| T-05-01-03 | Information Disclosure | goreleaser env / token surface | accept | See Accepted Risks Log. | closed |
| T-05-01-04 | Denial of Service | Pre-release version pollution | mitigate | `replace .Version "-" "~"` template at `packaging/goreleaser.yml` L46+L56 only handles `vX.Y.Z[-rcN]` forms; release.yml `on.push.tags` filter rejects other tag forms. | closed |
| T-05-01-05 | Elevation of Privilege | nfpms file_info.mode for state dir | mitigate | `/var/lib/sftp-jailer` declared mode `0755` at goreleaser.yml L122; observation DB mode handled at runtime; observer.cursor pre-created `0600` in postinst. No `0777` anywhere. | closed |
| T-05-01-06 | Spoofing | Goreleaser changelog regex over arbitrary commits | accept | See Accepted Risks Log. | closed |

### 05-02 — manpage generator + CI guard (5 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-02-01 | Tampering | gatherSubcommands stub list drift | mitigate | `scripts/check-manpage-fresh.sh` runs in CI on every PR; diffs generator output against committed `docs/man/`. (Known minor glitch: `.gitkeep` placeholder leftover noted in 05-07-SUMMARY; does not relax the contract — generator still produces 4 expected pages.) | closed |
| T-05-02-02 | Information Disclosure | Generated man page leaking ldflag-injected secrets | accept | See Accepted Risks Log. | closed |
| T-05-02-03 | Repudiation | Non-deterministic generator output | mitigate | `cmd/gen-manpage/main.go` L51 hardcodes `fixedDate := time.Date(2026, time.April, 29, ...)`; passed as `GenManHeader.Date`. Deterministic output. | closed |
| T-05-02-04 | Denial of Service | CI guard adds ~5-10s per CI run | accept | See Accepted Risks Log. | closed |
| T-05-02-05 | Elevation of Privilege | rootcmd.Build accepts function pointer | accept | See Accepted Risks Log. | closed |

### 05-03 — purge-sshd-cleanup subcommand (7 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-03-01 | Tampering | applysetup.DropInPath constant | mitigate | `cmd/sftp-jailer/purge_cleanup.go` L101+L106+L109 reads the path via `applysetup.DropInPath` (compile-time const). No runtime override. Test `TestPurgeBackupDir_OutsideVarLib` pins value. | closed |
| T-05-03-02 | Tampering | /var/backups/sftp-jailer between Apply and Compensate | accept | See Accepted Risks Log. | closed |
| T-05-03-03 | Denial of Service | Hung systemctl/sshd during reload | mitigate | `purgeSshdCleanupTimeout = 30 * time.Second` (purge_cleanup.go L50); subprocess timeouts in `internal/sysops/real.go` (`10 * time.Second` default) bound individual exec calls. | closed |
| T-05-03-04 | Elevation of Privilege | sshd -t output as untrusted parsed input | accept | See Accepted Risks Log. | closed |
| T-05-03-05 | Repudiation | No audit log of removed drop-in path | mitigate | Backup file at `/var/backups/sftp-jailer/<ts>-50-sftp-jailer.conf.bak` preserves prior bytes; subcommand prints to dpkg's stream (apt's invocation log). `internal/txn/steps.go` L156-L158 writes the backup mode `0o600`. | closed |
| T-05-03-06 | Information Disclosure | Drop-in content in backup file readable post-purge | accept | See Accepted Risks Log. | closed |
| T-05-03-07 | Tampering | isCompensateFailure substring fallback could misclassify | mitigate | Predicate over-classifies as "compensate failure" (exit 2) — safe direction (admin investigates "ROLLBACK FAILED"); caveat documented in code at `cmd/sftp-jailer/purge_cleanup.go` L126-L138. | closed |

### 05-04 — Debian maintainer scripts (9 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-04-01 | Tampering | postinst's addgroup --system sftp-jailer | mitigate | `packaging/debian/postinst` L26: `getent group sftp-jailer >/dev/null \|\| addgroup --system sftp-jailer` — idempotent, no variable interpolation. | closed |
| T-05-04-02 | Tampering | postrm's rm -rf /var/lib/sftp-jailer | mitigate | `packaging/debian/postrm` L38: hardcoded literal path; no globbing; no variable expansion. | closed |
| T-05-04-03 | Spoofing | prerm's invocation of /usr/bin/sftp-jailer purge-sshd-cleanup | accept | See Accepted Risks Log. | closed |
| T-05-04-04 | Denial of Service | Hung purge-sshd-cleanup stalls apt purge | mitigate | 30-second `context.WithTimeout` (purge_cleanup.go L95); `\|\| true` wrapper in prerm L64 lets apt purge continue on non-zero exit. | closed |
| T-05-04-05 | Elevation of Privilege | observer.cursor mode 0600 root:root drift | mitigate | `packaging/debian/postinst` L67-L68: `: > /var/lib/sftp-jailer/observer.cursor` then `chmod 0600 /var/lib/sftp-jailer/observer.cursor` — explicit mode set. | closed |
| T-05-04-06 | Information Disclosure | rm -rf leaks observations.db state via undelete | accept | See Accepted Risks Log. | closed |
| T-05-04-07 | Repudiation | No audit trail mapping .deb version to scripts run | accept | See Accepted Risks Log. | closed |
| T-05-04-08 | Tampering | Malicious /etc/ssh/sshd_config write during prerm | accept | See Accepted Risks Log. | closed |
| T-05-04-09 | Tampering | lintian-overrides used to suppress security-relevant warnings | mitigate | `packaging/debian/lintian-overrides` entries each carry a `# WHY:` rationale block referencing CONTEXT.md decisions or REQUIREMENTS.md (24 entries with rationale comments at file head of each group). | closed |

### 05-05 — Release workflow (10 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-05-01 | Spoofing | Compromised goreleaser-action major version | mitigate | `.github/workflows/release.yml` L103: `goreleaser/goreleaser-action@v6` (major-version pin); goreleaser binary pinned at `v2.15.4` (L106). | closed |
| T-05-05-02 | Tampering | Tag forgery (attacker pushes v1.2.0) | accept | See Accepted Risks Log. | closed |
| T-05-05-03 | Information Disclosure | secrets.GITHUB_TOKEN leakage to logs | mitigate | release.yml passes token only via `env:` block (L109+L151); GHA auto-redacts. No `echo "$GITHUB_TOKEN"` or curl-with-token args. | closed |
| T-05-05-04 | Denial of Service | Long-running step exceeds GHA timeout | mitigate | release.yml has no `timeout-minutes:` override; ubuntu-24.04 default 6h easily covers expected 10-15 min wall time. No infinite-loop step. | closed |
| T-05-05-05 | Elevation of Privilege | govulncheck `go install ...@latest` pulls malicious version | mitigate | release.yml L70-L71: govulncheck is `golang.org/x/vuln/cmd/govulncheck` — Google-maintained module. Trade-off (vuln-DB freshness vs supply-chain risk) accepted; documented for future tightening. | closed |
| T-05-05-06 | Spoofing | Tag-pattern attacker pushes malicious commit | accept | See Accepted Risks Log. | closed |
| T-05-05-07 | Tampering | lintian-overrides used to suppress security-relevant warnings | mitigate | Same control as T-05-04-09: each entry carries a `# WHY:` rationale; PR review on changes. | closed |
| T-05-05-08 | Repudiation | Release artifact provenance | accept | See Accepted Risks Log. | closed |
| T-05-05-09 | Tampering | Released .deb's lintian-overrides expanded mid-release | accept | See Accepted Risks Log. | closed |
| T-05-05-10 | Information Disclosure | SHA256SUMS.txt does not authenticate provenance | accept | See Accepted Risks Log. | closed |

### 05-06 — Empirical UAT runbook (9 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-06-01 | Tampering | cmd/uat-05 binary on the VM | mitigate | Built CGO_ENABLED=0; `cmd/uat-05/main.go` does not bypass sysops (`check-no-exec-outside-sysops.sh` passes per 05-06-SUMMARY). | closed |
| T-05-06-02 | Tampering | UAT_BASELINE_SHA256 env var | mitigate | `cmd/uat-05/main.go` L439-L470 uses the env var for string comparison only; no command/path interpolation. | closed |
| T-05-06-03 | Information Disclosure | /var/log/sftp-jailer-uat-05/ receipts world-readable | accept | See Accepted Risks Log. | closed |
| T-05-06-04 | Spoofing | Operator copies tampered .deb | mitigate | Runbook references operator's own goreleaser snapshot (same dev box as source); SHA256SUMS verification documented in README Install for end-users. | closed |
| T-05-06-05 | Denial of Service | runObserveFire 2-minute polling loop hangs | mitigate | `cmd/uat-05/main.go` L369: `deadline := time.Now().Add(2 * time.Minute)`; loop exits at deadline (L371+L384). | closed |
| T-05-06-06 | Repudiation | Runbook PASS/FAIL filled without traceable signature | mitigate | Operator signoff present (commit `d27eb2d` per 05-06-SUMMARY L347 and `28df7f5` per recent git log); JSON receipts at `/var/log/sftp-jailer-uat-05/<subcmd>.json` provide audit trail. | closed |
| T-05-06-07 | Elevation of Privilege | Stub subcommands imply automation but require operator | accept | See Accepted Risks Log. | closed |
| T-05-06-08 | Tampering | UAT-MARKER on a non-staging box | accept | See Accepted Risks Log. | closed |
| T-05-06-09 | Information Disclosure | Lintian-overrides `# WHY:` could leak sensitive context | mitigate | All `# WHY:` entries in `packaging/debian/lintian-overrides` reference public planning artifacts (CONTEXT.md, REQUIREMENTS.md, plan numbers, lintian tag rationale). PR review on changes. | closed |

### 05-07 — postinst init-db (10 threats)

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-05-07-01 | Tampering | postinst init-db invocation could be subverted between unpack and configure | accept | See Accepted Risks Log. | closed |
| T-05-07-02 | Tampering | Schema-drift gate bypass via direct sqlite write | accept | See Accepted Risks Log. | closed |
| T-05-07-03 | Denial of Service | init-db hangs apt install due to sqlite lock | mitigate | `cmd/sftp-jailer/init_db.go` L56+L97: `initDBTimeout = 30 * time.Second` via `context.WithTimeout`; postinst's `set -e` propagates the failure. | closed |
| T-05-07-04 | Denial of Service | Schema-drift refusal blocks legitimate downgrade-install | accept | See Accepted Risks Log. | closed |
| T-05-07-05 | Information Disclosure | observations.db at mode 0644 leaks SFTP metadata | mitigate | Pre-existing posture preserved (sqlite default mode 0644 root:root, observer.service runs as User=root). init-db does not relax. CONTEXT.md decision stands. | closed |
| T-05-07-06 | Repudiation | Operator signs off step 2.4 PASS without PRAGMA evidence | mitigate | `05-UAT.md` L55-L60+L76-L80 captures empirical PRAGMA user_version=3 on Ubuntu 24.04 (192.168.1.187) and Debian 13 (192.168.1.170); `05-VERIFICATION.md` L19-L20 documents byte-identical 73728-byte DB at install time on both hosts. | closed |
| T-05-07-07 | Elevation of Privilege | init-db invoked by arbitrary local user | mitigate | rootCmd PersistentPreRunE → `safeRootGate` (cmd/sftp-jailer/main.go L111+L125) gates EUID; `Hidden: true` (init_db.go L84) excludes from `--help`. | closed |
| T-05-07-08 | Tampering | initDBOsExit test seam abused to suppress production exit | accept | See Accepted Risks Log. | closed |
| T-05-07-09 | Information Disclosure | Lintian-overrides `# WHY:` leaks internal CVE/incident references | mitigate | New override entries (lintian-overrides L56-L65) reference plan 05-07 + DIST-04 SC3 + ROADMAP — all public planning artifacts. | closed |
| T-05-07-10 | Spoofing | Malicious .deb ships backdoored init-db | accept | See Accepted Risks Log. | closed |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-05-01-03 | T-05-01-03 | This plan does not invoke goreleaser with any token. Only `goreleaser check` (offline schema validation) runs locally; token surface lives in 05-06's GitHub Actions workflow. | gsd-secure-phase | 2026-04-30 |
| AR-05-01-06 | T-05-01-06 | Changelog is informational only; a malicious commit message cannot escalate privilege through goreleaser's git-log changelog (plain markdown in the GitHub release body). Standard markdown injection at most — same surface as any GitHub release. | gsd-secure-phase | 2026-04-30 |
| AR-05-02-02 | T-05-02-02 | `versionString()` returns the literal `"1"` — does not pull from `internal/version` (ldflag-injected at production link time). No secret surface in the generated man pages. | gsd-secure-phase | 2026-04-30 |
| AR-05-02-04 | T-05-02-04 | Runtime overhead is negligible relative to the test suite (~30s) and govulncheck (~30s). The invariants job already runs grep-based scripts in <2s; this adds Go compile time but stays within job budget. | gsd-secure-phase | 2026-04-30 |
| AR-05-02-05 | T-05-02-05 | `rootcmd.Build` is consumed by exactly two call sites: `cmd/sftp-jailer` (production) and `cmd/gen-manpage` (build-time). Both owned by the project. External callers via `go install` would need write access to the repo first. | gsd-secure-phase | 2026-04-30 |
| AR-05-03-02 | T-05-03-02 | Window between Apply and Compensate is bounded by 30s context timeout. Backup directory is root-owned. An attacker who can write `/var/backups/sftp-jailer` already has root; threat model is moot. | gsd-secure-phase | 2026-04-30 |
| AR-05-03-04 | T-05-03-04 | The subcommand does not parse sshd -t output — it only checks the exit code via the `SshdT` typed wrapper. Parser-induced exploits out of scope; non-zero exit triggers txn rollback. | gsd-secure-phase | 2026-04-30 |
| AR-05-03-06 | T-05-03-06 | sshd drop-in contains no secrets (Subsystem path, `Match Group sftp-jailer`, ChrootDirectory, ForceCommand). Backup mode 0600 root-owned. Admin reading own root-owned file is in-policy. | gsd-secure-phase | 2026-04-30 |
| AR-05-04-03 | T-05-04-03 | If `/usr/bin/sftp-jailer` has been replaced with a malicious binary by an attacker who already has root, the threat model is moot. The .deb itself ships the binary atomically via dpkg. | gsd-secure-phase | 2026-04-30 |
| AR-05-04-06 | T-05-04-06 | Debian convention is "purge means purge", not secure-erase. Admins on shared hardware should configure their filesystems with secure-erase semantics if needed. Out of scope for the .deb. | gsd-secure-phase | 2026-04-30 |
| AR-05-04-07 | T-05-04-07 | dpkg's own audit log (`/var/log/dpkg.log`) records package + version + action. Maintainer scripts' stdout/stderr captured by apt's invocation log. No separate audit destination needed. | gsd-secure-phase | 2026-04-30 |
| AR-05-04-08 | T-05-04-08 | Any attacker who can write `/etc/ssh/sshd_config` during prerm already has root. Brownfield safety guards against ACCIDENTAL admin tampering, not malicious actors with root. | gsd-secure-phase | 2026-04-30 |
| AR-05-05-02 | T-05-05-02 | Only repo collaborators with tag-push permission can fire the workflow. The threat is "compromised collaborator" — out of scope (resolved via GitHub branch protection / required reviews). | gsd-secure-phase | 2026-04-30 |
| AR-05-05-06 | T-05-05-06 | Same as AR-05-05-02 — threat requires tag-push permission. GitHub's tag-push log is the audit trail. | gsd-secure-phase | 2026-04-30 |
| AR-05-05-08 | T-05-05-08 | DIST-v2-02 (SLSA L3 provenance) deferred. v1.2 trust chain is "GitHub Releases TLS + SHA256SUMS.txt + workflow audit log under github.com/.../actions". Sufficient for v1.2 admin-trusted posture. | gsd-secure-phase | 2026-04-30 |
| AR-05-05-09 | T-05-05-09 | The override-list is committed to git at `packaging/debian/lintian-overrides`; PR review surfaces every addition. The CI gate runs lintian against the .deb (which embeds the same overrides), so gate behavior is consistent with what end-users would see. | gsd-secure-phase | 2026-04-30 |
| AR-05-05-10 | T-05-05-10 | Sums prove "what you downloaded matches what we built", not "who built it." Provenance signing (cosign + SLSA) explicitly deferred to DIST-v2-01/02. README install instructions document the trust chain. | gsd-secure-phase | 2026-04-30 |
| AR-05-06-03 | T-05-06-03 | Receipts are mode 0644 (world-readable). Contents include uname, dpkg arch, sshd -T excerpt — no secrets. STAGING VM exposure acceptable; runbook explicitly notes UAT is staging-only. | gsd-secure-phase | 2026-04-30 |
| AR-05-06-07 | T-05-06-07 | Each stub returns an informative error pointing to the runbook section that owns the TUI flow. Operators see exactly where to go. The accepted limitation is that the helper cannot fully drive the TUI (would require teatest scripting + headless flag — high effort for v1.2). | gsd-secure-phase | 2026-04-30 |
| AR-05-06-08 | T-05-06-08 | Runbook explicitly warns "Run on a CLEAN Ubuntu 24.04 VM dedicated to UAT — never production." Brownfield variant uses a SECOND VM. Marker is a deliberate test edit; misuse is operator error, not a tool issue. | gsd-secure-phase | 2026-04-30 |
| AR-05-07-01 | T-05-07-01 | Standard Debian unpack-then-configure model. dpkg writes `/usr/bin/sftp-jailer` atomically. The `[ -x ... ]` guard tolerates the unpack window but does not defend against a malicious post-unpack write — that would require root, which already trusts the package. | gsd-secure-phase | 2026-04-30 |
| AR-05-07-02 | T-05-07-02 | Defense-in-depth: Migrate is forward-only. If an attacker with root edits user_version, they have already compromised the box; the OBS-04 gate is a guardrail against ACCIDENTAL downgrade, not adversarial defense. | gsd-secure-phase | 2026-04-30 |
| AR-05-07-04 | T-05-07-04 | The exit-2 refusal is the documented OBS-04 contract. Admin debugging via downgrade can `rm /var/lib/sftp-jailer/observations.db` first (DB is reproducible from journalctl per README Recovery section). SAFE-by-default behavior — silent migration loss would be worse. | gsd-secure-phase | 2026-04-30 |
| AR-05-07-08 | T-05-07-08 | Package-var seams not exposed via flags or env vars. Code review catches any production caller that overrides them. The same pattern is established for `purgeOsExit` (05-03) without incident. | gsd-secure-phase | 2026-04-30 |
| AR-05-07-10 | T-05-07-10 | Standard "trust the .deb" surface — addressed at the GHA SHA256SUMS layer (DIST-08 in 05-05) and the operator's `apt install` decision. init-db itself does not introduce new exposure; uses the same binary the systemd timer would invoke later. | gsd-secure-phase | 2026-04-30 |

---

## Unregistered Threat Flags

The seven plan SUMMARY.md files were inspected for `## Threat Flags`,
`## Threat Surface Scan`, and `## Threat surface` sections. All seven
plans report no unregistered flags:

- 05-01: "No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced."
- 05-02: (no threat-flags subsection — fully covered by plan threat register)
- 05-03: "No new network endpoints, auth paths, file access patterns, or schema changes introduced."
- 05-04: "None. No new network endpoints, auth paths, file access patterns beyond `/var/lib/sftp-jailer/` and the `sftp-jailer` system group were introduced."
- 05-05: "No new network endpoints, auth paths, file access patterns, or schema changes introduced."
- 05-06: (no threat-flags subsection — fully covered by plan threat register)
- 05-07: "No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond what the original plan's threat_model already documents."

No additional surfaces detected during implementation that required
post-hoc registration.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-04-30 | 56 | 56 | 0 | gsd-security-auditor |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log (25 entries)
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-04-30
