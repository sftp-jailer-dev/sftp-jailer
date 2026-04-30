---
phase: 5
slug: packaging-install-purge-automated-release
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-30
reconstructed_from: 05-01..07 SUMMARY.md (State B reconstruction)
---

# Phase 5 — Validation Strategy

> Per-phase validation contract reconstructed retroactively from SUMMARY artifacts. Two CI-guard gaps closed during validation: `check-maintainer-scripts-syntax.sh` and `check-no-etc-ssh-in-maintainer-scripts.sh`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` (Go 1.25.x) |
| **Config file** | `go.mod` (no separate runner config) |
| **Quick run command** | `go test -count=1 ./cmd/sftp-jailer/... ./cmd/gen-manpage/... ./internal/txn/... ./internal/sysops/...` |
| **Full suite command** | `go test -race -count=1 ./...` |
| **Estimated runtime** | ~6 s (quick), ~45 s (full with `-race`) |
| **Architecture invariants** | `bash scripts/check-*.sh` (7 scripts after this phase: 5 inherited + manpage-fresh from 05-02 + 2 added retroactively here) |

---

## Sampling Rate

- **After every task commit:** `go test -count=1 ./<package-touched>/...` (≤ 2 s feedback)
- **After every plan wave:** Quick run command above
- **Before `/gsd:verify-work`:** Full suite + all 7 invariant scripts must be green
- **Max feedback latency:** 6 s on the focused subset

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 5-01-01 | 01 | 1 | DIST-02 | T-05-01-01 | nfpms contents block uses hardcoded literal paths only | config-validation | `bash scripts/check-go-mod-pins.sh && goreleaser check --config packaging/goreleaser.yml` (CI-only) | ✅ | ✅ green (CI-gated) |
| 5-01-02 | 01 | 1 | DIST-02 | T-05-01-05 | No mode 0777 in nfpms contents | grep | `! grep -nE 'mode:.*0?777' packaging/goreleaser.yml` | ✅ | ✅ green |
| 5-02-01 | 02 | 1 | DIST-02 (no-manual-page) | — | Hidden:true subcommands skipped by GenManTree | unit | `go test -count=1 ./cmd/gen-manpage/... -run TestGatherSubcommands_HasExpectedNames` | ✅ | ✅ green |
| 5-02-02 | 02 | 1 | DIST-02 | — | rootcmd.Build factors PersistentPreRunE + Subcommands without behavioral drift | unit | `go test -count=1 ./cmd/sftp-jailer/... -run 'TestRootCmd_BuildsExpectedTree\|TestSafeRootGate_VersionExempt'` | ✅ | ✅ green |
| 5-02-03 | 02 | 1 | DIST-02 | — | docs/man/ regenerated output is byte-identical to committed (deterministic) | CI guard | `bash scripts/check-manpage-fresh.sh` | ✅ | ✅ green |
| 5-03-01 | 03 | 1 | DIST-05 (SAFE-06) | T-05-03-01,03,07 | NewRemoveSshdDropInStep backs up then removes; restores on Compensate | unit | `go test -count=1 ./internal/txn/... -run TestRemoveSshdDropIn` | ✅ | ✅ green (5 tests) |
| 5-03-02 | 03 | 1 | DIST-05 | — | purge-sshd-cleanup is Hidden, registered, excluded from --help, composes the right step order, backup dir outside /var/lib | unit | `go test -count=1 ./cmd/sftp-jailer/... -run 'TestPurgeSshdCleanupCmd_Hidden\|TestRootCmd_RegistersPurgeSshdCleanup\|TestRootCmd_HelpOutputExcludesHiddenCmd\|TestPurgeStepsFn_OrderAndNames\|TestPurgeBackupDir_OutsideVarLib'` | ✅ | ✅ green (5 tests) |
| 5-04-01 | 04 | 1 | DIST-04, DIST-05 | T-05-04-* | postinst/prerm/postrm are POSIX sh syntax-valid | CI guard (NEW) | `bash scripts/check-maintainer-scripts-syntax.sh` | ✅ | ✅ green (added 2026-04-30) |
| 5-04-02 | 04 | 1 | DIST-09 (brownfield) | T-05-04-* | postinst/prerm/postrm never reference /etc/ssh | CI guard (NEW) | `bash scripts/check-no-etc-ssh-in-maintainer-scripts.sh` | ✅ | ✅ green (added 2026-04-30) |
| 5-04-03 | 04 | 1 | DIST-04 | — | Group create / timer enable / cursor pre-create empirically verified | manual | UAT runbook step 2.x (Ubuntu) + D.2.x (Debian 13) | ✅ | ✅ operator-signed PASS |
| 5-04-04 | 04 | 1 | DIST-05 | — | apt purge round-trip leaves no residue; sshd survives | manual | UAT runbook step 8.x + D.8.x | ✅ | ✅ operator-signed PASS |
| 5-05-01 | 05 | 1 | DIST-08 | — | release.yml triggers only on `v[0-9]+.[0-9]+.[0-9]+(-rc[0-9]+)?` tag push | grep | acceptance grep set in 05-05-SUMMARY.md (run inline at PR time) | ✅ | ✅ green |
| 5-05-02 | 05 | 1 | DIST-03 | — | lintian --pedantic exits 0 against shipped overrides | CI guard | release.yml step "lintian --pedantic" loop with fail=1 | ✅ | ✅ green |
| 5-06-01 | 06 | 1 | DIST-09 | T-05-06-* | /var/backups/sftp-jailer/ is on the AtomicWriteFile allowlist (BUG-05-A regression) | unit | `go test -count=1 ./internal/sysops/... -run TestAtomicWriteFile_allowlist_accepts_var_backups_sftp_jailer_prefix` | ✅ | ✅ green |
| 5-06-02 | 06 | 1 | DIST-10 | — | Debian 13 thesis flow PASS on 192.168.1.170; portability deltas filed as findings | manual | docs/uat/05-debian13-uat.md (operator-signed) | ✅ | ✅ operator-signed PASS (2 deltas, 0 blocks) |
| 5-06-03 | 06 | 1 | DIST-09 | — | sha256(/etc/ssh/sshd_config) byte-identical pre-install vs post-purge | manual + uat-05 | docs/uat/05-ubuntu24-uat.md Variant B + `uat-05 brownfield-purge` JSON receipt assertion | ✅ | ✅ operator-signed PASS (sha256 597db2fa...) |
| 5-07-01 | 07 | 1 | DIST-04 SC3 | T-05-07-* | init-db is Hidden, registered, excluded from --help; fresh install creates DB at ExpectedSchemaVersion=3; idempotent re-invoke is no-op; schema-drift downgrade exits with code 2 | unit | `go test -count=1 ./cmd/sftp-jailer/... -run 'TestInitDB\|TestRootCmd_RegistersInitDB\|TestRootCmd_HelpOutputExcludesInitDB'` | ✅ | ✅ green (6 tests) |
| 5-07-02 | 07 | 1 | DIST-04 SC3 | — | observations.db at install time is mode 0644 root:root with PRAGMA user_version=3 | manual | docs/uat/05-ubuntu24-uat.md step 2.4 + docs/uat/05-debian13-uat.md step D.2.4 | ✅ | ✅ operator-signed PASS (both hosts, 2026-04-30) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. Two new CI-guard scripts authored retroactively during validation:

- [x] `scripts/check-maintainer-scripts-syntax.sh` — POSIX sh syntax gate for postinst/prerm/postrm
- [x] `scripts/check-no-etc-ssh-in-maintainer-scripts.sh` — DIST-09 brownfield invariant
- [x] Wired into `.github/workflows/ci.yml` (architecture-invariants job) and `.github/workflows/release.yml` (Architecture invariants step)

No additional Go test framework setup or fixtures required — the phase reused the existing `go test` infrastructure end-to-end.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real-host install / purge round-trip on Ubuntu 24.04 (clean + brownfield variants) | DIST-02, DIST-04, DIST-05, DIST-09 | dpkg `configure`/`prerm`/`postrm` semantics, real systemd, real /etc filesystem state — cannot be programmatically substituted | `docs/uat/05-ubuntu24-uat.md` Variant A + B; capture sha256 baseline pre-install; assert byte-identical post-purge |
| Real-host thesis flow on Debian 13 lab host | DIST-10 | systemd version delta (253 vs 257), distro-specific GID allocation, ufw default-state delta — DIST-10 is the *empirical* portability gate by design | `docs/uat/05-debian13-uat.md` against 192.168.1.170; file portability deltas |
| TUI-driven SAFE-04 3-minute auto-revert lockdown cycle | DIST-04 / DIST-05 (lockdown surface) | Headless Bubble Tea harness for the SAFE-04 timer is intentionally deferred (T-05-06-07 accepted); operator drives the TUI | UAT step 7.2 / D.7.2 — SKIP-OPERATOR by design |
| Tag-push GitHub Actions release pipeline | DIST-08 | A workflow that runs only on tag push cannot be exercised without an actual tag push to the GitHub remote | First real `git tag v1.x.y && git push --tags` exercises end-to-end; until then, `release.yml` is grep-validated against the 05-05-SUMMARY acceptance set |
| `goreleaser check` schema validation | DIST-02 / DIST-08 | `goreleaser` is not on the macOS dev machine; the binary lives on the ubuntu-24.04 CI runner | Runs inline in `release.yml` `goreleaser-action@v6 v2.15.4` step before publishing |

These five behaviors are inherent to the phase contract (real hosts, tag-push trigger, interactive TUI). They are tracked here for visibility, not because they could become automated.

---

## Validation Sign-Off

- [x] All tasks have automated verify or are explicitly listed under Manual-Only
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every plan ships at least one Go test or CI-gated script)
- [x] Wave 0 covers all MISSING references (2 CI guards added 2026-04-30)
- [x] No watch-mode flags (`-count=1` everywhere)
- [x] Feedback latency < 10 s on the focused subset
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-04-30
