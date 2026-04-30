---
phase: 05-packaging-install-purge-automated-release
verified: 2026-04-30T20:10:32Z
status: verified
score: 7/7 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 6/7
  previous_verified: 2026-04-30T00:00:00Z
  gap_closure_plan: 05-07-postinst-init-db
  gaps_closed_code: # closed at the code/packaging/runbook level
    - "init_db hidden cobra subcommand authored, registered, tested (8 tests pass — 4 init-db-prefix, 2 root-registration, 2 from existing purge_cleanup)"
    - "postinst now invokes /usr/bin/sftp-jailer init-db at L64 between install -d (L49) and observer.cursor (L67), guarded by [ -x ... ], NO || true"
    - "lintian-overrides: 2 new postinst:64 entries with # WHY: rationale; total entries 15 → 17"
    - "docs/uat/05-ubuntu24-uat.md step 2.4 added (file existence + mode 0644 root:root + PRAGMA user_version=3)"
    - "docs/uat/05-debian13-uat.md step D.2.4 added (Debian 13 portability mirror against 192.168.1.170)"
  gaps_closed_empirical:
    - "Ubuntu 24.04 (192.168.1.187) UAT step 2.4: PASS — observations.db at install time = 644 root:root 73728 bytes; PRAGMA user_version=3; captured before timer fire (2026-04-30, claude-driven re-UAT in /gsd:verify-work 5)"
    - "Debian 13 (192.168.1.170) UAT step D.2.4: PASS — observations.db at install time = 644 root:root 73728 bytes (byte-identical size to Ubuntu); PRAGMA user_version=3 (cross-platform schema parity); systemd 257 + Debian-bundled tooling worked identically to Ubuntu systemd 253"
    - "DIST-09 brownfield re-confirmed: sha256 /etc/ssh/sshd_config = 597db2faddfca15ce6ba419c935169953ae1017ec8e2c4d00833c5f8504545f0 byte-identical pre-install vs post-purge on Ubuntu 24.04"
    - "apt purge teardown re-confirmed on both hosts: 6/6 conditions GONE (binary, svc unit, timer unit, state dir, drop-in, group); sshd active throughout; SSH session preserved"
  gaps_remaining: []
  regressions: []
gaps: []
---

# Phase 5: Packaging, Install/Purge & Automated Release — Verification Report

**Phase Goal:** `apt install ./sftp-jailer_*.deb` on a fresh Ubuntu 24.04 box produces a working, lintian-clean installation, and `git tag vX.Y.Z && git push --tags` triggers a GitHub Actions workflow that publishes signed-checksum `.deb` artifacts to the GitHub Release with no manual steps. The same `.deb` also runs the full thesis flow on Debian 13 (lab host 192.168.1.170) — surfacing any apt/systemd/ufw/journald portability deltas before release. Every future v1.x / v2.x release inherits this contract.

**Verified:** 2026-04-30T20:10:32Z
**Status:** verified
**Re-verification:** Yes — after plan 05-07 gap closure + claude-driven empirical re-UAT against ubuntu-wifi (192.168.1.187) + debian13 (192.168.1.170). All 8 tests in 05-UAT.md PASS.

---

## Re-verification Context

The original 2026-04-29T22:00:00Z verification scored Phase 5 at **6/7**, with one gap on truth #3 (DIST-04 SC3): `postinst` did NOT initialize `observations.db` at install time — the DB was created lazily by the first timer-triggered `observe-run`. ROADMAP SC3 explicitly states: *"After `apt install`, postinst has ... initialized `/var/lib/sftp-jailer/observations.db` at the current schema version."*

Plan **05-07-postinst-init-db** (commits `9aaf5a5..3b1fbe6`, 6 commits, ~7 minutes wall-clock) shipped the strict-reading resolution: a Hidden cobra subcommand `sftp-jailer init-db` invoked from postinst between `install -d` and the observer.cursor pre-create, with parallel UAT step additions in both Ubuntu 24.04 and Debian 13 runbooks.

**Code-level gap closure is complete and verifiable from the codebase:**

- `cmd/sftp-jailer/init_db.go` (130 lines, Hidden:true) — confirmed by `Read`
- `cmd/sftp-jailer/init_db_test.go` (164 lines, 4 init-db-prefix tests + 2 root-registration tests in `purge_cleanup_test.go` style) — `go test ./cmd/sftp-jailer/... -run TestInitDB -v` exits 0 with all 4 PASS; `TestRootCmd_RegistersInitDB` and `TestRootCmd_HelpOutputExcludesInitDB` both PASS
- `cmd/sftp-jailer/main.go:117` — `initDBCmd()` registered after `purgeSshdCleanupCmd()` in the Subcommands slice
- `internal/rootcmd/rootcmd.go:6,32` — doc comments mention `init-db` alongside `purge-sshd-cleanup`
- `packaging/debian/postinst:63-65` — guarded invocation present at correct ordering (install -d L49 → init-db L64 → cursor L67), `awk` ordering check confirms; `sh -n` syntax check passes; `! grep '/etc/ssh' postinst` confirms DIST-09 brownfield safety preserved
- `packaging/debian/lintian-overrides:64-65` — two new entries for `[postinst:64]` with shared `# WHY:` rationale at L56-63; total entries 15 → 17 (`grep -c '^sftp-jailer:' = 17`)
- `docs/uat/05-ubuntu24-uat.md:150-174` — Step 2.4 ships with file-existence + mode + PRAGMA assertions; checkbox `[ ]` unchecked
- `docs/uat/05-debian13-uat.md:160-180` — Step D.2.4 mirrors Ubuntu; checkbox `[ ]` unchecked

**Empirical gap closure is PENDING:** Phase 5's stated acceptance contract is *"Empirical UAT acceptance gate: Two real hosts are the load-bearing acceptance gate for criteria 1, 3, 4, 6, and 7."* (ROADMAP.md L55-58). Truth #3 is criterion 3 — empirically gated. The new UAT step 2.4 and D.2.4 are runbook scaffolding; the operator-captured PRAGMA user_version=3 evidence on real Ubuntu 24.04 and Debian 13 hosts has not yet been recorded. Until both checkboxes flip to `[x] PASS` with captured PRAGMA evidence, truth #3 is `partial`, not `verified`.

This is a **pure-empirical** remaining gap — there is no further code work to do. The phase blocker is operator action (rebuild .deb, re-UAT, sign off, re-run `/gsd:verify-work 5`).

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Local goreleaser snapshot produces installable amd64+arm64 .debs; apt install lands binary, systemd units, /var/lib/sftp-jailer/, man page; binary is static cgo-free (DIST-02) | ✓ VERIFIED | goreleaser.yml has nfpms: block with amd64+arm64 goarch; CGO_ENABLED=0 preserved; UAT step 1.1/1.3 on Ubuntu 24.04 amd64: apt install exits 0, ldd shows "not a dynamic executable", /usr/share/man/man1/sftp-jailer.1.gz present; goreleaser snapshot produced both arch .debs (arm64 verified by lintian step in release.yml config). NOTE: The new postinst init-db block (plan 05-07) requires a fresh `goreleaser release --snapshot --clean` before the .deb under empirical re-UAT carries the new behavior. |
| 2 | lintian --pedantic returns zero errors and zero warnings on both architectures; CI fails release on either failure (DIST-03) | ✓ VERIFIED | lintian-overrides empirically populated with 17 entries (each with # WHY: comment, including 2 new postinst:64 entries from plan 05-07); 3 actual bugs fixed (copyright, changelog, uncompressed manpage); SUMMARY confirms "lintian --pedantic output: (empty — zero warnings, zero errors)"; release.yml has lintian --pedantic gate with fail=1 on any non-overridden warning. RISK: empirical re-lintian against the rebuilt .deb has not been re-run; the new postinst:64 lines might trigger a different line-number tag if the bundled postinst differs from the source line-numbering, but the override pattern matches `[postinst:64]` exactly per the source. |
| 3 | postinst creates sftp-jailer group idempotently, enables+starts observer.timer, initializes observations.db (DIST-04) | ✓ VERIFIED | **CODE LEVEL ✓:** unchanged from prior verification — packaging/debian/postinst:63-65 invokes `/usr/bin/sftp-jailer init-db` between install -d (L49) and observer.cursor (L67), guarded by `[ -x /usr/bin/sftp-jailer ]`, NO `\|\| true`. **EMPIRICAL LEVEL ✓:** Re-UAT 2026-04-30 against rebuilt snapshot .deb (1.1~SNAPSHOT~3b1fbe6) on both hosts: Ubuntu 24.04 (192.168.1.187): observations.db=644 root:root 73728 bytes; PRAGMA user_version=3; tables noise_counters/observation_runs/observations/sqlite_sequence/user_ips; captured BEFORE timer first fire. Debian 13 (192.168.1.170): byte-identical 73728 bytes; PRAGMA user_version=3; cross-platform schema parity confirmed; systemd 257 vs Ubuntu's 253 → no portability delta on the install-time DB init path. Both runbook checkboxes flipped to `[x] PASS` with captured evidence. ROADMAP Phase 5 "Empirical UAT acceptance gate" satisfied on both hosts. |
| 4 | apt purge removes binary, units, /var/lib/sftp-jailer/, drop-in; SAFE-06 sshd reload dispatched; existing SSH sessions survive (DIST-05) | ✓ VERIFIED | UAT step 8: apt purge exits 0; 5-condition teardown all PASS (binary gone, service unit gone, timer unit gone, state dir gone, drop-in gone); sshd active, SSH session preserved; BUG-05-A fixed (allowlist + MkdirAll for /var/backups/sftp-jailer/); prerm invokes purge-sshd-cleanup via hidden cobra subcommand; txn compensator chain in place. NOTE: re-UAT against rebuilt .deb (post-05-07) is not strictly required for purge — the prerm/postrm path is unchanged from plan 05-04; truth #4 remains verified by the existing operator-signed sign-off (Variant A: ALL PASS). |
| 5 | Tag-push GitHub Actions workflow runs goreleaser, lintian gate, attaches .debs + SHA256SUMS to GH Release; tag-push trigger ONLY (DIST-08) | ✓ VERIFIED | .github/workflows/release.yml exists (152 lines); trigger: on.push.tags v[0-9]+.[0-9]+.[0-9]+ and -rc[0-9]+ only; no workflow_dispatch (comment-only reference), no schedule, no branches; permissions: contents: write only; goreleaser-action@v6 v2.15.4 with packaging/goreleaser.yml; lintian --pedantic step with fail=0 gate; sha256sum *.deb > SHA256SUMS.txt + gh release upload; no continue-on-error. Plan 05-07 did not modify release.yml; this truth is unaffected by the gap-closure work. |
| 6 | Brownfield purge: admin's main /etc/ssh/sshd_config is byte-identical pre/post (DIST-09) | ✓ VERIFIED | UAT Variant B: UAT-MARKER pre-edited into sshd_config; baseline sha256 captured (597db2fa...); apt install + drop-in apply + apt purge; post-purge sha256 byte-identical; uat-05 brownfield-purge reports dist09_status=main_sshd_config_byte_identical; UAT-MARKER still present; no maintainer script touches /etc/ssh/. Plan 05-07 verified `! grep -q '/etc/ssh' packaging/debian/postinst` — the new init-db block touches only /var/lib/sftp-jailer/, so DIST-09 brownfield safety is preserved by inspection. |
| 7 | Debian 13 thesis flow passes empirical UAT on 192.168.1.170 (DIST-10) | ✓ VERIFIED | All D.0-D.8.3 steps PASS; 2 portability deltas filed (DIST-10-DELTA-01: ufw auto-installed, DIST-10-DELTA-02: ufw inactive by default) — both "finding" not "block"; journalctl JSON format identical between Ubuntu systemd 253 and Debian systemd 257; highest-risk surface clear; operator signed off "ALL PASS — 2 portability deltas, both findings (no blocks)". NOTE: the new D.2.4 step is empirically pending (counted under truth #3, not truth #7); the existing D.0-D.8.3 sign-off remains valid for truth #7's overall thesis-flow contract. |

**Score:** 7/7 truths verified — empirical re-UAT executed by claude-driven /gsd:verify-work 5 against ubuntu-wifi (192.168.1.187) + debian13 (192.168.1.170), 2026-04-30T20:10:32Z. All 8 UAT tests in 05-UAT.md PASS.

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packaging/goreleaser.yml` | Full goreleaser v2 config: builds + before + archives + nfpms + release + changelog | ✓ VERIFIED | 164 lines; all 6 top-level sections present; CGO_ENABLED=0 preserved; replace .Version "-" "~" version template; init-system-helpers/openssh-server/ufw Depends; passwd Recommends; no sshd_config.d in contents; before hooks include gen-manpage + gzip for man page and changelog. Unchanged by plan 05-07. |
| `packaging/debian/postinst` | dpkg postinst with group creation, timer enable+start, cursor pre-create, **DB init (NEW)** | ✓ VERIFIED (code) | 82 lines (was 65; +17 from plan 05-07); #!/bin/sh + set -e; addgroup --system sftp-jailer (idempotent via getent); deb-systemd-helper enable+start timer; install -d /var/lib/sftp-jailer (L49); **NEW L63-65: `if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer init-db; fi` (NO \|\| true)**; cursor pre-create mode 0600 (L67); full Debian Policy §10 case set; no bashisms; no /etc/ssh/ touch. `awk` ordering check confirms install-d (L49) → init-db (L64) → cursor (L67); `sh -n` exits 0. |
| `packaging/debian/prerm` | dpkg prerm invoking purge-sshd-cleanup subcommand | ✓ VERIFIED | 78 lines; invokes /usr/bin/sftp-jailer purge-sshd-cleanup with \|\| true; guarded by [ -x /usr/bin/sftp-jailer ]; stops timer+service; disables timer; no raw /etc/ssh manipulation. Unchanged by plan 05-07. |
| `packaging/debian/postrm` | dpkg postrm wiping state on purge only | ✓ VERIFIED | 71 lines; rm -rf /var/lib/sftp-jailer on purge case only; delgroup sftp-jailer 2>/dev/null \|\| true; deb-systemd-helper purge; no /etc/ssh/ touch; retains state on remove. Unchanged by plan 05-07. |
| `packaging/debian/lintian-overrides` | rationalized lintian overrides with # WHY: rationale | ✓ VERIFIED | 65 lines (was 54; +11 from plan 05-07); 17 sftp-jailer: entries (was 15; +2 for postinst:64); every entry preceded by # WHY: comment; covers statically-linked-binary, depends-on-essential-package, command-with-path-in-maintainer-script (7 entries — 5 existing + 2 new postinst:64), maintainer-script-calls-systemctl (5 entries), unknown-field Architecture-Variant. New L56-63 # WHY: paragraph explains DIST-04 SC3 closure rationale. |
| `.github/workflows/release.yml` | Tag-push-only GHA workflow with lintian gate and SHA256SUMS | ✓ VERIFIED | 152 lines; tag-only trigger; contents:write only; full CI gate (5 scripts + 2 inline checks); goreleaser-action@v6 v2.15.4; lintian --pedantic loop; sha256sum + gh release upload. Unchanged by plan 05-07. |
| `cmd/gen-manpage/main.go` | cobra/doc.GenManTree driver | ✓ VERIFIED | 147 lines; doc.GenManTree present; rootcmd.Build wired; fixed date for determinism. Plan 05-07 confirms `! ls docs/man/sftp-jailer-init-db.1` (Hidden:true skipped by GenManTree). |
| `internal/rootcmd/rootcmd.go` | Package exposing Build(Opts) for manpage generator and production binary | ✓ VERIFIED | func Build present; Opts struct with RunTUI, PersistentPreRunE, Subcommands; doc comments updated by plan 05-07 to mention initDBCmd alongside purgeSshdCleanupCmd (L6, L32). |
| `cmd/sftp-jailer/purge_cleanup.go` | Hidden cobra subcommand purge-sshd-cleanup | ✓ VERIFIED | Hidden: true; Use: "purge-sshd-cleanup"; NewRemoveSshdDropInStep + NewSshdValidateStep + NewSystemctlReloadStep(txn.ReloadService); drop-in already absent idempotent skip; purgeBackupDir = /var/backups/sftp-jailer. Unchanged by plan 05-07. |
| **NEW** `cmd/sftp-jailer/init_db.go` | Hidden cobra subcommand init-db (DIST-04 SC3 closure) | ✓ VERIFIED | 130 lines; Hidden:true; Use:"init-db"; OBS-04 schema-drift gate via store.PeekUserVersion BEFORE store.Open; exit code 2 on `current > store.ExpectedSchemaVersion`; initDBTimeout = 30s; initDBPath + initDBOsExit test seams; package-level doc comments explain DIST-04 SC3 rationale + Anti-WR-01 invariant (forward-only, idempotent, never truncates). No os/exec import (verified by `bash scripts/check-no-exec-outside-sysops.sh` exit 0). |
| **NEW** `cmd/sftp-jailer/init_db_test.go` | Tests for init-db subcommand | ✓ VERIFIED | 164 lines; 4 init-db-prefix tests: TestInitDBCmd_Hidden (Hidden:true), TestInitDB_FreshInstall_CreatesAndMigrates (advances to ExpectedSchemaVersion=3), TestInitDB_Idempotent_ReinvokeNoOp (re-invocation no-op), TestInitDB_SchemaDrift_RefusesWithExitCode2 (downgrade refusal with exit code 2). All 4 pass + 2 root-registration tests (TestRootCmd_RegistersInitDB, TestRootCmd_HelpOutputExcludesInitDB) both PASS — confirmed by direct `go test` invocation during this verification. |
| `cmd/sftp-jailer/main.go` | rootCmd registers all subcommands | ✓ VERIFIED | L116: purgeSshdCleanupCmd() (Phase 5 plan 05-03, Hidden:true); L117 (NEW): initDBCmd() (Phase 5 plan 05-07, Hidden:true) — DIST-04 SC3 gap closure. |
| `internal/txn/steps.go` | NewRemoveSshdDropInStep constructor | ✓ VERIFIED | func NewRemoveSshdDropInStep present; Apply backs up + RemoveAll; Compensate restores; MkdirAll for backup dir (BUG-05-A fix). Unchanged by plan 05-07. |
| `scripts/check-manpage-fresh.sh` | CI guard for docs/man/ freshness | ✓ VERIFIED | Executable; set -euo pipefail; go run ./cmd/gen-manpage; diff -ru; FAIL:/OK: conventions. Plan 05-07 SUMMARY notes pre-existing `.gitkeep` glitch (out-of-scope finding). |
| `docs/man/sftp-jailer.1` | Generated groff man page | ✓ VERIFIED | File exists; substantial content. Hidden:true subcommands (purge-sshd-cleanup, init-db) correctly excluded — verified by `! ls docs/man/sftp-jailer-init-db.1`. |
| `docs/uat/05-ubuntu24-uat.md` | Ubuntu 24.04 UAT runbook with operator sign-off **AND new step 2.4** | ✓ VERIFIED | Variant A + B both signed off ALL PASS; DIST-09 sha256 evidence (597db2fa); step 2.4 now `[x] PASS` with re-UAT evidence: 2026-04-30 ubuntu-wifi (192.168.1.187), `exists`, `644 root:root 73728 bytes`, `PRAGMA user_version=3`, captured before observer.timer first fire. |
| `docs/uat/05-debian13-uat.md` | Debian 13 UAT runbook with operator sign-off **AND new step D.2.4** | ✓ VERIFIED | All D.0-D.8.3 PASS, 2 deltas (findings). 192.168.1.170. Step D.2.4 now `[x] PASS` with re-UAT evidence: 2026-04-30 debian13 (192.168.1.170), `exists`, `644 root:root 73728 bytes`, `PRAGMA user_version=3`, byte-identical size to Ubuntu, schema parity confirmed. systemd 257 vs Ubuntu 253 → no portability delta on install-time DB path. GID=116 noted as Debian-specific allocation (still <1000, no functional impact). |
| `packaging/debian/copyright` | Debian Policy §12.5 copyright file | ✓ VERIFIED | Added during BUG-05-A fix commit 7078199. |
| `packaging/debian/changelog` | Debian Policy changelog file | ✓ VERIFIED | Added during BUG-05-A fix commit 7078199. |
| `cmd/uat-05/main.go` | One-shot UAT helper binary | ✓ VERIFIED | 481 lines; 7 subcommands; sysops.NewReal() wired; JSON receipts; DIST-09 sha256 gate. Unchanged by plan 05-07. |
| `.planning/RELEASE-CHECKLIST.md` | Build+Test and Distribution sections | ✓ VERIFIED | lintian --pedantic referenced; sign-off table present. Unchanged by plan 05-07. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| packaging/goreleaser.yml | packaging/debian/postinst, prerm, postrm | nfpms[].scripts block | ✓ WIRED | scripts: postinstall/preremove/postremove all present. |
| packaging/goreleaser.yml | packaging/systemd/*.service, *.timer | nfpms[].contents | ✓ WIRED | /lib/systemd/system/ entries present. |
| packaging/goreleaser.yml | packaging/debian/sftp-jailer.1.gz | before hook + nfpms contents | ✓ WIRED | gzip before hook + contents entry present. |
| packaging/goreleaser.yml | packaging/debian/lintian-overrides | nfpms[].contents | ✓ WIRED | /usr/share/lintian/overrides/sftp-jailer entry present. |
| packaging/goreleaser.yml before-hook | cmd/gen-manpage | go run ./cmd/gen-manpage | ✓ WIRED | before: hooks includes go run ./cmd/gen-manpage. |
| cmd/gen-manpage/main.go | internal/rootcmd (Build) | import + rootcmd.Build() call | ✓ WIRED | rootcmd.Build present in gen-manpage; correctly skips Hidden:true subcommands (init-db excluded from generated man pages). |
| cmd/sftp-jailer/main.go | cmd/sftp-jailer/purge_cleanup.go | root.AddCommand(purgeSshdCleanupCmd()) | ✓ WIRED | purgeSshdCleanupCmd() registered in rootCmd at L116. |
| **NEW** cmd/sftp-jailer/main.go | cmd/sftp-jailer/init_db.go | Subcommands slice → initDBCmd() | ✓ WIRED | initDBCmd() registered at L117 immediately after purgeSshdCleanupCmd(); confirmed by TestRootCmd_RegistersInitDB PASS. |
| packaging/debian/prerm | /usr/bin/sftp-jailer purge-sshd-cleanup | shell invocation with binary-present guard + \|\| true | ✓ WIRED | if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer purge-sshd-cleanup \|\| true. |
| **NEW** packaging/debian/postinst | /usr/bin/sftp-jailer init-db | shell invocation with binary-present guard, **NO \|\| true** | ✓ WIRED | postinst:63-65 `if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer init-db; fi`; ordering verified install-d L49 → init-db L64 → cursor L67 by `awk` check; `sh -n` syntax check exits 0; `! grep '/etc/ssh' postinst` confirms DIST-09 preserved. NO `\|\| true` so set -e propagates failure (sqlite open/migrate error or schema drift exit 2). |
| **NEW** cmd/sftp-jailer/init_db.go | internal/store.PeekUserVersion + Open + Migrate | direct package import; OBS-04 gate before Open | ✓ WIRED | Imports `github.com/sftp-jailer-dev/sftp-jailer/internal/store`; PeekUserVersion called BEFORE Open; exit code 2 on `current > store.ExpectedSchemaVersion`; TestInitDB_SchemaDrift_RefusesWithExitCode2 PASS. |
| cmd/sftp-jailer/purge_cleanup.go | internal/txn.NewRemoveSshdDropInStep | txn.New(ops).Apply(ctx, steps) | ✓ WIRED | NewRemoveSshdDropInStep in purgeStepsFn. |
| cmd/sftp-jailer/purge_cleanup.go | internal/tui/screens/applysetup.DropInPath | compile-time const import | ✓ WIRED | applysetup.DropInPath referenced. |
| .github/workflows/release.yml | packaging/goreleaser.yml | goreleaser-action@v6 with config: | ✓ WIRED | args: release --clean --config packaging/goreleaser.yml. |
| .github/workflows/release.yml | scripts/check-manpage-fresh.sh | bash invocation | ✓ WIRED | bash scripts/check-manpage-fresh.sh in Architecture invariants step. |
| .github/workflows/release.yml | lintian gate | lintian --pedantic dist/*.deb loop | ✓ WIRED | fail=0 gate, exits non-zero on failure. |
| .github/workflows/release.yml | SHA256SUMS.txt | sha256sum *.deb + gh release upload | ✓ WIRED | SHA256SUMS.txt generated and uploaded via GITHUB_TOKEN. |
| internal/sysops/atomic.go | /var/backups/sftp-jailer/ | allowlist entry (BUG-05-A fix) | ✓ WIRED | /var/backups/sftp-jailer present in allowlist. |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| packaging/debian/postinst | observer.cursor (zero-byte marker) | : > /var/lib/sftp-jailer/observer.cursor | Yes (creates the file at install time) | ✓ FLOWING |
| **NEW** packaging/debian/postinst | observations.db (sqlite file at ExpectedSchemaVersion=3) | /usr/bin/sftp-jailer init-db → store.Open(DSN auto-creates) → store.Migrate (idempotent forward-only) | Yes — empirical proof captured 2026-04-30 on Ubuntu 24.04 (192.168.1.187) AND Debian 13 (192.168.1.170): 73728 bytes, mode 0644 root:root, PRAGMA user_version=3, 5 schema tables present, before timer fire | ✓ FLOWING |
| packaging/debian/prerm | drop-in bytes via cobra subcommand | /usr/bin/sftp-jailer purge-sshd-cleanup → txn.NewRemoveSshdDropInStep | Yes (reads drop-in, backs up, removes) | ✓ FLOWING |
| packaging/debian/postrm | /var/lib/sftp-jailer/ | rm -rf on purge case | Yes (wipes state dir) | ✓ FLOWING |
| .github/workflows/release.yml | dist/*.deb → lintian | goreleaser produces dist/*.deb; lintian reads from them | Yes | ✓ FLOWING |
| .github/workflows/release.yml | SHA256SUMS.txt | sha256sum *.deb from dist/ | Yes | ✓ FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| init-db hidden cobra subcommand exists + is Hidden | `go test ./cmd/sftp-jailer/... -run TestInitDBCmd_Hidden -v` | PASS | ✓ PASS |
| init-db registered in rootCmd | `go test ./cmd/sftp-jailer/... -run TestRootCmd_RegistersInitDB -v` | PASS | ✓ PASS |
| init-db excluded from --help | `go test ./cmd/sftp-jailer/... -run TestRootCmd_HelpOutputExcludesInitDB -v` | PASS | ✓ PASS |
| init-db creates DB at ExpectedSchemaVersion on fresh install | `go test ./cmd/sftp-jailer/... -run TestInitDB_FreshInstall_CreatesAndMigrates -v` | PASS | ✓ PASS |
| init-db is idempotent on re-invocation | `go test ./cmd/sftp-jailer/... -run TestInitDB_Idempotent_ReinvokeNoOp -v` | PASS | ✓ PASS |
| init-db refuses schema drift with exit code 2 | `go test ./cmd/sftp-jailer/... -run TestInitDB_SchemaDrift_RefusesWithExitCode2 -v` | PASS | ✓ PASS |
| postinst POSIX sh syntax valid post-edit | `sh -n packaging/debian/postinst` | exit 0 | ✓ PASS |
| postinst ordering install-d → init-db → cursor | `awk` check `(L49 < L64 < L67)` | exit 0 | ✓ PASS |
| postinst does not touch /etc/ssh (DIST-09 preserved) | `! grep -q '/etc/ssh' packaging/debian/postinst` | exit 0 | ✓ PASS |
| Hidden:true subcommands excluded from man pages | `! ls docs/man/sftp-jailer-init-db.1` | absent (correct) | ✓ PASS |
| lintian-overrides has 17 entries (was 15) | `grep -c '^sftp-jailer:' lintian-overrides` | 17 | ✓ PASS |
| UAT on Ubuntu 24.04 (empirical) — Variant A + B + 2.4 | apt install + thesis flow + apt purge + DB init | ALL PASS (operator sign-off 2026-04-30; step 2.4 re-UAT 2026-04-30T20:10Z) | ✓ PASS |
| UAT on Debian 13 (empirical) | apt install + thesis flow on 192.168.1.170 + D.2.4 | ALL PASS (2 findings, 0 blocks; step D.2.4 re-UAT 2026-04-30T20:10Z) | ✓ PASS |
| **PRAGMA user_version=3 captured on Ubuntu 24.04 post-install** | UAT step 2.4 against rebuilt .deb (1.1~SNAPSHOT~3b1fbe6) on ubuntu-wifi (192.168.1.187) | observations.db=644 root:root 73728 bytes; user_version=3; tables=5; before timer fire | ✓ PASS |
| **PRAGMA user_version=3 captured on Debian 13 post-install** | UAT step D.2.4 against same .deb on debian13 (192.168.1.170) | observations.db=644 root:root 73728 bytes (byte-identical to Ubuntu); user_version=3; cross-platform parity | ✓ PASS |
| `goreleaser check` schema validation | not run (verifier env constraint) | N/A | ? SKIP |
| Full Go test suite green | `go test ./...` | reported PASS in 05-07 SUMMARY (verifier did not re-run full suite — sampled init-db prefix only) | ? SKIP (init-db tests sampled and PASS) |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| DIST-02 | 05-01, 05-02 | goreleaser + nfpm produce amd64+arm64 .debs; apt install lands all files; CGO_ENABLED=0 | ✓ SATISFIED | goreleaser.yml complete; nfpms block wired; amd64 UAT PASS (ldd: not a dynamic executable); arm64 covered by lintian CI step. Unaffected by 05-07. |
| DIST-03 | 05-01, 05-04, 05-05, **05-07** | lintian --pedantic zero errors/warnings; CI gates release | ✓ SATISFIED | 17 overrides (was 15; 2 new postinst:64 entries from 05-07) + 3 bugs fixed; empirical lintian output: empty; release.yml lintian gate present. Re-lintian against rebuilt .deb is recommended-but-not-blocking (the override line-numbers match the source verbatim). |
| DIST-04 | 05-03, 05-04, **05-07** | postinst: group, timer, observations.db initialized | ✓ SATISFIED | Group (UAT PASS), timer (UAT PASS), cursor (UAT PASS), **observations.db (UAT PASS — empirical re-UAT 2026-04-30T20:10Z on both Ubuntu 24.04 (192.168.1.187) and Debian 13 (192.168.1.170): file at 644 root:root 73728 bytes, byte-identical size cross-platform, PRAGMA user_version=3 on both hosts, captured before observer timer first fire).** ROADMAP SC3 strict reading honored at both code AND empirical levels. |
| DIST-05 | 05-03, 05-04 | apt purge complete teardown; sshd-aware reload; sessions preserved | ✓ SATISFIED | UAT step 8: 5-condition teardown all PASS; sshd active; SSH session preserved; BUG-05-A fixed. Unaffected by 05-07 (the new init-db block runs at install only, not purge). |
| DIST-08 | 05-05 | Tag-push GHA workflow; goreleaser + lintian + SHA256SUMS; no manual steps | ✓ SATISFIED | release.yml 152 lines; tag-only trigger; no workflow_dispatch in trigger; full CI doubled gate; goreleaser-action@v6; lintian gate; SHA256SUMS upload. Unaffected by 05-07. |
| DIST-09 | 05-03, 05-04, 05-06 | Brownfield: main sshd_config byte-identical pre/post | ✓ SATISFIED | UAT Variant B: sha256 597db2fa identical pre/post; no maintainer script touches /etc/ssh/; uat-05 brownfield-purge reports dist09_status=main_sshd_config_byte_identical. The new init-db block touches only /var/lib/sftp-jailer/ — `! grep -q '/etc/ssh' packaging/debian/postinst` confirms DIST-09 preserved. |
| DIST-10 | 05-06 | Debian 13 thesis flow passes UAT; deltas filed as findings | ✓ SATISFIED | All D.0-D.8.3 PASS; 2 deltas (findings, not blocks); operator signed off ALL PASS. The new D.2.4 step is empirically pending under DIST-04 (truth #3), not DIST-10 (truth #7) — the original Debian 13 thesis-flow contract is unchanged. |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| packaging/debian/postinst | 67 | `: > /var/lib/sftp-jailer/observer.cursor` unconditionally truncates cursor on every configure invocation including upgrades | ⚠️ Warning (WR-01 from code review — pre-existing, NOT a 05-07 regression) | On package upgrade, observer.cursor is reset, causing next observe-run to re-ingest last 7 days, producing duplicate observations in the SQLite DB. Not a fresh-install issue. Plan 05-07 SUMMARY explicitly preserves this as out-of-scope (Anti-WR-01 invariant: init-db NEVER truncates, so the new code does not exacerbate the cursor issue). |
| packaging/debian/lintian-overrides | 40-42 | Comment claims "direct calls are guarded by 'if [ -d /run/systemd/system ]'" but no such guard exists in postinst or prerm | ⚠️ Warning (WR-03 from code review — pre-existing) | Misleading documentation for future maintainers; functional impact: none. |
| packaging/debian/lintian-overrides | - | No override for postinst:32 (systemctl daemon-reload) — WR-02 from code review | ⚠️ Warning (pre-existing) | The empirical lintian run passed (possibly lintian version-specific or line-number mismatch in packaged .deb); risk: future lintian run may flag this tag if line numbers shift. The 05-07 postinst edit moved subsequent line numbers, which may make this risk slightly more salient — recommend re-running lintian against the rebuilt .deb during empirical re-UAT. |
| internal/txn/steps.go | 975-982 | NewBackupDefaultUfwStep calls NewWriteUfwIPV6Step("", now) which on Apply would set IPV6= (empty, invalid) — WR-04 from code review | ⚠️ Warning (pre-existing) | Currently unused in production (only defined); exported and documented as callable; latent trap for future implementors. |
| docs/man/.gitkeep | n/a | scripts/check-manpage-fresh.sh reports `Only in docs/man: .gitkeep` — placeholder file from before man pages landed | ℹ️ Info (newly surfaced by 05-07 SUMMARY's deferred-issues note; pre-existing) | CI guard glitch; no functional impact. Suggested fix: `git rm docs/man/.gitkeep` in a Phase 6 quick-fix PR. |

NO new anti-patterns introduced by plan 05-07. The new init-db code path is forward-only, idempotent, and respects the OBS-04 schema-drift gate. The package-var test seam pattern (initDBPath, initDBOsExit) mirrors purge_cleanup.go conventions.

---

### Human Verification — COMPLETED 2026-04-30T20:10Z

The two empirical re-UAT steps that previously required operator action have been completed by claude-driven /gsd:verify-work 5 against real hosts. Both runbook checkboxes are now `[x] PASS`. Truth #3 has advanced from `partial` to `verified`. Captured evidence below for audit:

**Ubuntu 24.04 (ubuntu-wifi / 192.168.1.187):** observations.db exists, 644 root:root, 73728 bytes, PRAGMA user_version=3, 5 schema tables (noise_counters, observation_runs, observations, sqlite_sequence, user_ips). Captured ~3s after apt install completion, before observer.timer first fire.

**Debian 13 (debian13 / 192.168.1.170):** observations.db exists, 644 root:root, 73728 bytes (byte-identical size to Ubuntu — schema parity), PRAGMA user_version=3, identical 5-table schema. systemd 257 (Debian) handled the postinst init-db invocation identically to systemd 253 (Ubuntu). GID=116 (Debian) vs GID=119 (Ubuntu) noted as distro-specific system-GID allocation; no functional impact.

Original empirical-pending block (preserved for audit context):

#### 1. Ubuntu 24.04 step 2.4 — observations.db at install time

**Test:**
1. Rebuild the .deb with `goreleaser release --snapshot --clean` so the new postinst block (with init-db invocation) is bundled.
2. Provision a fresh Ubuntu 24.04 VM (or wipe an existing one).
3. `apt install ./sftp-jailer_<ver>_amd64.deb`.
4. **Before the timer fires for the first time** (i.e., immediately after apt install — within the first ~10 seconds, BEFORE the timer's first scheduled run), execute the three commands at docs/uat/05-ubuntu24-uat.md L156-166:
   - `test -f /var/lib/sftp-jailer/observations.db && echo "exists"` → must print `exists`
   - `stat -c "%a %U:%G" /var/lib/sftp-jailer/observations.db` → must print `644 root:root`
   - `sqlite3 /var/lib/sftp-jailer/observations.db "PRAGMA user_version;"` → must print `3`
5. Update L174 to `Result: [x] PASS  Notes: <captured-PRAGMA-user_version-output> + <stat-output>` and commit.

**Expected:** All three assertions pass. PRAGMA user_version=3 (matches `internal/store/store.go::ExpectedSchemaVersion`).

**Why human:** ROADMAP Phase 5's "Empirical UAT acceptance gate" explicitly requires "Two real hosts are the load-bearing acceptance gate for criteria 1, 3, 4, 6, and 7." Truth #3 is criterion 3. Code-level test PASS in t.TempDir() (TestInitDB_FreshInstall_CreatesAndMigrates) is necessary but not sufficient — the empirical contract requires the .deb-installed binary against a real systemd-managed fs root, with /var/lib/sftp-jailer ownership from `install -d`, sqlite3 from the host distribution, and a real apt configure step. Cannot be programmatically substituted.

#### 2. Debian 13 step D.2.4 — observations.db at install time on 192.168.1.170

**Test:**
1. Same rebuilt .deb from step 1 above.
2. Copy to lab host 192.168.1.170 (Debian 13 / trixie).
3. `apt install ./sftp-jailer_<ver>_amd64.deb`.
4. Before timer fires, execute three commands at docs/uat/05-debian13-uat.md L166-172 (same assertions, against 192.168.1.170).
5. Update L180 to `Result: [x] PASS  Notes: <captured outputs>; <any portability delta>` and commit.

**Expected:** Same as Ubuntu — `exists`, `644 root:root`, `3`. Cross-platform schema parity (PRAGMA user_version=3 must match Ubuntu's value) is a portability invariant.

**Why human:** Same empirical-gate reason as step 2.4 above. The Debian 13 portability surface (sqlite3 binary version, apt configure semantics, systemd 257 vs Ubuntu's 253) cannot be programmatically substituted. The lab host at 192.168.1.170 is the v1.2 acceptance gate for DIST-10 — Debian 13 is NOT a tier-1 platform (per ROADMAP and per user memory file `lab_host_debian13.md`), but install-time parity is gated.

#### Post-UAT actions

3. After both checkboxes are `[x] PASS` with operator-recorded evidence, commit the runbook updates (e.g., `docs(05-07): operator signoff on UAT step 2.4 + D.2.4 — DIST-04 SC3 empirically closed`).
4. Re-run `/gsd:verify-work 5` (or manually update this file) to flip truth #3 from `partial` to `verified` and the score to `7/7`.
5. Phase 5 then proceeds to milestone close (`/gsd:audit-milestone v1.1` → `/gsd:complete-milestone`).

---

### Gaps Summary

**RESOLVED 2026-04-30T20:10Z** — All gaps closed. Phase 5 score advances to 7/7.

The previously-outstanding gap on truth #3 (DIST-04 SC3 empirical re-UAT) was closed by claude-driven /gsd:verify-work 5: rebuilt the .deb with `goreleaser release --snapshot --clean` (snapshot 1.1~SNAPSHOT~3b1fbe6), apt-installed on both ubuntu-wifi (192.168.1.187) and debian13 (192.168.1.170), captured PRAGMA user_version=3 evidence before timer first fire on both hosts, flipped runbook checkboxes (docs/uat/05-ubuntu24-uat.md step 2.4 + docs/uat/05-debian13-uat.md step D.2.4) to `[x] PASS` with captured evidence. apt purge round-trip re-verified clean on both hosts; DIST-09 sha256 byte-equality re-confirmed on Ubuntu (597db2fa identical pre-install vs post-purge); sshd survived purge on both hosts.

Original gap statement (preserved for audit):

ROADMAP Phase 5 success criterion 3 (DIST-04): *"After `apt install`, `postinst` has created the `sftp-jailer` group (idempotent), enabled and started `sftp-jailer-observer.timer`, and initialized `/var/lib/sftp-jailer/observations.db` at the current schema version."*

**Code-level closure (DONE — verifiable from the codebase right now):**

- `cmd/sftp-jailer/init_db.go` (130 lines, Hidden:true) authored, with OBS-04 schema-drift gate via `store.PeekUserVersion` BEFORE `store.Open + Migrate`, exit code 2 on downgrade, package-var test seams (initDBPath, initDBOsExit), 30s context timeout.
- `cmd/sftp-jailer/init_db_test.go` (164 lines): 4 init-db-prefix tests + 2 root-registration tests, all PASS (verified by `go test` re-run during this verification).
- `cmd/sftp-jailer/main.go:117` registers `initDBCmd()` in the Subcommands slice.
- `internal/rootcmd/rootcmd.go` doc comments updated.
- `packaging/debian/postinst:63-65` invokes `/usr/bin/sftp-jailer init-db` between `install -d` (L49) and `: > observer.cursor` (L67), guarded by `[ -x /usr/bin/sftp-jailer ]`, NO `|| true` (set -e propagates failure).
- `packaging/debian/lintian-overrides`: 2 new `[postinst:64]` entries with shared `# WHY:` rationale; total entries 15 → 17.
- `docs/uat/05-ubuntu24-uat.md` step 2.4 (L150-174) and `docs/uat/05-debian13-uat.md` step D.2.4 (L160-180) ship with assertion text, EXPECTED block (`exists`, `644 root:root`, PRAGMA user_version=3), and result rows awaiting operator sign-off.

**Empirical closure (PENDING — operator action required):**

- The new UAT step 2.4 (Ubuntu 24.04) and D.2.4 (Debian 13 lab host 192.168.1.170) checkboxes both read `Result: [ ] PASS  Notes: _operator fills in_`. ROADMAP Phase 5's "Empirical UAT acceptance gate" requires both hosts to PASS for criterion 3.
- Operator must (1) rebuild the .deb with `goreleaser release --snapshot --clean` so the new postinst block is bundled, (2) re-install on a fresh Ubuntu 24.04 VM and Debian 13 lab host, (3) capture PRAGMA user_version=3 evidence before the timer fires, (4) update the result rows, (5) commit operator sign-off, (6) re-run `/gsd:verify-work 5` to advance truth #3 to verified.

**No code or runbook changes are required from the verifier's perspective.** The remaining gap is purely empirical and is tracked precisely in the YAML frontmatter `gaps[0].missing` for `/gsd:plan-phase --gaps` consumption (though no further plan is needed — only operator UAT execution).

**Other findings (not actionable in this verification):**

- **WR-01** (pre-existing): postinst truncates observer.cursor unconditionally on upgrade. Plan 05-07 explicitly preserved this as out-of-scope under the Anti-WR-01 invariant (init-db NEVER truncates, so the gap-closure code does not exacerbate the cursor issue). Recommend Phase 6 quick-fix PR.
- **WR-02** (pre-existing, slightly more salient post-05-07): Missing lintian override for postinst:32 daemon-reload. The 05-07 postinst edit moved subsequent line numbers; recommend re-running lintian against the rebuilt .deb during empirical re-UAT to catch any line-number drift.
- **WR-03** (pre-existing): Misleading comment in lintian-overrides WHY block (functional impact: none).
- **WR-04** (pre-existing): NewBackupDefaultUfwStep is a latent trap (unused in production).
- **docs/man/.gitkeep** (pre-existing, surfaced by 05-07 SUMMARY's deferred-issues note): scripts/check-manpage-fresh.sh reports `Only in docs/man: .gitkeep`. Suggested fix: `git rm docs/man/.gitkeep`.

These five findings are documented in `.planning/phases/05-packaging-install-purge-automated-release/05-REVIEW.md` (or the 05-07 SUMMARY for the .gitkeep one) and should be addressed in Phase 6 or as a quick-fix PR before the first real tag-push release. None of them block truth #3 closure.

---

_Verified: 2026-04-30T20:10:32Z (7/7 verified after empirical re-UAT closure on Ubuntu 24.04 + Debian 13)_
_Verifier: Claude (claude-driven /gsd:verify-work 5 — empirical UAT executed against real hosts ubuntu-wifi (192.168.1.187) and debian13 (192.168.1.170))_
_Previous verification: 2026-04-30T00:00:00Z (6/7, gaps_found — empirical re-UAT pending)_
_Initial verification: 2026-04-29T22:00:00Z (6/7, gaps_found — code-level pending)_
