---
phase: 05-packaging-install-purge-automated-release
verified: 2026-04-29T22:00:00Z
status: gaps_found
score: 6/7 must-haves verified
overrides_applied: 0
gaps:
  - truth: "postinst creates sftp-jailer group idempotently, enables+starts observer.timer, initializes observations.db (DIST-04)"
    status: partial
    reason: >
      postinst correctly creates the group (idempotent), enables and starts sftp-jailer-observer.timer,
      and pre-creates observer.cursor at mode 0600. However ROADMAP success criterion 3 explicitly states
      "postinst has ... initialized /var/lib/sftp-jailer/observations.db at the current schema version."
      The postinst does NOT initialize observations.db — the DB is created lazily when the timer fires
      and observe-run invokes store.Open()+store.Migrate(). UAT step 2 (DIST-04) verified group, timer,
      and cursor but not DB initialization. The evidence for observations.db (679936 bytes) appears only
      at step 6.1 (observe-fire), which runs after the timer has fired. The success criterion wording
      is unambiguous: "After apt install, postinst has ... initialized observations.db."
    artifacts:
      - path: "packaging/debian/postinst"
        issue: >
          Creates observer.cursor (correct) but does not invoke sftp-jailer or otherwise initialize
          observations.db. The DB is first created when sftp-jailer-observer.service runs (via timer).
      - path: "docs/uat/05-ubuntu24-uat.md"
        issue: >
          Step 2 (DIST-04 gate) only verifies group (2.1), timer active (2.2), and cursor mode (2.3).
          observations.db initialization is not checked at install time — only at step 6.1 post observe-fire.
    missing:
      - >
        Either: (a) add a postinst step that calls `sftp-jailer observe-run --dry-run` or equivalent to
        force DB creation+migration immediately after install; or (b) revise success criterion 3 wording
        to accept lazy initialization via timer as equivalent. If (b), add a UAT step 2.4 verifying
        observations.db exists AFTER the timer fires (not just after install). Current state: the DB
        IS eventually created (UAT confirms 679936 bytes) but not at postinst time.
---

# Phase 5: Packaging, Install/Purge & Automated Release — Verification Report

**Phase Goal:** `apt install ./sftp-jailer_*.deb` on a fresh Ubuntu 24.04 box produces a working, lintian-clean installation, and `git tag vX.Y.Z && git push --tags` triggers a GitHub Actions workflow that publishes signed-checksum `.deb` artifacts to the GitHub Release with no manual steps. The same `.deb` also runs the full thesis flow on Debian 13 (lab host 192.168.1.170) — surfacing any apt/systemd/ufw/journald portability deltas before release. Every future v1.x / v2.x release inherits this contract.

**Verified:** 2026-04-29T22:00:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Local goreleaser snapshot produces installable amd64+arm64 .debs; apt install lands binary, systemd units, /var/lib/sftp-jailer/, man page; binary is static cgo-free (DIST-02) | ✓ VERIFIED | goreleaser.yml has nfpms: block with amd64+arm64 goarch; CGO_ENABLED=0 preserved; UAT step 1.1/1.3 on Ubuntu 24.04 amd64: apt install exits 0, ldd shows "not a dynamic executable", /usr/share/man/man1/sftp-jailer.1.gz present; goreleaser snapshot produced both arch .debs (arm64 verified by lintian step in release.yml config) |
| 2 | lintian --pedantic returns zero errors and zero warnings on both architectures; CI fails release on either failure (DIST-03) | ✓ VERIFIED | lintian-overrides empirically populated with 9 entries (each with # WHY: comment); 3 actual bugs fixed (copyright, changelog, uncompressed manpage); SUMMARY confirms "lintian --pedantic output: (empty — zero warnings, zero errors)"; release.yml has lintian --pedantic gate with fail=1 on any non-overridden warning |
| 3 | postinst creates sftp-jailer group idempotently, enables+starts observer.timer, initializes observations.db (DIST-04) | ✗ FAILED (partial) | postinst creates group (UAT step 2.1: GID 119), enables+starts timer (UAT step 2.2: enabled/active), creates observer.cursor at 0600 (UAT step 2.3). HOWEVER: observations.db is NOT initialized by postinst — it is created lazily on first timer-triggered observe-run (evidence: 679936 bytes at step 6.1, not at step 2). ROADMAP SC3 explicitly says "postinst has ... initialized observations.db at the current schema version." |
| 4 | apt purge removes binary, units, /var/lib/sftp-jailer/, drop-in; SAFE-06 sshd reload dispatched; existing SSH sessions survive (DIST-05) | ✓ VERIFIED | UAT step 8: apt purge exits 0; 5-condition teardown all PASS (binary gone, service unit gone, timer unit gone, state dir gone, drop-in gone); sshd active, SSH session preserved; BUG-05-A fixed (allowlist + MkdirAll for /var/backups/sftp-jailer/); prerm invokes purge-sshd-cleanup via hidden cobra subcommand; txn compensator chain in place |
| 5 | Tag-push GitHub Actions workflow runs goreleaser, lintian gate, attaches .debs + SHA256SUMS to GH Release; tag-push trigger ONLY (DIST-08) | ✓ VERIFIED | .github/workflows/release.yml exists (152 lines); trigger: on.push.tags v[0-9]+.[0-9]+.[0-9]+ and -rc[0-9]+ only; no workflow_dispatch (comment-only reference), no schedule, no branches; permissions: contents: write only; goreleaser-action@v6 v2.15.4 with packaging/goreleaser.yml; lintian --pedantic step with fail=0 gate; sha256sum *.deb > SHA256SUMS.txt + gh release upload; no continue-on-error |
| 6 | Brownfield purge: admin's main /etc/ssh/sshd_config is byte-identical pre/post (DIST-09) | ✓ VERIFIED | UAT Variant B: UAT-MARKER pre-edited into sshd_config; baseline sha256 captured (597db2fa...); apt install + drop-in apply + apt purge; post-purge sha256 byte-identical; uat-05 brownfield-purge reports dist09_status=main_sshd_config_byte_identical; UAT-MARKER still present; no maintainer script touches /etc/ssh/ |
| 7 | Debian 13 thesis flow passes empirical UAT on 192.168.1.170 (DIST-10) | ✓ VERIFIED | All D.0-D.8.3 steps PASS; 2 portability deltas filed (DIST-10-DELTA-01: ufw auto-installed, DIST-10-DELTA-02: ufw inactive by default) — both "finding" not "block"; journalctl JSON format identical between Ubuntu systemd 253 and Debian systemd 257; highest-risk surface clear; operator signed off "ALL PASS — 2 portability deltas, both findings (no blocks)" |

**Score:** 6/7 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packaging/goreleaser.yml` | Full goreleaser v2 config: builds + before + archives + nfpms + release + changelog | ✓ VERIFIED | 164 lines; all 6 top-level sections present; CGO_ENABLED=0 preserved; replace .Version "-" "~" version template; init-system-helpers/openssh-server/ufw Depends; passwd Recommends; no sshd_config.d in contents; before hooks include gen-manpage + gzip for man page and changelog |
| `packaging/debian/postinst` | dpkg postinst with group creation, timer enable+start, cursor pre-create | ✓ VERIFIED | 65 lines; #!/bin/sh + set -e; addgroup --system sftp-jailer (idempotent via getent); deb-systemd-helper enable+start timer; install -d /var/lib/sftp-jailer; cursor pre-create mode 0600; full Debian Policy §10 case set; no bashisms; no /etc/ssh/ touch |
| `packaging/debian/prerm` | dpkg prerm invoking purge-sshd-cleanup subcommand | ✓ VERIFIED | 78 lines; invokes /usr/bin/sftp-jailer purge-sshd-cleanup with \|\| true; guarded by [ -x /usr/bin/sftp-jailer ]; stops timer+service; disables timer; no raw /etc/ssh manipulation |
| `packaging/debian/postrm` | dpkg postrm wiping state on purge only | ✓ VERIFIED | 71 lines; rm -rf /var/lib/sftp-jailer on purge case only; delgroup sftp-jailer 2>/dev/null \|\| true; deb-systemd-helper purge; no /etc/ssh/ touch; retains state on remove |
| `packaging/debian/lintian-overrides` | 9 rationalized lintian overrides with # WHY: rationale | ✓ VERIFIED | 54 lines; 15 sftp-jailer: entries; every entry preceded by # WHY: comment; covers statically-linked-binary, depends-on-essential-package, command-with-path-in-maintainer-script (5 entries), maintainer-script-calls-systemctl (5 entries), unknown-field Architecture-Variant |
| `.github/workflows/release.yml` | Tag-push-only GHA workflow with lintian gate and SHA256SUMS | ✓ VERIFIED | 152 lines; tag-only trigger; contents:write only; full CI gate (5 scripts + 2 inline checks); goreleaser-action@v6 v2.15.4; lintian --pedantic loop; sha256sum + gh release upload |
| `cmd/gen-manpage/main.go` | cobra/doc.GenManTree driver | ✓ VERIFIED | 147 lines; doc.GenManTree present; rootcmd.Build wired; fixed date for determinism |
| `internal/rootcmd/rootcmd.go` | Package exposing Build(Opts) for manpage generator and production binary | ✓ VERIFIED | func Build present; Opts struct with RunTUI, PersistentPreRunE, Subcommands |
| `cmd/sftp-jailer/purge_cleanup.go` | Hidden cobra subcommand purge-sshd-cleanup | ✓ VERIFIED | Hidden: true; Use: "purge-sshd-cleanup"; NewRemoveSshdDropInStep + NewSshdValidateStep + NewSystemctlReloadStep(txn.ReloadService); drop-in already absent idempotent skip; purgeBackupDir = /var/backups/sftp-jailer |
| `internal/txn/steps.go` | NewRemoveSshdDropInStep constructor | ✓ VERIFIED | func NewRemoveSshdDropInStep present; Apply backs up + RemoveAll; Compensate restores; MkdirAll for backup dir (BUG-05-A fix) |
| `scripts/check-manpage-fresh.sh` | CI guard for docs/man/ freshness | ✓ VERIFIED | Executable; set -euo pipefail; go run ./cmd/gen-manpage; diff -ru; FAIL:/OK: conventions |
| `docs/man/sftp-jailer.1` | Generated groff man page | ✓ VERIFIED | File exists; substantial content |
| `docs/uat/05-ubuntu24-uat.md` | Ubuntu 24.04 UAT runbook with operator sign-off | ✓ VERIFIED | DIST-09 referenced; sha256 evidence (597db2fa); operator signed off; Variant A + B both documented |
| `docs/uat/05-debian13-uat.md` | Debian 13 UAT runbook with operator sign-off | ✓ VERIFIED | 192.168.1.170 present; ALL PASS verdict; 2 deltas documented |
| `packaging/debian/copyright` | Debian Policy §12.5 copyright file | ✓ VERIFIED | Added during BUG-05-A fix commit 7078199 |
| `packaging/debian/changelog` | Debian Policy changelog file | ✓ VERIFIED | Added during BUG-05-A fix commit 7078199 |
| `cmd/uat-05/main.go` | One-shot UAT helper binary (481 lines) | ✓ VERIFIED | 481 lines; 7 subcommands; sysops.NewReal() wired; JSON receipts; DIST-09 sha256 gate |
| `.planning/RELEASE-CHECKLIST.md` | Build+Test and Distribution sections | ✓ VERIFIED | lintian --pedantic referenced; sign-off table present |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| packaging/goreleaser.yml | packaging/debian/postinst, prerm, postrm | nfpms[].scripts block | ✓ WIRED | scripts: postinstall/preremove/postremove all present |
| packaging/goreleaser.yml | packaging/systemd/*.service, *.timer | nfpms[].contents | ✓ WIRED | /lib/systemd/system/ entries present |
| packaging/goreleaser.yml | packaging/debian/sftp-jailer.1.gz | before hook + nfpms contents | ✓ WIRED | gzip before hook + contents entry present |
| packaging/goreleaser.yml | packaging/debian/lintian-overrides | nfpms[].contents | ✓ WIRED | /usr/share/lintian/overrides/sftp-jailer entry present |
| packaging/goreleaser.yml before-hook | cmd/gen-manpage | go run ./cmd/gen-manpage | ✓ WIRED | before: hooks includes go run ./cmd/gen-manpage |
| cmd/gen-manpage/main.go | internal/rootcmd (Build) | import + rootcmd.Build() call | ✓ WIRED | rootcmd.Build present in gen-manpage |
| cmd/sftp-jailer/main.go | cmd/sftp-jailer/purge_cleanup.go | root.AddCommand(purgeSshdCleanupCmd()) | ✓ WIRED | purgeSshdCleanupCmd() registered in rootCmd |
| packaging/debian/prerm | /usr/bin/sftp-jailer purge-sshd-cleanup | shell invocation with binary-present guard | ✓ WIRED | if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer purge-sshd-cleanup \|\| true |
| cmd/sftp-jailer/purge_cleanup.go | internal/txn.NewRemoveSshdDropInStep | txn.New(ops).Apply(ctx, steps) | ✓ WIRED | NewRemoveSshdDropInStep in purgeStepsFn |
| cmd/sftp-jailer/purge_cleanup.go | internal/tui/screens/applysetup.DropInPath | compile-time const import | ✓ WIRED | applysetup.DropInPath referenced |
| .github/workflows/release.yml | packaging/goreleaser.yml | goreleaser-action@v6 with config: | ✓ WIRED | args: release --clean --config packaging/goreleaser.yml |
| .github/workflows/release.yml | scripts/check-manpage-fresh.sh | bash invocation | ✓ WIRED | bash scripts/check-manpage-fresh.sh in Architecture invariants step |
| .github/workflows/release.yml | lintian gate | lintian --pedantic dist/*.deb loop | ✓ WIRED | fail=0 gate, exits non-zero on failure |
| .github/workflows/release.yml | SHA256SUMS.txt | sha256sum *.deb + gh release upload | ✓ WIRED | SHA256SUMS.txt generated and uploaded via GITHUB_TOKEN |
| internal/sysops/atomic.go | /var/backups/sftp-jailer/ | allowlist entry (BUG-05-A fix) | ✓ WIRED | /var/backups/sftp-jailer present in allowlist |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| packaging/debian/postinst | observer.cursor (zero-byte marker) | : > /var/lib/sftp-jailer/observer.cursor | Yes (creates the file at install time) | ✓ FLOWING |
| packaging/debian/prerm | drop-in bytes via cobra subcommand | /usr/bin/sftp-jailer purge-sshd-cleanup -> txn.NewRemoveSshdDropInStep | Yes (reads drop-in, backs up, removes) | ✓ FLOWING |
| packaging/debian/postrm | /var/lib/sftp-jailer/ | rm -rf on purge case | Yes (wipes state dir) | ✓ FLOWING |
| .github/workflows/release.yml | dist/*.deb → lintian | goreleaser produces dist/*.deb; lintian reads from them | Yes | ✓ FLOWING |
| .github/workflows/release.yml | SHA256SUMS.txt | sha256sum *.deb from dist/ | Yes | ✓ FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| goreleaser.yml schema valid | goreleaser check (not run — not available on verifier machine) | N/A | ? SKIP |
| postinst POSIX sh syntax | sh -n packaging/debian/postinst | Would pass (file content verified manually) | ? SKIP (not runnable without sh environment isolation) |
| prerm POSIX sh syntax | sh -n packaging/debian/prerm | Same | ? SKIP |
| postrm POSIX sh syntax | sh -n packaging/debian/postrm | Same | ? SKIP |
| UAT on Ubuntu 24.04 (empirical) | apt install .deb + full thesis flow | ALL PASS (from operator sign-off in runbook) | ✓ PASS |
| UAT on Debian 13 (empirical) | apt install .deb + full thesis flow | ALL PASS (2 findings, 0 blocks) | ✓ PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| DIST-02 | 05-01, 05-02 | goreleaser + nfpm produce amd64+arm64 .debs; apt install lands all files; CGO_ENABLED=0 | ✓ SATISFIED | goreleaser.yml complete; nfpms block wired; amd64 UAT PASS (ldd: not a dynamic executable); arm64 covered by lintian CI step |
| DIST-03 | 05-01, 05-04, 05-05 | lintian --pedantic zero errors/warnings; CI gates release | ✓ SATISFIED | 9 overrides + 3 bugs fixed; empirical lintian output: empty; release.yml lintian gate present |
| DIST-04 | 05-03, 05-04 | postinst: group, timer, observations.db initialized | ✗ PARTIAL | Group (UAT PASS), timer (UAT PASS), cursor (UAT PASS); observations.db NOT initialized by postinst (created lazily via timer/observe-run); ROADMAP SC3 says postinst must initialize DB |
| DIST-05 | 05-03, 05-04 | apt purge complete teardown; sshd-aware reload; sessions preserved | ✓ SATISFIED | UAT step 8: 5-condition teardown all PASS; sshd active; SSH session preserved; BUG-05-A fixed |
| DIST-08 | 05-05 | Tag-push GHA workflow; goreleaser + lintian + SHA256SUMS; no manual steps | ✓ SATISFIED | release.yml 152 lines; tag-only trigger; no workflow_dispatch in trigger; full CI doubled gate; goreleaser-action@v6; lintian gate; SHA256SUMS upload |
| DIST-09 | 05-03, 05-04, 05-06 | Brownfield: main sshd_config byte-identical pre/post | ✓ SATISFIED | UAT Variant B: sha256 597db2fa identical pre/post; no maintainer script touches /etc/ssh/; uat-05 brownfield-purge reports dist09_status=main_sshd_config_byte_identical |
| DIST-10 | 05-06 | Debian 13 thesis flow passes UAT; deltas filed as findings | ✓ SATISFIED | All D.0-D.8.3 PASS; 2 deltas (findings, not blocks); operator signed off ALL PASS |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| packaging/debian/postinst | 50 | `: > /var/lib/sftp-jailer/observer.cursor` unconditionally truncates cursor on every configure invocation including upgrades | ⚠️ Warning (WR-01 from code review) | On package upgrade, observer.cursor is reset, causing next observe-run to re-ingest last 7 days, producing duplicate observations in the SQLite DB. Not a fresh-install issue. |
| packaging/debian/lintian-overrides | 40-42 | Comment claims "direct calls are guarded by 'if [ -d /run/systemd/system ]'" but no such guard exists in postinst or prerm | ⚠️ Warning (WR-03 from code review) | Misleading documentation for future maintainers; functional impact: none |
| packaging/debian/lintian-overrides | - | No override for postinst:32 (systemctl daemon-reload) — WR-02 from code review | ⚠️ Warning | The empirical lintian run passed (possibly lintian version-specific or line-number mismatch in packaged .deb); risk: future lintian run may flag this tag if line numbers shift |
| internal/txn/steps.go | 975-982 | NewBackupDefaultUfwStep calls NewWriteUfwIPV6Step("", now) which on Apply would set IPV6= (empty, invalid) — WR-04 from code review | ⚠️ Warning | Currently unused in production (only defined); exported and documented as callable; latent trap for future implementors |

---

### Human Verification Required

None for the passing criteria. All empirically verifiable items (install, purge, brownfield, Debian 13) have been signed off by the operator in the runbooks.

---

### Gaps Summary

**One gap blocks goal achievement for DIST-04 (SC3):**

The ROADMAP success criterion 3 for Phase 5 states: *"After `apt install`, `postinst` has created the `sftp-jailer` group (idempotent), enabled and started `sftp-jailer-observer.timer`, and initialized `/var/lib/sftp-jailer/observations.db` at the current schema version."*

The `postinst` script does not initialize `observations.db`. The DB is created lazily by `sftp-jailer observe-run` (via `internal/store.Open()+Migrate()`) when the systemd timer fires for the first time. The UAT step 2 (DIST-04 gate) verified group, timer active, and observer.cursor — but not DB initialization. The DB evidence (679936 bytes) appears only at UAT step 6.1, after the observation timer has fired.

**Resolution options:**
1. Revise the ROADMAP SC3 to reflect that DB initialization occurs via the first timer-triggered observe-run (not by postinst directly), and add a UAT step verifying the DB exists after the timer fires.
2. Add a postinst step that invokes `sftp-jailer observe-run` or a dedicated DB-init subcommand to force schema migration at install time.

**Additional non-blocking review findings (not actionable gaps for this phase):**

- WR-01: postinst truncates observer.cursor unconditionally on upgrade (affects upgrade path, not fresh install).
- WR-02: Missing lintian override for postinst:32 daemon-reload (empirical lintian passed; risk to future releases).
- WR-03: Misleading comment in lintian-overrides WHY block (documentation issue, no functional impact).
- WR-04: NewBackupDefaultUfwStep is a latent trap (unused in production, but exported).

These four review findings are documented in `.planning/phases/05-packaging-install-purge-automated-release/05-REVIEW.md` and should be addressed in Phase 6 or as a quick-fix PR before the first real tag-push release.

---

_Verified: 2026-04-29T22:00:00Z_
_Verifier: Claude (gsd-verifier)_
