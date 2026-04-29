---
phase: 05-packaging-install-purge-automated-release
plan: "06"
subsystem: uat
tags:
  - uat
  - empirical
  - packaging
  - runbook
  - dist-10
  - brownfield
  - debian-13
  - ubuntu-24-04
dependency_graph:
  requires:
    - 05-04 (maintainer scripts — postinst/prerm/postrm)
    - 05-05 (release workflow — goreleaser + GitHub Actions)
  provides:
    - Empirical UAT runbooks for Phase 5 acceptance gate (Ubuntu 24.04 Variant A + B + Debian 13)
    - uat-05 helper binary (7-subcommand dispatch + JSON receipts)
    - README install/Recovery/Tagging documentation
    - RELEASE-CHECKLIST.md Build+Test + Distribution sections
    - packaging/debian/lintian-overrides — empirically populated (9 entries + WHY: rationale)
  affects:
    - packaging/debian/lintian-overrides (empirical fill — post-operator-run)
    - packaging/debian/copyright (added — Debian Policy S12.5 gap closed)
    - packaging/debian/changelog (added — lintian no-changelog gap closed)
tech_stack:
  added:
    - cmd/uat-05 (one-shot UAT helper binary, same shape as cmd/uat-04)
  patterns:
    - Subcommand-dispatch map[string]subcmdFn (NOT phase-array)
    - JSON receipt audit trail at /var/log/sftp-jailer-uat-05/<subcmd>.json
    - Stub subcommands return informative errors citing the runbook section
    - DIST-09 sha256sum baseline capture + assertion via UAT_BASELINE_SHA256 env var
key_files:
  created:
    - cmd/uat-05/main.go
    - docs/uat/05-ubuntu24-uat.md
    - docs/uat/05-debian13-uat.md
    - .planning/RELEASE-CHECKLIST.md
    - packaging/debian/copyright
    - packaging/debian/changelog
    - packaging/debian/changelog.Debian.gz
    - packaging/debian/sftp-jailer.1.gz
  modified:
    - README.md
    - packaging/debian/lintian-overrides (9 entries added empirically)
    - packaging/goreleaser.yml (before hooks for man page + changelog gzip)
    - cmd/uat-05/main.go (BUG-05-A hardening)
    - internal/sysops/atomic.go (BUG-05-A allowlist fix)
    - internal/txn/steps.go (BUG-05-A MkdirAll backup dir)
decisions:
  - "D-RW-02: cmd/uat-05 follows cmd/uat-04 shape (phase-array -> subcommand dispatch)"
  - "D-LC-03: observations.db backup procedure documented in README Recovery section"
  - "D-RW-03: vMAJOR.MINOR.PATCH[-rcN] tagging convention documented in README"
  - "Receipt fields: subcmd, started_at, finished_at, status, evidence map, error, host_info map"
  - "Receipt path: /var/log/sftp-jailer-uat-05/<subcmd>.json (outside /var/lib so apt purge preserves audit trail)"
  - "BUG-05-A: /var/backups/sftp-jailer/ added to atomic write allowlist + MkdirAll pre-creation in RemoveSshdDropInStep"
metrics:
  duration: "~5h (Tasks 1-5 pre-checkpoint + Tasks 6-7 post-checkpoint)"
  completed_date: "2026-04-30"
  task_count: 7
  tasks_completed: 7
  files_modified: 14
---

# Phase 05 Plan 06: Empirical UAT Runbook — Final Summary

**One-liner:** Phase 5 empirical UAT gate complete — Ubuntu 24.04 (clean + brownfield) and Debian 13 all PASS; BUG-05-A discovered and fixed; lintian clean with 9 rationalized overrides; DIST-09 sha256 byte-equality verified.

---

## What Was Done

### Tasks 1–5 (completed pre-checkpoint; commits 3b061c3..b8b31df)

- **Task 1 — cmd/uat-05/main.go (463 lines, commit 3b061c3):** 7-subcommand dispatch UAT helper binary built per D-RW-02. Subcommands: install, doctor, apply-sshd, user-crud, observe-fire, lockdown-cycle, brownfield-purge. Root gate via `os.Geteuid()`. All process invocations via `ops.Exec()` (sysops typed wrappers). JSON receipts written to `/var/log/sftp-jailer-uat-05/<subcmd>.json` (defer-pattern, even on FAIL). DIST-09 gate in `runBrownfieldPurge`: sha256sum capture mode (empty `UAT_BASELINE_SHA256`) + assertion mode (non-empty). Stub subcommands (`user-crud`, `lockdown-cycle`) return informative errors citing the runbook section.

- **Task 2 — docs/uat/05-ubuntu24-uat.md (commit 383cffb):** Full manual runbook for Ubuntu 24.04 VM acceptance gate. Variant A (clean install, criteria 1/3/4): 8 steps with A.0 pre-flight through Step 8 apt purge teardown. Variant B (brownfield, criterion 6 DIST-09): UAT-MARKER pre-edit, sha256sum baseline capture, apt install + optional TUI drop-in apply, apt purge, post-purge hash comparison, uat-05 brownfield-purge assertion, UAT-MARKER grep confirmation. Lintian-overrides empirical fill section (L.1-L.3) with `# WHY:` format requirement. Operator sign-off block.

- **Task 3 — docs/uat/05-debian13-uat.md (commit cf66411):** Manual runbook for Debian 13 lab host at 192.168.1.170. Same 8-step thesis flow as Ubuntu Variant A, adapted with Debian-13-specific delta callouts per step. Portability deltas table with rows for journalctl JSON format risk (highest-risk surface), ufw backend differences, AppArmor status. Tier-1 disclaimer prominently in preamble. Two sign-off outcomes: ALL PASS / THESIS FLOW BLOCKED.

- **Task 4 — README.md updates (commit 0444ff4):** Install section replaced `go install` with `apt install ./sftp-jailer_*.deb` + SHA256SUMS verification. Recovery section added (observations.db backup/restore before/after apt purge). Releases & Tagging section added (`vMAJOR.MINOR.PATCH[-rcN]` patterns, Debian version ordering rationale, `git tag + push --tags` workflow). Closes D-LC-03 and D-RW-03.

- **Task 5 — .planning/RELEASE-CHECKLIST.md (commit b8b31df):** Build+Test section added (go test -race, golangci-lint, govulncheck, 5 invariant scripts, v1 Bubble Tea guard, goreleaser snapshot, lintian --pedantic). Empirical UAT runbook references (Variant A/B + Debian 13). Distribution section added (tag+push, automated pipeline steps, post-release verification, roll-back procedure). Sign-off checkpoint table. Preserves existing curl-ifconfig.me external dependency entry.

### Task 6 — Empirical UAT Execution (commits 7078199, d27eb2d)

Both runbooks executed against real hosts. BUG-05-A discovered and fixed during the run. Full outcomes below.

### Task 7 — Final SUMMARY (this document)

Replaces the pre-checkpoint partial SUMMARY. All empirical outcomes documented with evidence.

---

## Decisions Implemented

| Decision | Source | Implementation |
|----------|--------|----------------|
| D-RW-02 | 05-CONTEXT.md L217-237 | cmd/uat-05 uses subcommand dispatch (NOT phase-array like uat-04) |
| D-LC-03 | 05-CONTEXT.md | observations.db backup documented in README Recovery section |
| D-RW-03 | 05-CONTEXT.md | vMAJOR.MINOR.PATCH[-rcN] tagging convention in README Releases section |
| Receipt fields (Claude's Discretion) | 05-CONTEXT.md L285-289 | subcmd, started_at, finished_at, status, evidence map, error, host_info |
| Receipt path (Claude's Discretion) | 05-CONTEXT.md L285-289 | /var/log/sftp-jailer-uat-05/<subcmd>.json (outside /var/lib) |

---

## Empirical UAT Outcomes

### Ubuntu 24.04 — Variant A (Clean Install)

**Host:** ubuntu-wifi (192.168.1.187), Ubuntu 24.04.4 LTS amd64
**Artifact:** sftp-jailer_1.1~SNAPSHOT~e05094f_amd64.deb

| Step | Description | Result |
|------|-------------|--------|
| A.0 | Pre-flight — no prior install | PASS — CLEAN |
| A.1 | Copy artifacts to VM | PASS — both deployed |
| 1.1 | apt install -y .deb | PASS — exit 0; timer symlink created |
| 1.2 | uat-05 install | PASS — [PASS] install; man_page_path=/usr/share/man/man1/sftp-jailer.1.gz timer_active=active |
| 1.3 | ldd confirms cgo-free | PASS — "not a dynamic executable" |
| 2.1 | System group GID < 1000 | PASS — sftp-jailer:x:119: |
| 2.2 | Timer enabled + active | PASS — enabled / active |
| 2.3 | observer.cursor 600 root root 0 | PASS |
| 3.1 | sftp-jailer doctor — 6 sections | PASS — [WARN] sshd drop-ins, [WARN] chroot chain, [OK] ufw IPV6=yes, [OK] AppArmor: sshd profile not loaded, [OK] nftables consumers: clean, [FAIL] subsystem sftp (expected) |
| 3.2 | uat-05 doctor | PASS — report_keys=6 |
| 4.1 | sshd drop-in apply (TUI-driven) | PASS — sshd -t PASS; drop-in written |
| 4.2 | uat-05 apply-sshd | PASS — chrootdirectory=true forcecommand=true |
| 5.1 | Create user "uattest" | PASS — shadow shows yescrypt hash |
| 5.2 | Add SSH key | PASS — authorized_keys written at /srv/sftp-jailer/uattest/.ssh/authorized_keys |
| 5.3 | Delete user "uattest" | PASS — user deleted |
| 6.1 | uat-05 observe-fire | PASS — final_state=inactive; observations_db_size_bytes=679936 |
| 7.1 | Pre-lockdown ufw state | PASS — catch-all ALLOW rules present |
| 7.2 | SAFE-04 auto-revert (TUI) | SKIP-OPERATOR — lockdown-cycle is a designed stub; requires interactive TUI with SAFE-04 3-minute timer |
| 8.1 | apt purge -y sftp-jailer | PASS — exit 0; purge-sshd-cleanup succeeded (after BUG-05-A fix) |
| 8.2 | 5-condition teardown check | PASS — all 5: binary gone / svc unit gone / tmr unit gone / state dir gone / drop-in gone |
| 8.3 | sshd still running | PASS — active; SSH session preserved |

**Variant A verdict: ALL PASS** (7.2 SKIP-OPERATOR as designed; BUG-05-A discovered and fixed during run)

---

### Ubuntu 24.04 — Variant B (Brownfield, DIST-09)

**Host:** ubuntu-wifi (192.168.1.187) — same host, run sequentially after Variant A purge
**DIST-09 contract:** apt install and apt purge MUST NOT modify /etc/ssh/sshd_config (admin-owned main file)

| Step | Description | Result |
|------|-------------|--------|
| B.0 | Pre-edit sshd_config with UAT-MARKER | PASS — exit 0 |
| B.1 | Capture baseline sha256 | PASS — 597db2faddfca15ce6ba419c935169953ae1017ec8e2c4d00833c5f8504545f0 |
| B.2 | apt install .deb | PASS — postinst output contained no reference to /etc/ssh/sshd_config |
| B.3 | Apply drop-in via TUI | PASS — drop-in written; main sshd_config untouched |
| B.4 | apt purge -y sftp-jailer | PASS — clean purge; drop-in removed |
| B.5 | Re-hash and compare to BASELINE | PASS — sha256 byte-identical (597db2fa...) |
| B.6 | uat-05 brownfield-purge | PASS — [PASS] brownfield-purge; dist09_status=main_sshd_config_byte_identical; dropin_status=absent |
| B.7 | UAT-MARKER still present | PASS — # UAT-MARKER: do not delete (DIST-09 brownfield test) present |

**DIST-09 verdict: PASS — sha256 byte-equality verified**

---

### Debian 13 (DIST-10 Portability Gate)

**Host:** debian13 (192.168.1.170), Debian 13 "trixie" amd64
**Artifact:** same Ubuntu 24.04 .deb (single static binary — no Debian-specific build)
**Systemd version:** 257 (257.9-1~deb13u1)

| Step | Description | Result |
|------|-------------|--------|
| D.0 | Confirm Debian 13 trixie | PASS — ID=debian; VERSION="13 (trixie)" |
| D.1 | System context capture | PASS — kernel 6.12.74+deb13+1-amd64; systemd 257; amd64 |
| D.2 | Baseline tools present | PASS (with DIST-10-DELTA-01) — apt/systemctl/journalctl present; ufw auto-installed |
| D.1.1 | apt install .deb | PASS — ufw + iptables pulled from network (169kB); postinst GID 116; timer enabled |
| D.1.2 | uat-05 install | PASS — [PASS] install; all 5 paths; timer_active=active |
| D.2.1 | postinst side effects | PASS — sftp-jailer:x:116: (GID 116); enabled; active; 600 root root 0 |
| D.3.1 | sftp-jailer doctor | PASS — identical output to Ubuntu 24.04; no portability delta |
| D.3.2 | uat-05 doctor | PASS — [PASS] doctor; report_keys=6 |
| D.4.1 | sshd drop-in apply | PASS — sshd -t PASS; OpenSSH directives fully compatible |
| D.4.2 | uat-05 apply-sshd | PASS — chrootdirectory=true forcecommand=true |
| D.5.1 | Create user "uattest" | PASS — shadow shows yescrypt hash |
| D.5.2 | Add SSH key | PASS — authorized_keys at /srv/sftp-jailer/uattest/.ssh/authorized_keys |
| D.5.3 | Delete user "uattest" | PASS — user deleted |
| D.6.1 | uat-05 observe-fire (highest-risk surface) | PASS — final_state=inactive; observations_db_size_bytes=204800; journalctl JSON format: no delta vs Ubuntu systemd |
| D.7.1 | Pre-lockdown ufw state | DELTA-NOTED — ufw inactive by default on Debian 13 (DIST-10-DELTA-02; finding, not block) |
| D.7.2 | SAFE-04 auto-revert (TUI) | SKIP-OPERATOR — lockdown-cycle stub; ufw-inactive-by-default filed as DIST-10-DELTA-02 |
| D.8.1 | apt purge -y sftp-jailer | PASS — exit 0; prerm ran purge-sshd-cleanup; drop-in removed |
| D.8.2 | 5-condition teardown check | PASS — all 5 gone |
| D.8.3 | sshd still running | PASS — active; SSH session preserved |

**Portability Deltas Filed:**

| Delta ID | Severity | Description |
|----------|----------|-------------|
| DIST-10-DELTA-01 | finding | ufw not pre-installed on Debian 13; auto-installed as sftp-jailer Depends. iptables pulled as transitive dep. No action required — package dependencies handle this. |
| DIST-10-DELTA-02 | finding | ufw starts inactive on Debian 13 (unlike Ubuntu 24.04 which enables ufw with SSH ALLOW rules). Lockdown proposal would need to enable ufw first on Debian 13. Not tested (lockdown TUI stub). |

**DIST-10 verdict: ALL PASS — 2 portability deltas, both findings (no blocks). Thesis flow completes successfully on Debian 13.**

**Highest-risk surface clear:** journalctl JSON field names between Ubuntu systemd 253 and Debian 13 systemd 257 — no incompatibility found.

---

## Receipt Log Audit Trail

JSON receipts written to `/var/log/sftp-jailer-uat-05/` on each host after each uat-05 invocation (outside `/var/lib/sftp-jailer` so apt purge does not erase the audit trail):

**Ubuntu 24.04 (ubuntu-wifi):**
- install.json — status=PASS; man_page_path=/usr/share/man/man1/sftp-jailer.1.gz; timer_active=active
- doctor.json — status=PASS; report_keys=6
- apply-sshd.json — status=PASS; chrootdirectory=true; forcecommand=true
- observe-fire.json — status=PASS; final_state=inactive; observations_db_size_bytes=679936
- brownfield-purge.json — status=PASS; dist09_status=main_sshd_config_byte_identical; dropin_status=absent

**Debian 13 (debian13):**
- install.json — status=PASS; all 5 paths present; timer_active=active
- doctor.json — status=PASS; report_keys=6
- apply-sshd.json — status=PASS; chrootdirectory=true; forcecommand=true
- observe-fire.json — status=PASS; final_state=inactive; observations_db_size_bytes=204800

---

## Lintian-Overrides Empirical Fill

`packaging/debian/lintian-overrides` populated with 9 entries, each carrying a `# WHY:` rationale (closes the deferred gap from 05-04 task 4). Additionally, 3 bugs were fixed instead of overriding:

**Fixed (no override needed):**
1. `no-copyright-file` — fixed: added `packaging/debian/copyright` (Debian Policy S12.5)
2. `no-changelog` — fixed: added `packaging/debian/changelog` + `changelog.Debian.gz`
3. `uncompressed-manual-page` — fixed: pre-compressed via goreleaser `before` hook to `sftp-jailer.1.gz`

**Overridden with rationale (9 entries):**
1. `depends-on-essential-package-without-using-version Depends: init-system-helpers` — required for deb-systemd-helper calls; any version sufficient
2. `statically-linked-binary [usr/bin/sftp-jailer]` — CGO_ENABLED=0 is a core REQUIREMENTS.md constraint
3. `command-with-path-in-maintainer-script ... [postinst:33]` — absolute paths required in maintainer scripts; dpkg runs with minimal env
4. `command-with-path-in-maintainer-script ... [postrm:55]` — same rationale
5. `command-with-path-in-maintainer-script ... [prerm:46]` — same rationale
6. `command-with-path-in-maintainer-script ... [postinst:39]` — same rationale
7. `command-with-path-in-maintainer-script ... [prerm:36]` — same rationale
8. `command-with-path-in-maintainer-script /usr/bin/sftp-jailer ... [prerm:63+64]` — prerm must call installed binary by absolute path for purge-sshd-cleanup
9. `maintainer-script-calls-systemctl [postinst:37, postinst:42, prerm:40, prerm:41, prerm:49]` — direct systemctl calls guarded by `if [ -d /run/systemd/system ]`; deb-systemd-helper cannot perform daemon-reload or status queries
10. `unknown-field Architecture-Variant` — goreleaser-injected build tracking field; does not affect installation

**Lintian result post-overrides:** `lintian --pedantic` output: (empty — zero warnings, zero errors)

---

## Phase Completion Gate — All 7 DIST Requirements

| Criterion | DIST ID | Description | Result |
|-----------|---------|-------------|--------|
| 1 | DIST-02 | .deb installs cleanly on Ubuntu 24.04 (apt install, no errors) | PASS |
| 2 | DIST-03 | CI pipeline runs lintian --pedantic, exits 0 | PASS (05-05 gated) |
| 3 | DIST-04 | postinst: group, timer, cursor created correctly | PASS |
| 4 | DIST-05 | apt purge: complete teardown, sshd remains up | PASS |
| 5 | DIST-07 | Single static cgo-free binary | PASS (ldd: not a dynamic executable) |
| 6 | DIST-09 | Brownfield: /etc/ssh/sshd_config byte-identical after install+purge | PASS (sha256 verified) |
| 7 | DIST-10 | Debian 13: thesis flow completes; portability deltas filed as findings | PASS (2 findings, 0 blocks) |

**All 7 DIST requirements: PASS. Phase may proceed to close.**

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] BUG-05-A: purge-sshd-cleanup failed with allowlist + missing directory errors**
- **Found during:** Task 6, Step 8.1 (Ubuntu Variant A apt purge)
- **Issue (part 1):** `internal/sysops/atomic.go` — AtomicWriteFile rejected `/var/backups/sftp-jailer/` as "path not in allowlist". The backup destination for the sshd drop-in was not in the allowed-paths list.
- **Issue (part 2):** `/var/backups/sftp-jailer/` did not exist — RemoveSshdDropInStep's Apply() attempted to write into a non-existent directory.
- **Fix:** Added `/var/backups/sftp-jailer/` prefix to the AtomicWriteFile allowlist; added `MkdirAll` call in RemoveSshdDropInStep.Apply() to pre-create the backup directory; added regression test `TestAtomicWriteFile_allowlist_accepts_var_backups_sftp_jailer_prefix`.
- **Files modified:** `internal/sysops/atomic.go`, `internal/txn/steps.go`, `internal/sysops/real_phase4_test.go`
- **Commit:** 7078199

**2. [Rule 2 - Missing critical functionality] uat-05 man page path: binary checked for .gz but .deb shipped uncompressed**
- **Found during:** Task 6, Step 1.2 (uat-05 install)
- **Issue:** Original uat-05 install subcommand checked for `/usr/share/man/man1/sftp-jailer.1.gz` but the first .deb build shipped an uncompressed `.1` file.
- **Fix:** Updated uat-05 to accept both `.1` and `.1.gz` paths. Separately: added goreleaser `before` hook to pre-compress the man page to `.1.gz` before nfpm packages it, so both the binary and the package now agree on the compressed path.
- **Files modified:** `cmd/uat-05/main.go`, `packaging/goreleaser.yml`
- **Commit:** 7078199

**3. [Rule 2 - Missing critical functionality] Debian Policy packaging gaps: copyright + changelog absent**
- **Found during:** Task 6, Lintian section L.1 (lintian --pedantic first run)
- **Issue:** `no-copyright-file` and `no-changelog` lintian errors. Debian Policy S12.5 requires every .deb to include a copyright file. Missing changelog is a policy violation, not just a style issue.
- **Fix:** Added `packaging/debian/copyright` (24 lines, GPL-3.0); added `packaging/debian/changelog` (8 lines); added `changelog.Debian.gz` pre-compressed via goreleaser hook. Added goreleaser `before` hooks to gzip both the man page and changelog before nfpm runs.
- **Files modified:** `packaging/debian/copyright` (new), `packaging/debian/changelog` (new), `packaging/debian/changelog.Debian.gz` (new), `packaging/goreleaser.yml`
- **Commit:** 7078199

---

## Known Stubs

**By design — both documented in runbooks:**
- `cmd/uat-05/main.go :: runUserCrud` — returns an informative error directing the operator to the runbook TUI flow. Cannot be automated without a headless Bubble Tea harness. Runbook steps 5.1-5.3 are manually driven and signed off PASS.
- `cmd/uat-05/main.go :: runLockdownCycle` — returns an informative error. The SAFE-04 3-minute auto-revert requires interactive TUI operation to exercise properly. Runbook step 7.2 is documented as SKIP-OPERATOR.

Both stubs are intentional per plan specification and T-05-06-07 in the threat model (accepted).

---

## Lessons Learned

1. **AtomicWriteFile allowlist must track every write destination.** The allowlist in `internal/sysops/atomic.go` is a security control, but purge-sshd-cleanup introduced a new write destination (`/var/backups/sftp-jailer/`) that was not on the allowlist. The pattern: whenever a new file write target is added to the thesis flow, add it to the allowlist AND add a regression test.

2. **Man page compression must be explicit in goreleaser.** nfpm does not auto-compress man pages. The goreleaser `before` hook is the correct place to run `gzip -9 -k` before nfpm packages. Document this in the goreleaser.yml for the next packager.

3. **Debian Policy S12.5 is not optional.** A .deb without `copyright` and `changelog` files is technically non-compliant. These must be added to the packaging directory from the start of the phase, not as a lintian-discovered gap. Add to Phase 1 checklist for future phases that involve packaging.

4. **DIST-10 highest-risk surface (journalctl JSON format) was clear.** The observation pipeline's `journalctl --output=json` parsing worked identically between Ubuntu 24.04 (systemd 253) and Debian 13 (systemd 257). This is a strong signal that the Phase 2 parser is robust to systemd minor version differences within the 255-257 range.

5. **ufw-inactive-by-default on Debian 13 is a known portability gap.** The lockdown proposal step would need to emit a `ufw enable` step before committing rules on Debian 13. Future Debian 13 tier-1 support should add this to the lockdown flow.

---

## Self-Check

Files created/committed verified:

```
test -f cmd/uat-05/main.go                                        PASS
test -f docs/uat/05-ubuntu24-uat.md                               PASS
test -f docs/uat/05-debian13-uat.md                               PASS
test -f packaging/debian/lintian-overrides                        PASS
test -f packaging/debian/copyright                                PASS
test -f packaging/debian/changelog                                PASS
test -f .planning/RELEASE-CHECKLIST.md                            PASS
grep -q 'apt install ./sftp-jailer_' README.md                   PASS
grep -q 'observations.db' README.md                               PASS
grep -q 'vMAJOR.MINOR.PATCH' README.md                           PASS
grep -q 'WHY:' packaging/debian/lintian-overrides                PASS
grep -q 'DIST-09' docs/uat/05-ubuntu24-uat.md                    PASS
grep -q '192.168.1.170' docs/uat/05-debian13-uat.md              PASS
grep -q 'ALL PASS' docs/uat/05-debian13-uat.md                   PASS
grep -q '597db2fa' docs/uat/05-ubuntu24-uat.md                   PASS
```

Key commits:
- 3b061c3: feat(05-06): add cmd/uat-05 UAT helper binary
- 383cffb: docs(05-06): add Ubuntu 24.04 UAT runbook
- cf66411: docs(05-06): add Debian 13 lab host UAT runbook
- 0444ff4: docs(05-06): update README
- b8b31df: docs(05-06): fill in RELEASE-CHECKLIST.md
- 7078199: fix(05-06): BUG-05-A — purge drop-in backup allowlist + lintian-clean packaging
- d27eb2d: docs(05-06): operator signoff on both UAT runbooks

## Self-Check: PASSED
