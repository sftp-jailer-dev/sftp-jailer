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
    - Empirical UAT runbooks for Phase 5 acceptance gate
    - uat-05 helper binary (7-subcommand dispatch + JSON receipts)
    - README install/Recovery/Tagging documentation
    - RELEASE-CHECKLIST.md Build+Test + Distribution sections
  affects:
    - packaging/debian/lintian-overrides (empirical fill — post-operator-run)
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
  modified:
    - README.md
decisions:
  - "D-RW-02: cmd/uat-05 follows cmd/uat-04 shape (phase-array → subcommand dispatch)"
  - "D-LC-03: observations.db backup procedure documented in README Recovery section"
  - "D-RW-03: vMAJOR.MINOR.PATCH[-rcN] tagging convention documented in README"
  - "Receipt fields chosen: subcmd, started_at, finished_at, status, evidence map, error, host_info map"
  - "Receipt path: /var/log/sftp-jailer-uat-05/<subcmd>.json (outside /var/lib so apt purge preserves audit trail)"
metrics:
  completed_date: "2026-04-30"
  task_count: 7
  tasks_completed_pre_checkpoint: 5
  checkpoint_gate: "Task 6 (human-verify — operator runs UAT on real hosts)"
---

# Phase 05 Plan 06: Empirical UAT Runbook — Summary

**One-liner:** Phase 5 empirical UAT gate: uat-05 helper binary + Ubuntu 24.04 + Debian 13 runbooks with DIST-09 brownfield and DIST-10 portability acceptance criteria.

---

## What Was Done

### Tasks 1–5 (completed pre-checkpoint)

- **Task 1 — cmd/uat-05/main.go (463 lines):** 7-subcommand dispatch UAT helper binary built per D-RW-02. Subcommands: install, doctor, apply-sshd, user-crud, observe-fire, lockdown-cycle, brownfield-purge. Root gate via `os.Geteuid()`. All process invocations via `ops.Exec()` (sysops typed wrappers — no raw os/exec import). JSON receipts written to `/var/log/sftp-jailer-uat-05/<subcmd>.json` on every invocation (defer-pattern, even on FAIL). DIST-09 gate in `runBrownfieldPurge`: sha256sum capture mode (empty `UAT_BASELINE_SHA256`) + assertion mode (non-empty). Stub subcommands (`user-crud`, `lockdown-cycle`) return informative errors citing the runbook section — not empty stubs.

- **Task 2 — docs/uat/05-ubuntu24-uat.md (489 lines):** Full manual runbook for Ubuntu 24.04 VM acceptance gate. Variant A (clean install, criteria 1/3/4): 8 steps with A.0 pre-flight through Step 8 apt purge teardown. Variant B (brownfield, criterion 6 DIST-09): UAT-MARKER pre-edit, sha256sum baseline capture, apt install + optional TUI drop-in apply, apt purge, post-purge hash comparison, uat-05 brownfield-purge assertion, UAT-MARKER grep confirmation. Lintian-overrides empirical fill section (L.1–L.3) with `# WHY:` format requirement. Operator sign-off block.

- **Task 3 — docs/uat/05-debian13-uat.md (402 lines):** Manual runbook for Debian 13 lab host at 192.168.1.170. Same 8-step thesis flow as Ubuntu Variant A, adapted with Debian-13-specific delta callouts per step: AppArmor detector differences (D.3.1), OpenSSH directive compatibility (D.4.1 — sshd -t; block-severity if fails), journalctl JSON field names (D.6.1 — highest-risk portability surface; block-severity if parser fails), ufw backend differences (D.7.2 — nftables vs iptables-legacy). Portability deltas table with 2 pre-populated empty rows. Tier-1 disclaimer prominently in preamble. Two sign-off outcomes: ALL PASS / THESIS FLOW BLOCKED.

- **Task 4 — README.md updates:** Install section replaced `go install` with `apt install ./sftp-jailer_*.deb` + SHA256SUMS verification. Recovery section added (observations.db backup/restore before/after apt purge). Releases & Tagging section added (`vMAJOR.MINOR.PATCH[-rcN]` patterns, Debian version ordering rationale, `git tag + push --tags` workflow).

- **Task 5 — .planning/RELEASE-CHECKLIST.md:** Build+Test section added (go test -race, golangci-lint, govulncheck, 5 invariant scripts, v1 Bubble Tea guard, goreleaser snapshot, lintian --pedantic). Empirical UAT runbook references (Variant A/B + Debian 13). Distribution section added (tag+push, automated pipeline steps, post-release verification, roll-back procedure). Sign-off checkpoint table. Preserves existing curl-ifconfig.me external dependency entry.

### Task 6 — CHECKPOINT (awaiting operator)

The operator must run both UAT runbooks against real hosts:
1. Ubuntu 24.04 VM — Variant A (criteria 1/3/4) + Variant B (DIST-09 brownfield)
2. Debian 13 lab host at 192.168.1.170 (DIST-10 portability)

This task is a `checkpoint:human-verify`. The plan cannot be marked complete until the operator provides their sign-off. See checkpoint details below.

### Task 7 — SUMMARY (this document — pre-checkpoint state)

This SUMMARY documents the pre-checkpoint state. After the operator returns with their UAT outcome, the continuation agent will append:
- Actual UAT results (PASS/FAIL per step)
- Lintian-overrides empirical entries added (N entries with `# WHY:` rationale)
- Portability deltas filed for Debian 13 (block / finding)
- Phase completion gate confirmation (all 7 DIST requirements)

---

## Decisions Implemented

| Decision | Source | Implementation |
|----------|--------|----------------|
| D-RW-02 | 05-CONTEXT.md L217-237 | cmd/uat-05 uses subcommand dispatch (NOT phase-array like uat-04) |
| D-LC-03 | 05-CONTEXT.md | observations.db backup documented in README Recovery section |
| D-RW-03 | 05-CONTEXT.md | vMAJOR.MINOR.PATCH[-rcN] tagging convention in README Releases section |
| Claude's Discretion (receipt fields) | 05-CONTEXT.md L285-289 | subcmd, started_at, finished_at, status, evidence map, error, host_info |
| Claude's Discretion (receipt path) | 05-CONTEXT.md L285-289 | /var/log/sftp-jailer-uat-05/<subcmd>.json (outside /var/lib) |

---

## Deviations from Plan

None for Tasks 1–5. Plan executed exactly as written.

The one note: Task 5's `.planning/RELEASE-CHECKLIST.md` required `git add -f` because `.planning/` is in the worktree's `.gitignore`. This is expected for planning artifact files — the force-add is correct since the file needs to be committed per the plan's `files_modified` list.

---

## Known Stubs

**By design:**
- `cmd/uat-05/main.go :: runUserCrud` — returns an informative error directing the operator to the runbook. Cannot be automated without a headless Bubble Tea harness.
- `cmd/uat-05/main.go :: runLockdownCycle` — returns an informative error. The SAFE-04 3-minute auto-revert requires interactive TUI operation to exercise properly.

Both stubs are intentional per the plan's "STUB returning informative error" specification and T-05-06-07 in the threat model (accepted).

---

## Pre-checkpoint Verification

All automated acceptance criteria passing:

```
test -f cmd/uat-05/main.go                        PASS
CGO_ENABLED=0 go build ./cmd/uat-05              PASS
bash scripts/check-no-exec-outside-sysops.sh      PASS
grep -q 'sysops.NewReal' cmd/uat-05/main.go       PASS
grep -q 'sha256.Sum256' cmd/uat-05/main.go        PASS
grep -q 'UAT_BASELINE_SHA256' cmd/uat-05/main.go  PASS
test -f docs/uat/05-ubuntu24-uat.md (489 lines)   PASS
test -f docs/uat/05-debian13-uat.md (402 lines)   PASS
grep -q 'DIST-09' docs/uat/05-ubuntu24-uat.md     PASS
grep -q '192.168.1.170' docs/uat/05-debian13-uat.md PASS
grep -q 'apt install ./sftp-jailer_' README.md    PASS
grep -q 'observations.db' README.md               PASS
grep -q 'vMAJOR.MINOR.PATCH' README.md            PASS
grep -q 'git push --tags' README.md               PASS
grep -q 'lintian --pedantic' .planning/RELEASE-CHECKLIST.md PASS
grep -q 'goreleaser release' .planning/RELEASE-CHECKLIST.md PASS
grep -q 'docs/uat/05-debian13-uat' .planning/RELEASE-CHECKLIST.md PASS
```

## Self-Check: PARTIAL

Pre-checkpoint commits verified:
- 3b061c3: feat(05-06): add cmd/uat-05 UAT helper binary
- 383cffb: docs(05-06): add Ubuntu 24.04 UAT runbook
- cf66411: docs(05-06): add Debian 13 lab host UAT runbook
- 0444ff4: docs(05-06): update README
- b8b31df: docs(05-06): fill in RELEASE-CHECKLIST.md

Status: CHECKPOINT REACHED — Tasks 1–5 complete; Task 6 awaiting operator UAT execution; Task 7 (final SUMMARY) deferred until post-checkpoint.
