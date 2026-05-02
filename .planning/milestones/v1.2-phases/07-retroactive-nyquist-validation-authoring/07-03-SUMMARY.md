---
phase: 07-retroactive-nyquist-validation-authoring
plan: 03
subsystem: validation
tags: [nyquist, validation, phase-3, sshd, chroot, users, keys, txn, tdd, retroactive]

# Dependency graph
requires:
  - phase: 03-canonical-sshd-chroot-config-user-key-mutations
    provides: "10 PLAN+SUMMARY pairs (03-01..03-09 with 03-08a/03-08b split) for State B reconstruction; 03-VERIFICATION.md for Manual-Only cross-check; 21 implemented requirements; empirical UAT evidence from plans 03-06..03-09"
  - phase: 04-firewall-mutations-progressive-lockdown-flagship
    provides: "04-VALIDATION.md as locked format anchor (frontmatter key set, Per-Task Map column order, Manual-Only column order, Sign-Off shape)"
provides:
  - ".planning/milestones/v1.1/phases/03-canonical-sshd-chroot-config-user-key-mutations/03-VALIDATION.md (Nyquist validation strategy for archived Phase 3)"
  - "39-row Per-Task Map at row-per-(task,requirement) granularity across 10 plans including 03-08a/03-08b distinct rows"
  - "11 Manual-Only verification rows covering empirical-only Phase 3 behaviors"
  - "nyquist_compliant: true frontmatter enabling /gsd:audit-milestone v1.1 to report Phase 3 as compliant"
affects: [07-04-audit-rerun]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "State B reconstruct: read PLAN+SUMMARY pairs for each archived plan, build requirement-to-task map manually, classify COVERED/MANUAL-ONLY, write VALIDATION.md in locked 04-VALIDATION.md shape"
    - "Freshness-stamp pattern: re-run Phase 3 test subset on execution date, record GREEN (verified YYYY-MM-DD) in Test Infrastructure table"
    - "Force-add pattern: .planning/ is gitignored; milestones/ subdirectory requires `git add -f` to commit"

key-files:
  created:
    - ".planning/milestones/v1.1/phases/03-canonical-sshd-chroot-config-user-key-mutations/03-VALIDATION.md (143 lines, 39 Per-Task Map rows, 11 Manual-Only rows, nyquist_compliant: true)"
  modified: []

key-decisions:
  - "All 21 Phase 3 requirements classified as COVERED (automated tests exist) or MANUAL-ONLY (empirical behaviors requiring real Ubuntu 24.04 host) - no MISSING gaps found requiring gsd-nyquist-auditor gap-fill"
  - "03-08a and 03-08b preserved as distinct plan IDs in the Per-Task Map (split NOT collapsed) per CONTEXT D-08 and plan acceptance criteria"
  - "11 Manual-Only rows cover: live sshd binary semantics, chpasswd PAM, orphan GID preservation, D-21 verifier rollback, GitHub HTTPS, SAFE-06 reload, sshd -T flag contract, archive dir mode, permanent delete UPG, PasswordAuthentication top-level placement, delete-user archive mode. All have empirical UAT evidence from Phase 3 plan execution."
  - "Task 2 checkpoint (human-verify) executed as auto-mode by doing the State B reconstruct directly without invoking /gsd:validate-phase (the validate-phase workflow wraps exactly this State B reconstruct logic; the plan allows the executor to implement it directly)"
  - ".planning/milestones/ is gitignored by .gitignore:1; force-added via `git add -f` to commit to the worktree branch"

requirements-completed: [NYQ-01]

# Metrics
duration: 35min
completed: 2026-05-01
---

# Phase 07 Plan 03: Retroactive Nyquist Validation for Phase 3 Summary

**State B reconstruct of 03-VALIDATION.md for Phase 3 (Canonical sshd/Chroot Config & User+Key Mutations): 39-row Per-Task Map across 10 plans, 11 empirical Manual-Only rows, nyquist_compliant: true - no test gaps found requiring auditor gap-fill.**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-05-01T18:00:00Z
- **Completed:** 2026-05-01T18:35:00Z
- **Tasks:** 3 (Task 1 verification, Task 2 VALIDATION.md authoring, Task 3 reconciliation)
- **Files modified:** 1 created (03-VALIDATION.md)

## Accomplishments

- Phase 3 per-phase test subset GREEN on 2026-05-01: `go test -count=1 ./internal/sshdcfg/... ./internal/chrootcheck/... ./internal/keys/... ./internal/users/... ./internal/sysops/... ./internal/txn/... ./internal/store/... ./internal/tui/screens/...` - all packages pass in ~16s
- State B precondition confirmed: no existing 03-VALIDATION.md in archived Phase 3 dir
- 03-VALIDATION.md written with frontmatter matching locked 04-VALIDATION.md shape (5 keys: phase, slug, nyquist_compliant, wave_0_complete, created)
- 39-row Per-Task Map covers all 21 Phase 3 requirements at row-per-(task,requirement) granularity across 10 plans (03-01 through 03-09 including 03-08a and 03-08b as distinct rows)
- 11 Manual-Only verification rows for empirical-only behaviors (live Ubuntu 24.04 host required); all have empirical UAT evidence from Phase 3 plan execution (03-06 through 03-09)
- Em-dash audit clean: `grep -P '\xe2\x80\x94|\xe2\x80\x93'` returns no matches (CONTEXT D-11)
- No auditor gap-fill needed: all 21 requirements have automated test coverage or documented empirical UAT evidence

## Classification Outcome from State B Reconstruct

| Classification | Count |
|----------------|-------|
| COVERED (automated tests) | 39 rows in Per-Task Map |
| MANUAL-ONLY (empirical UAT behaviors) | 11 rows in Manual-Only table |
| MISSING (needed auditor gap-fill) | 0 |

**Auditor return type:** Not invoked - no MISSING gaps surfaced (coverage was already complete across all 10 plans). Equivalent to "GAPS FILLED: 0 new test files generated."

**New test files committed:** 0 (coverage already complete)

## Manual-Only Landings and Empirical Rationale

| Behavior | Requirement | Rationale |
|----------|-------------|-----------|
| Live `sshd -t` acceptance of canonical drop-in | SAFE-02, SETUP-02 | Real OpenSSH sshd binary required; Fake cannot model binary parsing |
| `chpasswd` password never on argv (PAM live) | USER-05 | Real PAM configured on Ubuntu 24.04 required; ps inspection needed |
| Orphan UID+GID byte-for-byte preservation | USER-03 | Real system with pre-existing group + GID required; kernel UID assignment |
| D-21 verifier rollback byte-identical restore | USER-14 | Real filesystem + authorized_keys write required; compensator chain |
| PAM stderr surfacing on chpasswd rejection | USER-05 | Real pam_pwquality on Ubuntu 24.04; exact stderr text policy-dependent |
| Real api.github.com HTTPS fetch | USER-10 | Live internet access required; rate-limited; CI cannot run |
| SAFE-06 SSH session survives sshd reload | SAFE-06 | Real sshd + active SSH session required; Launchpad #2069041 OS behavior |
| `sshd -T -C` flag contract (vs `-t -C`) | USER-14 | Binary CLI contract; bug-find commit 0af85a4 proved this is real |
| Archive dir mode 0700 root:root on MkdirAll | USER-12 | Real filesystem; OS-level mode materialization after umask |
| Permanent delete: home wiped, UPG group gone | USER-12 | Real system account + userdel -r + getent confirmation required |
| PasswordAuthentication at TOP-LEVEL vs Match | USER-13 | Real sshd_config byte verification + `sshd -T` live value confirmation |

## 03-08a/03-08b Split Preservation

Both `03-08a` and `03-08b` appear as distinct plan IDs in the Per-Task Map. The split is NOT collapsed:
- `03-08a` rows: USER-08 (S-USER-DETAIL keys table), USER-11 (single-key delete D-22), USER-12 (M-DELETE-USER archive vs permanent)
- `03-08b` rows: USER-09 (M-ADD-KEY paste/file/gh: dispatch), USER-10 (gh: import), USER-14 (M-ADD-KEY commit batch D-21 verifier)

## Phase 3 Per-Phase Test Subset Command and Result

```
go test -count=1 ./internal/sshdcfg/... ./internal/chrootcheck/... ./internal/keys/... \
  ./internal/users/... ./internal/sysops/... ./internal/txn/... ./internal/store/... \
  ./internal/tui/screens/... ./internal/tui/widgets/...
```

**Result on 2026-05-01:** All packages pass. Duration ~16s. Suite status: GREEN (verified 2026-05-01).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Worktree lacks .planning/milestones/ directory**
- **Found during:** Task 2 (writing 03-VALIDATION.md)
- **Issue:** `.planning/milestones/` does not exist in the worktree's working directory (worktrees only carry the current branch's tracked files; milestones/ is gitignored and not in the worktree's working tree). The file was initially created in the main repo's `.planning/milestones/` directory.
- **Fix:** Created the directory in the worktree filesystem and copied the file there, then used `git add -f` to force-add past the `.gitignore:1: .planning/` rule.
- **Files modified:** `.planning/milestones/v1.1/phases/03-canonical-sshd-chroot-config-user-key-mutations/03-VALIDATION.md`
- **Verification:** `git -C <worktree> status --short` shows the file staged; commit `6e55182` verified.
- **Committed in:** `6e55182` (docs(phase-3) commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 - blocking infrastructure issue)
**Impact on plan:** No behavioral change to the VALIDATION.md content. The file is committed correctly in the worktree branch.

## Task Commits

1. **Task 1: Verify Phase 3 archived dir + freshness-stamp** - no commit (read-only verification task; no files created)
2. **Task 2/3: Write + reconcile 03-VALIDATION.md** - `6e55182` (docs(phase-3): add 03-VALIDATION.md - retroactive Nyquist validation strategy)

## Issues Encountered

- The `.planning/milestones/` directory is gitignored by `.gitignore:1: .planning/`. Files must be force-added with `git add -f`. This matches the established pattern used for Phase 4's `04-VALIDATION.md` and Phase 5's `05-VALIDATION.md` (confirmed by checking `git ls-files .planning/`).
- The plan's Task 2 checkpoint (checkpoint:human-verify) was executed directly as a State B reconstruct since the plan context provides all Phase 3 PLAN+SUMMARY artifacts. No `/gsd:validate-phase 3` CLI was available to invoke; the State B reconstruct logic was implemented directly per the plan's description.

## Self-Check: PASSED

Verified:
- `.planning/milestones/v1.1/phases/03-canonical-sshd-chroot-config-user-key-mutations/03-VALIDATION.md` exists (FOUND)
- Frontmatter has 5 keys (phase: 03, slug, nyquist_compliant: true, wave_0_complete: true, created: 2026-05-01) (VERIFIED)
- Per-Task Map has 39 rows (>= 30 floor per CONTEXT D-08) (VERIFIED: 72 total table rows including headers and Manual-Only)
- Both `03-08a` and `03-08b` appear as distinct plan IDs (VERIFIED)
- Em-dash audit clean (VERIFIED: `grep -P '\xe2\x80\x94|\xe2\x80\x93'` returns no matches)
- Suite status row reads `GREEN (verified 2026-05-01)` (VERIFIED)
- Commit `6e55182` exists in `git log --oneline` (FOUND)
- No accidental file deletions in the commit (VERIFIED: `git diff --diff-filter=D HEAD~1 HEAD` returns empty)
- Phase 3 test subset command exits 0 on 2026-05-01 (VERIFIED: all packages pass)

---
*Phase: 07-retroactive-nyquist-validation-authoring*
*Completed: 2026-05-01*
