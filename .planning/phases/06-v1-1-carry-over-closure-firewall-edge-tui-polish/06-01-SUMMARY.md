---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
plan: "01"
subsystem: firewall-fw09
tags:
  - firewall
  - ufw
  - ipv6
  - tests
  - uat
  - bug-04-b
  - fw-09
requirements: [FW-09]
status: verified-code, UAT-pending
ship_status: verified-code, UAT-pending
dependency_graph:
  requires:
    - "Phase 4 plan 04-12 (NewUfwDeleteCatchAllByEnumerateStep + dual-family fixture)"
    - "Phase 4 plan 04-03 (firewall.AddRule, ufwcomment.Encode/Decode grammar)"
    - "Phase 5 plan 05-06 (docs/uat/05-ubuntu24-uat.md template structure mirrored here)"
  provides:
    - "internal/firewall/testdata/ufw-status-numbered-v6-only.txt - v6-only host enumerate fixture"
    - "internal/firewall/testdata/ufw-status-numbered-v6-source.txt - post-insert v6-source fixture"
    - "internal/txn/steps_test.go::TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6 - v6-only edge regression net"
    - "internal/firewall/mutate_test.go::TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment - v6 AddRule round-trip"
    - "internal/firewall/enumerate_test.go::TestEnumerate_v6_source_rule_decodes_user_round_trip - protocol-agnostic Decode round-trip"
    - "docs/uat/06-fw09-uat.md - dual-family + v6-only operator runbook (12 numbered steps)"
  affects:
    - "06-VERIFICATION.md (FW-09 row will record `verified-code, UAT-pending` ship status when authored)"
    - "ROADMAP Phase 6 SC1 (FW-09 BUG-04-B closure: code + tests + runbook = ship; empirical UAT deferred to v1.2.x)"
tech_stack:
  added: []
  patterns:
    - "Stateful ExecResponseQueue FIFO for multi-call Enumerate paths (mirrors plan 04-12 dual-family pattern)"
    - "Independent-assertion test design (Source / Proto / User / ParseErr) for asymmetric failure-mode pinning per Pitfall 3"
    - "Shared testdata fixture between mutate_test.go (AddRule) and enumerate_test.go (Decode round-trip) to keep stdout shape contract single-sourced"
    - "UAT runbook structural mirror: operator sign-off header + numbered Variant steps + evidence capture + sign-off (mirrors docs/uat/05-ubuntu24-uat.md)"
key_files:
  created:
    - "internal/firewall/testdata/ufw-status-numbered-v6-only.txt (6 lines - v6-only host fixture)"
    - "internal/firewall/testdata/ufw-status-numbered-v6-source.txt (5 lines - post-insert v6-source fixture)"
    - "docs/uat/06-fw09-uat.md (291 lines - 12-step UAT runbook, two Variants)"
    - ".planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-01-SUMMARY.md (this file)"
  modified:
    - "internal/txn/steps_test.go (+44 lines: 2 fixture helpers + TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6)"
    - "internal/firewall/mutate_test.go (+38 lines incl. os import: TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment)"
    - "internal/firewall/enumerate_test.go (+27 lines: TestEnumerate_v6_source_rule_decodes_user_round_trip)"
decisions:
  - "D-14 honored: production code in NewUfwDeleteCatchAllByEnumerateStep / Enumerate / stripV6Suffix / ufwcomment was already protocol-agnostic. Plan 06-01 is regression-net only - zero production code lines changed."
  - "D-15 honored: 3 tests + 2 fixtures + 1 UAT runbook delivered as scoped."
  - "D-16 honored: ship status `verified-code, UAT-pending` recorded ONLY here and in this runbook (06-VERIFICATION.md frontmatter to follow when that doc is authored). NOT in ROADMAP, NOT in changelog."
  - "D-17 honored: NO m1.linuxbe.com or any specific hostname appears in docs/uat/06-fw09-uat.md. Generic placeholders only (`<vm-ip>`, `192.168.x.y`)."
  - "D-22 honored: 4 atomic commits on the worktree branch (`test(06-01)` x2, `docs(06-01)` x2 once SUMMARY commit lands)."
  - "Independent assertions on Source / Proto / User / ParseErr in TestEnumerate_v6_source_rule_decodes_user_round_trip - asymmetric failure-mode pinning per Pitfall 3."
  - "Existing scriptUfw helper used in mutate_test.go (sets ExecResponses, not ExecResponseQueue) - AddRule only Enumerates once post-insert so a single scripted response suffices."
metrics:
  duration: "~5 minutes"
  completed: "2026-05-01"
  tasks_completed: 3
  files_created: 4
  files_modified: 3
  commits: 4
---

# Phase 6 Plan 01: FW-09 BUG-04-B v6-only / dual-family regression-net + UAT runbook Summary

Closed BUG-04-B carry-over from v1.1 by authoring the empirical-grade regression-net (3 tests + 2 fixtures) plus the FW-09 UAT runbook for dual-family and v6-only hosts. Production code in NewUfwDeleteCatchAllByEnumerateStep, firewall.Enumerate (v6 detection at lines 135-140), stripV6Suffix (lines 199-202), and the ufwcomment grammar was already protocol-agnostic (D-14): this plan does NOT rewrite that code. It builds the regression-net that proves the existing code is correct under the v6-only and v6-source conditions, and authors the runbook for the empirical UAT half. Per D-16 the FW-09 release gate is code-complete + teatest + UAT runbook authored = ship v1.2.0 with status `verified-code, UAT-pending`; empirical UAT execution becomes a v1.2.x checkbox flip when an IPv6 VM is available.

---

## What shipped

### Tests (3 new, all green on first run per D-14)

1. **`TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6`** in `internal/txn/steps_test.go`
   - Models a v6-only Ubuntu 24.04 host (one v6 catch-all + one sftpj rule, no v4 default).
   - Uses ExecResponseQueue FIFO: first call returns the v6-only initial state; second call returns the post-delete state with sftpj renumbered to id=1.
   - Asserts: count of UfwDelete calls == 1; the deleted id is the v6 catch-all (id=1) from the first enumerate.
   - Pins BUG-04-B: if the predicate ever drifts to v4-only, this test fails because zero deletes occur on a v6-only host.

2. **`TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment`** in `internal/firewall/mutate_test.go`
   - Calls `AddRule(ctx, fake, "alice", "2001:db8::/32", "22")` with the v6-source fixture pre-scripted as the post-insert Enumerate stdout.
   - Asserts: returned id == 1; UfwInsert recorded with `pos=1`, `src=2001:db8::/32` (verbatim, no v4-mangling), and `comment=sftpj:v=1:user=alice` (protocol-agnostic comment grammar).
   - Pins Pitfall 3: comment grammar verified end-to-end on the v6-source path; ufw 0.36.2 auto-routes the family from the source CIDR.

3. **`TestEnumerate_v6_source_rule_decodes_user_round_trip`** in `internal/firewall/enumerate_test.go`
   - Loads the v6-source fixture and runs `Enumerate(ctx, fake)`.
   - Asserts independently: `r.Source == "2001:db8::/32"`, `r.Proto == "v6"`, `r.User == "alice"`, `r.ParseErr == nil`.
   - Independent assertions break asymmetrically: comment grammar drift affects only User; v6 detection drift affects only Proto; over-aggressive stripV6Suffix affects only Source.

### Testdata fixtures (2 new)

- **`internal/firewall/testdata/ufw-status-numbered-v6-only.txt`** - 6-line ufw status for a v6-only host (one v6 catch-all + one sftpj v6 rule).
- **`internal/firewall/testdata/ufw-status-numbered-v6-source.txt`** - 5-line ufw status for a single-rule post-insert state with an IPv6 source CIDR (`2001:db8::/32` + `sftpj:v=1:user=alice`).

### UAT runbook

- **`docs/uat/06-fw09-uat.md`** - 291 lines, 12 numbered steps total:
  - **Variant A** (dual-family host): A.0-A.6 = 7 steps covering the BUG-04-C regression guard (both v4 and v6 catch-alls deleted in one S-LOCKDOWN pass).
  - **Variant B** (v6-only host): B.0-B.4 = 5 steps covering BUG-04-B closure (single v6 catch-all delete terminates cleanly).
  - Operator sign-off header table, evidence capture section with empty code blocks for paste-in, final sign-off table with PASS/FAIL/PASS-WITH-NOTES tickboxes.
  - Generic placeholders only per D-17; no m1.linuxbe.com or any host-specific identifier.

---

## Files modified

- `internal/firewall/testdata/ufw-status-numbered-v6-only.txt` (created)
- `internal/firewall/testdata/ufw-status-numbered-v6-source.txt` (created)
- `internal/txn/steps_test.go` (+44 lines: 2 fixture helpers + 1 test)
- `internal/firewall/mutate_test.go` (+38 lines incl. `os` import; +1 test)
- `internal/firewall/enumerate_test.go` (+27 lines: +1 test)
- `docs/uat/06-fw09-uat.md` (created, 291 lines)
- `.planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-01-SUMMARY.md` (this file, created)

---

## Commits (atomic, on `worktree-agent-a080e64a8472ec280`)

| # | Hash    | Type | Message |
|---|---------|------|---------|
| 1 | 4941378 | test | RED - v6-only host catch-all delete fixture + assertion |
| 2 | 6e4735d | test | RED - v6-source AddRule and Enumerate round-trip tests |
| 3 | 8041129 | docs | FW-09 UAT runbook for dual-family + v6-only hosts |
| 4 | (this)  | docs | plan 06-01 SUMMARY (FW-09 verified-code, UAT-pending) |

---

## Verification

```
go test ./internal/firewall/... ./internal/txn/... -count=1
ok  	github.com/sftp-jailer-dev/sftp-jailer/internal/firewall	0.401s
ok  	github.com/sftp-jailer-dev/sftp-jailer/internal/txn	0.676s

bash scripts/check-no-exec-outside-sysops.sh
OK: no exec.Command outside internal/sysops

# Em-dash absent across all new files (D-20)
! grep -P '[\x{2014}\x{2013}]' internal/firewall/testdata/ufw-status-numbered-v6-only.txt \
                                 internal/firewall/testdata/ufw-status-numbered-v6-source.txt \
                                 internal/txn/steps_test.go \
                                 internal/firewall/mutate_test.go \
                                 internal/firewall/enumerate_test.go \
                                 docs/uat/06-fw09-uat.md
PASS

# UAT runbook structural compliance
grep -cE '^- \[ \] \*\*[A-Z]\.[0-9]+\*\*' docs/uat/06-fw09-uat.md
12   # >= 10 numbered steps required
```

**Pre-existing dual-family regression test still passes (no regression):**

```
go test ./internal/txn/ -run TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6 -count=1
PASS
```

**Ship status: `verified-code, UAT-pending`** per D-16. Recorded only in this SUMMARY frontmatter and in docs/uat/06-fw09-uat.md preamble. NOT in ROADMAP. NOT in changelog. v1.2.0 ships with this regression-net + runbook; empirical execution moves the status to `verified` in a future v1.2.x checkbox flip.

---

## Open items

- **Empirical UAT execution deferred:** docs/uat/06-fw09-uat.md needs to be run against a real Ubuntu 24.04 + IPv6 VM (Variant A) and a real v6-only VM (Variant B) when one is available. This is intentionally out of scope for v1.2.0 per D-16; it becomes a v1.2.x patch-release evidence capture.
- **06-VERIFICATION.md not yet authored:** when the verification doc for Phase 6 lands, FW-09 should appear in its traceability table with status `verified-code, UAT-pending` and a link to docs/uat/06-fw09-uat.md.

---

## Self-Check: PASSED

Verified files exist:
- internal/firewall/testdata/ufw-status-numbered-v6-only.txt FOUND
- internal/firewall/testdata/ufw-status-numbered-v6-source.txt FOUND
- docs/uat/06-fw09-uat.md FOUND
- internal/txn/steps_test.go FOUND (helpers + test added)
- internal/firewall/mutate_test.go FOUND (test added)
- internal/firewall/enumerate_test.go FOUND (test added)

Verified commits exist on worktree branch:
- 4941378 test(06-01): RED - v6-only host catch-all delete fixture + assertion
- 6e4735d test(06-01): RED - v6-source AddRule and Enumerate round-trip tests
- 8041129 docs(06-01): FW-09 UAT runbook for dual-family + v6-only hosts

All success criteria met:
- [x] 3 new tests committed and passing
- [x] 2 new testdata fixtures committed
- [x] docs/uat/06-fw09-uat.md authored with 12 numbered steps, two Variants, operator sign-off, no host-specific identifiers, no em-dash
- [x] 06-01-SUMMARY.md authored documenting `verified-code, UAT-pending` ship status per D-16
- [x] Full firewall + txn test suite green; no regression in pre-existing dual-family test
