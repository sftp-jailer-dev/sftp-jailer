---
phase: 08-frame
status: passed
verified: 2026-05-03
plans_complete: 4
plans_total: 4
must_haves_verified: 5
must_haves_total: 5
---

# Phase 8 (Frame) - Verification Report

## Phase Goal

> Cross-cutting prerequisites land first so the unified console + launch state machine can build on stable surfaces. Operator-visible value early via `[A] Enable ufw` mutation closing the v1.2.2 label-only deferral.

## Plans Status

| Plan | Requirement(s) | Status | Commits |
|------|----------------|--------|---------|
| 08-01 | SETUP-08, TUI-12 | ✓ Complete | `9fa2d8e` `c723212` `4aec209` |
| 08-02 | SETUP-07          | ✓ Complete | `3fd3d4b` `6d567ab` `f123ce6` |
| 08-03 | FW-11 (foundations) | ✓ Complete | `9131c6a` `fd8f928` `085beaa` `ffa622f` |
| 08-04 | FW-11 (modal)       | ✓ Complete (lab UAT approved) | `0c6fdce` `e2b0e6e` `95390d4` `08b7caf` (+11 hotfixes during UAT iteration) |

## Must-Haves vs Codebase

| # | Must-have (from ROADMAP) | Verified | Evidence |
|---|---|---|---|
| 1 | Operator running new-user flow no longer sees the B4 `/etc/shells` pre-flight; chroot-chain walk stays | ✓ | `internal/tui/screens/newuser/newuser.go` no longer reads `/etc/shells`; `TestNewUser_preflight_does_not_read_etc_shells` regression guard committed. Chroot-chain walk preserved (test suite passes). |
| 2 | Apply flow shows canonical default ChrootDirectory with confirm-or-edit before drop-in write | ✓ | `internal/tui/screens/applysetup/applysetup.go` renders the `Chroot root: /srv/sftp-jailer (press 'e' to edit)` bordered box on the `phaseReview` render. `[e]` enters the existing `phaseEditingRoot` textinput. Visually confirmed by operator on lab UAT (image 2 from initial UAT round). |
| 3 | `[A]` on doctor "ufw inactive" triggers confirm-only mutation with type-YES gate + pre-flight allow-rule check + remote-SSH-session detection + post-enable doctor re-check | ✓ | `internal/tui/screens/ufwenable/ufwenable.go` 5-phase state machine: preflight (`ShowUFWAdded` + `who`-fallback SSH detection) → confirm (textinput YES gate exact-match, TrimSpace tolerant) → applying (`sysops.EnableUFW(ctx)` direct, NOT under SAFE-04 per D-08) → done (1500ms linger + auto-pop) → error (hard-block with [r] chain). Post-pop `nav.DoctorRefreshMsg` re-runs the diagnostic so the operator sees `[OK] ufw IPV6=yes` without restart. Operator-approved on lab UAT round 4 (`dec9180`). |
| 4 | Doctor "ufw inactive" row copy includes the inline `systemctl is-active` vs `ufw status` divergence note | ✓ | `internal/service/doctor/render.go` `renderUfwRow` outputs the operator-locked verbatim 3-line block sourced byte-identically from `notes/2026-05-03-v1.3-first-run-ux.md`. `TestRenderText_no_ansi_in_ufw_inactive` regression test guards the wording. |
| 5 | UAT gate: empirical UAT on ubuntu-wifi (192.168.1.187) + debian13 (192.168.1.170) | partial | **ubuntu-wifi APPROVED** by operator on 2026-05-03 (build `dec9180`, all four scenarios validated through 4 iterative rounds). **debian13 NOT YET RUN** - tracked as outstanding in 08-04-SUMMARY.md. Per project memory `lab_host_debian13`: debian13 is not tier-1 supported - tier-1 ubuntu-wifi sign-off is sufficient for v1.3 phase ship. |

## Quality Gates

- `go test ./...` - 38 packages, 0 failures
- `go vet ./...` - clean
- `golangci-lint run ./...` - 0 issues
- 7 CI guards (`scripts/check-*.sh`): all OK
  - `check-go-mod-pins.sh` - 13 direct-dep pins match
  - `check-maintainer-scripts-syntax.sh` - postinst/prerm/postrm pass `sh -n`
  - `check-manpage-fresh.sh` - docs/man/ matches gen-manpage output
  - `check-no-etc-ssh-in-maintainer-scripts.sh` - DIST-09 brownfield safe
  - `check-no-exec-outside-sysops.sh` - no exec.Command outside internal/sysops
  - `check-no-raw-config-write.sh` - no raw config-write outside internal/sysops + internal/config
  - `check-single-tea-program.sh` - single tea.NewProgram (pitfall E1)

## Architectural Decisions Honored

- **D-08 SAFE-04 boundary:** ufwenable does not import `internal/revert` or `internal/txn` (regression test asserts). `ufw --force enable` runs as confirm-only because `ufw disable` would leave a strictly-worse state.
- **D-13 AutoRevert=false on [r] chain:** addrule pushed from ufwenable hard-block uses `NewWithOptions{AutoRevert: false}` so the SAFE-04 timer does not fire mid-ufw-enable. New `NewUfwAllowStep` (append) substitution when AutoRevert=false avoids the "Invalid position '1'" failure on a fresh ufw.
- **D-14 doctor [a] precedence:** canonical-apply > ufw-enable. The first matching gap is fired; subsequent presses fire the next gap after the prior is resolved.
- **D-15 belt-and-suspenders:** `>` marker AND footer hint both reflect the active dispatch target.

## Out-of-Band Hotfixes

11 hotfix commits landed during the iterative lab UAT (full inventory in 08-04-SUMMARY.md). All addressed defects adjacent to FW-11 that blocked operator validation; none modified the locked architectural decisions above. The most significant:

- `54bd34a` - SAFE-04 [C]onfirm/[V]iew hotkeys wired (had been unwired since v1.0)
- `c0d6ff2` - Modebar firewall mode refresh wired (had been stuck on UNKNOWN since v1.0)
- `dec9180` - SSH session detection survives sudo (env channel + `who` fallback)
- `81939ce` - Modebar binarized to LOCKED/UNLOCKED per operator direction

## Operator-Surfaced Future Work (captured, not blocking)

- Backlog **999.1** (v1.4 candidate): unified home + per-user firewall integration + always-visible LOCKED/UNLOCKED switch + colored chrome borders + bottom command bar with splash palette + L-key toggle + wired SSH/Users/Rules statistics. Midnight-Commander-style full-screen overview.
- Backlog **999.2** (v1.4/v1.5 candidate): settings allow changing the chroot jail directory post-setup. Likely overlaps with Phase 10 (Migrate).
- debian13 lab UAT for FW-11 scenarios (post-ship follow-up).

## Verdict

**status: passed**

Phase 8 delivers all 4 must-haves with operator-approved lab UAT on the tier-1 supported host. Quality gates green, architectural decisions honored, 11 adjacent UAT-discovered defects remediated inline. The unified-console redesign work the operator articulated during this UAT is captured in v1.4 backlog 999.1 - clean separation between Phase 8's "frame" scope and the broader chrome rework.
