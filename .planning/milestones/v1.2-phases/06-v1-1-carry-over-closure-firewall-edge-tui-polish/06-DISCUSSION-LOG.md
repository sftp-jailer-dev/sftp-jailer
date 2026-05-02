# Phase 6: v1.1 Carry-over Closure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in 06-CONTEXT.md - this log preserves the alternatives considered.

**Date:** 2026-05-01
**Phase:** 06-v1-1-carry-over-closure-firewall-edge-tui-polish
**Mode:** discuss (interactive)
**Areas discussed:** TUI-10 modal placement, TUI-11 cancellation UX, FW-09 release gate, Per-user log window

---

## Pre-locked Constraints (entered with discussion)

- Phase 7 (NYQ-01) deferred to v1.2.1; milestone closes after Phase 6.
- No IPv6 VM available for FW-09 empirical UAT; do NOT test on `m1.linuxbe.com`.
- FW-09 ships code-complete + teatest + UAT runbook; empirical UAT operator-pending.
- 4 reqs are independent per ROADMAP; plans should be parallelizable.
- Em-dash forbidden everywhere (memory rule).
- All shell-outs through `internal/sysops`; SAFE-04 revert window pattern preserved.
- Atomic commits per plan; teatest/v2 for TUI flows.

---

## Gray Area Selection

**Question:** Phase 6 has 4 gray areas worth your input. Which to discuss?

| Option | Description | Selected |
|--------|-------------|----------|
| TUI-10 modal placement | Where does the per-user log-detail modal live? Existing S-USERS 'd' already opens S-USER-DETAIL (SSH keys). | ✓ |
| TUI-11 cancellation UX | What does the modal show during the 2s SIGTERM->SIGKILL grace? | ✓ |
| FW-09 release gate | How does FW-09 affect v1.2.0 without an IPv6 VM? | ✓ |
| Per-user log window | TUI-10 'last 90 days' - fixed, reuse, or new knob? | ✓ |

**User's choice:** All four selected for discussion.

---

## TUI-10 modal placement

**Question:** Where does the new per-user log-detail modal live in the navigation?

| Option | Description | Selected |
|--------|-------------|----------|
| New 'L' keybind on S-USERS (Recommended) | Uppercase 'L' on S-USERS opens M-USER-LOG directly. S-USER-DETAIL keeps SSH-keys focus. Cleanest separation, follows the W1 'D' uppercase precedent from Plan 04-06. | ✓ |
| Replace S-USER-DETAIL | Refocus S-USER-DETAIL onto logs; move SSH keys to a new screen. Breaks Phase 3 muscle memory. | |
| Tab inside S-USER-DETAIL | Two togglable views (SSH keys + logs) on the same screen. Adds tab/section state. | |

**User's choice:** New 'L' keybind on S-USERS (Recommended).
**Notes:** Recorded as D-01 in CONTEXT.md.

---

## TUI-11 cancellation UX

**Question:** What does the modal show during the 2s SIGTERM->SIGKILL grace window after Esc?

| Option | Description | Selected |
|--------|-------------|----------|
| 'Cancelling...' spinner, modal stays open (Recommended) | Modal shows 'Cancelling...' indicator; closes only when subprocess exits or SIGKILL fallback fires. Matches sftp-jailer's safety-first ethos. | ✓ |
| Immediate close, background cleanup | Esc closes modal instantly; subprocess termination happens silently. Risks 'phantom in-flight' state. | |
| Countdown timer 'Cancelling (Xs)' | Show countdown with locked input. Most explicit but feels twitchy for 2s. | |

**User's choice:** 'Cancelling...' spinner, modal stays open (Recommended).
**Notes:** Recorded as D-06, D-07 in CONTEXT.md.

---

## FW-09 release gate

**Question:** How does FW-09 affect the v1.2.0 release without an IPv6 VM available?

| Option | Description | Selected |
|--------|-------------|----------|
| Ship v1.2.0 with FW-09 code-complete + UAT-pending (Recommended) | Land code + teatest + UAT runbook. UAT becomes a v1.2.x checkbox flip when IPv6 VM available. | ✓ |
| Drop FW-09 from v1.2 milestone | Defer to v1.2.1 alongside NYQ-01. Slips the BUG-04-B carry-over. | |
| Wait for IPv6 VM, tag v1.2.0-rc2 in between | Most rigorous, adds RC dance and external dependency. | |

**User's choice:** Ship v1.2.0 with FW-09 code-complete + UAT-pending (Recommended).
**Notes:** Recorded as D-16, D-17 in CONTEXT.md.

---

## Per-user log window

**Question:** Where does the per-user log time window come from for the TUI-10 modal?

| Option | Description | Selected |
|--------|-------------|----------|
| Reuse config.LockdownProposalWindowDays (Recommended) | Already configurable, default 90, range [1, 3650], persisted in config.yaml. Avoids config-knob proliferation. | ✓ |
| Fixed 90 days, no config knob | Hardcoded const. Simplest; admins can't tune. | |
| New dedicated config knob LogDetailWindowDays | Most flexibility but adds a config surface admins rarely touch. | |

**User's choice:** Reuse config.LockdownProposalWindowDays (Recommended).
**Notes:** Recorded as D-04 in CONTEXT.md. The same window admins already chose for lockdown proposal generation is the natural same window for log review.

---

## TUI-10 row structure (follow-up)

**Question:** How does the per-user log modal display the last 20 raw entries?

| Option | Description | Selected |
|--------|-------------|----------|
| Match S-LOGS 5-column wide-mode (Recommended) | ts (UTC) | source IP | event type | tier | raw line excerpt. Reuses renderEvent. OSC 52 per-row copy. | ✓ |
| Condensed 3-column | ts | tier glyph | one-line summary. More compact but loses source-IP-per-row. | |
| Free-form: paste full RawJSON per entry | Full JSON per entry. More info but harder to scan. | |

**User's choice:** Match S-LOGS 5-column wide-mode (Recommended).
**Notes:** Recorded as D-02 in CONTEXT.md.

---

## TUI-11 hang escalation (follow-up)

**Question:** What if SIGKILL fails to release the subprocess after the 2s grace? (Pathological case but possible with stuck syscalls.)

| Option | Description | Selected |
|--------|-------------|----------|
| Show error, keep modal locked, surface PID for manual kill (Recommended) | 'Cancellation failed - subprocess PID=N still alive. Run kill -9 N from another shell.' Honest about failure mode. | ✓ |
| Force-close modal after SIGKILL regardless | Snappier UX but admin gets no signal something is wrong. | |
| Escalate to SIGABRT after another 2s | Mostly placebo; processes that survive SIGKILL rarely fall to SIGABRT. | |

**User's choice:** Show error, keep modal locked, surface PID for manual kill (Recommended).
**Notes:** Recorded as D-08 in CONTEXT.md.

---

## FW-09 docs visibility (follow-up)

**Question:** Where is FW-09's 'UAT-pending' status surfaced for visibility?

| Option | Description | Selected |
|--------|-------------|----------|
| VERIFICATION.md frontmatter + ROADMAP.md note + changelog (Recommended) | Triple visibility for partial-verification ship. | |
| VERIFICATION.md only | Quietly noted in verification report. Doesn't surface to ROADMAP or release notes. | ✓ |
| Dedicated UAT-PENDING.md tracking file | New artifact convention this milestone has to define. | |

**User's choice:** VERIFICATION.md only.
**Notes:** Recorded as D-16 in CONTEXT.md. User chose minimal visibility surface; the partial-verification status is internal to the verification report and does not propagate to ROADMAP or Debian changelog.

---

## Plan shape (follow-up)

**Question:** How should Phase 6's 4 requirements be split into plans?

| Option | Description | Selected |
|--------|-------------|----------|
| 4 independent plans (06-01..06-04), one per requirement (Recommended) | Matches ROADMAP. RED-test-first, atomic commits. No cross-plan refactors. | ✓ |
| Wave-0 cancellable-context refactor first, then 4 reqs | Plan 06-00 lands shared helper; more architectural overhead. | |
| 3 plans: TUI-11 spans all 4 sites in one plan | Reduces drift but produces one larger plan. | |

**User's choice:** 4 independent plans (06-01..06-04), one per requirement (Recommended).
**Notes:** Recorded as D-18 in CONTEXT.md. Planner is also free to extract a shared cancellable-Cmd helper during execution if drift emerges across the TUI-11 sites (D-10 in CONTEXT.md).

---

## Claude's Discretion

Areas the user delegated to Claude/planner judgment:
- Spinner glyph + style for the `Cancelling...` indicator.
- Exact column widths in M-USER-LOG modal (responsive to terminal width).
- Whether to extract a shared cancellable-Cmd helper if drift emerges.
- Specific `ufw allow proto tcp from 2001:db8::/32 ...` syntax probe for FW-09 v6-source rule-add.

---

## Deferred Ideas

- **NYQ-01 retroactive Nyquist authoring** (Phase 7) -> v1.2.1 alongside future carry-over.
- **Cancellation as a shared helper** (TUI-11 wave-0 refactor) -> only if drift emerges during execution.
- **Per-user log filtering by tier inside M-USER-LOG** -> v1.3 polish.
- **Multi-distro portability** -> out of scope per PROJECT.md.
- **Surfacing FW-09 UAT-pending in ROADMAP or changelog** -> rejected this phase per user choice.

---

*Discussion conducted: 2026-05-01*
*Captured in 06-CONTEXT.md - this log preserves the alternatives considered.*
