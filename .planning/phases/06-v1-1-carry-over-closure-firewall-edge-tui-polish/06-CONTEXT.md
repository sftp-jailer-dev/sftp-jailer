# Phase 6: v1.1 Carry-over Closure - Firewall edge + TUI polish - Context

**Gathered:** 2026-05-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Close 4 v1.1 carry-over items (FW-09, TUI-09, TUI-10, TUI-11) so the v1.2 milestone closes. v1.2.0 ships once Phase 6 lands. Phase 7 (NYQ-01 retroactive Nyquist authoring) is deferred to v1.2.1.

In scope:
- **FW-09:** Close BUG-04-B - extend the existing `NewUfwDeleteCatchAllByEnumerateStep` and `firewall.AddRule` paths to be empirically correct on dual-family (v4 + v6) and v6-only ufw policies. Code + teatest + UAT runbook author. Empirical UAT operator-pending.
- **TUI-09:** `S-SETTINGS` exposes `PasswordAgingDays` and `PasswordStaleDays` as editable textinput rows with positive-integer validation (max 3650).
- **TUI-10:** New per-user log-detail modal accessible from `S-USERS`.
- **TUI-11:** Replace detached `context.Background()` with cancellable contexts in `addkey`, `deleteuser`, `applysetup`, `pwauthdisable`. Esc -> SIGTERM -> 2s -> SIGKILL.

Out of scope (deferred):
- NYQ-01 retroactive Nyquist authoring (Phase 7 -> v1.2.1).
- BUG-04-B empirical UAT (operator-pending until an IPv6 VM is available).
- Multi-distro portability beyond Ubuntu 24.04 + Debian 13.
- New TUI features beyond the 4 named requirements.

</domain>

<decisions>
## Implementation Decisions

### TUI-10: Per-user log-detail modal
- **D-01:** New uppercase `L` keybind on S-USERS opens M-USER-LOG modal directly. S-USER-DETAIL keeps its current SSH-keys focus unchanged. Follows the W1 keybind precedent from Plan 04-06 (uppercase `D` on S-USERS for delete-rule, lowercase `d` reserved for S-USER-DETAIL).
- **D-02:** Modal renders the last 20 raw entries in the same 5-column layout as S-LOGS wide-mode: `ts (UTC) | source IP | event type | tier | raw line excerpt`. Reuse the existing `renderEvent` helper or its underlying primitives. OSC 52 copies the focused row.
- **D-03:** Modal also renders the LOG-06 tier counters (success / targeted / noise / unmatched) as a header strip. Source: `Queries.PerUserBreakdown(ctx, user)` (already shipped in Phase 2 plan 02-01).
- **D-04:** Time window for "last N days" is read from `config.LockdownProposalWindowDays` (already configurable, default 90, range [1, 3650], persisted in config.yaml). Avoids config-knob proliferation. The modal shows the active window in its header strip ("Last 90 days").
- **D-05:** Empty state copy: "No login attempts for `<user>` in the last `<N>` days."

### TUI-11: Cancellable resolveAsync paths
- **D-06:** Esc on a resolveAsync-active modal sends SIGTERM to the in-flight subprocess via the cancellable context, then waits up to 2s, then sends SIGKILL if the process is still alive.
- **D-07:** Modal UX during cancellation: shows `Cancelling...` indicator with spinner; modal stays open; closes only when the subprocess exits (or the SIGKILL fallback timer fires and the wait clears). Most predictable; matches sftp-jailer's safety-first ethos.
- **D-08:** Hang escalation (SIGKILL doesn't release within 2s after sending): modal shows `Cancellation failed - subprocess PID=N still alive. Run kill -9 N from another shell.` Modal stays locked but admin can press Esc again to force-close the modal frame (the orphan subprocess remains; not the tool's job to fix a stuck syscall). Honest about the failure mode; surfaces actionable info.
- **D-09:** Scope: ALL detached `context.Background()` sites in the 4 named files (`addkey`, `deleteuser`, `applysetup`, `pwauthdisable`). Initial scout found 7 sites (addkey:380, addkey:532, deleteuser:229, deleteuser:464, applysetup:290, pwauthdisable:290, pwauthdisable:488). Planner enumerates the final list against the codebase at plan time.
- **D-10:** Cancellation infrastructure lives in each modal site (no shared wrapper plan 06-00). The pattern is local: create context with cancel, expose cancel to the Esc handler, call cancel on Esc, wait for subprocess exit. If a shared helper emerges naturally during execution, planner may extract it; otherwise the 4 plans land independent.

### TUI-09: S-SETTINGS password-aging knobs
- **D-11:** Two new rows in S-SETTINGS: `Password aging (days)` -> `PasswordAgingDays`, `Password stale (days)` -> `PasswordStaleDays`. Routed through the existing inline-edit + textinput pattern that `fieldPasswordAuthN` and other configurable rows already use.
- **D-12:** Validation: positive integer, range [1, 3650]. Reuse the koanf-side Validate constraint already in `internal/config/config.go` (strict ordering `0 < aging < stale` per Phase 2 plan 02-11). Inline error on save attempt with invalid value.
- **D-13:** Persistence: `config.Save` (existing atomic-write path); round-trip on TUI restart.

### FW-09: BUG-04-B closure (dual-family + v6-only)
- **D-14:** Codebase already has v6 detection (`firewall.Enumerate` line 135-140) and `stripV6Suffix` source normalization (line 199-202). The `NewUfwDeleteCatchAllByEnumerateStep` predicate already matches both v4 and v6 catch-alls. The "DORMANT" status from 04-13-SUMMARY reflects missing empirical UAT, not missing code.
- **D-15:** What this plan adds:
  - **Test fixtures**: explicit teatest-equivalent unit fixtures for v6-only host (no v4 catch-all) and IPv6 source rule add (`firewall.AddRule(ctx, ops, user, "2001:db8::/32", "22")`).
  - **Comment-schema test**: `sftpj:v=1:user=<name>` Decode round-trip on v6-source rules. Confirms the existing `internal/ufwcomment` parser is protocol-agnostic (which it should be).
  - **Edge-case hardening**: any small fixes surfaced by the v6-only fixture (e.g., per-user rule add for v6 source if `ufw insert` syntax differs).
  - **UAT runbook**: `docs/uat/06-fw09-uat.md` mirroring the Phase 5 runbook structure - dual-family setup steps, v6-only setup steps, expected `ufw status numbered` outputs, evidence to capture.
- **D-16:** Release gate: code-complete + teatest + UAT runbook authored = ship v1.2.0 with FW-09 marked `verified-code, UAT-pending` in `06-VERIFICATION.md` frontmatter only. Not surfaced in ROADMAP or Debian changelog. Empirical UAT becomes a v1.2.x checkbox flip when an IPv6 VM is available.
- **D-17:** Empirical UAT environment: NO testing on `m1.linuxbe.com` or any host without explicit user authorization at UAT time. The runbook documents the setup (Ubuntu 24.04 VM with IPv6 enabled) without prescribing a specific host.

### Plan structure
- **D-18:** 4 independent plans, one per requirement: `06-01-FW-09`, `06-02-TUI-09`, `06-03-TUI-10`, `06-04-TUI-11`. Each plan is RED-test-first with atomic commit-per-step. No cross-plan refactors. Parallelizable; planner may schedule in any order.

### Cross-cutting
- **D-19:** All shell-outs go through `internal/sysops` (architectural invariant `scripts/check-no-exec-outside-sysops.sh`). TUI-11's SIGTERM/SIGKILL signaling is the cancellable-context wrapping; the Exec call itself stays in sysops.
- **D-20:** Em-dash forbidden everywhere (memory rule). Use `-` or `:`.
- **D-21:** SAFE-04 revert window pattern is preserved unchanged for any FW-09 mutation paths that touch it. (FW-09 is mostly read-only test fixture work; if the v6-only edge case requires a small fix in `firewall.AddRule`, the SAFE-04 wrapping is inherited from the existing modal callers.)
- **D-22:** Atomic commit-per-step: each red-test commit is followed by a green-implementation commit; SUMMARY.md per plan.

### Claude's Discretion
- Spinner glyph + style for the `Cancelling...` indicator (planner picks; consistent with existing toast/spinner widgets).
- Exact column widths in M-USER-LOG modal (responsive to terminal width per existing S-LOGS pattern).
- Whether to extract a shared cancellable-Cmd helper in `internal/tui/widgets/` if drift emerges across the 4 TUI-11 sites during execution.
- Specific `ufw allow proto tcp from 2001:db8::/32 to any port 22` syntax probe for FW-09 v6-source rule-add (planner verifies against ufw 0.36.2 docs).

### Folded Todos
None - the open todo from STATE.md ("Confirm contribution guidance and security reporting path") is project-level, not Phase 6 scope.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 6 source-of-truth
- `.planning/REQUIREMENTS.md` - FW-09 (line 81 region), TUI-09, TUI-10, TUI-11 definitions
- `.planning/ROADMAP.md` §"Phase 6" - phase goal, 4 success criteria, parallelization hints
- `.planning/PROJECT.md` - core value, constraints, conventions

### Phase 4 firewall pattern (FW-09 base)
- `.planning/milestones/v1.1/phases/04-firewall-mutations-progressive-lockdown-flagship/04-CONTEXT.md` - decisions D-FW-01..D-FW-07 (writer surface, position-1 insert, comment grammar)
- `internal/txn/steps.go:782-866` - `NewUfwDeleteCatchAllByEnumerateStep` (the existing position-independent loop FW-09 extends)
- `internal/firewall/enumerate.go:130-205` - v6 detection + `stripV6Suffix` already in place
- `internal/firewall/mutate.go` - `firewall.AddRule` writer (FW-09 may add v6-source path)
- `internal/ufwcomment/{encode,decode}.go` - `sftpj:v=1:user=<name>` grammar (protocol-agnostic, FW-09 confirms via test)

### Phase 3 modal pattern (TUI-09/10/11 base)
- `.planning/milestones/v1.1/phases/03-canonical-sshd-chroot-config-user-key-mutations/03-CONTEXT.md` - modal D-* decisions
- `internal/tui/screens/settings/settings.go` - inline-edit + textinput pattern (TUI-09 reuses `fieldPasswordAuthN` row idiom)
- `internal/tui/screens/users/users.go` - S-USERS keybind dispatcher (TUI-10 entry point)
- `internal/tui/screens/userdetail/userdetail.go` - S-USER-DETAIL preserved unchanged (W1 lowercase 'd')
- `internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` - the 4 TUI-11 sites

### Phase 2 data layer (TUI-10 source)
- `internal/store/queries.go:208-244` - `Queries.PerUserBreakdown(ctx, user) UserBreakdown`
- `internal/observe/classify.go` - 4-tier classifier (success / targeted / noise / unmatched)

### Config layer (TUI-09 + TUI-10)
- `internal/config/config.go` - `PasswordAgingDays` / `PasswordStaleDays` already exist (Phase 2 plan 02-11); strict-ordering Validate; `LockdownProposalWindowDays` (Phase 4 plan 04-07)
- `internal/sysops/atomic.go` - atomic-write path for config.yaml

### sysops (TUI-11 cancellation surface)
- `internal/sysops/sysops.go` - SystemOps interface
- `internal/sysops/real.go` - Real.Exec implementation (cancellable context already plumbed via `exec.CommandContext`)

### UAT runbook template (FW-09)
- `docs/uat/05-ubuntu24-uat.md` - Phase 5 Ubuntu 24.04 runbook (template structure for `06-fw09-uat.md`)
- `docs/uat/05-debian13-uat.md` - Phase 5 Debian 13 runbook (mirror structure)

### Architectural invariants
- `scripts/check-no-exec-outside-sysops.sh` - all subprocess via sysops
- `scripts/check-go-mod-pins.sh` - 13 direct deps pinned
- `scripts/check-single-tea-program.sh` - one tea.NewProgram

### Memory rules
- User memory `feedback_no_emdash.md` - never use em-dash; use `-` or `:`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/firewall.Enumerate` already detects `(v6)` substring -> `Rule.Proto = "v6"` (line 135-140) and `stripV6Suffix` normalizes Source to plain "Anywhere" for both families (line 199-202). FW-09's catch-all loop predicate already matches both v4 and v6.
- `TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6` (steps_test.go:1314) - existing dual-family unit test. FW-09 adds the v6-only fixture as a sibling.
- `Queries.PerUserBreakdown` (queries.go:208-244) - LOG-06 aggregation already shipped in Phase 2 plan 02-01. TUI-10 reads this directly; no new query needed.
- S-LOGS' `renderEvent` helper (logs.go) - 5-column row renderer. TUI-10 reuses or factors out.
- `internal/tui/screens/settings/settings.go` `fieldPasswordAuthN` row idiom - TUI-09 follows the same shape but routes through the standard inline-edit + Validate path (NOT the dispatch shortcut).
- Existing `widgets.Toast.Flash` and spinner pattern - TUI-11 'Cancelling...' indicator can reuse spinner from `internal/tui/widgets/`.

### Established Patterns
- **Modal lifecycle**: every modal has `attemptParse -> resolveAsync -> phaseReview -> attemptCommit -> phaseDone | phaseError`. TUI-11 inserts cancellable contexts at the resolveAsync + commit-batch sites.
- **Inline-edit S-SETTINGS row**: `case row == fieldX` -> focus textinput -> Enter -> Validate -> Save -> Toast.Flash. TUI-09 adds 2 rows following this exact pattern.
- **Atomic config save**: `config.Save` does CreateTemp + Write + Sync + Chmod + Rename. TUI-09 inherits.
- **TDD-RED-then-GREEN per plan**: each plan ships failing test commit first, implementation commit second, SUMMARY commit third. Phase 5 already follows this religiously (see 05-* commit log).

### Integration Points
- S-USERS keybind dispatcher (`users.go` Update method) - add uppercase `L` case alongside the existing `D` (delete-rule) and `d` (S-USER-DETAIL) handlers.
- S-SETTINGS row enum (`settings.go`) - add `fieldPasswordAgingDays` and `fieldPasswordStaleDays` row constants + render order.
- The 4 TUI-11 modal Update methods - replace `context.Background()` with `context.WithCancel(parent)` and store cancel; route Esc to call cancel + wait for subprocess exit.

</code_context>

<specifics>
## Specific Ideas

- **TUI-10 columns match S-LOGS exactly**: admins already have muscle memory for the 5-column layout. Modal should NOT introduce a different per-row format.
- **TUI-11 'Cancelling...' indicator**: the same Toast-style ephemeral feedback used elsewhere in the TUI. Spinner glyph at minimum; static `Cancelling...` text acceptable if spinner integration is awkward in a particular modal.
- **FW-09 UAT runbook structure**: copy the discipline of `docs/uat/05-ubuntu24-uat.md` - numbered steps, expected outputs, evidence-capture lines, operator sign-off table. The Phase 5 runbook is the gold standard.
- **No m1.linuxbe.com testing**: any UAT runbook example commands should use generic placeholders (192.168.x.y) NOT m1.linuxbe.com. Documentation must not imply that host is a sftp-jailer test target.

</specifics>

<deferred>
## Deferred Ideas

- **NYQ-01 retroactive Nyquist authoring** (Phase 7) -> v1.2.1 alongside any future carry-over.
- **Cancellation as a shared helper** (TUI-11 wave-0 refactor) -> only if drift emerges during execution; otherwise stays per-site.
- **Per-user log filtering by tier inside M-USER-LOG** -> v1.3 polish; current scope is "show last 20 + tier counts", filtering is a v1.3 enhancement.
- **Multi-distro portability beyond Ubuntu/Debian 13** -> out of scope for v1.x per PROJECT.md.
- **Surfacing FW-09 UAT-pending in ROADMAP or changelog** -> rejected this phase; visibility lives in 06-VERIFICATION.md frontmatter only.

### Reviewed Todos (not folded)
None - the only open todo (security reporting path) is project-level, not Phase 6 scope.

</deferred>

---

*Phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish*
*Context gathered: 2026-05-01*
