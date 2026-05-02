---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
verified: 2026-05-01T13:30:00Z
status: verified
score: 4/4 must-haves verified (1 pre-agreed UAT-pending: FW-09 IPv6 VM execution per D-16)
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 3/4
  previous_verified: 2026-05-01T00:00:00Z
  gap_closure_plan: 06-05-PLAN
  gaps_closed_code:
    - "CR-01 (production safety hazard: PID=0 rendered 'Run kill -9 0'): all 4 mutation modals now gate on `if msg.pid <= 0` and emit a subprocess-free fallback ('Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef | grep <child-binary>` from another shell to identify the live PID.'). Verbatim D-08 live-PID copy preserved on the `pid > 0` branch (Feed*ForTestWithPID seams)."
    - "IN-02 (addkey HTTP/file-fetch hang dishonestly referenced 'subprocess'): addkey.go:528-538 now renders fetch-specific copy ('Cancellation failed - in-flight HTTP / file read did not abort within 2s. Modal stays open until the request returns.'); no subprocess wording, no kill instruction."
    - "WR-01 (dead lastPID field on 4 Model structs): field removed from all 4 mutation modals; doc-comments updated."
    - "11 new regression tests added: paired *_PID0Fallback_does_not_render_kill_minus_9_zero + *_LivePID_still_renders_kill_minus_9_pid across addkey/applysetup/deleteuser (metaLoaded + submitDone)/pwauthdisable, plus addkey HTTP-fetch fallback test for IN-02."
  gaps_remaining:
    - "FW-09 empirical IPv6 VM UAT execution (pre-agreed acceptance posture per D-16; production code is already protocol-agnostic per D-14, zero production lines changed). Operator must provision dual-family + v6-only Ubuntu 24.04 VMs and sign off docs/uat/06-fw09-uat.md Variants A and B; this is deferred to v1.2.x point release per ROADMAP."
  regressions: []
  full_test_suite: "go test -race ./... — green; scripts/check-no-exec-outside-sysops.sh — green; scripts/check-go-mod-pins.sh — green; scripts/check-single-tea-program.sh — green; go vet ./... — green"
requirements:
  - id: FW-09
    status: verified-code, UAT-pending
    plan: 06-01
    evidence: 3 tests + 2 fixtures + 12-step UAT runbook; production code already protocol-agnostic per D-14; empirical IPv6 VM execution deferred to v1.2.x checkbox flip per D-16
  - id: TUI-09
    status: satisfied
    plan: 06-02
    evidence: 2 new fieldKind iota constants, 5 switch arms, max=3650 cap in config.Validate, 6 teatest cases + 5 config_test cases pin the contract
  - id: TUI-10
    status: satisfied
    plan: 06-03
    evidence: new internal/tui/screens/userlog package, PerUserBreakdown signature extended with sinceNs, uppercase L keybind dispatched, factory wiring in main.go, 5+ teatest cases pin header / empty / OSC 52 / window / 20-row cap
  - id: TUI-11
    status: satisfied
    plan: 06-04 + 06-05
    evidence: "Cancellation core (06-04): sysops.Exec SIGTERM+2s+SIGKILL policy lands; ExecResult.PID populated; 9 detached contexts replaced; 4 modals wire Esc to cancelFn with Cancelling indicator; D-08 verbatim copy preserved on live-PID branch. Hang-diagnostic safety closure (06-05): PID=0 fallback gate added in all 4 modals (addkey:706-716, applysetup:678-685, deleteuser:392-400 + 428-435, pwauthdisable:732-739) — production never renders `Run kill -9 0`. IN-02 addkey HTTP-fetch fallback (06-05): fetch-specific copy at addkey.go:528-538. WR-01 dead lastPID field removal (06-05). 11 new regression tests pin all three closures."
gaps: []
human_verification:
  - test: "FW-09 Variant A - dual-family UAT runbook execution"
    expected: "On a real Ubuntu 24.04 VM with IPV6=yes and a dual-family ufw policy, S-LOCKDOWN commit deletes both v4 and v6 catch-all rules in one pass; per-user v4 and v6 rules with `# sftpj:v=1:user=alice` comments survive. Operator signs off in docs/uat/06-fw09-uat.md."
    why_human: "Empirical UAT acceptance gate per ROADMAP Phase 6 SC1. teatest fixtures prove the predicate is family-agnostic on synthetic stdouts; the real ufw 0.36.2 binary on a kernel-netfilter-backed v6 path can only be exercised on a live VM."
    pre_agreed_deferral: "D-16: ship status `verified-code, UAT-pending` for v1.2; UAT execution flips checkbox in v1.2.x point release."
  - test: "FW-09 Variant B - v6-only UAT runbook execution"
    expected: "On a v6-only VM (no v4 default policy), S-LOCKDOWN commit deletes the single v6 catch-all and terminates cleanly; admin verifies `ufw status numbered` shows zero catch-all rows; operator signs off."
    why_human: "Same UAT acceptance gate, v6-only edge. Documented in docs/uat/06-fw09-uat.md as Variant B (5 numbered steps)."
    pre_agreed_deferral: "Same as Variant A — D-16."
deferred: []
---

# Phase 6: v1.1 Carry-over Closure - Verification Report

**Phase Goal:** Close the v1.1 carry-over tech debt that was opportunistically deferred from Phase 4 - one firewall correctness bug (FW-09), two UX polish items (TUI-09, TUI-10), and one code-quality cleanup (TUI-11).
**Verified:** 2026-05-01T13:30:00Z
**Status:** verified
**Re-verification:** Yes - re-verified after plan 06-05 closed CR-01 / IN-02 / WR-01.

---

## Re-verification Context

The original 2026-05-01T00:00:00Z verification scored Phase 6 at **3/4**, with one critical gap on truth #4 (TUI-11 D-08 hang diagnostic). The 4 mutation modal goroutines hardcoded `pid: 0` in their done-msgs because `txn.Tx.Apply` does not surface per-step `ExecResult.PID`; production hang escalation rendered `Run kill -9 0` — a Linux/POSIX safety hazard (kill(2) PID 0 = SIGKILL the calling process group, so an admin copy-pasting the instruction from a TTY where sftp-jailer was backgrounded could DoS their own session).

Plan **06-05-PLAN.md** (commits `ce389b2..ec33e0a`, 7 commits, 2026-05-01T05:19) closed three findings:

- **CR-01 (production safety):** All 4 production cancellation classifiers now gate on `if msg.pid <= 0` and emit a subprocess-free fallback. Verbatim D-08 live-PID copy preserved on the `pid > 0` branch (the `Feed*ForTestWithPID` seams always inject non-zero PIDs, so existing tests still exercise the live-PID path).
- **IN-02 (HTTP/file-fetch hang dishonest copy):** addkey.go:528-538 renders fetch-specific copy with no subprocess wording or kill instruction.
- **WR-01 (dead lastPID field):** Removed from all 4 Model structs.

11 new regression tests pin the gap-closure: paired `*_PID0Fallback_does_not_render_kill_minus_9_zero` + `*_LivePID_still_renders_kill_minus_9_pid` across all 4 modals (deleteuser pinned twice for metaLoaded + submitDone arms), plus `TestAddkey_handleFetched_HTTPHang_does_not_reference_subprocess_or_kill` for IN-02.

**Re-review (06-REVIEW.md, 2026-05-01T12:00:00Z) confirms:** 0 critical / 0 warning / 2 info-only items post-closure. The two info items (slightly stale fetch-fallback wording and a pre-existing structural divergence in `deleteuser.Model.errFatal`) are cosmetic and do not affect TUI-11 correctness.

**FW-09 status remains `verified-code, UAT-pending`** per D-16 pre-agreed acceptance posture: production code is already family-agnostic (zero production lines changed in 06-01 per D-14); the 12-step IPv6 VM UAT runbook (`docs/uat/06-fw09-uat.md`) awaits operator execution and is deferred to v1.2.x checkbox flip — this is by design, not a code gap.

---

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | BUG-04-B closure on dual-family + v6-only hosts (FW-09). Empirical UAT on IPv6-enabled VM is acceptance gate. | VERIFIED-CODE, UAT-PENDING | 3 new tests (TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6, TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment, TestEnumerate_v6_source_rule_decodes_user_round_trip) all green; 2 testdata fixtures committed; docs/uat/06-fw09-uat.md authored with 12 numbered steps across Variant A (dual-family) and Variant B (v6-only); production code already protocol-agnostic per D-14 (zero production lines changed). UAT VM execution deferred per D-16. |
| 2 | S-SETTINGS exposes password-aging knobs (TUI-09). Editable, validated (positive int, max 3650), round-trip via existing settings writer. | VERIFIED | fieldPasswordAgingDays + fieldPasswordStaleDays iota constants land before fieldKindCount; 5 switch arms wired (name/hint/currentValue/valueFor/attemptSave); `between 1 and 3650` cap in config.Validate for both fields; strict-ordering rule (aging < stale) preserved verbatim; 6 teatest cases + 5 config_test cases pin the contract. |
| 3 | Per-user log-detail modal (TUI-10). Last 90 days, tier counts + last 20 entries. | VERIFIED | New internal/tui/screens/userlog package (Model, Init, Update, View, KeyMap); store.Queries.PerUserBreakdown signature extended with sinceNs int64 (sentinel zero disables - mirrors FilterEvents.SinceNs); logs.DisplayN/ColorByTier/TierGlyph re-exported for cross-package row formatter parity; userLogFactory + SetUserLogFactory injection seam in usersscreen; case "L" handler in handleKey; cmd/sftp-jailer/main.go wires SetUserLogFactory at TUI bootstrap; 5+ teatest cases pin header rendering / empty state / OSC 52 / window from config / 20-row cap; W-03 d/D regression guards still pass. |
| 4 | Cancellable resolveAsync paths (TUI-11). SIGTERM + 2s SIGKILL grace in addkey/deleteuser/applysetup/pwauthdisable. | VERIFIED (post-06-05 closure) | **Cancellation core (06-04):** sysops.Exec sets cmd.Cancel = SIGTERM closure (with os.ErrProcessDone -> nil, Pitfall 1) and cmd.WaitDelay = 2s; ExecResult.PID populated via cmd.Process.Pid captured before Wait; 9 detached context.Background() sites replaced with stored cancellable contexts; all 4 modals route Esc-during-async to m.cancelFn() with Cancelling indicator (D-07); cancellation classified via errors.Is(context.Canceled) BEFORE success/fatal branches (Pitfall 2). **Hang-diagnostic safety closure (06-05):** all 4 modals now gate the D-08 hang diagnostic on `if msg.pid <= 0` and render the subprocess-free fallback ('Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef \| grep <child-binary>` from another shell to identify the live PID.') so production never renders `Run kill -9 0`. Verbatim D-08 live-PID copy preserved on the `pid > 0` branch. Implementations at addkey.go:706-716, applysetup.go:678-685, deleteuser.go:392-400 + 428-435, pwauthdisable.go:732-739 — fallback string byte-identical across all 4 modals. **IN-02 closure:** addkey.go:528-538 renders fetch-specific copy ('Cancellation failed - in-flight HTTP / file read did not abort within 2s.'). **WR-01 closure:** dead lastPID field removed from all 4 Model structs. **Regression net:** 11 new tests pin the gap-closure (paired `*_PID0Fallback_*` + `*_LivePID_*` across 4 modals + addkey HTTP-fetch fallback). |

**Score:** 4/4 truths verified after plan 06-05 closure. FW-09 carries `verified-code, UAT-pending` status per D-16 pre-agreed deferral (UAT execution → v1.2.x).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/firewall/testdata/ufw-status-numbered-v6-only.txt` | v6-only host fixture | VERIFIED | 6 lines, contains `Status: active`, `(v6)`, `sftpj:v=1:user=alice`, no v4 catch-all |
| `internal/firewall/testdata/ufw-status-numbered-v6-source.txt` | post-insert v6-source fixture | VERIFIED | 5 lines, contains `2001:db8::/32`, `sftpj:v=1:user=alice`, `(v6)` marker |
| `internal/txn/steps_test.go` | TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6 + 2 fixture helpers | VERIFIED | Test passes; helpers ufwStatusFixtureV6OnlyHost + ufwStatusFixtureV6OnlyAfterDelete present |
| `internal/firewall/mutate_test.go` | TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment | VERIFIED | Test passes; asserts UfwInsert carries 2001:db8::/32 verbatim + sftpj:v=1:user=alice comment |
| `internal/firewall/enumerate_test.go` | TestEnumerate_v6_source_rule_decodes_user_round_trip | VERIFIED | Test passes; independent assertions on Source/Proto/User/ParseErr |
| `docs/uat/06-fw09-uat.md` | FW-09 dual-family + v6-only operator runbook | VERIFIED | 12 numbered steps (A.0-A.6 + B.0-B.4), Variant A + Variant B, operator sign-off table, no `m1.linuxbe.com`, no em-dash |
| `internal/tui/screens/settings/settings.go` | fieldPasswordAgingDays + fieldPasswordStaleDays iotas + 5 switch arms | VERIFIED | Both iotas before fieldKindCount; PasswordAgingDaysRowIndexForTest/PasswordStaleDaysRowIndexForTest exports; 5 switch arms each (name/hint/currentValue/valueFor/attemptSave) |
| `internal/config/config.go` | max=3650 cap on PasswordAgingDays + PasswordStaleDays | VERIFIED | Two `between 1 and 3650` error messages land for aging and stale; strict-ordering message preserved verbatim |
| `internal/tui/screens/settings/settings_test.go` | teatest assertions for cursor/edit/save/validation | VERIFIED | 6 new teatest cases land |
| `internal/config/config_test.go` | Validate tests for max=3650 | VERIFIED | TestConfig_PasswordAging_max_3650 with 5 sub-cases |
| `internal/store/queries.go` | PerUserBreakdown signature extended with sinceNs | VERIFIED | `func (q *Queries) PerUserBreakdown(ctx context.Context, user string, sinceNs int64) (UserBreakdown, error)` lands; SQL idiom `(? = 0 OR ts_unix_ns >= ?)` mirrors FilterEvents convention |
| `internal/tui/screens/userlog/userlog.go` | M-USER-LOG model: Init, Update, View; loads events + breakdown; renders header strip + 5-col table; OSC 52 row copy | VERIFIED | 320+ lines; Model fields windowDays/breakdown/events/cursor; Init dispatches tea.Batch(loadBreakdown, loadEvents); View renders header + tier strip + 5-col rows or empty-state; OSC 52 via tea.SetClipboard on 'c' |
| `internal/tui/screens/userlog/userlog_test.go` | teatest assertions for render/empty/OSC52/window/20-row cap | VERIFIED | 6 unit tests land |
| `internal/tui/screens/users/users.go` | uppercase L keybind dispatch + userLogFactory injection seam | VERIFIED | `var userLogFactory func(username string) nav.Screen` + `func SetUserLogFactory` + `case "L":` in handleKey; W-03 d/D regression guards still present |
| `cmd/sftp-jailer/main.go` | usersscreen.SetUserLogFactory wiring | VERIFIED | `usersscreen.SetUserLogFactory(...)` invoked at TUI bootstrap immediately after SetDeleteUserFwRulesFactory; userlog package import present |
| `internal/sysops/sysops.go` | ExecResult.PID field | VERIFIED | `PID int` field added to ExecResult |
| `internal/sysops/real.go` | cmd.Cancel SIGTERM closure + cmd.WaitDelay 2s + cmd.Process.Pid capture | VERIFIED | Cancel closure with os.ErrProcessDone -> nil; cmd.WaitDelay = 2 * time.Second; cmd.Start + cmd.Wait split (replacing CombinedOutput); res.PID = cmd.Process.Pid captured before Wait |
| `internal/sysops/real_test.go` | TestExec_cancel_sends_SIGTERM_then_SIGKILL_after_2s + TestExec_returns_pid_after_start | VERIFIED | Tests pass within 60s timeout |
| `internal/tui/screens/addkey/addkey.go` | stored cancelFn + Esc handler + Cancelling indicator + D-08 hang diagnostic + PID=0 fallback gate (06-05) + IN-02 fetch-specific copy (06-05) + WR-01 lastPID removal (06-05) | VERIFIED | cancelFn/cancelling fields land; m.cancelFn() invoked from Esc; Cancelling indicator renders. **06-05 closures:** handleCommitted at addkey.go:706-716 gates on `if msg.pid <= 0` to render subprocess-free fallback (CR-01); handleFetched at addkey.go:528-538 renders fetch-specific copy with no subprocess wording (IN-02); lastPID field removed from Model (WR-01). Verbatim D-08 live-PID copy preserved at the `pid > 0` branch. |
| `internal/tui/screens/deleteuser/deleteuser.go` | same as addkey + dual-arm gating (metaLoaded + submitDone) | VERIFIED | Cancellation core lands; **06-05 closure (CR-01):** PID=0 fallback gates added at deleteuser.go:392-400 (metaLoaded arm) and 428-435 (submitDone arm); WR-01 dead lastPID field removed. |
| `internal/tui/screens/applysetup/applysetup.go` | same as addkey + shared `applyCancellationClassification` helper-level gate | VERIFIED | Cancellation core lands; **06-05 closure (CR-01):** shared helper at applysetup.go:678-685 gates on `if msg.pid <= 0`; preflightLoadedMsg + rePreflightLoadedMsg call sites updated from `m.lastPID` to literal `0` (made production path explicit); WR-01 dead lastPID field removed. |
| `internal/tui/screens/pwauthdisable/pwauthdisable.go` | same as applysetup | VERIFIED | Cancellation core lands; **06-05 closure (CR-01):** shared helper at pwauthdisable.go:732-739 gates on `if msg.pid <= 0`; preflightLoadedMsg call site updated from `m.lastPID` to literal `0`; WR-01 dead lastPID field removed. |
| `internal/tui/screens/addkey/addkey_test.go` | 3 new regression tests (CR-01 PID=0 fallback + live-PID guard + IN-02 fetch fallback) | VERIFIED (06-05) | TestAddkey_handleCommitted_PID0Fallback_does_not_render_kill_minus_9_zero, TestAddkey_handleCommitted_LivePID_still_renders_kill_minus_9_pid, TestAddkey_handleFetched_HTTPHang_does_not_reference_subprocess_or_kill — all green. |
| `internal/tui/screens/applysetup/applysetup_test.go` | 2 new regression tests (CR-01 + live-PID guard) | VERIFIED (06-05) | TestApplysetup_applyDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero, TestApplysetup_applyDoneMsg_LivePID_still_renders_kill_minus_9_pid — green. |
| `internal/tui/screens/deleteuser/deleteuser_test.go` | 4 new regression tests (CR-01 metaLoaded + submitDone arms + 2 live-PID guards) | VERIFIED (06-05) | TestDeleteuser_metaLoadedMsg_PID0Fallback / _LivePID + TestDeleteuser_submitDoneMsg_PID0Fallback / _LivePID — all 4 green. |
| `internal/tui/screens/pwauthdisable/pwauthdisable_test.go` | 2 new regression tests (CR-01 + live-PID guard) | VERIFIED (06-05) | TestPwauthdisable_submitDoneMsg_PID0Fallback / _LivePID — green. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|------|--------|---------|
| `internal/txn/steps_test.go::TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6` | `internal/txn/steps.go::NewUfwDeleteCatchAllByEnumerateStep` | step.Apply against sysops.Fake pre-loaded with v6-only fixture | WIRED | Test passes; deletion count == 1; deleted id matches v6 catch-all from first enumerate |
| `internal/firewall/mutate_test.go::TestAddRule_v6_source_...` | `internal/firewall/mutate.go::AddRule` | `AddRule(ctx, fake, "alice", "2001:db8::/32", "22")` | WIRED | Test passes; UfwInsert recorded with v6 CIDR verbatim + sftpj:v=1:user=alice comment |
| `internal/firewall/enumerate_test.go::TestEnumerate_v6_source_...` | `internal/ufwcomment/decode.go::Decode` | Enumerate parses v6-source row whose RawComment was produced by ufwcomment.Encode("alice") | WIRED | Test passes; r.Source contains 2001:db8::/32, r.Proto == "v6", r.User == "alice", r.ParseErr == nil |
| `internal/tui/screens/settings/settings.go::attemptSave` | `internal/config/config.Validate` | candidate.PasswordAgingDays = v + Validate(candidate) | WIRED | Switch arm `case fieldPasswordAgingDays: candidate.PasswordAgingDays = v` lands; Validate returns errors on out-of-range or strict-ordering violations |
| `internal/tui/screens/settings/settings.go::attemptSave` | `internal/config/config.Save` | successful Validate -> tea.Cmd that calls config.Save off main loop | WIRED | Save round-trip pinned by TestSettings_password_aging_days_save_via_config + TestSettings_password_stale_days_save_via_config |
| `internal/config/config.go::Validate` | Settings.PasswordAgingDays/StaleDays | range check `< 1 || > 3650` for both fields, plus strict-ordering | WIRED | `between 1 and 3650` substring present for both fields; existing `strictly greater than password_aging_days` message preserved |
| `internal/tui/screens/users/users.go::handleKey case L` | `internal/tui/screens/userlog/userlog.go::New` | userLogFactory(username) nav.Screen | WIRED | case "L" handler invokes selectedRealRow + nil-factory guard + userLogFactory(r.Username) + push(screen) |
| `internal/tui/screens/userlog/userlog.go::Init` | `store.Queries.PerUserBreakdown` AND `FilterEvents` | tea.Batch of two queries; sinceNs derived from config.LockdownProposalWindowDays | WIRED | Init returns tea.Batch(m.loadBreakdown(), m.loadEvents()); both compute sinceNs from m.windowDays |
| `cmd/sftp-jailer/main.go::runTUI` | `internal/tui/screens/users/users.go::SetUserLogFactory` | factory injection at bootstrap mirroring SetDeleteUserFwRulesFactory | WIRED | Wiring lands at line ~424 with userlog.New(username, queries, &usersCfg) |
| `internal/sysops/real.go::Exec` | syscall.SIGTERM via cmd.Cancel closure + cmd.WaitDelay = 2s | single edit between exec.CommandContext and cmd.Wait | WIRED | TestExec_cancel_sends_SIGTERM_then_SIGKILL_after_2s pins the timing |
| `internal/sysops/real.go::Exec` | ExecResult.PID populated from cmd.Process.Pid after cmd.Start | result.PID = cmd.Process.Pid | WIRED | TestExec_returns_pid_after_start pins the contract |
| each modal's done-msg goroutine | done-msg PID field populated from ExecResult.PID | msg.pid = result.PID | NOT_WIRED (BY DESIGN — path B) | CR-01 closed via path (B) gating, not path (A) plumbing. tx.Apply still does not surface ExecResult.PID; production goroutines emit `pid: 0` and the modals' classification helpers gate on `if msg.pid <= 0` to render the subprocess-free fallback. Test seams (Feed*ForTestWithPID) inject synthetic non-zero PIDs to exercise the live-PID branch verbatim D-08 copy. Path (A) — extending tx.Apply to return per-step ExecResult — tracked as v1.3 follow-up per 06-05-SUMMARY.md. |
| each modal's handleKey case esc during async phase | stored m.cancelFn func from context.WithCancel | `if m.cancelFn != nil { m.cancelFn() }; m.cancelling = true` | WIRED | All 4 modals have m.cancelFn() invocation in Esc handler |
| each modal's handleCommitted (or equivalent done-handler) | neutral cancelled-state branch | `if m.cancelling && (err==nil || errors.Is(err, context.Canceled)) -> render 'cancelled by Esc'` | WIRED | All 4 modals classify cancellation via errors.Is BEFORE success/fatal branches (Pitfall 2 closed) |
| each modal's handleCommitted hang branch | D-08 verbatim diagnostic copy with live PID OR safe fallback when PID unavailable | path (B): `if msg.pid <= 0 { fallback } else { fmt.Sprintf("Cancellation failed - subprocess PID=%d still alive. Run kill -9 %d from another shell.", pid, pid) }` | WIRED (post-06-05) | All 4 modals gate on `if msg.pid <= 0` and emit subprocess-free fallback ('Cancellation failed - subprocess refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef \| grep <child-binary>` from another shell to identify the live PID.'). Live-PID branch preserves verbatim D-08 copy; exercised by Feed*ForTestWithPID seams. Production never renders `Run kill -9 0`. |
| each modal's View() during phaseCancelling | 'Cancelling...' indicator render | lipgloss render of 'Cancelling...' when m.cancelling == true | WIRED | 'Cancelling' substring lands 8-9x in each modal source (View + tests) |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `userlog.Model.events` | events []store.Event | FilterEvents(ctx, FilterOpts{User, SinceNs, Limit:20}) | Yes (real DB query: SELECT FROM observations WHERE user = ? AND (...) LIMIT 20) | FLOWING |
| `userlog.Model.breakdown` | breakdown store.UserBreakdown | PerUserBreakdown(ctx, user, sinceNs) | Yes (real DB query: SELECT tier, COUNT(*) FROM observations WHERE user = ? AND (? = 0 OR ts_unix_ns >= ?) GROUP BY tier) | FLOWING |
| `settings.Model.settings` | settings *config.Settings | config.Load -> overlayDefaults -> tied to Save round-trip | Yes (koanf-loaded YAML; round-trip pinned by save test) | FLOWING |
| Each modal's done-msg `pid` field | msg.pid int | tx.Apply does NOT propagate ExecResult.PID; goroutines emit `pid: 0` by design (path B); modals gate on `if msg.pid <= 0` and render subprocess-free fallback | YES (gated correctly) | FLOWING via path (B) gate (post-06-05). Path (A) live-PID plumbing tracked as v1.3 follow-up. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full test suite green | `go test ./... -count=1 -timeout 180s` | All 39 packages PASS | PASS |
| sysops invariant | `bash scripts/check-no-exec-outside-sysops.sh` | "OK: no exec.Command outside internal/sysops" | PASS |
| go.mod pins | `bash scripts/check-go-mod-pins.sh` | "OK: all 13 direct-dep pins match" | PASS |
| Single tea.NewProgram | `bash scripts/check-single-tea-program.sh` | "OK: single tea.NewProgram (pitfall E1 retired)" | PASS |
| go vet | `go vet ./...` | No findings | PASS |
| FW-09 v6-only test | `go test ./internal/txn/ -run TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6` | PASS | PASS |
| FW-09 v6-source AddRule test | `go test ./internal/firewall/ -run TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment` | PASS | PASS |
| FW-09 v6-source Enumerate test | `go test ./internal/firewall/ -run TestEnumerate_v6_source_rule_decodes_user_round_trip` | PASS | PASS |
| TUI-11 sysops cancellation timing | `go test ./internal/sysops/ -run TestExec_cancel_sends_SIGTERM_then_SIGKILL_after_2s` | PASS | PASS |
| TUI-11 PID after Start | `go test ./internal/sysops/ -run TestExec_returns_pid_after_start` | PASS | PASS |
| TUI-10 userlog suite | `go test ./internal/tui/screens/userlog/...` | PASS | PASS |
| Em-dash absence in 25 modified files | `LC_ALL=C grep -P '[\xe2][\x80][\x94\x93]' <files>` | No matches | PASS |
| TUI-11/CR-01 PID=0 fallback regression (addkey) | `go test ./internal/tui/screens/addkey/... -run TestAddkey_handleCommitted_PID0Fallback_does_not_render_kill_minus_9_zero` | PASS | PASS |
| TUI-11/CR-01 PID=0 fallback regression (applysetup) | `go test ./internal/tui/screens/applysetup/... -run TestApplysetup_applyDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero` | PASS | PASS |
| TUI-11/CR-01 PID=0 fallback regression (deleteuser metaLoaded) | `go test ./internal/tui/screens/deleteuser/... -run TestDeleteuser_metaLoadedMsg_PID0Fallback_does_not_render_kill_minus_9_zero` | PASS | PASS |
| TUI-11/CR-01 PID=0 fallback regression (deleteuser submitDone) | `go test ./internal/tui/screens/deleteuser/... -run TestDeleteuser_submitDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero` | PASS | PASS |
| TUI-11/CR-01 PID=0 fallback regression (pwauthdisable) | `go test ./internal/tui/screens/pwauthdisable/... -run TestPwauthdisable_submitDoneMsg_PID0Fallback_does_not_render_kill_minus_9_zero` | PASS | PASS |
| TUI-11/CR-01 live-PID guard (all 4 modals) | `go test ./internal/tui/screens/{addkey,applysetup,deleteuser,pwauthdisable}/... -run "_LivePID_still_renders_kill_minus_9_pid"` | PASS | PASS |
| TUI-11/IN-02 addkey HTTP-fetch fallback regression | `go test ./internal/tui/screens/addkey/... -run TestAddkey_handleFetched_HTTPHang_does_not_reference_subprocess_or_kill` | PASS | PASS |
| TUI-11/WR-01 lastPID field absent from production tree | `! grep -rn lastPID internal/tui/screens/` (excluding `.claude/worktrees/`) | exit 0 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| FW-09 | 06-01 | Close BUG-04-B - catch-all delete on dual-family + v6-only | SATISFIED-CODE / NEEDS HUMAN (UAT) | 3 tests + 2 fixtures + 12-step UAT runbook authored. Production code already protocol-agnostic per D-14. Empirical IPv6 VM execution deferred to v1.2.x checkbox flip per D-16 - this is a pre-agreed acceptance posture, not a gap. |
| TUI-09 | 06-02 | S-SETTINGS exposes PasswordAgingDays + PasswordStaleDays as editable fields | SATISFIED | 2 iotas + 5 switch arms + max=3650 cap in config.Validate + 6 teatest cases pin the contract |
| TUI-10 | 06-03 | Per-user log-detail modal on uppercase L | SATISFIED | New userlog package + L keybind dispatch + factory wiring + sinceNs filter close Pitfall 5 |
| TUI-11 | 06-04 + 06-05 | Cancellable resolveAsync paths in 4 modals (SIGTERM + 2s SIGKILL grace) + safe hang diagnostic | SATISFIED | Cancellation core (SIGTERM+2s+SIGKILL) works as specified by ROADMAP SC4. D-08 hang diagnostic now uses path (B) gating: `if msg.pid <= 0` renders subprocess-free fallback ('refused SIGTERM and SIGKILL within 2s. Inspect `ps -ef \| grep <child-binary>` from another shell'); verbatim D-08 live-PID copy preserved on `pid > 0` branch. Production never renders `Run kill -9 0` (CR-01 closed by 06-05). IN-02 addkey HTTP-fetch fallback closed at addkey.go:528-538. WR-01 dead lastPID field removed across 4 modals. 11 new regression tests pin all three closures. |

No orphaned requirements - REQUIREMENTS.md maps exactly FW-09 / TUI-09 / TUI-10 / TUI-11 to Phase 6 and all four are claimed by plans 06-01 / 06-02 / 06-03 / 06-04 (with 06-05 as gap-closure for TUI-11) respectively.

### Anti-Patterns Found

**CR-01, IN-02, WR-01 closed by plan 06-05 — see Re-verification Context above.**

Remaining items (all pre-existing or v1.3 candidates; none block TUI-11 ship):

| File | Line | Pattern | Severity | Impact | Status |
|------|------|---------|----------|--------|--------|
| ~~internal/tui/screens/addkey/addkey.go:624~~ | ~~624~~ | ~~Hardcoded `pid: 0` in committedMsg (production path)~~ | ~~Blocker (CR-01)~~ | ~~Renders `Run kill -9 0` on D-08 hang escalation~~ | **CLOSED 06-05** — `if msg.pid <= 0` gate at addkey.go:706-716 renders subprocess-free fallback. |
| ~~internal/tui/screens/applysetup/applysetup.go:645~~ | ~~645~~ | ~~Hardcoded `pid: 0` in applyDoneMsg~~ | ~~Blocker (CR-01)~~ | ~~Same~~ | **CLOSED 06-05** — shared helper gate at applysetup.go:678-685. |
| ~~internal/tui/screens/deleteuser/deleteuser.go:585~~ | ~~585~~ | ~~Hardcoded `pid: 0` in submitDoneMsg~~ | ~~Blocker (CR-01)~~ | ~~Same~~ | **CLOSED 06-05** — dual-arm gates at deleteuser.go:392-400 + 428-435. |
| ~~internal/tui/screens/pwauthdisable/pwauthdisable.go~~ | ~~577,590,607,615~~ | ~~submitDoneMsg without pid: field (zero-default)~~ | ~~Blocker (CR-01)~~ | ~~Same~~ | **CLOSED 06-05** — shared helper gate at pwauthdisable.go:732-739. |
| ~~internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go~~ | ~~various~~ | ~~`lastPID int` field declared on Model but never written from goroutine~~ | ~~Warning (WR-01)~~ | ~~Dead code~~ | **CLOSED 06-05** — field removed from all 4 Model structs. |
| ~~internal/tui/screens/addkey/addkey.go:533-541~~ | ~~533-541~~ | ~~Hang diagnostic on resolveAsync (HTTP/file-fetch) renders "subprocess PID=0 still alive"~~ | ~~Info (IN-02)~~ | ~~Misleading copy~~ | **CLOSED 06-05** — fetch-specific copy at addkey.go:528-538. |
| cmd/sftp-jailer/main.go | 284-291,401,424 | `&usersCfg` captured by factory closures; S-SETTINGS save updates m.settings (private copy) but not the shared usersCfg | Warning (WR-02) | Phase 6 regression: TUI-09 added editable rows, but live TUI sees stale aging/stale/window values until restart. Disk write succeeds; in-process reads are stale. | OPEN — deferred to v1.3 per 06-05-SUMMARY.md (TUI-restart-required toast hint as v1.2 mitigation). |
| internal/tui/screens/userlog/userlog.go | 196,217 | `context.WithTimeout(context.Background(), 30*time.Second)` not cancelled on modal pop | Info (IN-01) | Up to 30s of wasted SQLite query time per pop on read-only modal | OPEN — deferred to v1.3 (performance polish, not correctness). |
| internal/store/queries.go | 243-246 | `rows.Err()` after `rows.Close()` instead of conventional Go ordering | Info (IN-03) | No functional bug; minor stylistic inconsistency with FilterEvents pattern. | OPEN — stylistic only. |
| internal/tui/screens/addkey/addkey.go | 533-534 | Fetch-fallback copy "Modal stays open until the request returns" is slightly stale (handleFetched runs after fetchedMsg arrives) | Info (06-REVIEW IN-01 post-06-05) | Cosmetic copy issue only; no integration impact. | OPEN — deferred to v1.3 polish pass. |
| internal/tui/screens/deleteuser/deleteuser.go | 121-153 | deleteuser.Model omits `errFatal` field that the other 3 modals carry | Info (06-REVIEW IN-02 post-06-05) | Pre-existing structural divergence; "cancelled by Esc" renders Critical instead of Warn. Visual-only. | OPEN — pre-existing; deferred to v1.3 polish pass. |

### Human Verification — Pre-agreed Deferral (D-16)

The two FW-09 UAT runbook executions below are **pre-agreed v1.2.x deferrals**, not v1.2 ship blockers. Per 06-01 D-14, production code is already protocol-agnostic (zero production lines changed in 06-01); per D-16, ship status is `verified-code, UAT-pending` for v1.2 with operator UAT execution flipping the checkbox in v1.2.x.

#### 1. FW-09 Variant A - Dual-family UAT Runbook Execution (v1.2.x)

**Test:** Provision a real Ubuntu 24.04 VM with `IPV6=yes` in `/etc/default/ufw` and a dual-family ufw policy (both v4 `Anywhere` and v6 `Anywhere (v6)` catch-alls present). Execute docs/uat/06-fw09-uat.md Variant A steps A.0-A.6: confirm pre-flight, add IPv4 + IPv6 per-user rules via M-ADD-RULE, trigger S-LOCKDOWN commit, capture `ufw status numbered` evidence pre/post commit, sign off.
**Expected:** Both v4 and v6 catch-all rules deleted in a single S-LOCKDOWN pass; per-user v4 + v6 rules with `# sftpj:v=1:user=alice` comments survive; zero catch-all rows after commit. Operator signs PASS in the runbook table.
**Why human:** Empirical UAT acceptance gate per ROADMAP Phase 6 SC1. teatest fixtures pin the predicate against synthetic stdouts; only a live `ufw 0.36.2` binary against kernel netfilter on a real v6-enabled VM can validate the end-to-end path. Documented as `verified-code, UAT-pending` in 06-01-SUMMARY.md per D-16.

#### 2. FW-09 Variant B - V6-only UAT Runbook Execution (v1.2.x)

**Test:** Provision a v6-only VM (no v4 default policy enabling Anywhere; `ufw status numbered` shows only a v6 catch-all). Execute docs/uat/06-fw09-uat.md Variant B steps B.0-B.4: confirm pre-flight, add a v6 per-user rule, trigger S-LOCKDOWN commit, verify exactly one delete occurred, capture evidence.
**Expected:** Single v6 catch-all delete terminates cleanly; loop exits because no catch-all remains; per-user v6 rule survives. Operator signs PASS.
**Why human:** Same UAT acceptance gate. v6-only edge is the precise BUG-04-B closure scenario.

### Gaps Summary

**RESOLVED 2026-05-01T13:30:00Z** — TUI-11 must-have #8 (D-08 hang diagnostic) closed by plan 06-05 via path (B) gating. All 4 mutation modals now safely render the subprocess-free fallback when no live PID is available (production path). The verbatim D-08 live-PID copy is preserved on the `pid > 0` branch (test-seam path, exercised by `Feed*ForTestWithPID` injection).

The cancellation core (06-04) works correctly:
- Esc dispatches m.cancelFn()
- cmd.Cancel sends SIGTERM (Pitfall 1 race handled)
- cmd.WaitDelay = 2s drives stdlib SIGKILL fallback
- handleCommitted/applyCancellationClassification classify via errors.Is(context.Canceled) BEFORE success/fatal (Pitfall 2 closed)
- D-07 'Cancelling...' indicator renders during cancellation phase
- Modal stays open until done-msg arrives

The hang-diagnostic safety closure (06-05) adds:
- `if msg.pid <= 0` gate in all 4 modals' classification helpers / Update arms
- Subprocess-free fallback string (byte-identical across all 4 modals) for the production path
- Verbatim D-08 live-PID copy preserved for the `pid > 0` branch
- 11 new regression tests pin both branches across all 4 modals
- IN-02 fetch-specific copy in addkey for the HTTP/file-fetch hang path
- WR-01 dead `lastPID` field removed from 4 Model structs

**Path (A) — extending `txn.Tx.Apply` to surface per-step `ExecResult.PID` so production hang diagnostics can render the live PID — is tracked as a v1.3 follow-up per 06-05-SUMMARY.md.** Not required for v1.2 ship.

### Outstanding (non-blocking, deferred to v1.3 per 06-05 + 06-REVIEW)

- WR-02: S-SETTINGS save does not refresh in-process `usersCfg` (TUI-restart-required toast hint as v1.2 mitigation)
- IN-01: userlog read-only goroutines not cancelled on modal pop (performance polish)
- IN-03: queries.go rows.Err() ordering (stylistic cleanup)
- 06-REVIEW IN-01 (post-06-05): addkey fetch-fallback copy slightly stale
- 06-REVIEW IN-02 (post-06-05): deleteuser.Model omits errFatal field (visual-only divergence)

### FW-09 — pre-agreed UAT-pending (D-16)

`docs/uat/06-fw09-uat.md` Variants A (dual-family) and B (v6-only) await operator execution on real IPv6 VMs. Production code is family-agnostic per 06-01 D-14 (zero production lines changed). Per D-16, this UAT is deferred to v1.2.x checkbox flip and is **not** a code gap — the regression net (3 unit tests + 2 testdata fixtures) holds the contract until empirical UAT lands.

---

_Verified: 2026-05-01T13:30:00Z (4/4 verified after plan 06-05 closure of CR-01 / IN-02 / WR-01)_
_Verifier: Claude (gsd:verify-work re-verify pass)_
_Previous verification: 2026-05-01T00:00:00Z (3/4, gaps_found — TUI-11 partial on CR-01)_
