---
phase: 06-v1-1-carry-over-closure-firewall-edge-tui-polish
verified: 2026-05-01T00:00:00Z
status: gaps_found
score: 3/4 must-haves verified (1 partial gap, 1 human-verification item)
overrides_applied: 0
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
    status: partially-satisfied
    plan: 06-04
    evidence: sysops.Exec SIGTERM+2s+SIGKILL policy lands; ExecResult.PID populated; 9 detached contexts replaced; 4 modals wire Esc to cancelFn with Cancelling indicator; D-08 verbatim copy substrings present; CR-01 partial gap - production renders `Run kill -9 0` because tx.Apply does not surface ExecResult.PID
gaps:
  - truth: "When SIGKILL fails to release the subprocess within 2s (hang escalation, D-08), the modal renders 'Cancellation failed - subprocess PID=<N> still alive. Run kill -9 <N> from another shell.' with the live PID injected."
    status: partial
    reason: "Production code path renders `Run kill -9 0` (not a live PID). The 4 modal goroutines hardcode `pid: 0` in their done-msgs because tx.Apply does not expose per-step ExecResult.PID. Test seams (FeedCommittedMsgForTestWithPID etc) inject synthetic PIDs (12345, 54321, 31415, 99001) which is what the teatest assertions exercise. The must-have explicitly requires `the live PID` - 0 is not a live PID. CR-01 is a SAFETY concern: kill(2) semantics on Linux/POSIX treat PID 0 as 'every process in the calling shell's process group', so an admin literally copy-pasting `kill -9 0` from a TTY where they backgrounded sftp-jailer could DoS their own session."
    artifacts:
      - path: "internal/tui/screens/addkey/addkey.go"
        issue: "line 624 hardcodes `return committedMsg{err: err, pid: 0}`; lastPID field declared but never written from a goroutine"
      - path: "internal/tui/screens/applysetup/applysetup.go"
        issue: "line 645 hardcodes `return applyDoneMsg{err: tx.Apply(ctx, steps), pid: 0}`"
      - path: "internal/tui/screens/deleteuser/deleteuser.go"
        issue: "line 585 hardcodes `return submitDoneMsg{err: err, pid: 0}`"
      - path: "internal/tui/screens/pwauthdisable/pwauthdisable.go"
        issue: "line 577,590,607,615 omit pid: field (zero-defaults)"
    missing:
      - "Plumb the most-recent ExecResult.PID out of tx.Apply (e.g. extend Tx.Apply to return *ExecResult or invoke a per-step callback) so production goroutines populate the field for real."
      - "OR add a `if msg.pid <= 0` fallback diagnostic (e.g. 'Cancellation failed - subprocess refused SIGTERM/SIGKILL within 2s. Inspect `ps -ef | grep <child-binary>` from another shell to identify the live PID.')."
      - "Add a regression test that pins the PID=0 fallback string so a future regression that re-introduces `kill -9 0` is caught."
      - "Distinguish HTTP/file-fetch hang from subprocess hang in addkey.go (IN-02): the resolveAsync path has no subprocess; rendering 'subprocess PID=0 still alive' is dishonest copy."
human_verification:
  - test: "FW-09 Variant A - dual-family UAT runbook execution"
    expected: "On a real Ubuntu 24.04 VM with IPV6=yes and a dual-family ufw policy, S-LOCKDOWN commit deletes both v4 and v6 catch-all rules in one pass; per-user v4 and v6 rules with `# sftpj:v=1:user=alice` comments survive. Operator signs off in docs/uat/06-fw09-uat.md."
    why_human: "Empirical UAT acceptance gate per ROADMAP Phase 6 SC1. teatest fixtures prove the predicate is family-agnostic on synthetic stdouts; the real ufw 0.36.2 binary on a kernel-netfilter-backed v6 path can only be exercised on a live VM."
  - test: "FW-09 Variant B - v6-only UAT runbook execution"
    expected: "On a v6-only VM (no v4 default policy), S-LOCKDOWN commit deletes the single v6 catch-all and terminates cleanly; admin verifies `ufw status numbered` shows zero catch-all rows; operator signs off."
    why_human: "Same UAT acceptance gate, v6-only edge. Documented in docs/uat/06-fw09-uat.md as Variant B (5 numbered steps); ship status `verified-code, UAT-pending` per D-16."
deferred: []
---

# Phase 6: v1.1 Carry-over Closure - Verification Report

**Phase Goal:** Close the v1.1 carry-over tech debt that was opportunistically deferred from Phase 4 - one firewall correctness bug (FW-09), two UX polish items (TUI-09, TUI-10), and one code-quality cleanup (TUI-11).
**Verified:** 2026-05-01
**Status:** gaps_found
**Re-verification:** No - initial verification.

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | BUG-04-B closure on dual-family + v6-only hosts (FW-09). Empirical UAT on IPv6-enabled VM is acceptance gate. | VERIFIED-CODE, UAT-PENDING | 3 new tests (TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6, TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment, TestEnumerate_v6_source_rule_decodes_user_round_trip) all green; 2 testdata fixtures committed; docs/uat/06-fw09-uat.md authored with 12 numbered steps across Variant A (dual-family) and Variant B (v6-only); production code already protocol-agnostic per D-14 (zero production lines changed). UAT VM execution deferred per D-16. |
| 2 | S-SETTINGS exposes password-aging knobs (TUI-09). Editable, validated (positive int, max 3650), round-trip via existing settings writer. | VERIFIED | fieldPasswordAgingDays + fieldPasswordStaleDays iota constants land before fieldKindCount; 5 switch arms wired (name/hint/currentValue/valueFor/attemptSave); `between 1 and 3650` cap in config.Validate for both fields; strict-ordering rule (aging < stale) preserved verbatim; 6 teatest cases + 5 config_test cases pin the contract. |
| 3 | Per-user log-detail modal (TUI-10). Last 90 days, tier counts + last 20 entries. | VERIFIED | New internal/tui/screens/userlog package (Model, Init, Update, View, KeyMap); store.Queries.PerUserBreakdown signature extended with sinceNs int64 (sentinel zero disables - mirrors FilterEvents.SinceNs); logs.DisplayN/ColorByTier/TierGlyph re-exported for cross-package row formatter parity; userLogFactory + SetUserLogFactory injection seam in usersscreen; case "L" handler in handleKey; cmd/sftp-jailer/main.go wires SetUserLogFactory at TUI bootstrap; 5+ teatest cases pin header rendering / empty state / OSC 52 / window from config / 20-row cap; W-03 d/D regression guards still pass. |
| 4 | Cancellable resolveAsync paths (TUI-11). SIGTERM + 2s SIGKILL grace in addkey/deleteuser/applysetup/pwauthdisable. | PARTIAL (CR-01) | Cancellation core works: sysops.Exec sets cmd.Cancel = SIGTERM closure (with os.ErrProcessDone -> nil, Pitfall 1) and cmd.WaitDelay = 2s; ExecResult.PID populated via cmd.Process.Pid captured before Wait; 9 detached context.Background() sites replaced with stored cancellable contexts; all 4 modals route Esc-during-async to m.cancelFn() with Cancelling indicator (D-07); cancellation classified via errors.Is(context.Canceled) BEFORE success/fatal branches (Pitfall 2). HOWEVER - production renders `Run kill -9 0` because tx.Apply does not surface ExecResult.PID; the 4 modal goroutines hardcode pid: 0 in their done-msgs. The must-have requires `the live PID injected` - 0 is not a live PID. See CR-01 in Gaps Summary. |

**Score:** 3/4 truths verified (1 partial gap on TUI-11 hang diagnostic).

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
| `internal/tui/screens/addkey/addkey.go` | stored cancelFn + Esc handler + Cancelling indicator + D-08 hang diagnostic | PARTIAL | cancelFn/cancelling/lastPID fields land; m.cancelFn() invoked from Esc; Cancelling substring lands 8x; Run kill -9, Cancellation failed, from another shell substrings land. CR-01: line 624 hardcodes `pid: 0` so production renders `Run kill -9 0`; lastPID field never written from goroutine |
| `internal/tui/screens/deleteuser/deleteuser.go` | same as addkey | PARTIAL | Same as above; line 585 hardcodes `pid: 0` |
| `internal/tui/screens/applysetup/applysetup.go` | same as addkey | PARTIAL | Same as above; line 645 hardcodes `pid: 0` |
| `internal/tui/screens/pwauthdisable/pwauthdisable.go` | same as addkey | PARTIAL | Same as above; lines 577/590/607/615 omit pid: (zero-defaults) |

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
| each modal's done-msg goroutine | done-msg PID field populated from ExecResult.PID | msg.pid = result.PID | NOT_WIRED | CR-01: production hardcodes `pid: 0` because tx.Apply does not surface ExecResult.PID. Test seams (FeedCommittedMsgForTestWithPID) inject synthetic PIDs to bypass the production path. |
| each modal's handleKey case esc during async phase | stored m.cancelFn func from context.WithCancel | `if m.cancelFn != nil { m.cancelFn() }; m.cancelling = true` | WIRED | All 4 modals have m.cancelFn() invocation in Esc handler |
| each modal's handleCommitted (or equivalent done-handler) | neutral cancelled-state branch | `if m.cancelling && (err==nil || errors.Is(err, context.Canceled)) -> render 'cancelled by Esc'` | WIRED | All 4 modals classify cancellation via errors.Is BEFORE success/fatal branches (Pitfall 2 closed) |
| each modal's handleCommitted hang branch | D-08 verbatim diagnostic copy with live PID | `fmt.Sprintf("Cancellation failed - subprocess PID=%d still alive. Run kill -9 %d from another shell.", pid, pid)` | PARTIAL | Substrings 'Cancellation failed', 'Run kill -9', 'from another shell' all land verbatim in source. The verbatim copy is grep-asserted; however the live PID injected at runtime is `0` in production, see CR-01. |
| each modal's View() during phaseCancelling | 'Cancelling...' indicator render | lipgloss render of 'Cancelling...' when m.cancelling == true | WIRED | 'Cancelling' substring lands 8-9x in each modal source (View + tests) |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `userlog.Model.events` | events []store.Event | FilterEvents(ctx, FilterOpts{User, SinceNs, Limit:20}) | Yes (real DB query: SELECT FROM observations WHERE user = ? AND (...) LIMIT 20) | FLOWING |
| `userlog.Model.breakdown` | breakdown store.UserBreakdown | PerUserBreakdown(ctx, user, sinceNs) | Yes (real DB query: SELECT tier, COUNT(*) FROM observations WHERE user = ? AND (? = 0 OR ts_unix_ns >= ?) GROUP BY tier) | FLOWING |
| `settings.Model.settings` | settings *config.Settings | config.Load -> overlayDefaults -> tied to Save round-trip | Yes (koanf-loaded YAML; round-trip pinned by save test) | FLOWING |
| Each modal's done-msg `pid` field | msg.pid int | tx.Apply does NOT propagate ExecResult.PID; goroutines hardcode `pid: 0` | NO (always 0 in production) | HOLLOW (CR-01) |

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

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| FW-09 | 06-01 | Close BUG-04-B - catch-all delete on dual-family + v6-only | SATISFIED-CODE / NEEDS HUMAN (UAT) | 3 tests + 2 fixtures + 12-step UAT runbook authored. Production code already protocol-agnostic per D-14. Empirical IPv6 VM execution deferred to v1.2.x checkbox flip per D-16 - this is a pre-agreed acceptance posture, not a gap. |
| TUI-09 | 06-02 | S-SETTINGS exposes PasswordAgingDays + PasswordStaleDays as editable fields | SATISFIED | 2 iotas + 5 switch arms + max=3650 cap in config.Validate + 6 teatest cases pin the contract |
| TUI-10 | 06-03 | Per-user log-detail modal on uppercase L | SATISFIED | New userlog package + L keybind dispatch + factory wiring + sinceNs filter close Pitfall 5 |
| TUI-11 | 06-04 | Cancellable resolveAsync paths in 4 modals (SIGTERM + 2s SIGKILL grace) | PARTIAL (CR-01) | Cancellation core (SIGTERM+2s+SIGKILL) works as specified by ROADMAP SC4. The D-08 hang-diagnostic must-have requires `the live PID injected` - production renders PID=0 because tx.Apply does not surface ExecResult.PID. |

No orphaned requirements - REQUIREMENTS.md maps exactly FW-09 / TUI-09 / TUI-10 / TUI-11 to Phase 6 and all four are claimed by plans 06-01 / 06-02 / 06-03 / 06-04 respectively.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| internal/tui/screens/addkey/addkey.go | 624 | Hardcoded `pid: 0` in committedMsg (production path) | Blocker (CR-01) | Renders `Run kill -9 0` on D-08 hang escalation; kill(2) PID 0 = SIGKILL the calling process group. Safety-relevant if admin copy-pastes. |
| internal/tui/screens/applysetup/applysetup.go | 645 | Hardcoded `pid: 0` in applyDoneMsg | Blocker (CR-01) | Same |
| internal/tui/screens/deleteuser/deleteuser.go | 585 | Hardcoded `pid: 0` in submitDoneMsg | Blocker (CR-01) | Same |
| internal/tui/screens/pwauthdisable/pwauthdisable.go | 577,590,607,615 | submitDoneMsg without pid: field (zero-default) | Blocker (CR-01) | Same |
| internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go | various | `lastPID int` field declared on Model but never written from goroutine | Warning (WR-01) | Dead code; misleading because plan said "the goroutine captures the most-recent ExecResult.PID into local lastPID variable". |
| cmd/sftp-jailer/main.go | 284-291,401,424 | `&usersCfg` captured by factory closures; S-SETTINGS save updates m.settings (private copy) but not the shared usersCfg | Warning (WR-02) | Phase 6 regression: TUI-09 added editable rows, but live TUI sees stale aging/stale/window values until restart. Disk write succeeds; in-process reads are stale. |
| internal/tui/screens/userlog/userlog.go | 196,217 | `context.WithTimeout(context.Background(), 30*time.Second)` not cancelled on modal pop | Info (IN-01) | Up to 30s of wasted SQLite query time per pop on read-only modal; same anti-pattern TUI-11 closed for mutation modals (read-only is out of TUI-11 scope). |
| internal/tui/screens/addkey/addkey.go | 533-541 | Hang diagnostic on resolveAsync (HTTP/file-fetch) renders "subprocess PID=0 still alive" - no subprocess in fetch path | Info (IN-02) | Misleading copy; compounds CR-01. |
| internal/store/queries.go | 243-246 | `rows.Err()` after `rows.Close()` instead of conventional Go ordering | Info (IN-03) | No functional bug; minor stylistic inconsistency with FilterEvents pattern. |

### Human Verification Required

#### 1. FW-09 Variant A - Dual-family UAT Runbook Execution

**Test:** Provision a real Ubuntu 24.04 VM with `IPV6=yes` in `/etc/default/ufw` and a dual-family ufw policy (both v4 `Anywhere` and v6 `Anywhere (v6)` catch-alls present). Execute docs/uat/06-fw09-uat.md Variant A steps A.0-A.6: confirm pre-flight, add IPv4 + IPv6 per-user rules via M-ADD-RULE, trigger S-LOCKDOWN commit, capture `ufw status numbered` evidence pre/post commit, sign off.
**Expected:** Both v4 and v6 catch-all rules deleted in a single S-LOCKDOWN pass; per-user v4 + v6 rules with `# sftpj:v=1:user=alice` comments survive; zero catch-all rows after commit. Operator signs PASS in the runbook table.
**Why human:** Empirical UAT acceptance gate per ROADMAP Phase 6 SC1. teatest fixtures pin the predicate against synthetic stdouts; only a live `ufw 0.36.2` binary against kernel netfilter on a real v6-enabled VM can validate the end-to-end path. Documented as `verified-code, UAT-pending` in 06-01-SUMMARY.md per D-16.

#### 2. FW-09 Variant B - V6-only UAT Runbook Execution

**Test:** Provision a v6-only VM (no v4 default policy enabling Anywhere; `ufw status numbered` shows only a v6 catch-all). Execute docs/uat/06-fw09-uat.md Variant B steps B.0-B.4: confirm pre-flight, add a v6 per-user rule, trigger S-LOCKDOWN commit, verify exactly one delete occurred, capture evidence.
**Expected:** Single v6 catch-all delete terminates cleanly; loop exits because no catch-all remains; per-user v6 rule survives. Operator signs PASS.
**Why human:** Same UAT acceptance gate. v6-only edge is the precise BUG-04-B closure scenario.

### Gaps Summary

**TUI-11 must-have #8** (D-08 hang diagnostic with live PID injected) is partially satisfied. The verbatim string contract is met in source (substrings `Cancellation failed`, `Run kill -9 %d`, `from another shell` all present); however the production runtime PID is always `0` because `tx.Apply` returns only `error` and does not surface per-step `ExecResult.PID` to the modal goroutine. The 4 modal goroutines hardcode `pid: 0` in their done-msgs; tests inject synthetic PIDs (12345, 54321, 31415, 99001) via `Feed*ForTestWithPID` seams to satisfy the verbatim assertion.

This is **CR-01** in 06-REVIEW.md and is explicitly flagged as critical because `kill -9 0` on Linux/POSIX kills the calling shell's process group - a literal copy-paste from a TTY where `sftp-jailer` was backgrounded would DoS the admin's session.

The cancellation core itself works correctly:
- Esc dispatches m.cancelFn()
- cmd.Cancel sends SIGTERM (Pitfall 1 race handled)
- cmd.WaitDelay = 2s drives stdlib SIGKILL fallback
- handleCommitted classifies via errors.Is(context.Canceled) BEFORE success/fatal (Pitfall 2 closed)
- D-07 'Cancelling...' indicator renders during cancellation phase
- Modal stays open until done-msg arrives

The fix is plumbing-only (extend `tx.Apply` signature OR add a `msg.pid <= 0` fallback diagnostic). Until then, hang escalation in production renders dangerous instructions.

---

## Re-verification path forward

To close this gap, plan a 06-05 patch plan:

1. Either extend `txn.Tx.Apply` to return `(*ExecResult, error)` (or invoke a per-step callback that updates `m.lastPID` via a tea.Cmd race-safe write), OR add a `if msg.pid <= 0` fallback diagnostic in each of the 4 modal handleCommitted/handleSubmitDone/handleApplyDone branches.
2. Add a regression test pinning the PID=0 fallback string so a future change doesn't accidentally re-introduce `Run kill -9 0`.
3. Address IN-02 (addkey HTTP/file-fetch hang diagnostic) at the same time - the resolveAsync path is not subprocess-based and the current "subprocess PID=0 still alive" copy is misleading.

Optional follow-ups (not required to close TUI-11):
- WR-02 (S-SETTINGS save does not refresh in-process usersCfg) - track for v1.3 unless v1.2 ships with a "TUI restart required" toast hint.
- IN-01 (userlog read-only goroutines not cancelled on modal pop) - performance polish.
- IN-03 (queries.go rows.Err() ordering) - stylistic cleanup.

---

_Verified: 2026-05-01_
_Verifier: Claude (gsd-verifier)_
