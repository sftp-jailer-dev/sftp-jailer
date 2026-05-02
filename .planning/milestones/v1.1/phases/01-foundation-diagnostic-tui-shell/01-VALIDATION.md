---
phase: 01
slug: foundation-diagnostic-tui-shell
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-01
---

# Phase 01 - Validation Strategy

> Retroactive Nyquist audit. Phase 01 (foundation, diagnostic & TUI shell) shipped 5 plans before this validation contract was written. This document reconstructs the verification map from PLAN/SUMMARY artifacts and cross-references against the existing Go test suite.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go 1.25 stdlib `testing` + `github.com/stretchr/testify v1.11.1` |
| **Config file** | `go.mod` (no separate test config) |
| **Quick run command** | `go test -count=1 ./internal/sysops/... ./internal/service/doctor/... ./internal/sshdcfg/... ./internal/observe/... ./internal/store/... ./internal/ufwcomment/... ./internal/version/... ./internal/tui/... ./cmd/sftp-jailer/...` |
| **Full suite command** | `make test` (`go test -race -count=1 ./...`) |
| **Estimated runtime** | ~40-60s full suite (race-enabled), ~10s quick subset |
| **TUI integration tests** | `github.com/charmbracelet/x/exp/teatest/v2` for TUI screens |
| **Test files (count)** | 29 across 16 packages (Phase 1 subset) |
| **Suite status** | GREEN (verified 2026-05-01) |

---

## Sampling Rate

- **After every task commit:** `go test -count=1 ./<package-touched>/...`
- **After every plan wave:** `make test` (full race-enabled suite)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~60s (full suite)

---

## Per-Task Verification Map

| Plan | Requirement | Description | Impl Files | Test File / Function | Automated Command | Status |
|------|-------------|-------------|------------|----------------------|-------------------|--------|
| 01-01 | SAFE-01 | Go module skeleton + pinned Bubble Tea v2 stack; SAFE-01 root check via pure `rootCheckMessage` helper; architectural invariant guards | `cmd/sftp-jailer/root.go`, `cmd/sftp-jailer/main.go` | `root_test.go::TestRootCheckMessage_NonRoot_ReturnsExitMessage`, `TestRootCheckMessage_Root_ReturnsEmpty` | `go test ./cmd/sftp-jailer/...` | ✅ green |
| 01-01 | SAFE-01 | `sysops.SystemOps` interface + `Real` impl (LookPath-cached allowlist, 10s timeout, context-error precedence) | `internal/sysops/sysops.go`, `internal/sysops/real.go` | `sysops_test.go::TestReal_Exec_rejects_unlisted_binary`, `TestReal_Exec_honors_context_deadline` | `go test ./internal/sysops/...` | ✅ green |
| 01-01 | SAFE-01 | `sysops.Fake` scriptable impl with call recording and longest-prefix Exec matching | `internal/sysops/fake.go` | `sysops_test.go::TestFake_*` (8 subtests) | `go test ./internal/sysops/...` | ✅ green |
| 01-02 | TUI-01 | `?` toggles context-aware help overlay built from top screen's KeyMap | `internal/tui/app/app.go`, `internal/tui/widgets/help.go` | `app_test.go::TestApp_help_toggle_*` | `go test ./internal/tui/app/...` | ✅ green |
| 01-02 | TUI-02 | `q`/Ctrl-C exits cleanly; panic recovery; WriteRecoveryScript for SIGKILL terminal restore | `internal/tui/app/app.go`, `internal/tui/terminal.go` | `app_test.go::TestApp_q_*`, `widgets_test.go::TestWriteRecoveryScript_creates_executable_script` | `go test ./internal/tui/app/... ./internal/tui/widgets/...` | ✅ green |
| 01-02 | TUI-03 | `/` opens fuzzy search on home screen (textinput + sahilm/fuzzy) | `internal/tui/widgets/search.go`, `internal/tui/screens/home/home.go` | `widgets_test.go::TestSearch_Filter` | `go test ./internal/tui/widgets/...` | ✅ green |
| 01-02 | TUI-04 | Mouse support via `v.MouseMode = tea.MouseModeCellMotion` in App.View | `internal/tui/app/app.go` | `app_test.go::TestApp_mouse_wheel_no_panic` | `go test ./internal/tui/app/...` | ✅ green |
| 01-02 | TUI-05 | SIGWINCH: `tea.WindowSizeMsg` broadcast to every screen on the nav stack | `internal/tui/app/app.go` | `app_test.go::TestApp_ResizeBroadcastsToAllScreens` | `go test -run TestApp_ResizeBroadcastsToAllScreens ./internal/tui/app/...` | ✅ green |
| 01-02 | TUI-06 | OSC 52 clipboard copy via `tea.SetClipboard` + Toast confirmation flash | `internal/tui/screens/doctor/doctor.go`, `internal/tui/widgets/toast.go` | `doctor_test.go::TestOSC52_clipboard_cmd_nonNil`, `TestDoctorScreen_c_copies_when_report_loaded` | `go test ./internal/tui/screens/doctor/...` | ✅ green |
| 01-02 | TUI-07 | Color degradation via `colorprofile.Detect(os.Stdout, os.Environ())` + 4 pre-rendered ANSI variants (go:embed) | `internal/tui/screens/splash/splash.go` | `splash_test.go::TestSplash_View_includes_embedded_logo`, `TestSplash_pickVariant_*` | `go test ./internal/tui/screens/splash/...` | ✅ green |
| 01-02 | TUI-08 | ANSI splash (4-variant chafa logo, 1s auto-dismiss); About modal reopens splash via `splash.NewModal` | `internal/tui/screens/splash/splash.go`, `internal/tui/screens/about/about.go` | `splash_test.go::TestSplash_View_contains_version_and_URL`, `TestSplash_auto_dismiss_*` | `go test ./internal/tui/screens/splash/...` | ✅ green |
| 01-03 | DIST-01 | `CGO_ENABLED=0 go build -trimpath` produces single static binary; Makefile enforces flags; CI test job runs `go test -race` | `Makefile`, `.github/workflows/ci.yml` | `go test ./...` (full suite as CI proxy) | `make test` | ✅ green |
| 01-03 | DIST-06 | GitHub repo: README (logo + sftp-jailer.com + install stub + GPL-3.0 notice); LICENSE (verbatim GPL-3.0) | `README.md`, `LICENSE` | (CI builds + govulncheck as proxy; content verified by 01-VERIFICATION.md SC5) | `make test` | ✅ green |
| 01-03 | DIST-07 | CI runs `go test` + `golangci-lint v2.1` + `govulncheck` + 3 architectural-invariant guards on ubuntu-24.04 | `.github/workflows/ci.yml`, `.golangci.yml`, `scripts/check-*.sh` | CI job green; invariant guards: `bash scripts/check-no-exec-outside-sysops.sh`, `bash scripts/check-go-mod-pins.sh`, `bash scripts/check-single-tea-program.sh` | `bash scripts/check-no-exec-outside-sysops.sh && bash scripts/check-go-mod-pins.sh && bash scripts/check-single-tea-program.sh` | ✅ green |
| 01-04 | SAFE-01 | `doctor` subcommand enforces SAFE-01 gate (non-root exits 1 with sudo hint) | `cmd/sftp-jailer/main.go` | `root_test.go::TestRootCheckMessage_NonRoot_ReturnsExitMessage` | `go test ./cmd/sftp-jailer/...` | ✅ green |
| 01-04 | SETUP-01 | Six read-only detectors: detectSshdDropIns + detectChrootChain + detectUfwIPv6 + detectAppArmor + detectNftConsumers + detectSubsystem | `internal/service/doctor/doctor.go` | `doctor_test.go::TestService_Run_*`, `TestDetect*_*` | `go test ./internal/service/doctor/...` | ✅ green |
| 01-04 | SETUP-01 | `sshdcfg.ParseDropIn` comment-preserving line-based parser; `HasMatchGroup` + `GetDirective` | `internal/sshdcfg/parse_readonly.go` | `parse_readonly_test.go::TestParseDropIn_*`, `TestHasMatchGroup_*` | `go test ./internal/sshdcfg/...` | ✅ green |
| 01-04 | SETUP-01 | `RenderText` [OK]/[WARN]/[FAIL]/[INFO] renderer; `--json` flag emits `model.DoctorReport` JSON | `internal/service/doctor/render.go`, `cmd/sftp-jailer/main.go` | `render_test.go::TestRenderText_*` | `go test ./internal/service/doctor/...` | ✅ green |
| 01-04 | SETUP-01 | Doctor TUI screen: async Init, `c` copy, esc/q pop; pitfalls A5/C4/C5 retired | `internal/tui/screens/doctor/doctor.go` | `doctor_test.go::TestDoctorScreen_*` | `go test ./internal/tui/screens/doctor/...` | ✅ green |
| 01-05 | ARCH-GATE | `scripts/smoke-ufw.sh` VM-gated ufw-reload comment preservation (architecture-invalidating pre-Phase 4 gate); `internal/ufwcomment` Encode/Decode grammar + fuzz tests; `internal/observe` 4-tier classifier; `internal/store` SQLite WAL + migrations skeleton | `internal/ufwcomment/encode.go`, `internal/ufwcomment/decode.go`, `internal/observe/parse.go`, `internal/observe/classify.go`, `internal/store/store.go`, `scripts/smoke-ufw.sh` | `ufwcomment_test.go::TestEncode_*`, `TestDecode_*`, `FuzzRoundTrip`, `FuzzDecodeNeverPanics`; `classify_test.go::TestClassify_*`; `store_test.go::TestOpen_*`, `TestMigrate_*`; smoke-ufw.sh - deferred to Phase 4 | `go test ./internal/ufwcomment/... ./internal/observe/... ./internal/store/...` | ✅ green (smoke-ufw.sh deferred Phase 4) |

*Status legend: ✅ green - ❌ red - ⚠️ flaky - ⬜ pending*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No Wave 0 stub work needed:
- Go stdlib `testing` was already in place.
- `testify v1.11.1` was pinned in `go.mod` from plan 01-01.
- `teatest/v2` was pinned from plan 01-01 for TUI integration tests.
- All Phase 1 packages shipped their test files alongside implementation.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Splash to home transition on launch (ANSI logo visible ~1s, color-profile variant matches terminal) | TUI-08 / TUI-07 | Requires real TTY with color profile detection; teatest covers model transitions but not visual ANSI timing. Unit tests `TestSplash_View_includes_embedded_logo` and `TestSplash_View_contains_version_and_URL` lock the model. | Run `sudo ./bin/sftp-jailer` in a real color terminal (iTerm2/kitty/alacritty for truecolor, tmux for 256-color). Verify logo visible ~1s then home dashboard. Last passed: 2026-04-24 per 01-VERIFICATION.md item 1. |
| OSC 52 clipboard copy with confirmation flash | TUI-06 | OSC 52 integration with terminal emulator + system clipboard is inherently interactive. `TestOSC52_clipboard_cmd_nonNil` proves the v2 API is linked; `TestDoctorScreen_c_copies_when_report_loaded` proves `c` key dispatches `tea.Batch(SetClipboard, toastFlash)`. | Run `sudo ./bin/sftp-jailer` - press `d` (diagnostic) - wait for report - press `c`. Paste into another app. Verify "copied via OSC 52" toast appears. Last passed: 2026-04-24 per 01-VERIFICATION.md item 2. |
| Terminal recovery after SIGKILL | TUI-02 | SIGKILL behavior is outside the teatest framework. Recovery script is unit-tested for existence, mode 0o700, and containing `stty sane` + `\033[?1049l`. End-to-end path requires live TTY + signal injection. | Run `sudo ./bin/sftp-jailer` in terminal A. In terminal B: `kill -9 $(pgrep sftp-jailer)`. Run `/tmp/sftp-jailer-recover-<pid>.sh` in terminal A. Verify terminal restores to usable state. Last passed: 2026-04-24 per 01-VERIFICATION.md item 3. |
| Live `sudo sftp-jailer doctor` on Ubuntu 24.04 | SETUP-01 | Dev box is macOS - no `aa-status`/`nft`/`ufw`/`sshd` binaries. All six detectors have `sysops.Fake` unit tests against checked-in fixtures. Producing a live report requires Ubuntu 24.04 + root. | On fresh Ubuntu 24.04 VM: `sudo ./sftp-jailer doctor` must show 6-row report with [OK]/[WARN]/[FAIL]/[INFO] labels. `sudo ./sftp-jailer doctor --json \| jq .` must produce valid JSON. Last passed: 2026-04-24 per 01-VERIFICATION.md item 4. |

---

## Deferred to Later Phases

The following Phase 1 truths are not satisfied at Phase 1 close but are explicitly addressed by later phases. Manual-Only above retains its meaning of "inherently manual at this phase"; the rows below are deferrals, not manual checks.

| Truth | Deferred to | Evidence Pointer |
|-------|-------------|------------------|
| j/k/arrows/g/G vim-style navigation on TUI | Phase 2 | REQUIREMENTS.md USER-02 explicitly requires vim-style navigation on the users table; Phase 2 ships the first list screen that consumes the nav.KeyBinding/nav.KeyMap scaffolding from Phase 1. Home is a landing screen with no scrollable surface. See `02-VALIDATION.md` rows for USER-02. |
| scripts/smoke-ufw.sh Ubuntu 24.04 VM execution | Phase 4 | Plan 01-05 SUMMARY documents Phase 4 phase-start gate: "Phase 4's first plan must run scripts/smoke-ufw.sh on an Ubuntu 24.04 VM as a phase-start gate before committing any firewall mutation code." See `04-VALIDATION.md` Manual-Only row for empirical UAT scenario. |
| DIST-07 lintian --pedantic gate on the .deb | Phase 5 | The `.deb` artifact does not exist until Phase 5's goreleaser/nfpm pipeline. ROADMAP Phase 5 retires pitfall F3. Phase 1 CI covers `go test`, `golangci-lint`, and `govulncheck` - the three portions of DIST-07 actionable pre-package. See `05-VALIDATION.md` (planned) for DIST-03 lintian gate. |

---

## Validation Sign-Off

- [x] All tasks have automated `<verify>` commands or are documented as manual-only with live TTY evidence from 01-VERIFICATION.md
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every plan committed test artifacts)
- [x] Wave 0 covers all MISSING references - none required, infrastructure pre-existed
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 60s (full race-enabled suite approximately 40-60s)
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Human verification items (splash visual, OSC 52, SIGKILL recovery, Ubuntu doctor run) validated 2026-04-24 per 01-VERIFICATION.md score 5/5 must-haves
- [x] 3 Phase 1 deferred truths documented in Deferred to Later Phases section with receiving phase cited

**Approval:** approved 2026-05-01

---

## Validation Audit 2026-05-01

| Metric | Count |
|--------|-------|
| Requirements analyzed | 12 (SAFE-01, SETUP-01, TUI-01..08, DIST-01, DIST-06, DIST-07) |
| COVERED | 11 (SAFE-01 + SETUP-01 + TUI-01..08 + DIST-01 + DIST-06; all have automated test coverage) |
| PARTIAL | 1 (DIST-07: Phase 1 CI covers test/lint/vuln; lintian --pedantic deferred to Phase 5) |
| MISSING | 0 |
| Manual-only items | 4 (splash visual, OSC 52, SIGKILL recovery, Ubuntu doctor live run) + 3 deferred truths |
| Suite status | GREEN (verified 2026-05-01) |
| Gaps filled this audit | 0 (no test code generated - coverage was already complete) |
