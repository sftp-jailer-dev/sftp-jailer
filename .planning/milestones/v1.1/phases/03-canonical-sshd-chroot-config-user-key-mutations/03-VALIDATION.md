---
phase: 03
slug: canonical-sshd-chroot-config-user-key-mutations
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-01
---

# Phase 03 - Validation Strategy

> Retroactive Nyquist audit. Phase 03 (Canonical sshd/Chroot Config and User+Key Mutations) shipped 10 plans (03-01 through 03-09 with 03-08a/03-08b split) before this validation contract was written. This document reconstructs the verification map from PLAN/SUMMARY artifacts and cross-references against the existing Go test suite.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go 1.25 stdlib `testing` + `github.com/stretchr/testify v1.11.1` |
| **Config file** | `go.mod` (no separate test config) |
| **Quick run command** | `go test -count=1 ./internal/sshdcfg/... ./internal/chrootcheck/... ./internal/keys/... ./internal/users/... ./internal/sysops/... ./internal/txn/... ./internal/store/... ./internal/tui/screens/applysetup/... ./internal/tui/screens/newuser/... ./internal/tui/screens/password/... ./internal/tui/screens/userdetail/... ./internal/tui/screens/deleteuser/... ./internal/tui/screens/addkey/... ./internal/tui/screens/pwauthdisable/...` |
| **Full suite command** | `make test` (`go test -race -count=1 ./...`) |
| **Estimated runtime** | ~16s Phase 3 subset (non-race), ~40s full race-enabled suite |
| **TUI integration tests** | `github.com/charmbracelet/x/exp/teatest/v2` for screens/widgets |
| **Test files (count)** | 27 across the Phase 3 package subset |
| **Suite status** | GREEN (verified 2026-05-01) |

---

## Sampling Rate

- **After every task commit:** `go test -count=1 ./<package-touched>/...`
- **After every plan wave:** `make test` (full race-enabled suite)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~40s (full suite)

---

## Per-Task Verification Map

| Plan | Requirement | Description | Impl Files | Test File / Function | Automated Command | Status |
|------|-------------|-------------|------------|----------------------|-------------------|--------|
| 03-01 | SAFE-02 | `SshdT` typed wrapper - sshd -t before reload (SAFE-02 gate infrastructure) | `internal/sysops/sysops.go`, `internal/sysops/real.go`, `internal/sysops/fake.go` | `sysops_test.go::TestFake_SshdT_*`, `TestReal_SshdT_*` | `go test ./internal/sysops/...` | ✅ green |
| 03-01 | SAFE-06 | `SystemctlReload/RestartSocket/DaemonReload` typed wrappers for SAFE-06 reload dispatcher (Launchpad #2069041) | `internal/sysops/real.go`, `internal/sysops/fake.go` | `sysops_test.go::TestFake_SystemctlReload_*`, `TestFake_SystemctlRestartSocket_*`, `TestFake_SystemctlDaemonReload_*` | `go test ./internal/sysops/...` | ✅ green |
| 03-01 | SETUP-05 | `Useradd/Gpasswd/Chmod/Chown` typed wrappers for per-user dir creation (mode 0750) | `internal/sysops/sysops.go`, `internal/sysops/real.go`, `internal/sysops/fake.go` | `sysops_test.go::TestFake_Useradd_*`, `TestFake_Gpasswd_*`, `TestFake_Chmod_*`, `TestFake_Chown_*` | `go test ./internal/sysops/...` | ✅ green |
| 03-01 | USER-04 | UID-collision rejection infrastructure + `/etc/shells` gate via `Useradd` typed opts | `internal/sysops/sysops.go` (`UseraddOpts`), `internal/sysops/real.go` | `sysops_test.go::TestFake_Useradd_records_call_with_typed_argv` | `go test ./internal/sysops/...` | ✅ green |
| 03-01 | USER-05 | `Chpasswd` stdin-piped wrapper - password never on argv (pitfall E3); `ChpasswdError` carries pam_pwquality stderr | `internal/sysops/chpasswd.go` | `sysops_test.go::TestFake_Chpasswd_*` | `go test -run TestFake_Chpasswd ./internal/sysops/...` | ✅ green |
| 03-01 | USER-07 | `Chage` typed wrapper for force-change-next-login (`chage -d 0`) | `internal/sysops/sysops.go`, `internal/sysops/real.go`, `internal/sysops/fake.go` | `sysops_test.go::TestFake_Chage_*` | `go test -run TestFake_Chage ./internal/sysops/...` | ✅ green |
| 03-01 | USER-12 | `Userdel/Tar/MkdirAll` typed wrappers for archive-vs-permanent delete paths | `internal/sysops/real.go`, `internal/sysops/fake.go` | `sysops_test.go::TestFake_Userdel_*`, `TestFake_Tar_*`, `TestFake_MkdirAll_*`, `TestFake_RemoveAll_*` | `go test ./internal/sysops/...` | ✅ green |
| 03-01 | USER-14 | `WriteAuthorizedKeys` composite typed wrapper (D-18) + `SshdTWithContext` for D-21 step 4; `AtomicWriteFile` for authorized_keys atomicity | `internal/sysops/atomic.go`, `internal/sysops/real.go`, `internal/sysops/fake.go` | `atomic_test.go::TestAtomicWriteFile_*`, `sysops_test.go::TestFake_WriteAuthorizedKeys_*`, `TestFake_SshdTWithContext_*`, `TestReal_Lstat_populates_ModTime` | `go test ./internal/sysops/...` | ✅ green |
| 03-02 | SETUP-04 | `chrootcheck.WalkRoot` path-walk validator (root:root + no group-write from / to chroot root) + D-10 read-only contract | `internal/chrootcheck/chrootcheck.go` | `chrootcheck_test.go::TestWalkRoot_*`, `TestWalkRoot_read_only_invariant`, `TestWalkRoot_ErrTargetNotAbsolute_isErrSentinel` | `go test ./internal/chrootcheck/...` | ✅ green |
| 03-02 | USER-14 | `chrootcheck.CheckAuthKeysFile` D-21 steps 1+2 verifier (path-walk + per-user dir 0750 + .ssh 0700 + authorized_keys 0600) + public test seam | `internal/chrootcheck/strictmodes.go`, `internal/chrootcheck/testseam.go` | `strictmodes_test.go::TestCheckAuthKeysFile_*` | `go test ./internal/chrootcheck/...` | ✅ green |
| 03-03 | SETUP-02 | `sshdcfg.Render` byte-identity writer + top-level-before-Match ordering (pitfall A3 / D-16); `CanonicalDropIn` D-07 template + `%%u` literal escape | `internal/sshdcfg/render.go` | `render_test.go::TestCanonicalDropIn_*`, `TestRender_*`, `TestParseRender_round_trip_property` | `go test ./internal/sshdcfg/...` | ✅ green |
| 03-04 | USER-08 | `keys.Parse` per-line source dispatcher (SourceDirect/GithubAll/GithubByID/SourceFile) + `ParsedKey{Algorithm, Fingerprint, Comment, ByteSize}` + `ParseErr` partial-batch | `internal/keys/parse.go` | `parse_test.go::TestParse_*`, `TestFingerprint_*` | `go test ./internal/keys/...` | ✅ green |
| 03-04 | USER-09 | `keys.FetchGitHub` + `FetchGitHubByID` with 5s timeout + no-retry on 429 + Retry-After surfacing; `SourceFile` path detection | `internal/keys/github.go` | `github_test.go::TestFetchGitHub_*`, `TestFetchGitHubByID_*` | `go test ./internal/keys/...` | ✅ green |
| 03-04 | USER-06 | `keys.Generate(24)` crypto/rand strong password + minclass=4 rejection sampling (pitfall 7 / pwquality defeat) | `internal/keys/password.go` | `password_test.go::TestGenerate_*` | `go test ./internal/keys/...` | ✅ green |
| 03-05 | SAFE-02 | `txn.NewSshdValidateStep` wraps SshdT; on failure compensator restores prior drop-in bytes | `internal/txn/steps.go` | `steps_test.go::TestNewSshdValidateStep_*` | `go test -run TestNewSshdValidateStep ./internal/txn/...` | ✅ green |
| 03-05 | SAFE-03 | `txn.NewWriteSshdDropInStep` writes timestamped backup (.bak) BEFORE atomic write; compensator restores prior bytes on rollback | `internal/txn/steps.go` | `steps_test.go::TestNewWriteSshdDropInStep_*` | `go test -run TestNewWriteSshdDropInStep ./internal/txn/...` | ✅ green |
| 03-05 | SAFE-06 | `txn.NewSystemctlReloadStep(ReloadDispatch)` socket-vs-service dispatcher; `CanonicalApplySetupSteps` composer for D-09 batch | `internal/txn/steps.go` | `steps_test.go::TestNewSystemctlReloadStep_*`, `TestCanonicalApplySetupSteps_*` | `go test -run "TestNewSystemctlReloadStep\|TestCanonicalApplySetupSteps" ./internal/txn/...` | ✅ green |
| 03-05 | USER-12 | `txn.NewUserdelStep` (D-15 standalone no-compensator) + `NewMkdirAllStep` (existedBefore-aware compensator) + `NewTarStep` (RemoveAll compensator) | `internal/txn/steps.go` | `steps_test.go::TestNewUserdelStep_*`, `TestNewMkdirAllStep_*`, `TestNewTarStep_*` | `go test -run "TestNewUserdelStep\|TestNewMkdirAllStep\|TestNewTarStep" ./internal/txn/...` | ✅ green |
| 03-05 | USER-14 | `txn.NewAtomicWriteAuthorizedKeysStep` (prior-bytes capture) + `NewVerifyAuthKeysStep` (injected verify func - no import cycle); saga apply-compensate with reverse-order rollback | `internal/txn/txn.go`, `internal/txn/steps.go` | `txn_test.go::TestApply_*`, `steps_test.go::TestNewAtomicWriteAuthorizedKeysStep_*`, `TestNewVerifyAuthKeysStep_*` | `go test ./internal/txn/...` | ✅ green |
| 03-06 | SETUP-02 | M-APPLY-SETUP modal: preflight + diff (SAFE-05) + Apply gate + 3-step txn (WriteSshdDropIn + SshdValidate + SystemctlReload); Doctor `[A]` action wiring | `internal/tui/screens/applysetup/applysetup.go`, `internal/service/doctor/doctor.go` | `applysetup_test.go::TestApplySetup_*` | `go test ./internal/tui/screens/applysetup/...` | ✅ green |
| 03-06 | SETUP-03 | Admin edits chroot root path in textinput; filepath.IsAbs gate (T-03-06-01); W-05 re-walk on root change clears stale violations | `internal/tui/screens/applysetup/applysetup.go` | `applysetup_test.go::TestApplySetup_edit_root_re_runs_chrootcheck_against_new_root` | `go test -run TestApplySetup_edit_root ./internal/tui/screens/applysetup/...` | ✅ green |
| 03-06 | SETUP-04 | M-APPLY-SETUP gates Apply on zero WalkRoot violations; preflight blocks modal advance when violations present | `internal/tui/screens/applysetup/applysetup.go` | `applysetup_test.go::TestApplySetup_blocks_apply_when_violations_present` | `go test ./internal/tui/screens/applysetup/...` | ✅ green |
| 03-06 | SETUP-06 | M-APPLY-SETUP warns on external Subsystem (advisory-only, no auto-fix per RESEARCH OQ-5) | `internal/tui/screens/applysetup/applysetup.go` | `applysetup_test.go::TestApplySetup_warns_on_external_subsystem` | `go test ./internal/tui/screens/applysetup/...` | ✅ green |
| 03-07 | USER-03 | `newuser.NewFromOrphan` - B-03 GID preservation; orphan path runs 2-step txn (Useradd+GpasswdAdd only - skips Chmod/Chown); UIDs/GIDs in UseraddOpts from orphan Lstat | `internal/tui/screens/newuser/newuser.go` | `newuser_test.go::TestNewUser_orphan_constructor_prefills_uid_AND_gid`, `TestNewUser_orphan_submit_uses_useradd_with_dash_g_and_skips_chmod_chown` | `go test -run TestNewUser_orphan ./internal/tui/screens/newuser/...` | ✅ green |
| 03-07 | USER-04 | UID-collision check (os/user.LookupId); reserved 60000-65535 rejection (N-04); /etc/shells gate (B4: /usr/sbin/nologin required) | `internal/tui/screens/newuser/newuser.go` | `newuser_test.go::TestNewUser_UID_reserved_range_rejected_at_*` (boundary tests at 999/60000/65535/65536) | `go test -run TestNewUser_UID ./internal/tui/screens/newuser/...` | ✅ green |
| 03-07 | USER-05 | M-PASSWORD pam_pwquality stderr surfacing via `errors.As(*ChpasswdError)`; inline errFatal display in styles.Critical | `internal/tui/screens/password/password.go` | `password_test.go::TestPassword_pam_pwquality_error_surfaces_inline` | `go test -run TestPassword_pam ./internal/tui/screens/password/...` | ✅ green |
| 03-07 | USER-06 | M-PASSWORD AutoGenerateMode: `keys.Generate(24)` shown ONCE; 'c' fires `tea.SetClipboard` (OSC 52); 'r' regenerates; `m.pw` cleared on submit success (hygiene) | `internal/tui/screens/password/password.go` | `password_test.go::TestPassword_pw_cleared_after_successful_submit`, `TestPassword_NEVER_records_password_literal_in_FakeCalls` | `go test ./internal/tui/screens/password/...` | ✅ green |
| 03-07 | USER-07 | Force-change checkbox defaults OFF; `ops.Chage(ChageOpts{LastDay:0})` on submit when checked; Warn-styled lockout-risk helper text | `internal/tui/screens/password/password.go` | `password_test.go::TestPassword_view_includes_chrootSFTP_lockout_warning_when_force_change_checked` | `go test -run TestPassword_view ./internal/tui/screens/password/...` | ✅ green |
| 03-07 | SETUP-05 | M-NEW-USER fresh-create 4-step txn [Useradd + GpasswdAdd + Chmod(0o750) + Chown]; D-11 chained handoff to M-PASSWORD on submit success | `internal/tui/screens/newuser/newuser.go` | `newuser_test.go::TestNewUser_fresh_create_submit_runs_4step_txn` | `go test -run TestNewUser_fresh ./internal/tui/screens/newuser/...` | ✅ green |
| 03-08a | USER-08 | S-USER-DETAIL 5-column authorized_keys table (algorithm + fingerprint + comment + bytes + added-on from FileInfo.ModTime via B-06); empty-state copy | `internal/tui/screens/userdetail/userdetail.go` | `userdetail_test.go::TestUserDetail_initial_loading_then_keysLoadedMsg_populates_table`, `TestUserDetail_added_on_column_uses_FileInfo_ModTime` | `go test ./internal/tui/screens/userdetail/...` | ✅ green |
| 03-08a | USER-11 | D-22 single-key delete via 2-step txn [AtomicWriteAuthorizedKeys + VerifyAuthKeys]; verifier failure rolls back to prior bytes | `internal/tui/screens/userdetail/userdetail.go` | `userdetail_test.go::TestUserDetail_d_runs_single_key_delete_txn`, `TestUserDetail_d_failure_to_verify_rolls_back` | `go test -run TestUserDetail_d ./internal/tui/screens/userdetail/...` | ✅ green |
| 03-08a | USER-12 | M-DELETE-USER modal: default Permanent (D-15 irreversibility-default); Tab toggles to Archive; Permanent path type-username-verbatim gate; Archive 3-step [MkdirAll + Tar + Userdel(removeHome=false)] | `internal/tui/screens/deleteuser/deleteuser.go` | `deleteuser_test.go::TestDeleteUser_*` | `go test ./internal/tui/screens/deleteuser/...` | ✅ green |
| 03-08b | USER-09 | M-ADD-KEY: textarea parse dispatch (paste/file/gh:); D-20 mandatory review table regardless of source; partial-batch reject on any parse error | `internal/tui/screens/addkey/addkey.go` | `addkey_test.go::TestAddKey_*` | `go test ./internal/tui/screens/addkey/...` | ✅ green |
| 03-08b | USER-10 | M-ADD-KEY gh:<user> and gh:<user>/<id> import; pre-fetch synchronous username regex validation (T-03-08b-01); no auto-retry on 429 | `internal/tui/screens/addkey/addkey.go` | `addkey_test.go::TestAddKey_gh_*`, `TestAddKey_attemptParse_gh_user_invalid_charset_rejects_before_fetch` | `go test -run TestAddKey_gh ./internal/tui/screens/addkey/...` | ✅ green |
| 03-08b | USER-14 | M-ADD-KEY commit batch [AtomicWriteAuthorizedKeysStep + VerifyAuthKeysStep(buildVerifier)]; D-21 four-step verifier in order; rollback restores prior bytes on verifier failure | `internal/tui/screens/addkey/addkey.go` | `addkey_test.go::TestAddKey_commit_success_*`, `TestAddKey_commit_verifier_failure_rolls_back` | `go test -run TestAddKey_commit ./internal/tui/screens/addkey/...` | ✅ green |
| 03-09 | USER-13 | M-DISABLE-PWAUTH: preflight enumerates sftp-group users via Enumerator+CheckAuthKeysFile; BLOCKED banner when keyless users; `I understand` case-sensitive override gate (T-03-09-02) | `internal/tui/screens/pwauthdisable/pwauthdisable.go` | `pwauthdisable_test.go::TestPwAuthDisable_*` | `go test ./internal/tui/screens/pwauthdisable/...` | ✅ green |
| 03-09 | SAFE-02 | M-DISABLE-PWAUTH 3-step txn [WriteSshdDropIn + SshdValidate + SystemctlReload(ReloadService)]; inline post-reload `ops.SshdDumpConfig` verifier checks live value | `internal/tui/screens/pwauthdisable/pwauthdisable.go` | `pwauthdisable_test.go::TestPwAuthDisable_submit_runs_txn_batch_then_verifies_via_sshd_dump` | `go test -run TestPwAuthDisable_submit ./internal/tui/screens/pwauthdisable/...` | ✅ green |
| 03-09 | SETUP-02 | `setTopLevelPasswordAuthentication` four-case helper (ADD/REMOVE/UPDATE/STRIP-FROM-MATCH per pitfall A3 / D-16 step 5 / T-03-09-01) | `internal/tui/screens/pwauthdisable/pwauthdisable.go` | `pwauthdisable_test.go::TestPwAuthDisable_setTopLevelPasswordAuthentication_*` (4 dedicated tests) | `go test -run TestPwAuthDisable_setTopLevel ./internal/tui/screens/pwauthdisable/...` | ✅ green |

*Status legend: ✅ green - ❌ red - ⚠️ flaky - ⬜ pending*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No Wave 0 stub work needed:
- Go stdlib `testing` was already in place pre-phase.
- `testify v1.11.1` was already a dep.
- `teatest/v2` was already integrated for TUI screens.
- `golang.org/x/crypto v0.50.0` added to direct requires in plan 03-04 (alongside the production import - no pin-keeper orphan).
- `go-udiff v0.4.1` promoted from indirect to direct in plan 03-06 (clean pin-keeper handoff in the same commit as the real import).
- `internal/chrootcheck/testseam.go` established the public Set/Reset test-seam pattern reused across Phase 3.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Live `sshd -t` validation against real sshd binary accepts the canonical drop-in | SAFE-02, SETUP-02 | Requires real OpenSSH sshd binary + `/etc/ssh/sshd_config` present; Fake-based tests use `SshdTError` scripted response and cannot model real binary parsing. Unit tests use `sysops.Fake` exclusively. | Run `cmd/uat-03-06/main.go` pattern on Ubuntu 24.04: `txn.New(real).Apply(ctx, txn.CanonicalApplySetupSteps(...))`. Verify drop-in bytes byte-identical to golden, sshd reloads, session survives. Empirically confirmed on `ubuntu-wifi` (OpenSSH 9.6p1) during plan 03-06 UAT. Last green: 2026-04-26. |
| `chpasswd` password never on argv - confirmed via process listing during live invocation | USER-05 | Requires a live Ubuntu 24.04 box with PAM configured; `ps` inspection at the moment of the chpasswd subprocess. Cannot be modeled by `sysops.Fake` (which records `len=N` not the literal). | Run `ops.Chpasswd(ctx, user, pw)` against real system; inspect `/proc/<pid>/cmdline` during execution to confirm no password literal; verify yescrypt hash appears in `/etc/shadow`. Empirically confirmed during plan 03-07 UAT on `ubuntu-wifi`. |
| Orphan UID+GID preservation byte-for-byte (B-03 invariant) on real system with pre-existing group | USER-03 | Requires a real system where a pre-existing group with a specific GID (e.g. 6308) was created before the user; `getent group` and `getent passwd` must confirm GID is preserved not fresh-assigned. Fake-based tests assert `UseraddOpts.GID` is set but cannot verify the kernel's actual UID assignment. | Pre-create group `groupadd -g 6308 orphan-grp` + dir `mkdir -p /srv/sftp-jailer/uat307 && chown 6308:6308 /srv/sftp-jailer/uat307`; run `newuser.NewFromOrphan`; verify `id -g <user>` returns 6308 and `getent group 6308` returns original group name. Empirically confirmed 2026-04-26 on `ubuntu-wifi`. |
| D-21 verifier rollback restores authorized_keys byte-identical after malformed-key commit attempt | USER-14 | Requires real file system + real authorized_keys write to confirm compensator byte-identity. Fake's `WriteAuthorizedKeysError` scripting cannot model the full compensator chain against real fs. | Seed authorized_keys with 2 valid keys (186 bytes); attempt commit with a deliberately-malformed third key; verify verifier aborts at step 3 with `ssh: no key found`; verify `cat authorized_keys | wc -c` returns 186. Empirically proved during plan 03-08b UAT on `ubuntu-wifi`. |
| Live PAM stderr surfacing on `chpasswd` rejection with policy-violating password | USER-05 | Requires real pam_pwquality configured on a live Ubuntu 24.04 box; the exact stderr text depends on pam_pwquality policy and cannot be known statically in tests. | Submit a password violating pam_pwquality (e.g. too short or no digit) via M-PASSWORD on a real system; verify `ChpasswdError.Stderr` contains verbatim pam_pwquality rejection text displayed in the modal's error UI. Empirically confirmed during plan 03-07 UAT. |
| Real api.github.com HTTPS fetch - valid + 404 + invalid-charset gh: usernames | USER-10 | Requires live internet access to api.github.com; rate-limited and cannot be part of CI. Tests stub via `SetGithubBaseURLForTest` httptest server (W-06 path-matching enforced). | Run M-ADD-KEY against real GitHub API: `gh:torvalds` fetches real ssh-rsa key; `gh:thisuserdefinitelydoesnotexist1234567890` returns typed 404 error verbatim; `gh:bad..user!` rejected by synchronous regex before network call. Empirically confirmed during plan 03-08b UAT on `ubuntu-wifi`. |
| SAFE-06 end-to-end: SSH session survives sshd reload via ReloadService (Launchpad #2069041 contract) | SAFE-06 | Requires real sshd + active SSH session on Ubuntu 24.04; the Launchpad bug is an OS-level behavior (socket-vs-service reload distinction) that cannot be simulated by `sysops.Fake`. | Run sshd config mutation (M-APPLY-SETUP or M-DISABLE-PWAUTH) from an SSH session; verify session survives the `systemctl reload ssh.service` call post-Apply. Confirmed LIVE THREE TIMES across Phase 3: plans 03-06 (M-APPLY-SETUP UAT), 03-09 Phase 1 (DISABLE), 03-09 Phase 2 (RE-ENABLE). Last green: 2026-04-27 on `ubuntu-wifi`. |
| `sshd -T -C user=<u>` flag semantics (OpenSSH 9.6p1 requires `-T` not `-t` with `-C`) | USER-14 | Binary CLI contract cannot be modeled by `sysops.Fake`. Bug-find during 03-08b UAT: real binary exits 255 with `Config test connection parameter (-C) provided without test mode (-T)`. Fixed in commit `0af85a4`. | Run `buildVerifier` via M-ADD-KEY commit path on real Ubuntu 24.04 with OpenSSH 9.6p1; verify SshdTWithContext exits 0 and verifier returns 0 violations for a valid authorized_keys. Confirmed fixed in plan 03-08b UAT Phase 1. |
| Delete-user Archive: `/var/lib/sftp-jailer/archive/` mode 0700 root:root created before tar (T-03-08a-05) | USER-12 | Requires real filesystem + real `tar` binary; mode verification after the MkdirAll step requires live `ls -la`. Fake records MkdirAll call but cannot verify OS-level mode materialization after `umask`. | Run M-DELETE-USER Archive path on real system; verify `ls -la /var/lib/sftp-jailer/` shows `drwx------ root root archive/` post-apply. Empirically confirmed 2026-04-26 on `ubuntu-wifi`. |
| Delete-user Permanent: userdel -r wipes home directory; UPG group also removed (userdel default) | USER-12 | Requires real system account + real home directory; `getent passwd` and `ls` after userdel confirms semantic. Fake records Userdel call but cannot model OS-level account removal. | Run M-DELETE-USER Permanent path; verify `getent passwd <user>` exits 2, `getent group <user>` exits 2 (UPG gone), `ls /srv/sftp-jailer/<user>/` returns "No such file or directory". Empirically confirmed 2026-04-26 on `ubuntu-wifi`. |
| M-DISABLE-PWAUTH: `PasswordAuthentication no` lands at TOP-LEVEL (above Match block), not inside Match body (pitfall A3 / D-16) | USER-13 | Requires verification of actual sshd_config drop-in bytes after write + `sshd -T` output to confirm runtime value. Unit tests verify `setTopLevelPasswordAuthentication` logic but cannot confirm the physical file's top-level placement against a live sshd parser. | Run M-DISABLE-PWAUTH Disable action on real system; verify proposed bytes show `PasswordAuthentication no` before the `Match Group` line; verify `sshd -T | grep passwordauthentication` returns `no`. Empirically confirmed 2026-04-26 on `ubuntu-wifi` (208-byte proposed drop-in with directive AT TOP-LEVEL). |

---

## Validation Sign-Off

- [x] All tasks have automated `<verify>` commands or are documented as manual-only with empirical UAT evidence
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (every plan committed test artifacts)
- [x] Wave 0 covers all MISSING references - none required; test infrastructure pre-existed or was co-shipped with each plan
- [x] No watch-mode flags in any test command
- [x] Feedback latency < 60s (full race-enabled suite ~40s; Phase 3 subset ~16s)
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Empirical UAT on real Ubuntu 24.04.4 LTS (host ubuntu-wifi, OpenSSH 9.6p1) confirmed for plans 03-06, 03-07, 03-08a, 03-08b, 03-09 - all 21 requirements implemented and functionally verified
- [x] One empirical bug-find during UAT (commit `0af85a4`: `sshd -t -C` rejected by OpenSSH - fixed to `sshd -T -C`) proves the empirical UAT loop catches real-binary-contract bugs that Fake-only tests cannot detect
- [x] Both `03-08a` and `03-08b` preserved as distinct plan IDs in the Per-Task Map (split preserved, not collapsed)

**Approval:** approved 2026-05-01

---

## Validation Audit 2026-05-01

| Metric | Count |
|--------|-------|
| Requirements analyzed | 39 (row count in Per-Task Map; Phase 3 has 21 requirements with multiple tasks each mapping to the same req) |
| COVERED | 39 (all rows have automated test coverage or empirical UAT evidence) |
| PARTIAL | 0 |
| MISSING | 0 |
| Manual-only items | 11 (empirical behaviors requiring real Ubuntu 24.04 host: live sshd binary, chpasswd PAM, orphan GID preservation, authorized_keys rollback, GitHub HTTPS, SAFE-06 reload, sshd -T flag contract, archive mode, permanent delete UPG, PasswordAuthentication placement, delete-user archive dir mode) |
| Suite status | GREEN (verified 2026-05-01) |
| Gaps filled this audit | 0 (no test code generated - coverage was already complete across all 10 plans) |
