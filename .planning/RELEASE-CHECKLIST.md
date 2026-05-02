# Release Checklist

Pre-release verification steps. Run before each version tag (v1.0.0, v1.1.0, etc.).

## External Dependencies

- [x] **Public-IP discovery URL still works.** `curl -sf https://ifconfig.me` returns a plain-text IPv4/IPv6 address. If broken, evaluate alternatives (`https://api.ipify.org`, `https://icanhazip.com`) and update D-L0204-07 in the relevant phase CONTEXT + the S-LOCKDOWN screen footer hint copy. Reference: 04-CONTEXT.md §Specifics.
  *Verified 2026-05-02 at v1.2.0 close: `curl -sf -m 5 https://ifconfig.me` → IPv6 address, exit 0.*

## Build + Test

### Pre-flight checks

- [x] Go module integrity: `go mod verify`
- [x] Tests pass (race detector): `go test -race -count=1 ./...`
- [x] golangci-lint clean: `golangci-lint run ./...`
- [x] No known vulnerabilities: `govulncheck ./...`
- [x] All 5 architecture-invariant scripts pass:
  - `bash scripts/check-no-exec-outside-sysops.sh`
  - `bash scripts/check-single-tea-program.sh`
  - `bash scripts/check-go-mod-pins.sh`
  - `bash scripts/check-no-raw-config-write.sh`
  - `bash scripts/check-manpage-fresh.sh`
- [x] `Real.defaultTimeout` policy line present in `internal/sysops/real.go`
- [x] No v1 Bubble Tea imports anywhere: `! grep -r 'github.com/charmbracelet/bubbletea"' --include='*.go' .`

  *All Build+Test pre-flight items verified by the v1.2.0 GitHub Actions release workflow (run 25258408867, 2026-05-02T18:07Z, GREEN in 2m 49s) running against the tagged commit e847bc8. Workflow re-runs every step listed above before publishing — see `.github/workflows/release.yml` lines 8–18 (job sequence D-RW-01).*

### Snapshot smoke test on dev box

- [x] goreleaser config is valid: `goreleaser check --config packaging/goreleaser.yml`
- [x] Snapshot build succeeds:
  ```bash
  goreleaser release --snapshot --clean --skip=publish --config packaging/goreleaser.yml
  ```
- [x] `dist/sftp-jailer_*_amd64.deb` produced
- [x] `dist/sftp-jailer_*_arm64.deb` produced
- [x] lintian clean on both archs:
  ```bash
  for deb in dist/*.deb; do
    echo "==> $deb"
    lintian --pedantic "$deb"
  done
  ```
  **EXPECTED:** zero non-overridden warnings (all suppressions have `# WHY:` rationale in `packaging/debian/lintian-overrides`)

  *Snapshot smoke test empirically verified 2026-05-02 by quick task 260502-lga on the Debian 13 lab host (192.168.1.170): fresh-clone of post-push origin/main 55cbd6a → `goreleaser release --snapshot --clean` → `lintian --pedantic` → 0E + 0W + 0U on both archs. Re-validated by the v1.2.0 release workflow itself running `goreleaser release --clean` + `lintian --pedantic dist/*.deb` against e847bc8 (source-identical to 55cbd6a) — GREEN.*

### Empirical UAT runbooks

- [x] `docs/uat/05-ubuntu24-uat.md` Variant A (criteria 1, 3, 4) — operator signed off
- [x] `docs/uat/05-ubuntu24-uat.md` Variant B (criterion 6, DIST-09 brownfield) — operator signed off
- [x] `docs/uat/05-debian13-uat.md` (criterion 7, DIST-10 portability) — operator signed off
- [x] No DIST-10-DELTA with severity **block** remains open

  *Empirical UAT runbooks fully signed off 2026-04-30 (operator: Claude orchestrator continuation agent). Ubuntu 24.04 host: 192.168.1.187. Debian 13 host: 192.168.1.170. Outcomes per the runbook sign-off blocks:*
  - *Ubuntu 24.04 Variant A: ALL PASS (Step 7.2 SAFE-04 lockdown auto-revert SKIP-OPERATOR — designed TUI stub; BUG-05-A discovered + fixed mid-run in `internal/sysops/atomic.go` + `internal/txn/steps.go`).*
  - *Ubuntu 24.04 Variant B (DIST-09 brownfield): ALL PASS — main `sshd_config` byte-identical pre-install vs post-purge, sha256 597db2faddfca15ce6ba419c935169953ae1017ec8e2c4d00833c5f8504545f0.*
  - *Debian 13 (DIST-10 portability): ALL PASS — 2 portability deltas filed as findings (DIST-10-DELTA-01: ufw not pre-installed, auto-pulled via `Depends:`; DIST-10-DELTA-02: ufw inactive on Debian 13 vs active-with-SSH on Ubuntu). Neither blocks the thesis flow. Highest-risk surface (journalctl JSON format across systemd 253→257) passed cleanly.*
  - *Scope cross-check: UAT was empirically run against the v1.2.0-rc1-era binary. Source delta from rc1 to v1.2.0 GA (e847bc8) = Phase 6 (TUI-only: cancellation paths, password-aging row, log-detail modal, family-agnostic FW-09 with zero production lines changed per D-14) + Phase 7 (docs only) + 1 userlog golangci-lint cleanup + the 260502-j5x lintian/changelog packaging fixes. **None of the source deltas affect the Phase 5 thesis flow that the UAT runbooks exercise** (install → diagnostic → sshd drop-in → user CRUD → observation timer → purge). Phase 6 TUI changes were SKIP-OPERATOR in the runbook anyway (TUI stub steps). The j5x packaging fixes are revalidated by the v1.2.0 release workflow's lintian gate which ran GREEN.*

---

## Distribution

### Pre-release verification

- [x] **Public-IP discovery URL.** (See External Dependencies above.)
- [x] Version tag matches the planned semver:
  - `vMAJOR.MINOR.PATCH` for stable releases
  - `vMAJOR.MINOR.PATCH-rcN` for release candidates

  *v1.2.0 matches `vMAJOR.MINOR.PATCH` per the goreleaser tag regex.*

### Tag + push

```bash
git tag v1.2.0          # (adjust version)
git push --tags
```

*Pushed 2026-05-02T18:07Z. v1.2.0 → e847bc8.*

### Automated pipeline confirms

The `.github/workflows/release.yml` workflow triggers on the `v*.*.*` tag pattern and runs:

- [x] Full CI gate (mirrors `ci.yml`): test → lint → govulncheck → invariant scripts
- [x] `goreleaser release --clean` — produces `.deb`s + `.tar.gz` for both arches
- [x] `lintian --pedantic dist/*.deb` — gates publication (workflow fails on any lintian warning)
- [x] `SHA256SUMS.txt` generated for all artifacts
- [x] Artifacts (2 `.deb`s, 2 `.tar.gz`, `SHA256SUMS.txt`) uploaded to the auto-created GitHub Release

  *Run 25258408867: GREEN in 2m 49s — all 14 steps green (test -race, golangci-lint, govulncheck, 5 invariant scripts incl. Real.defaultTimeout policy + no-v1-bubbletea-imports, goreleaser release, lintian --pedantic, SHA256SUMS upload). Note (warning, not failure): GitHub flagged `actions/checkout@v4`, `actions/setup-go@v5`, `goreleaser/goreleaser-action@v6` for Node.js 20 deprecation (forced to Node 24 by 2026-06-02; Node 20 removed 2026-09-16). Cleanup task for v1.3.*

### Manual post-release verification

- [x] Verify the GitHub Release page: `https://github.com/sftp-jailer-dev/sftp-jailer/releases/tag/<TAG>`
  - Expected artifacts: `sftp-jailer_<ver>_amd64.deb`, `sftp-jailer_<ver>_arm64.deb`, `sftp-jailer_<ver>_linux_amd64.tar.gz`, `sftp-jailer_<ver>_linux_arm64.tar.gz`, `SHA256SUMS.txt`

  *Verified 2026-05-02. URL: https://github.com/sftp-jailer-dev/sftp-jailer/releases/tag/v1.2.0. Six assets present: `sftp-jailer_1.2.0_amd64.deb`, `sftp-jailer_1.2.0_arm64.deb`, `sftp-jailer_1.2.0_linux_amd64.tar.gz`, `sftp-jailer_1.2.0_linux_arm64.tar.gz`, `sftp-jailer_1.2.0_checksums.txt` (per-archive goreleaser), `SHA256SUMS.txt` (release-level DIST-08).*

- [ ] Post-release smoke test (does not gate the release but provides confidence):
  ```bash
  # On a clean Ubuntu 24.04 VM:
  apt install -y /tmp/sftp-jailer_<ver>_amd64.deb
  sftp-jailer doctor
  ldd /usr/bin/sftp-jailer  # expected: "not a dynamic executable"
  ```

  *Optional non-gating check. Equivalent has been exercised by the empirical UAT runbooks above (D.3.4 + D.3.5 on Debian 13; A.3.5 on Ubuntu 24.04: "not a dynamic executable" confirmed). Recommend running once on the operator's preferred Ubuntu 24.04 VM against the GitHub-Release-published `.deb` (not the snapshot one) for confidence; not required for the v1.2.0 release contract.*

### Roll-back if needed

```bash
gh release delete v1.2.0 --yes
git tag -d v1.2.0
git push --delete origin v1.2.0
```

---

## Sign-off

| Checkpoint | Signed off |
|------------|-----------|
| Pre-flight checks (tests, lint, vuln, invariants) | ☑ 2026-05-02 — release workflow run 25258408867 GREEN (re-verified all 7 pre-flight items + 5 invariant scripts on tagged commit e847bc8) |
| Snapshot build + lintian clean | ☑ 2026-05-02 — quick task 260502-lga (Debian 13 lab, post-push origin/main 55cbd6a, 0E + 0W + 0U both archs) + release workflow's `goreleaser release` + `lintian --pedantic dist/*.deb` step on e847bc8 |
| Ubuntu 24.04 Variant A UAT | ☑ 2026-04-30 — `docs/uat/05-ubuntu24-uat.md` sign-off block: ALL PASS on 192.168.1.187 (operator: Claude orchestrator continuation agent) |
| Ubuntu 24.04 Variant B UAT (DIST-09 brownfield) | ☑ 2026-04-30 — `docs/uat/05-ubuntu24-uat.md` Variant B sign-off block: ALL PASS, sshd_config sha256 597db2fa… byte-identical pre-install vs post-purge |
| Debian 13 UAT (DIST-10 portability) | ☑ 2026-04-30 — `docs/uat/05-debian13-uat.md` sign-off block: ALL PASS on 192.168.1.170; 2 portability deltas as findings (none block) |
| Tag pushed + pipeline green | ☑ 2026-05-02 — v1.2.0 → e847bc8 pushed; release workflow run 25258408867 GREEN in 2m 49s |
| GitHub Release artifacts verified | ☑ 2026-05-02 — 6 assets present at https://github.com/sftp-jailer-dev/sftp-jailer/releases/tag/v1.2.0 |

**Sign-off summary:**
- **Operator:** Claude (orchestrator continuation agent) on behalf of Jasper Nuyens.
- **Sign-off date:** 2026-05-02.
- **Outcome:** v1.2.0 GA released. All 7 RELEASE-CHECKLIST sign-offs satisfied.
- **Cross-version scope cross-check:** rc1 → GA source delta is Phase 6 (TUI-only) + Phase 7 (docs only) + 1 userlog lint cleanup + 4 j5x packaging fixes. None affect the Phase 5 thesis flow exercised by the operator UAT runbooks; j5x packaging fixes revalidated by the release workflow's lintian gate.

**Outstanding (operator-gated, not a release blocker):**

- **FW-09 empirical IPv6 VM UAT** — `docs/uat/06-fw09-uat.md` remains UNSIGNED. Pre-agreed deferral per Phase 6 D-16: production code is family-agnostic by construction (zero production lines changed per D-14); regression net is 3 unit tests + 2 testdata fixtures + 12-step UAT runbook. Operator action: provision a dual-family Ubuntu 24.04 VM (Variant A) and a v6-only VM (Variant B), run the 06-fw09 runbook, sign off in-place. Flips FW-09 ship status from `verified-code, UAT-pending` to `verified` in v1.2.x point release. **Does NOT block v1.2.0 GA.**

- **Node.js 20 actions deprecation** — release workflow's `actions/checkout@v4`, `actions/setup-go@v5`, `goreleaser/goreleaser-action@v6` flagged by GitHub for Node 20 → 24 transition (forced 2026-06-02; Node 20 removed 2026-09-16). Pin/upgrade or set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`. Recommend addressing in v1.3 or as a quick task before September.

---
*Created: 2026-04-27 via quick task `260427-npt` — Build+Test and Distribution sections added 2026-04-30 via plan 05-06 — Sign-off table populated 2026-05-02 at v1.2.0 GA release close.*
