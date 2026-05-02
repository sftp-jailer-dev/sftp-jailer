# Release Checklist

Pre-release verification steps. Run before each version tag (v1.0.0, v1.1.0, etc.).

## External Dependencies

- [ ] **Public-IP discovery URL still works.** `curl -sf https://ifconfig.me` returns a plain-text IPv4/IPv6 address. If broken, evaluate alternatives (`https://api.ipify.org`, `https://icanhazip.com`) and update D-L0204-07 in the relevant phase CONTEXT + the S-LOCKDOWN screen footer hint copy. Reference: 04-CONTEXT.md §Specifics.

## Build + Test

### Pre-flight checks

- [ ] Go module integrity: `go mod verify`
- [ ] Tests pass (race detector): `go test -race -count=1 ./...`
- [x] golangci-lint clean: `golangci-lint run ./...`
- [x] No known vulnerabilities: `govulncheck ./...`
- [ ] All 5 architecture-invariant scripts pass:
  - `bash scripts/check-no-exec-outside-sysops.sh`
  - `bash scripts/check-single-tea-program.sh`
  - `bash scripts/check-go-mod-pins.sh`
  - `bash scripts/check-no-raw-config-write.sh`
  - `bash scripts/check-manpage-fresh.sh`
- [ ] `Real.defaultTimeout` policy line present in `internal/sysops/real.go`
- [ ] No v1 Bubble Tea imports anywhere: `! grep -r 'github.com/charmbracelet/bubbletea"' --include='*.go' .`

### Snapshot smoke test on dev box

- [ ] goreleaser config is valid: `goreleaser check --config packaging/goreleaser.yml`
- [ ] Snapshot build succeeds:
  ```bash
  goreleaser release --snapshot --clean --skip=publish --config packaging/goreleaser.yml
  ```
- [ ] `dist/sftp-jailer_*_amd64.deb` produced
- [ ] `dist/sftp-jailer_*_arm64.deb` produced
- [x] lintian clean on both archs:
  ```bash
  for deb in dist/*.deb; do
    echo "==> $deb"
    lintian --pedantic "$deb"
  done
  ```
  **EXPECTED:** zero non-overridden warnings (all suppressions have `# WHY:` rationale in `packaging/debian/lintian-overrides`)

### Empirical UAT runbooks

- [ ] `docs/uat/05-ubuntu24-uat.md` Variant A (criteria 1, 3, 4) — operator signed off
- [ ] `docs/uat/05-ubuntu24-uat.md` Variant B (criterion 6, DIST-09 brownfield) — operator signed off
- [ ] `docs/uat/05-debian13-uat.md` (criterion 7, DIST-10 portability) — operator signed off
- [ ] No DIST-10-DELTA with severity **block** remains open

---

## Distribution

### Pre-release verification

- [ ] **Public-IP discovery URL.** (See External Dependencies above.)
- [ ] Version tag matches the planned semver:
  - `vMAJOR.MINOR.PATCH` for stable releases
  - `vMAJOR.MINOR.PATCH-rcN` for release candidates

### Tag + push

```bash
git tag v1.2.0          # (adjust version)
git push --tags
```

### Automated pipeline confirms

The `.github/workflows/release.yml` workflow triggers on the `v*.*.*` tag pattern and runs:

- [ ] Full CI gate (mirrors `ci.yml`): test → lint → govulncheck → invariant scripts
- [ ] `goreleaser release --clean` — produces `.deb`s + `.tar.gz` for both arches
- [ ] `lintian --pedantic dist/*.deb` — gates publication (workflow fails on any lintian warning)
- [ ] `SHA256SUMS.txt` generated for all artifacts
- [ ] Artifacts (2 `.deb`s, 2 `.tar.gz`, `SHA256SUMS.txt`) uploaded to the auto-created GitHub Release

### Manual post-release verification

- [ ] Verify the GitHub Release page: `https://github.com/sftp-jailer-dev/sftp-jailer/releases/tag/<TAG>`
  - Expected artifacts: `sftp-jailer_<ver>_amd64.deb`, `sftp-jailer_<ver>_arm64.deb`, `sftp-jailer_<ver>_linux_amd64.tar.gz`, `sftp-jailer_<ver>_linux_arm64.tar.gz`, `SHA256SUMS.txt`
- [ ] Post-release smoke test (does not gate the release but provides confidence):
  ```bash
  # On a clean Ubuntu 24.04 VM:
  apt install -y /tmp/sftp-jailer_<ver>_amd64.deb
  sftp-jailer doctor
  ldd /usr/bin/sftp-jailer  # expected: "not a dynamic executable"
  ```

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
| Pre-flight checks (tests, lint, vuln, invariants) | ☐ |
| Snapshot build + lintian clean | ☐ |
| Ubuntu 24.04 Variant A UAT | ☐ |
| Ubuntu 24.04 Variant B UAT (DIST-09 brownfield) | ☐ |
| Debian 13 UAT (DIST-10 portability) | ☐ |
| Tag pushed + pipeline green | ☐ |
| GitHub Release artifacts verified | ☐ |

---
*Created: 2026-04-27 via quick task `260427-npt` — Build+Test and Distribution sections added 2026-04-30 via plan 05-06*
