---
phase: 05-packaging-install-purge-automated-release
plan: "05"
subsystem: ci
tags: [github-actions, goreleaser, lintian, release, sha256sums, tag-push]

# Dependency graph
requires:
  - phase: 05-01-goreleaser-nfpm
    provides: "packaging/goreleaser.yml with builds/archives/nfpms sections; lintian-overrides inside .deb"
  - phase: 05-02-manpage-generator
    provides: "scripts/check-manpage-fresh.sh architecture invariant script"
  - phase: 05-04-debian-maintainer-scripts
    provides: "packaging/debian/lintian-overrides committed with WHY rationale entries"
provides:
  - ".github/workflows/release.yml — tag-push-only GitHub Actions release pipeline (DIST-08)"
  - "Automated goreleaser build + lintian --pedantic gate + SHA256SUMS.txt upload on every vX.Y.Z tag push"
  - "DIST-03 zero-tolerance lintian enforcement in CI (release never publishes on non-overridden warning)"
affects:
  - 05-06-empirical-uat-runbook  # downloads artifacts from GitHub Release produced by this workflow

# Tech tracking
tech-stack:
  added:
    - "goreleaser/goreleaser-action@v6 (goreleaser v2.15.4 binary pin)"
    - "golangci/golangci-lint-action@v9 (v2.11)"
    - "lintian (installed via apt on ubuntu-24.04 runner)"
    - "gh CLI (preinstalled on ubuntu-24.04 runner; used for release upload)"
  patterns:
    - "Tag-push-only CI trigger with no workflow_dispatch / nightly / main-push surface"
    - "Doubled gate: release workflow re-runs full CI gate before publishing (release != flaky main pass)"
    - "SHA256SUMS.txt generated independently of goreleaser checksum block — defense-in-depth"
    - "lintian --pedantic zero-tolerance: non-overridden warning = workflow failure = release blocked"

key-files:
  created:
    - ".github/workflows/release.yml — tag-push-only release pipeline (151 lines)"
    - ".planning/phases/05-packaging-install-purge-automated-release/05-05-SUMMARY.md — this file"
  modified: []

key-decisions:
  - "D-RW-01: Full CI gate (10 steps) runs inline before goreleaser — the doubled gate trade-off"
  - "D-RW-03: Tag pattern restricted to vMAJOR.MINOR.PATCH and vMAJOR.MINOR.PATCH-rcN only; other forms do not fire workflow"
  - "REQUIREMENTS.md Out of Scope: NO workflow_dispatch, NO schedule, NO branches triggers"
  - "SHA256SUMS.txt generated post-goreleaser independently (not via goreleaser checksum block) — defense-in-depth"
  - "Token surface: only secrets.GITHUB_TOKEN with contents: write; no PAT, no id-token: write, no packages: write"

patterns-established:
  - "Release pipeline pattern: tag-push → doubled CI gate → goreleaser → lintian --pedantic → SHA256SUMS upload"
  - "lintian-overrides as policy gate: each override requires WHY rationale, non-overridden warning blocks release"

requirements-completed:
  - DIST-08
  - DIST-03

# Metrics
duration: 2min
completed: "2026-04-29"
---

# Phase 5 Plan 05: Release Workflow Summary

**Tag-push-only GitHub Actions pipeline (DIST-08) that gates on the full CI suite + goreleaser + lintian --pedantic + SHA256SUMS upload, with contents:write-only token and no trigger surface beyond vX.Y.Z tag push**

## Performance

- **Duration:** 2 min
- **Started:** 2026-04-29T21:49:12Z
- **Completed:** 2026-04-29T21:51:39Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Authored `.github/workflows/release.yml` (151 lines) implementing DIST-08 end-to-end
- Enforced DIST-03 zero-tolerance lintian gate: release blocks on any non-overridden warning across both amd64 + arm64 .debs
- SHA256SUMS.txt generated independently of goreleaser's internal hashing path (defense-in-depth)
- Trigger surface explicitly narrowed to tag-push only per CONTEXT.md D-RW-01 + REQUIREMENTS.md §Out of Scope

## What Was Done

- Authored `.github/workflows/release.yml` (~151 lines):
  - **Trigger:** `on.push.tags` matching `v[0-9]+.[0-9]+.[0-9]+` and `v[0-9]+.[0-9]+.[0-9]+-rc[0-9]+` ONLY
  - **Permissions:** `contents: write` only (no `id-token: write`, no `packages: write`, no `actions: write`)
  - **Job sequence:** 10 steps — checkout (full history) → setup-go 1.25.x → mod verify → test -race → golangci-lint v2.11 → govulncheck → 5 architecture scripts + 2 inline grep guards → goreleaser → lintian --pedantic → SHA256SUMS upload
  - **All step pins explicit:** actions/checkout@v4, actions/setup-go@v5, golangci-lint-action@v9 v2.11, goreleaser-action@v6 v2.15.4, govulncheck @latest

## Decisions Implemented

- **D-RW-01** — Full CI gate runs inline before goreleaser (the "doubled gate" trade-off). A release ≠ a flaky main pass; the tagged commit re-proves all invariants regardless of what the main-branch CI run showed.
- **D-RW-01** — 10-step job sequence verbatim per CONTEXT.md L200-L212.
- **D-RW-03** — Tag pattern restricted to `vMAJOR.MINOR.PATCH[-rcN]`; other tag forms (e.g. `v1.2`, `v1.2.0+build`) do not match the filter and the workflow does not fire. Tag-to-deb-version mapping (`v1.2.0-rc1` → `1.2.0~rc1`) is handled inside goreleaser.yml (05-01); release.yml is not involved in the version transform.
- **REQUIREMENTS.md §Out of Scope** — NO `workflow_dispatch`, NO `schedule:`, NO `branches:` triggers. Each of these would expand the release surface beyond the intentionally narrow tag-push-only contract.

## Trigger-Surface Narrowness — Explicit Non-Goals

The following triggers are intentionally ABSENT from release.yml:

- **No nightly:** A tagged release ≠ a build off main. Main may be ahead of the most recent release tag; nightly builds of untagged commits would create un-releasable artifacts.
- **No `workflow_dispatch`:** No UI button to trigger a release. Forces every release through the explicit `git tag && git push --tags` gesture, making releases auditable and intentional.
- **No main-push:** A commit landing on main does NOT produce an artifact. Releases happen on tags, period. ci.yml handles main-push CI; release.yml is for tagged releases only.
- **No PR builds:** PRs run ci.yml. release.yml is exclusively for tagged releases.

This narrowness is per CONTEXT.md D-RW-01 + REQUIREMENTS.md §Out of Scope, and is a deliberate product decision: releasing is an intentional human gesture, not an automated side-effect of merging.

## Defense-in-Depth: SHA256SUMS Independent of goreleaser

goreleaser CAN generate checksums via a `checksum:` block in its config. However, 05-01's `packaging/goreleaser.yml` does NOT include this section (omission was intentional). `release.yml` generates `SHA256SUMS.txt` as an explicit post-goreleaser step:

```sh
cd dist
sha256sum *.deb > SHA256SUMS.txt
gh release upload "$GITHUB_REF_NAME" SHA256SUMS.txt
```

This means the sums are independent of goreleaser's internal hashing path. If a future goreleaser release introduces a bug in its checksum emission, the `release.yml` step is unaffected. The SHA256SUMS.txt covers ONLY the `.deb` files (the primary distributable); goreleaser uploads `.tar.gz` archives on its own.

## Token Surface

| Token | Status | Reason |
|-------|--------|--------|
| `secrets.GITHUB_TOKEN` | USED | Auto-provisioned by GitHub Actions; scoped to `contents: write` for the GitHub Release artifact upload |
| `secrets.PAT` / `PERSONAL_ACCESS_TOKEN` | NOT USED | No PAT needed; auto-provisioned token is sufficient |
| `id-token: write` | NOT GRANTED | Cosign keyless signing deferred to DIST-v2-01 |
| `packages: write` | NOT GRANTED | No GitHub Container Registry push in v1.2 |
| `actions: write` | NOT GRANTED | Workflow does not modify itself |

## DIST-03 Enforcement Contract

The lintian gate in step 9 exits non-zero on ANY non-overridden warning across BOTH .debs (amd64 + arm64). Behavior:

- Installs `lintian` via `apt-get install -y lintian` (not preinstalled on ubuntu-24.04 runner)
- Runs `lintian --pedantic "$deb"` for every .deb in `dist/`
- Accumulates failures; exits 1 if ANY .deb produced a non-zero lintian exit
- The lintian-overrides file shipped INSIDE each .deb at `/usr/share/lintian/overrides/sftp-jailer` (per 05-01 nfpms `contents:`) is consulted automatically by lintian when it inspects the package
- Each override in `packaging/debian/lintian-overrides` carries a `# WHY:` rationale comment per CONTEXT.md "Specific Ideas" — adding an override is a policy decision, not a workaround
- **If goreleaser produces a draft release before lintian fails:** The release remains in draft state on GitHub (goreleaser creates the Release before publishing artifacts). Empirical verification of this behavior is a DIST-10 UAT finding item (documented in 05-06 runbook).

## Downstream Consumers

- **05-06 empirical UAT runbook:** Testers download the `.deb` from a real `vX.Y.Z` GitHub Release (produced by this workflow), then run the install/purge/brownfield flow against it on the Debian 13 lab host at 192.168.1.170. The workflow is the artifact source; UAT validates the artifact, not just the build pipeline.
- **README.md tagging workflow documentation** (deferred to 05-06): The release tagging contract (`git tag v1.2.0 && git push --tags`) is documented in the README's Release section. Until then, refer to CONTEXT.md D-RW-03 and this summary.

## Verification Commands Run

All 40+ acceptance criteria from the plan passed:

```sh
# Core file existence
test -f .github/workflows/release.yml                              # PASS
grep -q '^name: Release$' .github/workflows/release.yml           # PASS

# Tag trigger
grep -q "'v\[0-9\]+\.\[0-9\]+\.\[0-9\]+'" release.yml            # PASS
grep -q "'v\[0-9\]+\.\[0-9\]+\.\[0-9\]+-rc\[0-9\]+'" release.yml # PASS

# No forbidden triggers (only in comments, not YAML keys)
grep -v '^#' release.yml | grep -q 'workflow_dispatch'            # PASS (none)
! grep -q 'schedule:' release.yml                                 # PASS
! grep -q 'branches:' release.yml                                 # PASS
! grep -q 'pull_request' release.yml                              # PASS

# Permissions
grep -q 'contents: write' release.yml                             # PASS
! grep -q 'id-token: write' release.yml                          # PASS
! grep -q 'packages: write' release.yml                          # PASS

# CI gate steps
grep -q 'actions/checkout@v4' release.yml                         # PASS
grep -q 'fetch-depth: 0' release.yml                              # PASS
grep -q "go-version: '1.25.x'" release.yml                       # PASS
grep -q 'go mod verify' release.yml                               # PASS
grep -q 'go test -race -count=1' release.yml                      # PASS
grep -q 'golangci-lint-action@v9' release.yml                     # PASS
grep -q 'version: v2.11' release.yml                              # PASS
grep -q 'govulncheck ./...' release.yml                           # PASS

# Architecture invariant scripts (5 + 2 inline)
grep -q 'check-no-exec-outside-sysops.sh' release.yml            # PASS
grep -q 'check-single-tea-program.sh' release.yml                 # PASS
grep -q 'check-go-mod-pins.sh' release.yml                        # PASS
grep -q 'check-no-raw-config-write.sh' release.yml                # PASS
grep -q 'check-manpage-fresh.sh' release.yml                      # PASS
grep -q 'Real.defaultTimeout' release.yml                         # PASS
grep -q 'github.com/charmbracelet/bubbletea' release.yml          # PASS

# goreleaser step
grep -q 'goreleaser/goreleaser-action@v6' release.yml             # PASS
grep -q 'version: v2.15.4' release.yml                            # PASS
grep -q 'release --clean --config packaging/goreleaser.yml' release.yml # PASS

# lintian gate
grep -q 'apt-get install -y lintian' release.yml                  # PASS
grep -q 'lintian --pedantic' release.yml                          # PASS

# SHA256SUMS
grep -q 'sha256sum *.deb > SHA256SUMS.txt' release.yml            # PASS
grep -q 'gh release upload "$GITHUB_REF_NAME" SHA256SUMS.txt' release.yml # PASS
grep -q '${{ secrets.GITHUB_TOKEN }}' release.yml                 # PASS

# Safety gates
! grep -q 'continue-on-error: true' release.yml                  # PASS
! grep -q 'PERSONAL_ACCESS_TOKEN\|secrets.PAT' release.yml       # PASS
```

## Task Commits

Each task was committed atomically:

1. **Task 1: Author .github/workflows/release.yml** - `c6ecf4a` (feat)
2. **Task 2: Write 05-05 SUMMARY** - (docs — this commit)

## Files Created

- `.github/workflows/release.yml` — tag-push-only release pipeline (151 lines, DIST-08)
- `.planning/phases/05-packaging-install-purge-automated-release/05-05-SUMMARY.md` — this file

## Deviations from Plan

None — plan executed exactly as written. The `workflow_dispatch` string appears in a comment in line 5 of release.yml (explaining why it is intentionally excluded), not as a YAML trigger key. The acceptance criterion was satisfied by verifying the `on:` block contains only `push.tags`.

## Issues Encountered

None.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The release.yml operates within the GitHub Actions trust model (runner-to-GitHub). The threat register in the plan's `<threat_model>` block fully covers the surface.

## Known Stubs

None — the release workflow is complete and ready to use. The only deferred element is README documentation of the tagging contract, which is delegated to the 05-06 UAT runbook plan.

## Next Phase Readiness

- `.github/workflows/release.yml` is complete and ready to gate releases
- 05-06 empirical UAT runbook can reference this workflow as the artifact source
- To release: `git tag v1.2.0 && git push --tags` — the workflow handles everything else
- Remaining concern: empirically verify goreleaser draft-release behavior on lintian failure (05-06 UAT finding)

---
*Phase: 05-packaging-install-purge-automated-release*
*Completed: 2026-04-29*
