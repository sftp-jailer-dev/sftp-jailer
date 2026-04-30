---
phase: 05-packaging-install-purge-automated-release
plan: "07"
subsystem: postinst-init-db
tags:
  - cobra
  - subcommand
  - sqlite
  - migrate
  - postinst
  - schema-drift
  - dist-04
  - gap-closure
dependency_graph:
  requires:
    - "05-01 (nfpm scripts declaration + lintian-overrides placeholder)"
    - "05-03 (rootcmd plumbing for hidden subcommands; purge_cleanup.go analog pattern)"
    - "05-04 (the postinst this plan extends — install -d /var/lib/sftp-jailer + observer.cursor pre-create)"
    - "05-06 (the UAT runbooks this plan augments — Ubuntu 24.04 + Debian 13 lab host)"
  provides:
    - "cmd/sftp-jailer/init_db.go — Hidden cobra subcommand `sftp-jailer init-db`"
    - "cmd/sftp-jailer/init_db_test.go — 6 tests covering Hidden, registration, --help exclusion, fresh install, idempotent re-invoke, schema-drift exit-2"
    - "packaging/debian/postinst — guarded `if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer init-db; fi` block at L64"
    - "packaging/debian/lintian-overrides — two new postinst:64 entries with # WHY: rationale"
    - "docs/uat/05-ubuntu24-uat.md step 2.4 — observations.db at install time (mode 0644 root:root, PRAGMA user_version=3)"
    - "docs/uat/05-debian13-uat.md step D.2.4 — Debian 13 portability mirror"
  affects:
    - "05-VERIFICATION.md (gap closure: truth #3 status moves from `partial` to `verified` after operator-signed re-UAT)"
    - "ROADMAP Phase 5 SC3 (strict reading honored: postinst initializes observations.db at install time)"
tech_stack:
  added: []
  patterns:
    - "Hidden:true cobra subcommand for postinst-only invocation (cobra/doc.GenManTree skips it)"
    - "Package-var test seam (initDBPath, initDBOsExit) mirroring purge_cleanup.go's purgePathFn / purgeOsExit"
    - "OBS-04 schema-drift gate: store.PeekUserVersion BEFORE store.Open + Migrate (mirrors observe.go::schemaCheck)"
    - "Distinct exit code 2 for schema drift vs exit 1 for generic failure (postinst set -e propagates both)"
    - "Guarded postinst invocation `[ -x /usr/bin/sftp-jailer ]` mirroring prerm:62-64 pattern but WITHOUT || true"
key_files:
  created:
    - "cmd/sftp-jailer/init_db.go (130 lines — Hidden cobra subcommand)"
    - "cmd/sftp-jailer/init_db_test.go (164 lines — 6 tests)"
    - ".planning/phases/05-packaging-install-purge-automated-release/05-07-SUMMARY.md (this file)"
  modified:
    - "cmd/sftp-jailer/main.go (+1 line: initDBCmd() registration in Subcommands slice)"
    - "internal/rootcmd/rootcmd.go (doc comment update — 2 hunks, additive only)"
    - "packaging/debian/postinst (was 65 lines; now 82 lines — +17 lines for guarded init-db invocation block)"
    - "packaging/debian/lintian-overrides (was 15 entries; now 17 entries — +2 for postinst:64)"
    - "docs/uat/05-ubuntu24-uat.md (+26 lines: step 2.4)"
    - "docs/uat/05-debian13-uat.md (+22 lines: step D.2.4)"
decisions:
  - "DIST-04 SC3 strict reading: observations.db MUST exist at install time, not after first timer fire (USER LOCKED via AskUserQuestion at gap-closure trigger time; alternative `revise SC3 wording` explicitly OUT OF SCOPE)"
  - "Hidden:true: subcommand invoked only by .deb postinst; cobra/doc.GenManTree skips Hidden subcommands so no man page generated"
  - "OBS-04 parity: init-db mirrors observe.go's schema-drift gate (PeekUserVersion → exit 2 on `current > ExpectedSchemaVersion`)"
  - "Anti-WR-01 invariant: init-db NEVER truncates or overwrites — store.Migrate is forward-only and idempotent. Distinct from existing `: > observer.cursor` line which DOES truncate (a pre-existing WR-01 issue out of scope here)"
  - "DIST-09 brownfield safety preserved: postinst still NEVER touches /etc/ssh/"
  - "30s context timeout caps postinst stall risk (initDBTimeout)"
  - "NO `|| true` on init-db invocation: failure must propagate via set -e so dpkg marks configure step failed and admin investigates"
metrics:
  duration: "~7 minutes"
  completed: "2026-04-30"
  tasks_completed: 5
---

# Phase 5 Plan 07: postinst init-db (DIST-04 SC3 gap closure) Summary

Closed the one outstanding gap from `.planning/phases/05-packaging-install-purge-automated-release/05-VERIFICATION.md`: ROADMAP Phase 5 SC3 wording requires postinst to initialize `/var/lib/sftp-jailer/observations.db` at install time, but the existing 05-04 postinst created the DB lazily on first timer fire. Added a Hidden cobra subcommand `sftp-jailer init-db` invoked by postinst between `install -d /var/lib/sftp-jailer` (L49) and `: > observer.cursor` (L67), with parallel UAT step additions in both Ubuntu 24.04 and Debian 13 runbooks.

---

## Gap addressed

From `05-VERIFICATION.md` gaps[0].truth (verified 2026-04-29T22:00:00Z):

> "postinst creates sftp-jailer group idempotently, enables+starts observer.timer, initializes observations.db (DIST-04)"

The original Phase 5 verification scored this as **partial** — group/timer/cursor verified, but `observations.db` was NOT initialized by postinst (created lazily on first timer fire; evidence at UAT step 6.1 showed 679936 bytes only after the timer fired). ROADMAP Phase 5 SC3 explicitly says: *"After `apt install`, postinst has ... initialized `/var/lib/sftp-jailer/observations.db` at the current schema version."* The strict reading of that SC required action.

---

## What was done

- **Authored `cmd/sftp-jailer/init_db.go` (130 lines)** — Hidden:true cobra subcommand mirroring `purge_cleanup.go`'s structure (file-header block comment, package-var test seam pattern, RunE returning error, distinct exit code 2 for schema drift). The OBS-04 schema-drift gate (`store.PeekUserVersion` BEFORE `store.Open`) refuses downgrade-installs with a clear stderr message: `"sftp-jailer: DB schema v%d newer than this binary expects (v%d). Run 'apt upgrade sftp-jailer'."`
- **Authored `cmd/sftp-jailer/init_db_test.go` (164 lines, 6 tests)** — `TestInitDBCmd_Hidden` (Hidden:true assertion), `TestRootCmd_RegistersInitDB` (root registration), `TestRootCmd_HelpOutputExcludesInitDB` (Hidden gate), `TestInitDB_FreshInstall_CreatesAndMigrates` (fresh-install path advances to ExpectedSchemaVersion=3), `TestInitDB_Idempotent_ReinvokeNoOp` (re-invocation no-op), `TestInitDB_SchemaDrift_RefusesWithExitCode2` (downgrade refusal). All 6 pass.
- **Edited `cmd/sftp-jailer/main.go`** — registered `initDBCmd()` in the rootCmd Subcommands slice immediately after `purgeSshdCleanupCmd()` (alphabetical-by-phase ordering: 02 → 05-03 → 05-07).
- **Edited `internal/rootcmd/rootcmd.go`** — updated doc comments to mention `init-db` alongside `purge-sshd-cleanup` as the two Hidden subcommands.
- **Edited `packaging/debian/postinst`** — inserted a guarded `if [ -x /usr/bin/sftp-jailer ]; then /usr/bin/sftp-jailer init-db; fi` block at L64, between L49 `install -d /var/lib/sftp-jailer` and L67 `: > observer.cursor`. NO `|| true` — failure propagates via set -e so dpkg marks the configure step failed and the admin investigates. Postinst grew from 65 → 82 lines.
- **Edited `packaging/debian/lintian-overrides`** — added two `command-with-path-in-maintainer-script /usr/bin/sftp-jailer ... [postinst:64]` entries (one for "in test syntax", one for "plain script") with `# WHY:` rationale, mirroring the existing `prerm:63`/`prerm:64` pattern. Existing 15 entries preserved verbatim; total now 17.
- **Edited `docs/uat/05-ubuntu24-uat.md`** — appended new step 2.4 (file existence + mode 0644 root:root + PRAGMA user_version=3) after existing step 2.3 and before Step 3. Checkbox unchecked `[ ]` — operator must re-run empirically.
- **Edited `docs/uat/05-debian13-uat.md`** — appended parallel D.2.4 step against lab host 192.168.1.170. Same expectations; cross-platform schema parity is a portability invariant.
- **Wrote 05-07-SUMMARY.md** (this file).

---

## Decisions implemented

- **DIST-04 SC3 (strict reading):** observations.db MUST exist at install time, not after first timer fire. Resolution direction: add a Hidden cobra subcommand invoked by postinst (USER LOCKED at gap-closure trigger time). Alternative resolutions (e.g., revising the SC3 wording) explicitly OUT OF SCOPE for this plan.
- **OBS-04 parity:** init-db mirrors `cmd/sftp-jailer/observe.go::schemaCheck` (PeekUserVersion → exit 2 on `current > store.ExpectedSchemaVersion`). The exit code 2 is the same as observe-run's drift gate, so postinst's `set -e` and dpkg's failure handling are uniform across both code paths.
- **Anti-WR-01 invariant:** init-db NEVER truncates or overwrites — `store.Migrate` is forward-only and idempotent (verified by `TestInitDB_Idempotent_ReinvokeNoOp`). Unlike the existing `: > /var/lib/sftp-jailer/observer.cursor` postinst line which DOES truncate state on every configure (a known WR-01 issue out of scope here; logged in 05-VERIFICATION.md anti-patterns table for Phase 6 or quick-fix PR before first real tag-push release).
- **DIST-09 brownfield safety preserved:** postinst still NEVER touches `/etc/ssh/`. The new init-db block touches only `/var/lib/sftp-jailer/`. Verified: `! grep -q '/etc/ssh' packaging/debian/postinst`.
- **`ExpectedSchemaVersion` constant referenced from `internal/store/store.go`** — currently 3 (Phase 4 plan 04-03 with `003_user_ips.sql`). When a future phase adds a new numbered .sql migration, both the constant and the UAT 2.4/D.2.4 expected values must be bumped in lockstep.
- **30s context timeout:** `initDBTimeout = 30 * time.Second` caps postinst stall risk if sqlite hangs. Mirrors `purgeSshdCleanupTimeout`.

---

## Code-review findings preserved as-is (NOT in scope for this plan)

These four items remain in `05-REVIEW.md` and should be addressed in Phase 6 or a quick-fix PR before the first real tag-push release:

- **WR-01:** postinst truncates `observer.cursor` unconditionally on upgrade. Affects upgrade path; out of scope per gap-closure trigger.
- **WR-02:** Missing lintian override for `postinst:32` daemon-reload. Empirical lintian passed; risk to future releases.
- **WR-03:** Misleading comment in lintian-overrides WHY block. Documentation-only.
- **WR-04:** `NewBackupDefaultUfwStep` latent trap. Unused in production; out of scope.

---

## Re-UAT REQUIRED before declaring DIST-04 SC3 fully closed

The new UAT step 2.4 (Ubuntu) and D.2.4 (Debian 13) ship as `[ ]` (unchecked). Operator post-execution actions:

1. **Rebuild the .deb:** `goreleaser release --snapshot --clean` (the new postinst block is bundled into the .deb).
2. **Re-run docs/uat/05-ubuntu24-uat.md step 2.4** against a FRESH Ubuntu 24.04 VM with the new .deb. Capture `PRAGMA user_version` output (must equal 3 — `internal/store/store.go::ExpectedSchemaVersion`). Mark `[x] PASS` with the recorded value in the Notes column.
3. **Re-run docs/uat/05-debian13-uat.md step D.2.4** against the Debian 13 lab host (192.168.1.170). Capture the same evidence. Mark `[x] PASS`.
4. **Re-verification:** Run `/gsd:verify-work 5` (or manually update `05-VERIFICATION.md`) to move truth #3 from `partial` to `verified`. Score becomes `7/7 must-haves verified`.
5. **Phase 5 then proceeds to milestone close** (`/gsd:audit-milestone v1.1` → `/gsd:complete-milestone`).

---

## Verification commands run during plan execution

| Command | Outcome |
|---------|---------|
| `go build ./cmd/sftp-jailer/...` | Exit 0 |
| `go build ./...` | Exit 0 (full project builds) |
| `go test ./cmd/sftp-jailer/... -run TestInitDB -v` | All 4 init-db-prefix tests PASS |
| `go test ./cmd/sftp-jailer/... -v -run 'TestRootCmd_Registers\|TestRootCmd_HelpOutput'` | All 4 (purge + init-db) PASS |
| `go test ./...` | Full suite green |
| `bash scripts/check-no-exec-outside-sysops.sh` | OK (init_db.go uses no os/exec) |
| `sh -n packaging/debian/postinst` | OK (POSIX sh syntax valid post-edit) |
| `awk '/install -d -m 0755 \/var\/lib\/sftp-jailer/{a=NR}/\/usr\/bin\/sftp-jailer init-db/{b=NR}/: > \/var\/lib\/sftp-jailer\/observer.cursor/{c=NR}END{exit !(a<b && b<c)}' packaging/debian/postinst` | Exit 0 (install -d L49 → init-db L64 → cursor L67) |
| `awk '/\*\*2.3\*\*/{a=NR}/\*\*2.4\*\*/{b=NR}/^### Step 3 /{c=NR}END{exit !(a<b && b<c)}' docs/uat/05-ubuntu24-uat.md` | Exit 0 (2.3 L140 → 2.4 L150 → Step 3 L178) |
| `! ls docs/man/sftp-jailer-init-db.1` | Confirmed (no man page generated for Hidden subcommand) |

---

## Deferred Issues (Rule scope boundary)

**Pre-existing `scripts/check-manpage-fresh.sh` glitch:** The CI guard reports `Only in docs/man: .gitkeep` because the placeholder `.gitkeep` file (added in commit 194afbd before man pages landed in 0aab1fd) was never removed once the actual `.1` pages were committed. This pre-dates plan 05-07 and is unrelated to the init-db work. The Hidden:true contract for `init-db` is verified empirically: no `sftp-jailer-init-db.1` is generated by `cmd/gen-manpage`, and `--help` does not list it. The pre-existing `.gitkeep` diff is a pre-existing WR-style finding, out of scope here. Suggested fix for a future Phase 6 quick-fix PR: `git rm docs/man/.gitkeep` and re-run `scripts/check-manpage-fresh.sh`.

This is a Rule scope boundary deviation — the issue is unrelated to the current plan's task surface (DIST-04 SC3 closure) and was present before the plan started.

---

## Threat surface

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond what the original plan's `<threat_model>` already documents. All threats either mitigated or explicitly accepted. The dominant pre-existing posture (root-trusted apt install, 0644 observations.db, sqlite via DSN) is preserved; init-db does not relax the security model.

---

## DIST-04 SC3 closure status: PARTIALLY CLOSED

Code + packaging + UAT-runbook scaffolding all in place. **Empirical re-UAT against Ubuntu 24.04 + Debian 13 (192.168.1.170) is the FINAL gate** — until both 2.4/D.2.4 checkboxes are operator-signed `[x] PASS` with `PRAGMA user_version=3` evidence captured, the gap remains in `partial` status in `05-VERIFICATION.md`. After re-UAT sign-off, run `/gsd:verify-work` or manually update 05-VERIFICATION.md status to `verified` and the score to `7/7 must-haves verified`.

---

## Self-Check: PASSED

- ✅ `cmd/sftp-jailer/init_db.go` exists (130 lines, contains `func initDBCmd() *cobra.Command`, `Hidden: true`, `store.PeekUserVersion`, `current > store.ExpectedSchemaVersion`, `initDBOsExit(2)`, `var initDBPath`, `var initDBOsExit`, no `os/exec` import)
- ✅ `cmd/sftp-jailer/init_db_test.go` exists (164 lines, 6 tests, all PASS)
- ✅ `cmd/sftp-jailer/main.go` registers `initDBCmd()` in Subcommands slice
- ✅ `internal/rootcmd/rootcmd.go` mentions `init-db` in doc comments (2 hunks)
- ✅ `packaging/debian/postinst` has `/usr/bin/sftp-jailer init-db` at L64, inside `[ -x /usr/bin/sftp-jailer ]` guard, NO `|| true`, NO `: >` adjacent, ordering preserved (install -d L49 → init-db L64 → cursor L67)
- ✅ `packaging/debian/lintian-overrides` has 17 entries (was 15) with two new `[postinst:64]` lines and `# WHY:` rationale
- ✅ `docs/uat/05-ubuntu24-uat.md` step 2.4 unchecked `[ ]`, between 2.3 and Step 3
- ✅ `docs/uat/05-debian13-uat.md` step D.2.4 unchecked `[ ]`, against 192.168.1.170
- ✅ `go build ./...` exits 0
- ✅ `go test ./...` full suite green
- ✅ `bash scripts/check-no-exec-outside-sysops.sh` exits 0
- ✅ `sh -n packaging/debian/postinst` exits 0
- ✅ Hidden:true contract: no `sftp-jailer-init-db.1` man page generated; `--help` excludes init-db
- ✅ All 5 commits present in git log: `9aaf5a5` (test RED), `0175c6c` (feat GREEN), `5afc7da` (registration), `da45e42` (postinst), `20ea9cf` (UAT)
