---
phase: 05-packaging-install-purge-automated-release
reviewed: 2026-04-29T00:00:00Z
depth: standard
files_reviewed: 20
files_reviewed_list:
  - cmd/gen-manpage/main_test.go
  - cmd/gen-manpage/main.go
  - cmd/sftp-jailer/main_test.go
  - cmd/sftp-jailer/main.go
  - cmd/sftp-jailer/purge_cleanup_test.go
  - cmd/sftp-jailer/purge_cleanup.go
  - cmd/uat-05/main.go
  - internal/rootcmd/rootcmd.go
  - internal/sysops/atomic.go
  - internal/sysops/real_phase4_test.go
  - internal/txn/steps_test.go
  - internal/txn/steps.go
  - packaging/debian/postinst
  - packaging/debian/postrm
  - packaging/debian/prerm
  - packaging/debian/lintian-overrides
  - packaging/debian/changelog
  - packaging/debian/copyright
  - packaging/goreleaser.yml
  - scripts/check-manpage-fresh.sh
findings:
  critical: 0
  warning: 4
  info: 4
  total: 8
status: issues_found
---

# Phase 05: Code Review Report

**Reviewed:** 2026-04-29T00:00:00Z
**Depth:** standard
**Files Reviewed:** 20
**Status:** issues_found

## Summary

The Phase 5 packaging and release work is overall well-structured. The Debian
maintainer scripts are correctly scoped, the `purge-sshd-cleanup` hidden cobra
subcommand is properly wired, and the `NewRemoveSshdDropInStep` / BUG-05-A
allowlist fix are correct. The `cmd/uat-05` UAT helper follows the sysops
typed-wrapper discipline for subprocess calls.

Four warnings are flagged, none of them security issues: the most impactful is
that `postinst`'s `configure` case unconditionally truncates the journal cursor
file (`observer.cursor`) on every invocation, including package upgrades — this
resets the observation window to 7 days on every upgrade. The remaining warnings
cover a missing lintian override, a misleading comment in `lintian-overrides`
about a systemd guard that does not exist in the scripts, and a deceptive
"alias" constructor (`NewBackupDefaultUfwStep`) that silently corrupts
`/etc/default/ufw` when called.

No critical issues (security vulnerabilities, data loss risks, or crashes) were
found.

---

## Warnings

### WR-01: `postinst` truncates `observer.cursor` on every upgrade, resetting the journal window

**File:** `packaging/debian/postinst:50`

**Issue:** The `configure` case runs on both fresh install and on every package
upgrade. The line `: > /var/lib/sftp-jailer/observer.cursor` unconditionally
truncates (zeroes out) the cursor file on every invocation. On a fresh install
this is correct — the empty cursor causes the first `observe-run` to use
`--since=7days`. On an upgrade, however, it discards the prior cursor position,
so the next scheduled `observe-run` re-ingests the last 7 days of events,
producing duplicate observations in the SQLite DB and re-triggering any
threshold alerts the admin already processed.

The `$2` argument to `configure` is the previous package version (empty on
first install, set on upgrade). The fix is a conditional create:

**Fix:**
```sh
# In postinst configure case, replace the unconditional truncate:
# : > /var/lib/sftp-jailer/observer.cursor

# With a conditional that only creates on fresh install:
if [ -z "$2" ] || [ ! -f /var/lib/sftp-jailer/observer.cursor ]; then
    : > /var/lib/sftp-jailer/observer.cursor
    chmod 0600 /var/lib/sftp-jailer/observer.cursor
fi
```

(`$2` is the previous version string passed by dpkg on upgrade; it is empty on
first install. The `-f` guard handles the edge case where a prior install ran
but the file was manually deleted.)

---

### WR-02: Missing lintian override for `systemctl daemon-reload` at `postinst:32`

**File:** `packaging/debian/lintian-overrides:43-47`

**Issue:** The lintian-overrides file covers the `maintainer-script-calls-systemctl`
tag for `postinst:37` and `postinst:42` (the `systemctl enable` and `systemctl start`
calls inside the `else` branches), but does NOT cover `postinst:32`:

```sh
systemctl daemon-reload || true
```

This bare `systemctl daemon-reload` call is not inside any `if [ -x /usr/bin/deb-systemd-helper ]`
branch — it is unconditional. Lintian's `maintainer-script-calls-systemctl` tag
fires for any direct `systemctl` invocation in a maintainer script. When the
CI runs `lintian --pedantic` (as described in the release workflow), this
uncovered call will surface as an unfixed tag and may fail the lintian gate
depending on strictness settings.

**Fix:** Add the override for `postinst:32`:
```
# WHY: systemctl daemon-reload is called unconditionally (not guarded by
# deb-systemd-helper) because it is the canonical way to pick up new unit
# files before enabling/starting them. The || true makes it safe on non-systemd.
sftp-jailer: maintainer-script-calls-systemctl [postinst:32]
```

---

### WR-03: `lintian-overrides` comment falsely claims systemctl calls are guarded by `/run/systemd/system`

**File:** `packaging/debian/lintian-overrides:38-47`

**Issue:** The WHY comment above the `maintainer-script-calls-systemctl` overrides
states:

> "The direct calls are guarded by 'if [ -d /run/systemd/system ]' so they are
> safe on non-systemd systems."

This is factually incorrect. Neither `postinst` nor `prerm` contains any
`if [ -d /run/systemd/system ]` guard. All `systemctl` calls in both scripts
are protected only by `|| true`, not by a systemd-presence check. On a
container or minimal chroot environment without systemd, these calls will fail
silently (which is acceptable due to `|| true`) but the comment misrepresents
the actual protection mechanism to future maintainers.

**Fix:** Correct the WHY comment:
```
# WHY: The postinst and prerm scripts call systemctl directly for operations
# that deb-systemd-helper cannot perform (systemctl daemon-reload). These
# calls are wrapped with `|| true` so they fail silently on non-systemd
# environments (containers, chroots). This is intentional — a failed
# daemon-reload on a non-systemd system does not affect the install.
```

---

### WR-04: `NewBackupDefaultUfwStep` corrupts `/etc/default/ufw` when called

**File:** `internal/txn/steps.go:975-982`

**Issue:** `NewBackupDefaultUfwStep` is documented as "the backup-half of the
`/etc/default/ufw` rewrite cycle." In practice it calls
`NewWriteUfwIPV6Step("", now)`, which on `Apply` reads the prior bytes and
then calls `ops.RewriteUfwIPV6(ctx, "")`. `rewriteIPV6Lines` with `value=""`
replaces or appends `IPV6=` (with an empty value) — it does NOT preserve the
prior content. Calling this step in isolation (as a "backup step") would set
`IPV6=` (empty), which is an invalid `ufw` configuration and would break IPv6
firewall rules on the next `ufw reload`.

The step is currently unused in production code (only defined as a "CONTEXT.md
alias"), so there is no active breakage. However it is exported and documented
as safe to call, making it a latent trap for future implementors.

**Fix:** Either delete the alias or implement it correctly as a no-op read
that only populates `priorBytes` without issuing a write:
```go
// Option A: delete NewBackupDefaultUfwStep entirely; callers use
// NewWriteUfwIPV6Step directly for the combined backup+rewrite.

// Option B: make it truly read-only — but then it has no compensator
// to restore from, so it is not a useful Step. Deletion is cleaner.
```

---

## Info

### IN-01: `gatherSubcommands()` in `cmd/gen-manpage/main.go` contains a TODO comment for a step never taken

**File:** `cmd/gen-manpage/main.go:97-101`

**Issue:** The comment at line 97 reads:

```go
// 05-03 appends: stubPurgeSshdCleanupCmd() — but that command will
// have Hidden:true so GenManTree skips it. (We add it here anyway
// so the rootcmd.Build subcommand list matches production exactly,
// and the Hidden filter does its job.)
```

The stub is never actually appended. The production `rootCmd()` in
`cmd/sftp-jailer/main.go:116` registers `purgeSshdCleanupCmd()`, so
`rootcmd.Build` receives 4 subcommands in production but 3 in
`gen-manpage`. The functional impact is zero (GenManTree would skip the hidden
command anyway), but the comment implies the lists should match "exactly," which
they do not. The `TestGatherSubcommands_HasExpectedNames` test also pins the
count at 3, so a future maintainer trying to add the stub will hit a failing test
with a misleading expectation count.

**Fix:** Either add the stub (and update the test to expect 4 subcommands with
the hidden one passing through the Hidden filter), or remove the comment:
```go
// Remove the misleading comment, or add:
stubPurgeSshdCleanupCmd := func() *cobra.Command {
    c := stubCmd("purge-sshd-cleanup", "Internal: invoked by .deb prerm to remove the sshd drop-in (hidden)")
    c.Hidden = true
    return c
}
// Append to the returned slice and update the test want slice to include
// "purge-sshd-cleanup" (or update len check to 4).
```

---

### IN-02: Generated `.gz` artifacts committed to repository risk shipping stale content

**File:** `packaging/goreleaser.yml:38-41` / `packaging/debian/sftp-jailer.1.gz` / `packaging/debian/changelog.Debian.gz`

**Issue:** The goreleaser `before` hook regenerates `sftp-jailer.1.gz` and
`changelog.Debian.gz` at release time, but the same files are committed to the
repository and referenced by the `nfpm` `contents` list. Between releases,
the committed `.gz` files can become stale (e.g., if a subcommand is added
between releases and a developer forgets to regenerate). The `check-manpage-fresh.sh`
CI guard checks `docs/man/` against the generator output, but does NOT verify
that `packaging/debian/sftp-jailer.1.gz` matches `docs/man/sftp-jailer.1`. A
stale `.gz` could be picked up by a local `goreleaser build --snapshot` or a
partial CI run that skips the `before` hooks.

**Fix:** Add a CI step (or extend `check-manpage-fresh.sh`) to verify that the
committed `.gz` is byte-identical to `gzip -9 -c docs/man/sftp-jailer.1`:
```sh
# Append to check-manpage-fresh.sh after the man-page freshness check:
tmpgz=$(mktemp)
gzip -9 -c docs/man/sftp-jailer.1 > "$tmpgz"
if ! cmp -s "$tmpgz" packaging/debian/sftp-jailer.1.gz; then
    echo "FAIL: packaging/debian/sftp-jailer.1.gz is stale — run 'gzip -9 -k -f docs/man/sftp-jailer.1 -c > packaging/debian/sftp-jailer.1.gz' and commit." >&2
    exit 1
fi
rm "$tmpgz"
```

Alternatively, do not commit the `.gz` files and add them to `.gitignore`,
relying on the `before` hook exclusively.

---

### IN-03: `runObserveFire` in `cmd/uat-05/main.go` treats a `failed` oneshot as a non-error PASS

**File:** `cmd/uat-05/main.go:398-406`

**Issue:** When `sftp-jailer-observer.service` exits with systemd state
`"failed"`, `runObserveFire` prints a NOTE and records evidence but does NOT
return an error, allowing the receipt to be written as `"PASS"`. The comment
even includes a commented-out `return fmt.Errorf(...)` acknowledging this is a
deliberate softening. On a staging box with no sshd events yet, a `failed`
oneshot is expected and acceptable. However a genuinely broken observer binary
(e.g., a schema-drift exit 2) would also be recorded as PASS, making DIST-05
acceptance weaker than intended.

This is a UAT-only helper (intended to be deleted post-UAT per the package doc
comment), so the risk surface is limited, but it creates a misleading audit
trail.

**Fix:** Consider uncommenting the hard-failure return, or splitting the two
cases:
```go
if finalState == "failed" {
    // Check if it's an expected "no events yet" failure by inspecting the exit code
    // via `journalctl -u sftp-jailer-observer.service -n 1 -o json` and reading
    // the MESSAGE field. For the DIST-05 gate a soft NOTE is acceptable
    // on a fresh box; document this explicitly in the receipt.
    r.Evidence["service_state_note"] = "failed; operator must verify journal to confirm expected vs unexpected failure"
    // For an automated CI gate, return the error unconditionally.
}
```

---

### IN-04: `NewRemoveSshdDropInStep` missing test for `Compensate`-after-`Apply` restoring content

**File:** `internal/txn/steps_test.go`

**Issue:** The `steps_test.go` file has comprehensive coverage for
`NewWriteSshdDropInStep` (apply+compensate with prior content, apply+compensate
with no prior). The new `NewRemoveSshdDropInStep` (Phase 5 plan 05-03) is
exercised indirectly via `TestPurgeStepsFn_OrderAndNames` (which calls
`purgeStepsFn`) and the allowlist test in `real_phase4_test.go`, but there is
no dedicated unit test verifying:

1. `Apply` writes the backup file and calls `RemoveAll` on the drop-in.
2. `Compensate` restores the prior bytes via `AtomicWriteFile`.
3. `Apply` with no prior file is a no-op (both `backupPath` and `RemoveAll`
   called with the absent path, which the `Fake` treats as success).

The `TestStepNames_are_unique_and_descriptive` test at line 355 also does not
include `NewRemoveSshdDropInStep` in its step list, so the `RemoveSshdDropIn`
name is not pinned by the uniqueness checker.

**Fix:** Add dedicated tests:
```go
func TestNewRemoveSshdDropInStep_apply_backs_up_then_removes_and_compensate_restores(t *testing.T) {
    const dropInPath = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"
    const backupDir  = "/var/backups/sftp-jailer"

    priorBytes := []byte("Subsystem sftp internal-sftp\n")
    f := sysops.NewFake()
    f.Files[dropInPath] = priorBytes
    sysops.SetAtomicWriteAllowlistForTest([]string{backupDir + "/", dropInPath})
    t.Cleanup(sysops.ResetAtomicWriteAllowlistForTest)

    step := NewRemoveSshdDropInStep(dropInPath, backupDir, 0o644, frozenNow())
    ctx := context.Background()

    require.NoError(t, step.Apply(ctx, f))
    // drop-in removed
    _, exists := f.Files[dropInPath]
    require.False(t, exists, "Apply must remove the drop-in")
    // backup written
    expectedBackup := filepath.Join(backupDir, frozenStamp+"-50-sftp-jailer.conf.bak")
    require.Equal(t, priorBytes, f.Files[expectedBackup])

    // Compensate restores
    require.NoError(t, step.Compensate(ctx, f))
    require.Equal(t, priorBytes, f.Files[dropInPath])
}
```

Also add `NewRemoveSshdDropInStep(...)` to `TestStepNames_are_unique_and_descriptive`.

---

_Reviewed: 2026-04-29T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
