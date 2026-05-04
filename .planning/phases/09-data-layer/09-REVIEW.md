---
phase: 09-data-layer
reviewed: 2026-05-04T00:00:00Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - internal/config/config.go
  - internal/config/config_test.go
  - internal/firewall/mode_test.go
  - internal/store/export_test.go
  - internal/store/migrations.go
  - internal/store/migrations/004_add_dedup_index.sql
  - internal/store/migrations_test.go
  - internal/store/queries.go
  - internal/store/queries_bench_test.go
  - internal/store/queries_test.go
  - internal/store/store.go
  - internal/store/store_test.go
  - internal/tui/screens/logs/logs_test.go
  - internal/ufwcomment/decode.go
  - internal/ufwcomment/encode.go
  - internal/ufwcomment/ufwcomment_test.go
findings:
  critical: 0
  warning: 3
  info: 6
  total: 9
status: issues_found
---

# Phase 09 (data-layer): Code Review Report

**Reviewed:** 2026-05-04
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

Phase 09 (data-layer) ships a clean, defensible piece of work. The SQL surface is uniformly parameterized; the SQL-injection regression tests for `FilterEvents`, `DedupRows`, and `EventsForPair` all pin the discipline (T-OBS-01). The single `fmt.Sprintf` into SQL (`migrations.go:179`) is for `PRAGMA user_version` with an int from a controlled source (file-name prefix), and the comment justifies the carve-out correctly.

The `ufwcomment` v=1 discriminated-union refactor is well-scoped: `KindUnknown` as zero value reads correctly on the error path, legacy v=0 explicitly sets `KindUser` (D-02), and the forward-compat contract via `ErrBadVersion` is consistent across version-mismatch, unknown-payload, and unknown-reason cases. Fuzz seeds cover the new subnet shapes.

Migration 004 + ANALYZE is sound: the EQP regression test pins `USING COVERING INDEX idx_observations_dedup` substring-match (resilient to format changes per sqlite.org/eqp.html), and the v3 to v4 row-count-preservation test is in its strong form (manually staging at v3, seeding, then running Migrate). The 100k-row CI benchmark gate at 1000ms is appropriately permissive for macOS dev hosts; the file header documents the rationale.

The `WithProgress` functional option is correctly designed: nil callback is safe, callback fires only on actually-applied migrations, label-mapping has a fallback for unknown migrations.

Three Warning-level findings flagged below: the most material is **WR-01** (lax integer parsing in `ufwcomment.Decode` via `fmt.Sscanf`), where `sftpj:v=1abc:user=alice` would currently decode as `Version=1` with `User=alice`. The other warnings are a brittle error-string match in migration discovery (WR-02) and a `rows.Err()` after explicit `Close()` ordering (WR-03). No security-critical issues, no data-loss risks, no test-only exports leaking to production.

No em-dash usage in any reviewed file (project memory respected).

## Warnings

### WR-01: Lax integer parsing in ufwcomment.Decode allows trailing garbage in v= field

**File:** `internal/ufwcomment/decode.go:79`

**Issue:** `fmt.Sscanf(parts[0], "%d", &v)` with the `%d` verb scans leading digits and stops at the first non-digit, returning `(1, nil)` for an input like `"1abc"`. Combined with the `SplitN(rest, ":", 2)` split, this means a comment like `sftpj:v=1abc:user=alice` decodes successfully as `{Version: 1, Kind: KindUser, User: "alice"}` rather than returning `ErrBadVersion`.

This is a forward-compat hygiene bug, not a security bug: the username payload still passes `userRE`, so the result is well-formed; but the contract documented in the file header ("Malformed v= field (non-numeric) -> ErrBadVersion") is not actually enforced, and a future v=2 binary writing `sftpj:v=2-rc1:...` (or similar) would be classified as v=2 cleanly while a partially-numeric v= field today silently downgrades to v=1.

The `FuzzDecodeNeverPanics` fuzz test asserts no panic but doesn't assert the parse result, so this regression slips through.

**Fix:**
```go
// Replace fmt.Sscanf with strconv.Atoi which rejects trailing garbage.
import "strconv"

v, err := strconv.Atoi(parts[0])
if err != nil {
    return Parsed{}, ErrBadVersion
}
```

Add a regression test:
```go
func TestDecode_v_field_with_trailing_garbage(t *testing.T) {
    p, err := ufwcomment.Decode("sftpj:v=1abc:user=alice")
    require.ErrorIs(t, err, ufwcomment.ErrBadVersion,
        "v= field with trailing non-digits must reject as bad version, not parse as v=1")
    _ = p
}
```

### WR-02: Migration directory error detection uses brittle string matching

**File:** `internal/store/migrations.go:117`

**Issue:** The fallback for an absent embedded `migrations` directory matches error strings:
```go
if strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "file does not exist") {
    return nil
}
```

This couples migration startup to the exact error wording produced by `embed.FS.ReadDir`, which can change between Go versions and is not part of the stdlib API contract. The idiomatic way is `errors.Is(err, fs.ErrNotExist)`. Today the directive is `//go:embed all:migrations` against a directory that has always existed, so this branch is effectively unreachable - but if a future refactor breaks the embed and this branch ever fires, the string match could silently fail and the wrapped error path would mask the cause.

**Fix:**
```go
import "io/fs"

entries, err := fs.ReadDir(migrationsFS, "migrations")
if err != nil {
    if errors.Is(err, fs.ErrNotExist) {
        return nil
    }
    return fmt.Errorf("store.Migrate: read embedded dir: %w", err)
}
```

(Requires importing `errors` alongside the existing `fs` import.)

### WR-03: PerUserBreakdown calls rows.Err() after explicit rows.Close()

**File:** `internal/store/queries.go:243-246`

**Issue:** The tier-counts loop uses an explicit `_ = rows.Close()` (line 243) followed immediately by `if err := rows.Err(); err != nil {` (line 244). Per `database/sql` documentation, `rows.Err()` should be checked AFTER iteration completes but BEFORE `Close()`; calling it after `Close()` is not formally specified and the documented contract for `rows.Err()` is "Err returns the error, if any, that was encountered during iteration" - state set during iteration is preserved across `Close()` in current implementations, but this ordering is fragile and inconsistent with the rest of the file (every other read path in this same file uses `defer rows.Close()` and checks `rows.Err()` while the rows handle is still live).

The `rows.Close()` immediately followed by `rows.Err()` likely originated as defensive cleanup before the second query (`perUserFirstSeenIPSQL`) issued through the same pool, but the standard pattern handles that correctly via `defer`.

**Fix:** Use `defer` to match the rest of the file:
```go
func (q *Queries) PerUserBreakdown(ctx context.Context, user string, sinceNs int64) (UserBreakdown, error) {
    var ub UserBreakdown

    rows, err := q.r.QueryContext(ctx, perUserTiersSQL, user, sinceNs, sinceNs)
    if err != nil {
        return ub, fmt.Errorf("queries.PerUserBreakdown tiers: %w", err)
    }
    func() {
        defer func() { _ = rows.Close() }()
        for rows.Next() {
            var tb TierBreakdown
            if err := rows.Scan(&tb.Tier, &tb.Count); err != nil {
                ub.Tiers = nil
                return
            }
            ub.Tiers = append(ub.Tiers, tb)
        }
    }()
    if err := rows.Err(); err != nil {
        return ub, fmt.Errorf("queries.PerUserBreakdown tiers rows.Err: %w", err)
    }
    // ... rest of function unchanged
}
```

(The error-flow inside the IIFE is awkward; an alternative is to extract the loop into a small helper that returns `([]TierBreakdown, error)` and invokes `defer rows.Close()` cleanly. Either is fine - the goal is to call `rows.Err()` while the rows handle is still open.)

## Info

### IN-01: PerUserBreakdown checks sql.ErrNoRows on a MAX() aggregate that always returns one row

**File:** `internal/store/queries.go:257`

**Issue:** `MAX(ts_unix_ns)` over zero rows returns a single row with a NULL value, not zero rows. The check `errors.Is(err, sql.ErrNoRows)` for `perUserLastSuccessSQL` is therefore dead code - the only error path here is a real driver error. The `sql.NullInt64` scan on line 256 already correctly handles the NULL case. The `errors.Is` branch costs nothing at runtime but is misleading to readers.

**Fix:** Drop the `errors.Is(err, sql.ErrNoRows)` clause:
```go
if err := q.r.QueryRowContext(ctx, perUserLastSuccessSQL, user).Scan(&lastSuccess); err != nil {
    return ub, fmt.Errorf("queries.PerUserBreakdown last-success: %w", err)
}
```

(The `perUserFirstSeenIPSQL` query on line 249 IS a `LIMIT 1` over potentially zero rows and the `errors.Is(sql.ErrNoRows)` check there is correct; only the MAX() one is redundant.)

### IN-02: SQLite DSN built via fmt.Sprintf without escaping path

**File:** `internal/store/store.go:69, 119`

**Issue:** `dsn := fmt.Sprintf("%s?_pragma=...", path)` and `dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)`. If a future caller passes a path containing `?` or `&` characters, the modernc driver would parse the trailing `?_pragma=...` as part of the path or mis-attribute the pragmas. Today the path comes from a known location (`/var/lib/sftp-jailer/observations.db`) controlled by root, so this is not exploitable - but it is a footgun if the path ever becomes config-driven.

**Fix:** Escape the path or use a safer DSN builder:
```go
import "net/url"

q := url.Values{}
q.Add("_pragma", "journal_mode(WAL)")
q.Add("_pragma", "busy_timeout(5000)")
q.Add("_pragma", "synchronous(NORMAL)")
q.Add("_pragma", "foreign_keys(ON)")
dsn := "file:" + url.PathEscape(path) + "?" + q.Encode()
```

(Defer to v1.1 if the path stays root-controlled and unconfigurable; flagging for the audit trail.)

### IN-03: Migrate file-name prefix parser silently skips files without underscore

**File:** `internal/store/migrations.go:137-138`

**Issue:** `dash := strings.Index(n, "_"); if dash < 1 { continue }` silently skips any file whose name has no underscore in the first position. This is intentional (the `001_init.sql` convention requires it) but a developer who creates `005migrate.sql` (typo) would have the migration silently ignored at runtime - no error, no warning.

**Fix:** Optional - add a debug/dev-time warning when a `.sql` file in the embedded directory is skipped due to a malformed name:
```go
if dash < 1 {
    // Defensive: a .sql file without an underscore prefix is almost certainly
    // a developer typo; surface it as an error rather than silently skipping.
    return fmt.Errorf("store.Migrate: migration file %q has no '_' separator (expected NNN_name.sql)", n)
}
```

This converts a silent skip to a loud failure on package builds. Defer if the policy is "embed only the well-formed files we put there."

### IN-04: TestMigrate_004_preserves_observations_row_count couples to test working directory

**File:** `internal/store/migrations_test.go:112`

**Issue:** `os.ReadFile(m.name)` where `m.name = "migrations/001_init.sql"` (etc.) relies on `go test`'s cwd being set to the package directory. The test's docstring acknowledges this:
> If a future contributor runs the test with a different working directory (e.g. via some `go test -C` flag combination), the relative path will fail and signal "fix me" rather than silently passing.

This is a reasonable trade-off (the alternative - exposing the embed.FS publicly or duplicating SQL into the test - is worse) but documenting it via a defensive `t.Skipf` if `os.Getwd()` doesn't end in `internal/store` would catch the future-cwd case more cleanly than a hard fail.

**Fix:** Optional - add a guard:
```go
cwd, _ := os.Getwd()
if !strings.HasSuffix(cwd, "internal/store") {
    t.Skipf("test relies on cwd=internal/store; got %s", cwd)
}
```

Or expose a test-only `MigrationsFS()` accessor in `export_test.go` and read through `fs.ReadFile(migrationsFS, ...)`.

### IN-05: Inconsistent NULL-vs-empty WHERE clauses across query layer

**File:** `internal/store/queries.go:278, 470`

**Issue:** `lastLoginPerUserSQL` filters with `WHERE tier = 'success' AND user != ''`; `lockdownObservationsSQL` filters with `WHERE user IS NOT NULL AND user != ''`. The schema (per the migrations) declares `user TEXT NOT NULL DEFAULT ''`, so `IS NOT NULL` is always true and the two predicates are functionally equivalent today. The lockdown query's comment documents the IS NOT NULL as defensive against future schema relaxation.

The inconsistency is harmless but confusing for readers. Either pick one style (recommend dropping IS NOT NULL since the NOT NULL constraint enforces it) or document the convention in a queries.go header comment.

**Fix:** Pick one style and apply uniformly. Recommend dropping `IS NOT NULL` in `lockdownObservationsSQL` for consistency with `lastLoginPerUserSQL` (the NOT NULL column constraint already guarantees it).

### IN-06: tableColumns helper uses untyped interface{} for db parameter

**File:** `internal/store/store_test.go:305-307`

**Issue:** The helper signature is:
```go
func tableColumns(t *testing.T, db interface {
    Query(query string, args ...interface{}) (*sql.Rows, error)
}, table string) map[string]bool {
```

This is an inline structural-interface declaration that exists solely to abstract over `*sql.DB` and `*sql.Tx`. The structural interface works but is hard to grep for and unconventional. Existing helpers in `queries_test.go` use `*sql.DB` directly. The two patterns coexist in the same package.

**Fix:** Either accept `*sql.DB` directly (the only caller passes `s.R`) or extract a named interface type if the polymorphism is genuinely needed:
```go
type queryable interface {
    Query(query string, args ...interface{}) (*sql.Rows, error)
}
```

Cosmetic.

---

_Reviewed: 2026-05-04_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
