---
phase: 09-data-layer
fixed_at: 2026-05-04T07:00:00Z
review_path: .planning/phases/09-data-layer/09-REVIEW.md
iteration: 1
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 09 (data-layer): Code Review Fix Report

**Fixed at:** 2026-05-04
**Source review:** `.planning/phases/09-data-layer/09-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope: 3 (Critical + Warning, per fix_scope=critical_warning)
- Fixed: 3
- Skipped: 0

All Warning-level findings from the standard-depth review were fixed and committed atomically. Info findings (IN-01 .. IN-06) were out of scope per the configured fix_scope. Local CI gates (`go build ./...`, `go vet ./...`, `go test ./... -count=1`, `golangci-lint run ./...`, plus all four `scripts/check-*.sh` guards) pass after every commit.

## Fixed Issues

### WR-01: Lax integer parsing in ufwcomment.Decode allows trailing garbage in v= field

**Files modified:** `internal/ufwcomment/decode.go`, `internal/ufwcomment/ufwcomment_test.go`
**Commit:** de45c42
**Applied fix:** Replaced `fmt.Sscanf(parts[0], "%d", &v)` with `strconv.Atoi(parts[0])` so trailing non-digit characters in the v= field reject as `ErrBadVersion` instead of silently parsing as the leading integer. Removed the `fmt` import (now unused) and added `strconv`. Added regression test `TestDecode_v_field_with_trailing_garbage` pinning that `sftpj:v=1abc:user=alice` returns `ErrBadVersion`. The pre-fix code violated the file-header `ErrBadVersion` contract because `fmt.Sscanf` with `%d` stops at the first non-digit and returns success.

### WR-02: Migration directory error detection uses brittle string matching

**Files modified:** `internal/store/migrations.go`
**Commit:** cf42cbf
**Applied fix:** Replaced `strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "file does not exist")` with `errors.Is(err, fs.ErrNotExist)`. Added the `errors` import alongside the existing `fs` import. The `strings` import remains in use for `HasSuffix` / `Index` elsewhere in the file. The previous string-match coupled migration startup to Go's internal error wording from `embed.FS.ReadDir`, which is not part of the stdlib API contract; `fs.ErrNotExist` is.

### WR-03: PerUserBreakdown calls rows.Err() after explicit rows.Close()

**Files modified:** `internal/store/queries.go`
**Commit:** af162a0
**Applied fix:** Extracted the per-user-tiers query loop into a new helper `(*Queries).perUserTiers(ctx, user, sinceNs)` that uses the canonical `defer rows.Close()` + `rows.Err()`-while-live pattern, matching every other read path in the file (`LastLoginPerUser`, `FilterEvents`, `LockdownObservations`, etc.). `PerUserBreakdown` now calls the helper and assigns the returned slice to `ub.Tiers`. The previous explicit `_ = rows.Close()` followed by `rows.Err()` called the error check after the rows handle was already closed, which is fragile and inconsistent with the rest of the file.

---

_Fixed: 2026-05-04_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
