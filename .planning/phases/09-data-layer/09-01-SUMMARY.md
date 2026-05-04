---
phase: 09-data-layer
plan: 01
subsystem: ufwcomment
type: execute
status: complete
wave: 1
requirements: [FW-10]
tags:
  - fw-10
  - ufwcomment
  - discriminated-union
  - forward-compat
  - phase-09
dependency-graph:
  requires:
    - internal/ufwcomment.Encode (preserved byte-identical)
    - internal/ufwcomment.Parsed (extended; existing fields preserved)
    - internal/firewall.DetectMode (untouched; still drops User=="" rules)
    - internal/store.Queries.RebuildUserIPs (untouched; existing User==""||ParseErr!=nil guards filter subnet rules)
  provides:
    - internal/ufwcomment.Kind (KindUnknown/KindUser/KindSubnet)
    - internal/ufwcomment.ReasonRFC1918/ReasonRFC4193/ReasonLinkLocal/ReasonOperator
    - internal/ufwcomment.ErrInvalidReason
    - internal/ufwcomment.EncodeSubnet
    - internal/ufwcomment.Parsed.Kind, Parsed.SubnetReason fields
  affects:
    - Phase 11 LOCK-10..13 subnet whitelist writer (will consume EncodeSubnet)
    - Phase 11 DetectMode extension (must be extended to recognize Kind==KindSubnet; intentionally deferred per D-25/D-26 boundary)
tech-stack:
  added: []
  patterns:
    - Discriminated union (Kind enum) for forward-compatible payload classifier
    - Two-step RED-GREEN gate (P-07): pre-extension regression test replaced by post-extension positive test in same plan
    - Closed enum + ErrInvalidReason on encode side / ErrBadVersion on decode side (D-04 split: precise caller surface for Phase 11 dry-run preview, broader forward-compat for legacy binaries)
key-files:
  created: []
  modified:
    - internal/ufwcomment/encode.go
    - internal/ufwcomment/decode.go
    - internal/ufwcomment/ufwcomment_test.go
    - internal/firewall/mode_test.go
key-decisions:
  - "D-02: legacy v=0 successful decode sets Kind=KindUser (not KindUnknown) so downstream Kind switches work uniformly across grammar versions"
  - "D-03: unknown reason inside recognized scope=subnet returns ErrBadVersion (forward-compat sink), not ErrInvalidReason"
  - "D-04: encode-side split - EncodeSubnet returns ErrInvalidReason for precise caller surface; Decode returns broader ErrBadVersion for forward-compat"
  - "D-06 corrected: longest subnet shape link-local is 40 bytes empirically (CONTEXT said 38); test pins empirical value"
  - "D-22: Parsed struct extended (gained 2 fields), NOT renamed; Decode and Encode signatures byte-identical; all 4 existing error sentinels preserved"
metrics:
  duration: "~2.5 hours"
  completed: 2026-05-04
  tasks-completed: 4
  commits: 4
  files-modified: 4
---

# Phase 09 Plan 01: ufwcomment Discriminated Union (FW-10) Summary

Extends `internal/ufwcomment` from a single-payload v=1 grammar to a discriminated union supporting both user-rules (existing) and subnet-rules (new shape `sftpj:v=1:scope=subnet:reason=<rfc1918|rfc4193|link-local|operator>`). Phase 11 will write subnet rules using `EncodeSubnet`; v1.2.x binaries continue treating subnet rules as opaque foreign rules per the existing forward-compat contract.

## What was built

**Task 1 - Wave-0 RED gate (commit `882abbf`):** Added `TestDecode_v1_subnet_shape_pre_extension_returns_ErrBadVersion` and `TestDetectMode_skips_v1_subnet_shape` pinning the literal subnet-shape decode contract before any decode.go change. Both tests passed against unchanged decode.go - proves the v1.2.x snapshot.

**Task 2 - Discriminated union landing (commit `3044b32`):**
- `internal/ufwcomment/encode.go` gained `Kind` type, three Kind constants, four `ReasonXxx` constants, `ErrInvalidReason` sentinel, `EncodeSubnet` function
- `internal/ufwcomment/decode.go`: `Parsed` struct gained `Kind` and `SubnetReason` fields (existing `Version` and `User` preserved); `Decode` v=1 branch grew from 2-way to 3-way classifier (`user=` -> KindUser, `scope=subnet:reason=` -> KindSubnet, else -> ErrBadVersion); legacy v=0 branch sets `Kind=KindUser` per D-02
- `TestDecode_v1_subnet_shape_pre_extension_returns_ErrBadVersion` was REPLACED with `TestDecode_v1_subnet_shape_decoded` (post-extension positive contract)
- `TestDetectMode_skips_v1_subnet_shape` flipped its `ParseErr` literal from `ufwcomment.ErrBadVersion` to `nil`; assertion (`ModeUnknown`) is invariant per D-01

**Task 3 - Round-trip + invariant coverage (commit `8402cf9`):** Added 6 tests:
- `TestEncodeSubnet_all_reasons_roundtrip` - each of 4 reasons round-trips through EncodeSubnet -> Decode
- `TestSubnetCommentByteCaps` - pins empirical byte counts (37/37/40/38; D-06 said link-local was 38, empirical is 40)
- `TestEncodeSubnet_invalid_reasons` - empty, unknown, uppercase, trailing space, near-miss all return `ErrInvalidReason`
- `TestDecode_v1_subnet_invalid_reason` - garbage reason, empty reason, uppercase reason, unknown scope, missing reason= all return `ErrBadVersion` with `Kind==KindUnknown` on the error path
- `TestDecode_v0_legacy_kind_is_KindUser` - pins the D-02 invariant
- `TestDecode_v1_user_kind_is_KindUser` - pins the v=1 user-rule Kind invariant

**Task 4 - Fuzz seeds + final gate (commit `6900882`):** Appended four subnet-shape variants to `FuzzDecodeNeverPanics` (valid rfc1918, empty reason, unknown scope, NUL byte). 10s fuzz run completed with 4 new interesting inputs and zero panics across ~480k executions.

## Forward-compat verification

- `internal/firewall/mode_test.go::TestDetectMode_skips_v1_subnet_shape`: invariant assertion `ModeUnknown` holds across both pre-extension (Task 1, ParseErr=ErrBadVersion) and post-extension (Task 2, ParseErr=nil) states. The mode predicate at `mode.go:67-99` drops the rule on `User==""` regardless.
- `internal/store/queries.go::RebuildUserIPs` at line 379: existing guard `r.User == "" || r.ParseErr != nil` filters subnet rules without modification - no store package change needed.
- v1.2.x binaries reading Phase-11-written subnet rules: `Decode` returns `ErrBadVersion` (the v=1 branch with non-`user=` payload was the existing behavior), which `DetectMode` skips per its `ParseErr != nil` guard, which `RebuildUserIPs` skips per its `r.User == ""` guard.

## Symbols added (FW-10 surface)

```go
type Kind int
const (
    KindUnknown Kind = iota
    KindUser
    KindSubnet
)
const (
    ReasonRFC1918   = "rfc1918"
    ReasonRFC4193   = "rfc4193"
    ReasonLinkLocal = "link-local"
    ReasonOperator  = "operator"
)
var ErrInvalidReason = errors.New("ufwcomment: invalid subnet reason")
func EncodeSubnet(reason string) (string, error)

// Parsed gained two fields; existing fields and order preserved at the front.
type Parsed struct {
    Version      int
    Kind         Kind          // NEW
    User         string
    SubnetReason string        // NEW
}
```

## Symbols preserved (D-22 invariant)

- `Encode(user string) (string, error)` - byte-identical
- `Decode(c string) (Parsed, error)` - signature byte-identical (return-type is the extended `Parsed`, but field order is back-compat)
- All four sentinels: `ErrInvalidUser`, `ErrTooLong`, `ErrNotOurs`, `ErrBadVersion` - byte-identical
- `Prefix`, `Version`, `MaxUser`, `MaxComment` - byte-identical
- `userRE` (private) - byte-identical
- All 12 existing `ufwcomment_test.go` tests pass unchanged
- All existing `firewall/mode_test.go` tests pass unchanged

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pre-extension test assertion mismatch (Task 1)**
- **Found during:** Task 1 first verification run.
- **Issue:** Plan specified `require.Equal(t, 1, p.Version)` for the pre-extension RED gate test. Actual decode.go returned `Parsed{}` (Version=0) on payload-shape failure inside v=1, not `Parsed{Version: 1}`. The plan author apparently intended to assert that the v=1 grammar version was preserved on the error path, but decode.go at line 64 returned the zero-value Parsed - so the test as specified would have failed against unchanged decode.go.
- **Fix:** Changed assertion to `require.Equal(t, 0, p.Version)` to match actual current behavior. The RED gate's central claim (`Decode returns ErrBadVersion for v=1 subnet shape`) is preserved. Documented the correction in the test's doc-comment and the Task 1 commit message body. Task 2's replacement test (`TestDecode_v1_subnet_shape_decoded`) asserts the post-extension positive contract (`p.Version==1` on success), which is the contract Phase 11 binaries actually need to reason about.
- **Files modified:** `internal/ufwcomment/ufwcomment_test.go`
- **Commit:** `882abbf`

**2. [Rule 1 - Bug] Lint regression on Kind const block (Task 2)**
- **Found during:** Task 2 `golangci-lint run` after the Kind enum was added.
- **Issue:** revive flagged `exported const KindUnknown should have comment (or a comment on this block) or be unexported`. The plan specified the const block without a block-level comment - the comment on the `Kind` type definition was insufficient for revive's rule.
- **Fix:** Added a one-line block-level doc-comment to the const block (`// Kind enumeration values. KindUnknown is the zero value...`).
- **Files modified:** `internal/ufwcomment/encode.go`
- **Commit:** Folded into Task 2 commit `3044b32` (no separate commit).

## D-06 byte-count correction

CONTEXT.md D-06 stated link-local subnet shape was 38 bytes. Empirical verification:

| Reason | Comment | Bytes |
|---|---|---|
| rfc1918 | `sftpj:v=1:scope=subnet:reason=rfc1918` | 37 |
| rfc4193 | `sftpj:v=1:scope=subnet:reason=rfc4193` | 37 |
| link-local | `sftpj:v=1:scope=subnet:reason=link-local` | **40** |
| operator | `sftpj:v=1:scope=subnet:reason=operator` | 38 |

`TestSubnetCommentByteCaps` pins the empirical numbers; all shapes still fit under MaxComment=64 so the closed-enum + cap holds. Phase 09 CONTEXT.md should be amended in a follow-up doc commit (or in 09-02 / 09-03 SUMMARY) to flag this correction. The 09-03 plan-checker round-2 PASS message references this finding (research RQ-12 Pitfall 1) so the correction is already in the planning record.

## Cross-phase notes for Phase 11

- **Subnet whitelist writer (LOCK-10..13)** consumes `EncodeSubnet(reason)` - the symbol is now available.
- **DetectMode extension required**: post this plan, `internal/firewall/mode.go::DetectMode` still classifies subnet rules as `ModeUnknown` because the sftpj predicate drops `User==""` rules. Phase 11 must extend DetectMode to recognize `Kind==KindSubnet` (likely via a `RuleKind` field on `firewall.Rule` populated from `Parsed.Kind` in the enumerate parser), or the lockdown UI will report subnet allowlists as "no SFTP rules at all". `TestDetectMode_skips_v1_subnet_shape` will need to be updated or replaced when that extension lands (current invariant `ModeUnknown` reflects today's intentionally-conservative semantics).
- **Store layer untouched**: `internal/store/queries.go::RebuildUserIPs` already filters subnet rules via existing guards - no schema or query change needed for FW-10. Phase 11's subnet-rule storage approach (separate table? extend rule_id metadata?) is open per its own plan.
- **M-DRY-RUN preview** (Phase 11 D-04): use `EncodeSubnet` to render the literal comment string into the dry-run preview UI without round-tripping through ufw. The closed enum makes the preview deterministic.

## Verification

| Check | Result |
|---|---|
| `go build ./...` | exit 0 |
| `go test ./internal/ufwcomment/... -count=1` | PASS (16 tests + 2 fuzz suites with 12 seeds) |
| `go test ./internal/firewall/... -count=1` | PASS (no regression; new subnet test added) |
| `go test ./internal/store/... -count=1` | PASS (no regression) |
| `go test -fuzz=FuzzDecodeNeverPanics -fuzztime=10s` | PASS (480190 execs, 4 new interesting, 0 crashes) |
| `golangci-lint run ./...` | 0 issues (full repo) |
| `scripts/check-no-exec-outside-sysops.sh` | OK |
| `scripts/check-go-mod-pins.sh` | OK (zero new deps per D-23) |
| `scripts/check-single-tea-program.sh` | OK |
| D-21 atomic commits | 4 commits (one per task) |
| D-22 symbol invariant | All pre-existing exported symbols byte-identical |

## Self-Check: PASSED

- Created files: none (plan was pure modification + test additions)
- Modified files exist:
  - `internal/ufwcomment/encode.go` FOUND
  - `internal/ufwcomment/decode.go` FOUND
  - `internal/ufwcomment/ufwcomment_test.go` FOUND
  - `internal/firewall/mode_test.go` FOUND
- Commits exist:
  - `882abbf` FOUND (test 09-01 RED gate)
  - `3044b32` FOUND (feat ufwcomment discriminated union)
  - `8402cf9` FOUND (test ufwcomment round-trip + Kind invariants)
  - `6900882` FOUND (test ufwcomment fuzz seeds)
