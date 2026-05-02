# Phase 6: v1.1 Carry-over Closure - Firewall edge + TUI polish - Research

**Researched:** 2026-04-30
**Domain:** Cancellable subprocess Go patterns, ufw IPv6 dual-family rules, Bubble Tea v2 modal idioms
**Confidence:** HIGH

## Summary

Phase 6 closes 4 v1.1 carry-over items - all of which sit in well-mapped territory. The codebase already ships every primitive each requirement needs:

- **TUI-11** maps cleanly onto Go's `Cmd.Cancel` + `Cmd.WaitDelay` standard-library pattern (stable since Go 1.20; Go 1.25 toolchain in use). The right move is NOT to hand-roll a SIGTERM/wait/SIGKILL loop in each modal - it is to add ONE typed `sysops.ExecOpts{Cancel: SIGTERM, GraceWindow: 2s}` overload so the cancellation policy lives in `internal/sysops/real.go::Exec` (architectural invariant: subprocess termination semantics belong next to subprocess invocation). Each of the 4 modal sites then swaps `context.Background()` for a stored `context.WithCancel(parent)` and routes Esc to the cancel func - a pattern the M-OBSERVE modal already pioneered (`internal/tui/screens/observerun/observerun.go:198-200`).
- **FW-09** is mostly fixture work + UAT runbook authoring. The runtime code (`firewall.Enumerate` v6 detection, `stripV6Suffix` source normalization, `NewUfwDeleteCatchAllByEnumerateStep` family-agnostic predicate) already handles dual-family and v6-only correctly - confirmed by `TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6` at `steps_test.go:1314`. What's missing is (a) a v6-only-host fixture (no v4 catch-all) and (b) a v6-source `firewall.AddRule` test exercising the `2001:db8::/32` syntax with the `sftpj:v=1:user=<name>` comment grammar.
- **TUI-10** reads from `Queries.PerUserBreakdown` (already shipped Phase 2 plan 02-01) for the tier-counts header strip and from `Queries.FilterEvents` (with `User` + `SinceNs` set per `LockdownProposalWindowDays`) for the last-20-events list. The S-LOGS `displayN` / `colorByTier` / `tierGlyph` row helpers are reusable verbatim - factor them into a tiny `internal/tui/widgets/eventrow` (or call them in place via package-internal exports added under `_test.go` build-tag-free helper functions). Modal frame: lipgloss `NormalBorder` + `Padding(0, 2)`, exactly as M-OBSERVE / M-ADD-KEY use.
- **TUI-09** is the most mechanical of the four: add 2 enum constants (`fieldPasswordAgingDays`, `fieldPasswordStaleDays`) to `settings.go`'s existing `fieldKind` iota chain, wire `currentValue` / `valueFor` / `attemptSave` switch arms, and lean on the existing `config.Validate` strict-ordering check (`0 < aging < stale`) to surface "must be strictly less than stale" / "must be strictly greater than aging" inline errors for free.

**Primary recommendation:** Land the 4 plans in any order; TUI-11 carries the largest architectural weight (sysops API surface change) and should ship FIRST so the discipline propagates cleanly across the 9 (not 7) detected `context.Background()` sites.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| FW-09 v4+v6 catch-all delete loop | `internal/txn` (Step) | `internal/firewall` (Enumerate read) | Delete is a transactional mutation in the SAFE-04 reverse-cmd contract; reads stay in the firewall reader package per Phase 4 D-FW-01. |
| FW-09 v6-source rule add | `internal/firewall.AddRule` (writer) | `internal/sysops.UfwInsert` (subprocess) | Single firewall WRITER per D-FW-01 - mutation surface lives here; sysops is the typed subprocess wrapper. |
| FW-09 v6-only / dual-family fixtures | `internal/txn/steps_test.go` + `internal/firewall/testdata/` | - | Test fixtures only - no runtime tier. |
| FW-09 UAT runbook | `docs/uat/06-fw09-uat.md` | - | Documentation tier; mirrors Phase 5 runbook structure. |
| TUI-09 password-aging knobs | `internal/tui/screens/settings` (TUI) | `internal/config` (Validate, Save) | Inline-edit + textinput is a screen-local concern; persistence and validation already exist in config. |
| TUI-10 per-user log modal | `internal/tui/screens/userlog` (NEW) | `internal/store.Queries` (data) | Modal is its own screen package per existing pattern (one screen per dir under `internal/tui/screens/`). Data layer untouched. |
| TUI-10 keybind dispatch | `internal/tui/screens/users.handleKey` | - | The S-USERS keybind dispatcher already routes uppercase 'D'; uppercase 'L' is a sibling addition. |
| TUI-11 cancellable Exec contract | `internal/sysops` (typed wrapper) | `internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}` (consumers) | Subprocess termination policy belongs next to subprocess invocation. CI guard `check-no-exec-outside-sysops.sh` enforces. |
| TUI-11 cancellable context plumbing | The 4 modal sites | - | Each modal stores its own `cancelFn`; routes Esc to it. Per-site (D-10) - no shared widget unless drift emerges. |
| TUI-11 'Cancelling...' indicator | `internal/tui/widgets` (Toast / spinner) | - | Existing Toast.Flash + spinner widgets cover this; no new widget needed. |

## Standard Stack

### Core (already pinned in `go.mod`)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go toolchain | 1.25.0 (go.mod), 1.26.2 (dev box) | Compiler | `Cmd.Cancel` + `Cmd.WaitDelay` stable since 1.20; trivially available on 1.25. `[VERIFIED: go.mod, go env GOVERSION]` |
| `charm.land/bubbletea/v2` | v2.0.6 | TUI framework | Phase 1 decision; all existing modals use it. `[VERIFIED: go.mod]` |
| `charm.land/bubbles/v2` | v2.1.0 | Components (textinput, spinner) | Settings + addkey + observerun all import directly. `[VERIFIED: go.mod]` |
| `charm.land/lipgloss/v2` | v2.0.3 | Styling (NormalBorder, JoinHorizontal) | M-OBSERVE / M-ADD-KEY modal frame already uses this. `[VERIFIED: go.mod]` |
| `modernc.org/sqlite` | (from Phase 2) | Observation DB driver | TUI-10 reads via `internal/store.Queries`; no driver-level work. `[CITED: CLAUDE.md tech stack]` |

### Supporting (already imported)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `dustin/go-humanize` | (existing) | "5 minutes ago" timestamp formatting | TUI-10 modal "last seen" column - mirror S-USERS' `humanize.Time(time.Unix(0, e.LastLoginNs))` idiom. `[VERIFIED: internal/tui/screens/users/users.go:39]` |
| `stretchr/testify` | v1.11.1 | Test assertions | Every `*_test.go` already uses `require`. `[VERIFIED: go.mod]` |
| `internal/store.Queries` | (Phase 2) | `PerUserBreakdown`, `FilterEvents` | TUI-10 reads via these. `PerUserBreakdown` is tier-counts (no time window) - `FilterEvents` is the events list with `User=<u>, SinceNs=<now-N*86400e9>` for the time-windowed last-20. `[VERIFIED: internal/store/queries.go:147,214]` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Cmd.Cancel + WaitDelay (stdlib) | Hand-rolled `cmd.Process.Signal(syscall.SIGTERM)` + goroutine timer + SIGKILL | The stdlib pattern is what Go documents (`pkg.go.dev/os/exec`); hand-rolling reinvents Wait coordination, pipe-close timing, and ErrWaitDelay surfacing. Reject. |
| Per-site cancellable infra (D-10) | Shared widget `internal/tui/widgets/cancellable.go` | D-10 explicitly says per-site is the default; only extract if drift emerges during execution. Honor the decision. |
| New SQL query for "last 20 events for user in last N days" | Reuse `FilterEvents` with `User`, `SinceNs`, `Limit=20` | Existing SQL already has the placeholders (`User`, `SinceNs`, `Limit`). Adding a new query would duplicate the index path. Reject. |
| Refactor `firewall.AddRule` to take `family` arg | Keep AddRule untouched; let net.ParseCIDR detection drive ufw syntax | ufw 0.36.2 auto-routes the family from the source CIDR per `[CITED: oneuptime.com IPv6 ufw guide]` - no caller-side family flag needed. Reject. |

**Installation:** No new dependencies; every package needed is already in `go.mod`.

**Version verification:** Confirmed via `go env GOVERSION` (1.26.2) and `go.mod` (`go 1.25.0` directive, bubbletea v2.0.6). Stack is current; nothing to upgrade for Phase 6. `[VERIFIED: go.mod, go env]`

## Architecture Patterns

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 6 surfaces                             │
└─────────────────────────────────────────────────────────────────┘

                      [Admin]
                         │
       ┌─────────────────┼─────────────────────────────┐
       │                 │                             │
       ▼                 ▼                             ▼
  [S-SETTINGS]      [S-USERS]                  [4 mutation modals]
   TUI-09            TUI-10 (uppercase 'L')    TUI-11
       │                 │                             │
       │                 ▼                             │
       │         [M-USER-LOG modal]                    │
       │              (NEW)                            │
       │                 │                             │
       │     ┌───────────┼─────────────┐               │
       │     ▼           ▼             ▼               │
       │  PerUser    FilterEvents  config.            │
       │  Breakdown  (User+SinceNs+ Lockdown          │
       │  (tier      Limit=20)      ProposalWindow    │
       │   counts)                  Days              │
       │     │           │                            │
       │     └────┬──────┘                            │
       │          ▼                                    │
       │   internal/store.Queries (sqlite)             │
       │                                               │
       ▼                                               ▼
   config.Save                              context.WithCancel
   (atomic write)                                       │
       │                                                ▼
       ▼                                       sysops.Exec(ctx,...)
   sysops.AtomicWriteFile                              │
                                                        ▼
                                              cmd.Cancel = SIGTERM
                                              cmd.WaitDelay = 2s
                                                        │
                                                        ▼
                                                  [subprocess]


┌─────────────────────────────────────────────────────────────────┐
│              FW-09 (commit-time firewall flow)                 │
└─────────────────────────────────────────────────────────────────┘

  S-LOCKDOWN commit
         │
         ▼
  txn.Apply(steps...)
         │
         ▼
  NewUfwDeleteCatchAllByEnumerateStep("22")
         │
         ▼
  for i := 0; i < maxCatchAllIterations; i++ {
       firewall.Enumerate(ctx, ops)        ← reads `ufw status numbered`
       │                                     │
       │ stripV6Suffix("Anywhere (v6)")     ← protocol-agnostic predicate
       │ → "Anywhere"                       │
       ▼                                     ▼
       findCatchAllID(rules)               match: Source=="Anywhere",
       │                                     ALLOW, RawComment=="",
       │                                     port matches "22"
       ▼
       ops.UfwDelete(ctx, id)
  }
  // Loop terminates when no catch-alls remain.
  // On dual-family hosts: 2 deletes (v4 + v6).
  // On v6-only hosts: 1 delete (just v6).
  // On already-locked hosts: 0 deletes (idempotent).
```

### Recommended Project Structure

No new top-level dirs. Additions:

```
internal/tui/screens/userlog/             # TUI-10 NEW package
├── userlog.go                            #   model, Init, Update, View
└── userlog_test.go                       #   teatest/v2 golden flows

internal/firewall/testdata/
├── ufw-status-numbered-mixed.txt         #   (existing) v4+v6 dual-family
├── ufw-status-numbered-v6-only.txt       #   NEW (FW-09): v6-only host
└── ufw-status-numbered-v6-source.txt     #   NEW (FW-09): IPv6 sftpj rule

internal/txn/steps_test.go                #   ADDS: v6-only fixture + test
internal/firewall/mutate_test.go          #   ADDS: AddRule v6 source test
internal/firewall/enumerate_test.go       #   (existing) v6 detection covered

internal/sysops/real.go                   #   ADDS: Cancel + WaitDelay plumbing in Exec()
internal/sysops/sysops.go                 #   ADDS: ExecOpts (or wrapper method) shape

internal/tui/screens/settings/settings.go #   ADDS: 2 fieldKind constants + switch arms
internal/tui/screens/users/users.go       #   ADDS: case "L" handler in handleKey
internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go
                                          #   REPLACES: 9 context.Background() sites with
                                          #             stored cancellable contexts

docs/uat/06-fw09-uat.md                   #   NEW: dual-family + v6-only runbook
```

### Pattern 1: Go stdlib SIGTERM-then-SIGKILL via Cmd.Cancel + WaitDelay

**What:** Set `Cmd.Cancel` to send SIGTERM, set `Cmd.WaitDelay` to the grace window. Go's stdlib coordinates the rest.

**When to use:** TUI-11. Replaces hand-rolled signaling loops.

**Example:**
```go
// Source: pkg.go.dev/os/exec - Cmd.Cancel + Cmd.WaitDelay
// [CITED: pkg.go.dev/os/exec accessed 2026-04-30]

cmd := exec.CommandContext(ctx, bin, args...)

// Override the default Cancel (which is os.Process.Kill / SIGKILL).
cmd.Cancel = func() error {
    err := cmd.Process.Signal(syscall.SIGTERM)
    if errors.Is(err, os.ErrProcessDone) {
        return nil // already exited - not an error
    }
    return err
}

// Grace window: if subprocess still running 2s after Cancel, stdlib
// invokes os.Process.Kill() (SIGKILL) automatically. Per D-06.
cmd.WaitDelay = 2 * time.Second

// Now ctx cancellation triggers SIGTERM, then 2s later SIGKILL.
out, err := cmd.CombinedOutput()
```

**Critical detail (verified at pkg.go.dev/os/exec):**
- If WaitDelay expires AND the subprocess exits successfully AFTER Cancel was called, `Wait` returns a non-zero error wrapping the Cancel return (or `ctx.Err()`). The TUI-11 modals MUST handle this case as "cancellation succeeded" not "subprocess failed" - check `errors.Is(err, context.Canceled)` first.
- If `Cancel` returns `os.ErrProcessDone`, stdlib treats it as a clean already-exited path (no error).
- WaitDelay starts when ctx is done OR process exits, whichever first. Worst-case wall time bound is `WaitDelay` from cancel-press.

### Pattern 2: M-OBSERVE-style cancellable subprocess with stored cancelFn

**What:** Modal stores a `context.CancelFunc` from `context.WithCancel(parent)`. Esc handler calls it. Subprocess sysops invocation uses the same ctx.

**When to use:** All 4 TUI-11 sites. Already exists in production at `internal/tui/screens/observerun/observerun.go:77,198`.

**Example:**
```go
// Source: internal/tui/screens/observerun/observerun.go (existing production)
// Adapted shape for the 4 TUI-11 modals.

type Model struct {
    // ... existing fields ...
    cancelFn   context.CancelFunc  // NEW: set by attemptCommit / resolveAsync
    cancelling bool                // NEW: true after Esc dispatched cancel
}

func (m *Model) attemptCommit() tea.Cmd {
    ctx, cancel := context.WithCancel(context.Background())  // NOT WithTimeout
    m.cancelFn = cancel
    // ... existing tea.Batch body, but use the cancellable ctx ...
    return tea.Batch(m.spinner.Tick, func() tea.Msg {
        defer cancel()  // safety net for happy-path cleanup
        // sysops calls inherit cancellation via ctx
        err := tx.Apply(ctx, steps)
        return committedMsg{err: err}
    })
}

func (m *Model) handleEscDuringCommit() tea.Cmd {
    if m.cancelFn != nil {
        m.cancelFn()  // triggers cmd.Cancel → SIGTERM, WaitDelay → SIGKILL
    }
    m.cancelling = true
    // Modal STAYS OPEN per D-07; closes when committedMsg arrives
    // (carrying ctx.Canceled error which we render as "cancelled").
    return nil
}
```

### Pattern 3: Bubble Tea v2 read-only modal with NormalBorder + Padding

**What:** Modal that loads data on Init, renders a table, supports cursor + OSC 52 row copy, no mutation.

**When to use:** TUI-10. Mirror is M-OBSERVE (which is the M-OBSERVE-style padding exception per UI-SPEC line 46 - re-applicable here because the modal is a focused full-screen overlay, not a small dialog).

**Example:**
```go
// Source: internal/tui/screens/observerun/observerun.go::wrapModal +
//         internal/tui/screens/logs/logs.go::renderList (5-column row).
// Pattern blends the two: M-OBSERVE frame, S-LOGS row format.

func (m *Model) View() string {
    var b strings.Builder
    // Header strip with tier counts (LOG-06 aggregation).
    b.WriteString(styles.Primary.Render("M-USER-LOG - " + m.username))
    b.WriteString("\n")
    b.WriteString(fmt.Sprintf(
        "Last %d days · success %d · targeted %d · noise %d · unmatched %d",
        m.windowDays,
        tierCount(m.breakdown, "success"),
        tierCount(m.breakdown, "targeted"),
        tierCount(m.breakdown, "noise"),
        tierCount(m.breakdown, "unmatched")))
    b.WriteString("\n\n")
    // 5-column row table - reuse logs.go displayN / colorByTier semantics.
    b.WriteString(styles.Dim.Render("ts(UTC)         user      src             t  raw"))
    b.WriteString("\n")
    for i, e := range m.events {
        // ... cursor marker, displayN, colorByTier, raw excerpt truncated ...
    }
    return wrapModal(b.String())
}

func wrapModal(content string) string {
    return lipgloss.NewStyle().
        Border(lipgloss.NormalBorder()).
        Padding(0, 2).
        Render(content)
}
```

**Empty state copy (D-05):** "No login attempts for `<user>` in the last `<N>` days."

### Pattern 4: S-SETTINGS inline-edit row (TUI-09)

**What:** New `fieldKind` constants slot into the existing iota chain; `currentValue` / `valueFor` / `attemptSave` switch arms get new cases; rendering and key handling are unchanged.

**When to use:** TUI-09. Pattern verbatim from `fieldDetail`/`fieldDBMax`/`fieldCompact`/`fieldLockdownWindow`.

**Example:**
```go
// Source: internal/tui/screens/settings/settings.go (existing pattern)

const (
    fieldDetail fieldKind = iota
    fieldDBMax
    fieldCompact
    fieldPasswordAuthN          // dispatch row (NOT inline-edit)
    fieldLockdownWindow
    fieldPasswordAgingDays      // NEW (TUI-09)
    fieldPasswordStaleDays      // NEW (TUI-09)
    fieldKindCount              // sentinel - placement of new constants
                                //   BEFORE this is mandatory.
)

func (k fieldKind) name() string {
    switch k {
    // ... existing cases ...
    case fieldPasswordAgingDays: return "password_aging_days"
    case fieldPasswordStaleDays: return "password_stale_days"
    }
    return "unknown"
}

func (k fieldKind) hint() string {
    switch k {
    // ... existing cases ...
    case fieldPasswordAgingDays: return "(default 180; must be < stale)"
    case fieldPasswordStaleDays: return "(default 365; must be > aging)"
    }
    return ""
}

func (m *Model) currentValue() int {
    switch m.cursor {
    // ... existing cases ...
    case fieldPasswordAgingDays: return m.settings.PasswordAgingDays
    case fieldPasswordStaleDays: return m.settings.PasswordStaleDays
    }
    return 0
}

func (m *Model) attemptSave() tea.Cmd {
    // ... existing parse + candidate ...
    candidate := m.settings
    switch m.cursor {
    // ... existing cases ...
    case fieldPasswordAgingDays: candidate.PasswordAgingDays = v
    case fieldPasswordStaleDays: candidate.PasswordStaleDays = v
    }
    if errs := config.Validate(candidate); len(errs) > 0 {
        m.errInline = errs[0].Error()  // strict-ordering message free
        return nil
    }
    // ... existing save goroutine ...
}
```

**Validation reuse (D-12):** `config.Validate` (lines 170-175) already enforces:
- `PasswordAgingDays < 1` → "must be a positive integer"
- `PasswordStaleDays <= PasswordAgingDays` → "must be strictly greater than password_aging_days"

The TUI-09 spec says "positive integer, max 3650" - the existing Validate enforces positivity but NOT the upper bound. **Decision for the planner:** either tighten `config.Validate` to add `> 3650` checks for both fields (preserves single source of truth) or duplicate the bound check in `attemptSave` (couples to TUI). Recommend the former - bound checks belong in `config.Validate`.

### Anti-Patterns to Avoid

- **Hand-rolling SIGTERM/timer/SIGKILL in each modal:** Reinvents `Cmd.Cancel` + `WaitDelay`. Reject - centralize the policy in `internal/sysops::Exec` once.
- **Adding a new SQL query for "user + last N days + limit 20":** `FilterEvents` already has `User`, `SinceNs`, `Limit` placeholders. Reuse.
- **Putting cancellation inside `internal/txn`:** The transaction layer already accepts `context.Context`; adding cancellation hooks there is wrong - the ctx is already propagated. Cancellation belongs at the Esc handler in the modal Update method.
- **Rendering ufw IPv6 source rules with ad-hoc parse code:** `firewall.Enumerate` already handles `(v6)` markers. Add fixtures to its test corpus, not new parser code.
- **Em-dash anywhere (memory rule):** Replace `--` / `—` with `-` or `:` everywhere - including in the new UAT runbook. Already a CI grep guard candidate.
- **Re-running M-USER-LOG queries on every keypress:** Load once on Init; keep in-model state. The query window is config-bound; only changes if `LockdownProposalWindowDays` changes, which requires a config save which requires going to S-SETTINGS - no need for re-query within a single modal lifetime.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SIGTERM-then-SIGKILL on subprocess | Goroutine + timer + manual signal call | `cmd.Cancel = SIGTERM closure` + `cmd.WaitDelay = 2s` | Stdlib since Go 1.20 handles Wait coordination, pipe-close, ErrWaitDelay surfacing. `[CITED: pkg.go.dev/os/exec]` |
| ufw v4/v6 detection | Substring scan in callers | `firewall.Rule.Proto` (set by Enumerate) + `stripV6Suffix` | Already in production at `enumerate.go:135-140,199-202`. |
| Per-user log query (last N days) | New SQL query | `Queries.FilterEvents{User, SinceNs, Limit}` | `internal/store/queries.go:147` - placeholders already exist; SinceNs is ns-since-epoch. |
| Tier counter aggregation | Manual GROUP BY | `Queries.PerUserBreakdown` | `internal/store/queries.go:214` - returns `UserBreakdown{Tiers: []TierBreakdown}`. |
| Atomic config persistence | Direct file write | `config.Save` → `sysops.AtomicWriteFile` | tmp+fsync+rename - already shipped Phase 2. |
| OSC 52 clipboard | Terminal escape codes | `tea.SetClipboard(text)` | Bubble Tea v2 builtin; existing screens use it. |
| Modal frame border | Custom rendering | `lipgloss.NormalBorder()` + `Padding(0, 2)` | M-OBSERVE / M-ADD-KEY pattern. |
| 5-column event row | New formatter | `displayN` + `colorByTier` + `tierGlyph` from logs.go | Factor out as package-internal exports OR re-export under capitalized names. |

**Key insight:** Phase 6 is the smallest of the v1.2 phases by design - every primitive each requirement needs is already in production. The risk is over-engineering (extracting widgets that aren't reused, adding queries that duplicate existing ones, refactoring sysops more than needed). The recommended posture: minimum surgical change to honor the 22 locked decisions in CONTEXT.md.

## Runtime State Inventory

> Phase 6 is feature work, not a rename / refactor / migration. No runtime state migration applies. Including this section explicitly to confirm "nothing found" for each category.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None - TUI-10 reads from existing `observations.db` schema; TUI-09 reads/writes existing `config.yaml` keys. | None. |
| Live service config | None - no new sshd / ufw / systemd unit changes. FW-09 deletes catch-alls during normal lockdown commit (existing flow). | None. |
| OS-registered state | None - no new systemd units, no new task registrations. | None. |
| Secrets/env vars | None - no new secrets. SOPS / .env files unaffected. | None. |
| Build artifacts | None - no rename. existing `cmd/sftp-jailer` binary surface unchanged. | None. |

**The canonical question - "After every file in the repo is updated, what runtime systems still have the old string cached, stored, or registered?":** Nothing applies. Phase 6 is purely additive code + 9 in-place context.Background() replacements.

## Common Pitfalls

### Pitfall 1: Cmd.Cancel error semantics confuse "cancelled" with "failed"

**What goes wrong:** When the subprocess exits cleanly (exit 0) AFTER `Cancel()` fires AND `Cancel()` itself returned an error (e.g., the SIGTERM signal couldn't be delivered because the process already self-exited), `cmd.Run()` / `cmd.Wait()` returns a non-nil error wrapping the Cancel return. The 4 TUI-11 modals receive a `committedMsg{err: <non-nil>}` and surface it as a fatal error - hiding the fact that the operation succeeded but was racing cancellation.

**Why it happens:** Documented at `pkg.go.dev/os/exec` - "If the command exits with a success status after Cancel is called, and Cancel does not return an error equivalent to os.ErrProcessDone, then Wait and similar methods will return a non-nil error."

**How to avoid:** In the Cancel closure, special-case `os.ErrProcessDone` to nil:
```go
cmd.Cancel = func() error {
    err := cmd.Process.Signal(syscall.SIGTERM)
    if errors.Is(err, os.ErrProcessDone) { return nil }
    return err
}
```
And in the modal's `handleCommitted`, check `errors.Is(err, context.Canceled)` BEFORE rendering as a fatal error - that path is "cancellation succeeded; show neutral done state", not "operation failed".

**Warning signs:** Test reports "subprocess error: signal: terminated" after Esc press - that means cancellation happened but the modal mis-rendered it.

### Pitfall 2: WaitDelay races with the modal's "done" auto-pop

**What goes wrong:** Admin presses Esc; `cancelFn()` fires; subprocess receives SIGTERM; subprocess exits before WaitDelay elapses. The modal's existing `tea.Tick(autoPopDelay, ...)` may already be in flight from a successful pre-Esc commit goroutine path. The modal pops to its parent screen WHILE the spinner still says "Cancelling..." - admin sees a flash of confusing UI.

**Why it happens:** `committedMsg{err: nil}` and `committedMsg{err: ctx.Canceled}` both arrive on the same channel; the existing `phaseDone → tea.Tick → autoPopMsg → nav.PopCmd` chain doesn't know about the cancelling state.

**How to avoid:** In `handleCommitted` (or equivalent), check `m.cancelling` flag:
- If `m.cancelling == true` AND `msg.err == nil OR errors.Is(msg.err, context.Canceled)`: render "cancelled" (Warn style) for AutoPopDelay, then pop. NOT the success path.
- If `m.cancelling == false` AND `msg.err == nil`: existing "done" path.

**Warning signs:** Tests that assert "press Esc → modal shows Cancelling..." pass, but "press Esc → modal pops with success toast" also passes - both can't be right.

### Pitfall 3: ufw IPv6 source comment-grammar version test gives false confidence

**What goes wrong:** A test that adds an IPv6 source rule, enumerates, and asserts `Rule.User == "alice"` could pass even if the comment grammar `sftpj:v=1:user=alice` is being misparsed - because the test fixture itself contains the version-1 marker the parser expects. We're not actually verifying that `ufwcomment.Decode` is protocol-agnostic.

**Why it happens:** Fixtures look like both fixture data AND test oracle. If the grammar is broken, fixture and oracle break together.

**How to avoid:** D-15 (FW-09): explicit `ufwcomment.Decode` round-trip test against a v6-source rule. Encode `alice` → `sftpj:v=1:user=alice`, paste into v6 rule fixture, run `Enumerate`, assert `Rule.User == "alice" AND Rule.Proto == "v6" AND Rule.ParseErr == nil`. Three independent assertions break asymmetrically if any link fails.

**Warning signs:** Test name like `TestEnumerate_v6_source_rule_decodes_user` should appear; if it doesn't, the round-trip isn't being checked.

### Pitfall 4: ufw v6-only host has no v4 rules but Enumerate still returns "Status: active"

**What goes wrong:** A v6-only host (e.g., IPv6-only VM) has `Status: active` in `ufw status numbered` output but ZERO v4 rules. The existing `findCatchAllID` predicate doesn't care about family - if there's no v4 catch-all, the loop just iterates once on the v6 catch-all and terminates. BUT: a poorly-written v6-only fixture could omit the `Status: active` line entirely, causing `Enumerate` to return `ErrUFWInactive`. Test would pass-by-accident.

**Why it happens:** ufw header rows differ subtly across active/inactive states. A copy-paste-and-modify fixture from `ufwStatusFixtureDualFamily` could lose the Status line.

**How to avoid:** New fixture `ufwStatusFixtureV6OnlyHost` MUST include `Status: active` AND must contain at least one `(v6)` marker. Test asserts: 1 UfwDelete call, deletion of the v6 catch-all (verify by checking the Args contains the right ID).

**Warning signs:** Test fails with `firewall: ufw status reports inactive` - means fixture is malformed.

### Pitfall 5: TUI-10 query timing - PerUserBreakdown is unbounded by time

**What goes wrong:** D-04 says "Time window for last N days is read from `config.LockdownProposalWindowDays`". But `PerUserBreakdown` does NOT take a time window parameter - it counts ALL observations for the user since the database was created. The header strip "Last 90 days · success 47 · targeted 3 · noise 12 · unmatched 1" would be a LIE: the counts are lifetime, not 90-day.

**Why it happens:** D-03 cites `Queries.PerUserBreakdown` as the source for tier counts; D-04 cites `LockdownProposalWindowDays` as the time window; the two assumptions are incompatible without a new SQL query.

**How to avoid:** Either:
1. **Add SinceNs to PerUserBreakdown** - extend `perUserTiersSQL` from `WHERE user = ?` to `WHERE user = ? AND ts_unix_ns >= ?`. Same shape as `FilterEvents`. Lowest-cost change. **RECOMMENDED.**
2. **Aggregate from FilterEvents in-modal** - call `FilterEvents{User, SinceNs, Limit: large}` and count tiers Go-side. Higher SQL cost (returns rows; aggregation client-side); avoid.
3. **Drop the time window from the header** - render "Lifetime · success 47 · ..." instead of "Last 90 days · ...". Reject - D-04 is explicit.

**Warning signs:** TUI-10 test passes with the existing PerUserBreakdown but the rendered string says "Last 90 days · success <number that includes pre-90d events>". The number is wrong even if the test text matches.

**Action for planner:** Plan 06-03-TUI-10 must include a `Queries.PerUserBreakdown(ctx, user, sinceNs int64)` signature change OR a new `PerUserBreakdownInWindow(ctx, user, sinceNs int64)` query alongside. The signature change is preferred (simpler API; existing callers pass 0 to disable the filter, mirroring `FilterEvents.SinceNs`-`0`-disables convention).

### Pitfall 6: 9 (not 7) context.Background() sites in the 4 TUI-11 files

**What goes wrong:** D-09 enumerates 7 sites; codebase verification finds 9. If the planner copy-pastes the D-09 list into Plan 06-04-TUI-11's task list, two sites are missed. The CI guard doesn't catch detached contexts (no grep idiom for "context.Background inside a goroutine spawned from a tea.Cmd").

**Why it happens:** D-09 says "Initial scout found 7 sites" but the actual `grep -n context.Background` over the 4 files returns 9 (verified during research):
- `addkey/addkey.go:380` (resolveAsync)
- `addkey/addkey.go:532` (attemptCommit) - matches D-09 :380 / :532
- `deleteuser/deleteuser.go:229` (startMetaLoad - NOT mutation, but pre-flight load that can hang on a wedged file walk)
- `deleteuser/deleteuser.go:464` (startSubmit)
- `applysetup/applysetup.go:290` (Init's runPreflight)
- `applysetup/applysetup.go:491` (runRePreflight - NOT in D-09 scout)
- `applysetup/applysetup.go:545` (commit goroutine - NOT in D-09 scout but at line 545 not 290)
- `pwauthdisable/pwauthdisable.go:290` (Init's runPreflight)
- `pwauthdisable/pwauthdisable.go:488` (startSubmit)

D-09 explicitly says "Planner enumerates the final list against the codebase at plan time" - so this isn't a CONTEXT.md error, it's a research-confirmed expansion.

**How to avoid:** Plan 06-04-TUI-11 MUST run `grep -n "context.Background()" internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` at plan time and enumerate all hits. Each hit becomes a task or sub-task.

**Warning signs:** A `git grep "context.Background()" internal/tui/screens/` after the phase ships still returns hits in the 4 named files - means cleanup was incomplete.

## Code Examples

Verified patterns from official sources and the existing codebase:

### Subprocess SIGTERM grace period (TUI-11 sysops change)

```go
// Source: pkg.go.dev/os/exec + internal/sysops/real.go::Exec()
// [CITED: pkg.go.dev/os/exec accessed 2026-04-30]
//
// Drop-in replacement for the existing exec.CommandContext
// at internal/sysops/real.go:191. Adds Cancel + WaitDelay.

func (r *Real) Exec(ctx context.Context, name string, args ...string) (ExecResult, error) {
    // ... existing allowlist + bin resolution ...

    if _, deadlineSet := ctx.Deadline(); !deadlineSet {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, r.defaultTimeout)
        defer cancel()
    }

    cmd := exec.CommandContext(ctx, bin, args...)
    cmd.Stdin = nil

    // NEW: SIGTERM-first cancellation policy (D-06).
    cmd.Cancel = func() error {
        if cmd.Process == nil {
            return nil
        }
        err := cmd.Process.Signal(syscall.SIGTERM)
        if errors.Is(err, os.ErrProcessDone) {
            return nil // race: process self-exited already
        }
        return err
    }
    // NEW: 2s grace then automatic SIGKILL (D-06).
    cmd.WaitDelay = 2 * time.Second

    start := time.Now()
    out, err := cmd.CombinedOutput()
    res := ExecResult{Stdout: out, Duration: time.Since(start)}
    if ctxErr := ctx.Err(); ctxErr != nil {
        return res, ctxErr
    }
    var exitErr *exec.ExitError
    if errors.As(err, &exitErr) {
        res.ExitCode = exitErr.ExitCode()
        res.Stderr = exitErr.Stderr
        return res, nil
    }
    return res, err
}
```

**One-line policy upgrade for ALL sysops Exec call sites - no per-site changes needed in `JournalctlStream`, `Useradd`, `Chage`, `UfwInsert`, etc. The 4 modal sites only need to swap their `context.Background()` for a stored cancellable context; the cancellation semantics ride the existing Exec path.**

### TUI-10 query reuse with time window

```go
// Source: internal/store/queries.go:147 (FilterEvents) +
//         internal/store/queries.go:214 (PerUserBreakdown - needs SinceNs)
// The window value comes from config.LockdownProposalWindowDays (D-04).

const windowDays = 90  // from m.settings.LockdownProposalWindowDays
sinceNs := time.Now().Add(-time.Duration(windowDays) * 24 * time.Hour).UnixNano()

// Last 20 raw entries (D-02).
events, err := q.FilterEvents(ctx, store.FilterOpts{
    User:    username,
    SinceNs: sinceNs,
    Limit:   20,
})

// Tier counts header strip (D-03).
// REQUIRES Plan 06-03 to extend PerUserBreakdown to accept SinceNs (Pitfall 5).
breakdown, err := q.PerUserBreakdown(ctx, username, sinceNs)
```

### Bubble Tea v2 modal cancellation glue (TUI-11 per-site)

```go
// Source: internal/tui/screens/observerun/observerun.go:198-200 +
//         pkg.go.dev/os/exec Cmd.Cancel pattern.
// Adapted for the 4 mutation modals.

func (m *Model) attemptCommit() tea.Cmd {
    if m.ops == nil { /* test path */ }
    ops, root, user := m.ops, m.chrootRoot, m.username
    m.phase = phaseCommitting

    // KEY CHANGE: WithCancel, not WithTimeout. Store cancel for Esc.
    ctx, cancel := context.WithCancel(context.Background())
    // Add deadline if needed (was 30s WithTimeout):
    ctx, _ = context.WithTimeout(ctx, commitTimeout)
    m.cancelFn = cancel

    return tea.Batch(m.spinner.Tick, func() tea.Msg {
        defer cancel()
        // ... existing tx.Apply body ...
        err := tx.Apply(ctx, steps)
        return committedMsg{err: err}
    })
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
    if msg.String() == "esc" && m.phase == phaseCommitting {
        if m.cancelFn != nil {
            m.cancelFn()  // → SIGTERM via cmd.Cancel → WaitDelay → SIGKILL
        }
        m.cancelling = true
        // Modal STAYS OPEN per D-07; closes when committedMsg arrives.
        return m, nil
    }
    // ... existing per-phase routing ...
}

func (m *Model) handleCommitted(msg committedMsg) (nav.Screen, tea.Cmd) {
    if m.cancelling {
        // Cancellation path - msg.err is context.Canceled or
        // context.DeadlineExceeded if WaitDelay+SIGKILL took the subprocess.
        m.phase = phaseError  // OR a new phaseCancelled
        m.errInline = "cancelled by Esc"
        m.errFatal = false
        return m, nil
    }
    // ... existing success / error branches ...
}
```

### TUI-09 enum extension (mechanical)

See Pattern 4 above. Mechanical `case` additions in 4 switch arms (`name`, `hint`, `currentValue`, `valueFor`, `attemptSave`).

### FW-09 v6-only fixture (NEW)

```go
// Source: extends internal/txn/steps_test.go:1262 fixture family.

// ufwStatusFixtureV6OnlyHost models a v6-only Ubuntu host (e.g. IPv6-only
// cloud VM): NO v4 catch-all, single v6 catch-all, single v6-source sftpj
// rule. Used by FW-09 to confirm NewUfwDeleteCatchAllByEnumerateStep
// terminates after exactly 1 delete on a v6-only state.
func ufwStatusFixtureV6OnlyHost() []byte {
    return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 2] 22/tcp (v6)                ALLOW IN    2001:db8::1                # sftpj:v=1:user=alice
`)
}

// ufwStatusFixtureV6OnlyAfterDelete: post-delete state - only the
// sftpj rule remains, renumbered to id=1.
func ufwStatusFixtureV6OnlyAfterDelete() []byte {
    return []byte(`Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp (v6)                ALLOW IN    2001:db8::1                # sftpj:v=1:user=alice
`)
}

func TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6(t *testing.T) {
    t.Parallel()
    f := sysops.NewFake()
    f.ExecResponseQueue["ufw status numbered"] = []sysops.ExecResult{
        {ExitCode: 0, Stdout: ufwStatusFixtureV6OnlyHost()},
        {ExitCode: 0, Stdout: ufwStatusFixtureV6OnlyAfterDelete()},
    }
    step := NewUfwDeleteCatchAllByEnumerateStep("22")
    require.NoError(t, step.Apply(context.Background(), f))

    deleteCount := 0
    for _, c := range f.Calls {
        if c.Method == "UfwDelete" { deleteCount++ }
    }
    require.Equal(t, 1, deleteCount,
        "v6-only host has exactly 1 catch-all (v6); step must delete it and stop")
}
```

### FW-09 v6-source AddRule test (NEW)

```go
// Source: extends internal/firewall/mutate_test.go AddRule family.

func TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment(t *testing.T) {
    t.Parallel()
    f := sysops.NewFake()
    // Pre-script the post-insert ufw status output - alice's v6 rule at id=1.
    scriptUfw(f, `Status: active

[ 1] 22/tcp (v6)                ALLOW IN    2001:db8::/32              # sftpj:v=1:user=alice
`)
    id, err := AddRule(context.Background(), f, "alice", "2001:db8::/32", "22")
    require.NoError(t, err)
    require.Equal(t, 1, id)

    insertCall := findCall(f, "UfwInsert")
    require.NotNil(t, insertCall, "UfwInsert must have been called for v6 source")
    require.True(t, argHas(insertCall, "src=2001:db8::/32"),
        "ufw insert must carry the v6 CIDR verbatim - ufw 0.36.2 auto-routes the family")
    require.True(t, argHas(insertCall, "comment=sftpj:v=1:user=alice"),
        "ufwcomment.Encode is protocol-agnostic - same comment grammar for v6 rules")
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `cmd.Process.Signal(SIGTERM)` + manual goroutine timer + `cmd.Process.Kill()` | `cmd.Cancel = SIGTERM closure` + `cmd.WaitDelay = grace` | Go 1.20 (Feb 2023) | Removes ~30 lines of goroutine/timer/race-coordination per call site. The pattern this project should adopt. `[CITED: pkg.go.dev/os/exec, golang/go#21135]` |
| Per-modal `context.Background()` in goroutine | Stored `cancelFn` from `context.WithCancel(parent)` invoked from Esc handler | M-OBSERVE in Phase 2 plan 02-08 | Already proven in production at `internal/tui/screens/observerun/observerun.go`. TUI-11 propagates the pattern to 4 more modals. |
| Hand-counting tier breakdowns in Go after `FilterEvents` | `Queries.PerUserBreakdown` (Phase 2 plan 02-01) | 2026-04-26 | Single SQL `GROUP BY tier` round-trip. TUI-10 reuses (with the SinceNs extension - Pitfall 5). |
| `ufw delete <id>` blocks on TTY prompt | `ufw --force delete <id>` | Phase 4 plan 04-02 (Real.UfwDelete) | Already in production - FW-09 inherits. |

**Deprecated/outdated:**
- Go's pre-1.20 `os/exec` cancellation story (manual SIGKILL on ctx done, no grace) - replaced by Cancel/WaitDelay. Don't write new code in the old style.
- `kevinburke/ssh_config` for sshd_config (CLAUDE.md note) - unrelated to Phase 6 but worth restating: never reach for it.

## Project Constraints (from CLAUDE.md)

The project's CLAUDE.md (read at research time) imposes these directives that Phase 6 must honor:

| Directive | Where Enforced | Phase 6 Touchpoint |
|-----------|----------------|---------------------|
| **All shell-outs through `internal/sysops`** (CI guard `scripts/check-no-exec-outside-sysops.sh`) | Build-time grep | TUI-11 sysops Exec change is the ONE exception - the CI guard inspects callers, not the sysops package itself. The 4 modals do NOT import `os/exec`. |
| **Em-dash forbidden everywhere** (memory rule) | Code review + memory rule | All new code, comments, docs, UAT runbook. Use `-` or `:`. |
| **Go 1.25.x toolchain** (`go 1.25.0` in go.mod) | `go.mod` directive | `Cmd.Cancel` + `WaitDelay` available since 1.20 - safely usable. |
| **CGO_ENABLED=0** (cgo-free single binary) | goreleaser config | No new cgo deps; modernc.org/sqlite still drives observation DB. |
| **Drop-in at `/etc/ssh/sshd_config.d/50-sftp-jailer.conf`** | Plan 03-05 + Phase 5 postinst | Phase 6 makes no sshd_config changes. |
| **`sshd -t` validation before reload** | Phase 3 SAFE-02 | TUI-11's pwauthdisable cancellation must not bypass `NewSshdValidateStep` - the txn.Apply contract handles this; our cancellation is Esc-during-running, not Esc-during-validate. |
| **One rolling backup of any config drop-in on first edit per session** | Phase 3 D-S03-04 | TUI-09 only edits `/etc/sftp-jailer/config.yaml` (which has its own atomic-write rotation, not the sshd backup). |
| **GPL-3.0 license** | LICENSE file | No new third-party deps; no license concerns. |
| **systemd timer (not cron)** | Phase 5 packaging | Phase 6 doesn't touch packaging. |
| **SAFE-04 revert window** (D-21 of CONTEXT.md) | Phase 4 NewScheduleRevertStep | FW-09 mutations inherit SAFE-04 wrapping from existing modal callers. TUI-11 cancellation does NOT short-circuit SAFE-04 - the revert timer is set BEFORE the cancellable subprocess; if the subprocess gets SIGTERM'd mid-flight, SAFE-04's reverse-cmd is what restores state. |

**Compliance check:** All Phase 6 plans MUST verify CLAUDE.md adherence in their VERIFICATION step. The plan-checker should be configured to grep for em-dash characters (`grep -P '[—–]' --include='*.{go,md}' .` returns hits → fail).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ufw allow proto tcp from 2001:db8::/32 ...` creates a v6-only rule (not dual-family) on Ubuntu 24.04 with IPV6=yes | FW-09 syntax probe | Low - confirmed by ufw upstream `[CITED: oneuptime.com IPv6 ufw guide; manpages.ubuntu.com/noble/man8/ufw.8.html]`. If wrong, FW-09 plan needs a bare-IP-promotion adjustment (already present in `firewall.AddRule` per `mutate.go:40`). |
| A2 | `ufw status numbered` for IPv6-source rules renders `(v6)` in BOTH the To column AND the From column | FW-09 fixture format | Low - existing testdata `ufw-status-numbered-mixed.txt` (line 9) shows `22/tcp (v6) ... 2001:db8::1` (only port has the marker; source is the bare CIDR). Confirmed by re-reading the testdata file. The new fixtures should mirror this format exactly. |
| A3 | The 4 TUI-11 modal `WantsRawKeys()` policies allow Esc to reach `handleKey` during `phaseCommitting` / `phaseFetching` etc. | TUI-11 cancellability | Verified in code: `addkey.go:192-194` `WantsRawKeys() == false` for phaseCommitting → Esc reaches handleKey. Same shape in the other 3. |
| A4 | `tea.Cmd` returned from a goroutine that holds `context.Cancel` does not leak the cancel func | TUI-11 cleanup discipline | The recommended pattern wraps `defer cancel()` inside the goroutine body - same as existing `context.WithTimeout` + `defer cancel()` flow. No leak. |
| A5 | `Queries.PerUserBreakdown` does NOT currently support a SinceNs filter | TUI-10 - Pitfall 5 | Verified: `internal/store/queries.go:214` signature is `(ctx, user)` only. Confirmed - extension is required. |
| A6 | The `LockdownProposalWindowDays` config knob (range [1, 3650], default 90) is the right source for TUI-10 time window | TUI-10 D-04 | CONTEXT.md D-04 explicitly chose this knob. Per memory MEMORY.md no contradicting prior decision. Honor as-decided. |
| A7 | OSC 52 clipboard write via `tea.SetClipboard` works inside a modal pushed onto the nav stack | TUI-10 D-02 | Verified in production: S-USERS handleCopy (`users.go:548-552`) uses `tea.SetClipboard` from a child screen. M-USER-LOG inherits the same machinery. |
| A8 | Empirical UAT for FW-09 must NOT prescribe `m1.linuxbe.com` or any host without explicit user authorization | FW-09 D-17 | Honored in CONTEXT.md D-17 + memory `lab_host_debian13.md`. UAT runbook uses generic placeholders only. |

**Above table is non-empty:** A1-A8 are research-confirmed assumptions with citations. None require user clarification - all align with CONTEXT.md decisions and existing code. `[ASSUMED]` tags appear inline elsewhere only where the planner / discuss-phase should validate before implementation.

## Open Questions

1. **Plan order: should TUI-11 (sysops change) ship FIRST so the cancellable Exec contract is in place when the 4 modal plans land?**
   - What we know: D-18 says 4 independent plans, parallelizable. D-10 says cancellation infra is per-site (no shared wrapper plan 06-00 by default).
   - What's unclear: If sysops.Exec gains Cancel/WaitDelay AFTER 06-04-TUI-11's per-site plumbing, the modal goroutines pass a context to a sysops that doesn't yet honor SIGTERM grace - so cancellation will SIGKILL immediately. The plumbing still works (Esc → cancel → ctx.Cancelled → Exec returns), but the 2s grace doesn't kick in.
   - Recommendation: Plan 06-04-TUI-11 must combine the sysops change AND the 4 modal plumbing changes in a single plan (or split into 06-04a-sysops + 06-04b-modals with strict ordering). Splitting into the 4 modal-by-modal plans is harmless because they all share the same sysops dependency. Actionable: planner schedules 06-04 to land its sysops change FIRST then 4 internal sub-tasks for the modal plumbing.

2. **Should `LockdownProposalWindowDays` rename hint at "log lookback" semantics now that TUI-10 also uses it?**
   - What we know: D-04 reuses this knob "to avoid config-knob proliferation".
   - What's unclear: The config key is `lockdown.proposal_window_days` - the YAML key implies lockdown-only semantics; admins reading config might be confused why TUI-10 uses it.
   - Recommendation: Don't rename in v1.2 (renaming a config key is a migration). Document the dual-use in `internal/config/config.go` doc comment AND in TUI-10's modal header strip ("Last 90 days (window: lockdown.proposal_window_days)").

3. **For TUI-10, should the modal show INFO on a no-data user, or just empty state?**
   - What we know: D-05 specifies "No login attempts for `<user>` in the last `<N>` days." for empty state.
   - What's unclear: A user with zero observations is different from a user with observations only OUTSIDE the window. Should the modal distinguish?
   - Recommendation: Don't distinguish. The empty-state copy "in the last `<N>` days" is honest about the bound. If the admin wants to see all-time activity, the deferred per-tier filter (in `## Deferred Ideas`) covers that.

## Environment Availability

> Phase 6 is purely code/test/doc - no new external dependencies beyond what Phase 5 already requires.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Build | ✓ | 1.26.2 (dev) / 1.25 floor (CI) | - |
| ufw 0.36.2 | FW-09 runtime | ✓ on target Ubuntu 24.04 | 0.36.2 | - |
| Bubble Tea v2 + Bubbles + Lip Gloss | TUI builds | ✓ | as pinned in go.mod | - |
| `teatest/v2` | Test infrastructure | ✓ | as pinned via x/exp | - |
| IPv6-enabled VM | FW-09 EMPIRICAL UAT | ✗ | - | UAT-pending status flagged in 06-VERIFICATION.md per D-16; runbook authored without prescribing a host (D-17). |
| `modernc.org/sqlite` | Observations DB read | ✓ | as pinned | - |

**Missing dependencies with no fallback:**
- (None for code/test work; the IPv6 VM gap is intentional per D-16 / D-17.)

**Missing dependencies with fallback:**
- IPv6-enabled VM for FW-09 empirical UAT: deferred to v1.2.x checkbox flip when available; v1.2.0 ships with `verified-code, UAT-pending` status in `06-VERIFICATION.md` frontmatter only.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `github.com/stretchr/testify/require` (v1.11.1) + `charmbracelet/x/exp/teatest/v2` (TUI golden-file flows) |
| Config file | none (idiomatic Go testing) |
| Quick run command | `go test ./internal/firewall/... ./internal/txn/... ./internal/tui/screens/{settings,users,userlog,addkey,deleteuser,applysetup,pwauthdisable}/... ./internal/sysops/... -count=1` |
| Full suite command | `go test ./... -race -count=1` (matches phase-5-era CI gate) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FW-09 | dual-family v4+v6 hosts: deletes BOTH catch-alls in one pass | unit | `go test ./internal/txn/ -run TestUfwDeleteCatchAllByEnumerate_dual_family_deletes_BOTH_v4_and_v6 -count=1` | EXISTS |
| FW-09 | v6-only host: deletes exactly 1 catch-all and terminates | unit | `go test ./internal/txn/ -run TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6 -count=1` | NEW (Wave 0) |
| FW-09 | AddRule with v6 source CIDR exercises ufwcomment.Encode | unit | `go test ./internal/firewall/ -run TestAddRule_v6_source_uses_correct_ufw_syntax_and_decodes_comment -count=1` | NEW (Wave 0) |
| FW-09 | Enumerate decodes sftpj:v=1:user= comment on a v6-source rule | unit | `go test ./internal/firewall/ -run TestEnumerate_v6_source_rule_decodes_user_round_trip -count=1` | NEW (Wave 0) |
| FW-09 | UAT runbook authored with dual-family + v6-only steps | manual | `test -f docs/uat/06-fw09-uat.md && grep -c "Step " docs/uat/06-fw09-uat.md` (expect ≥10) | NEW (Wave 0) |
| TUI-09 | S-SETTINGS exposes 2 new password-aging rows; cursor cycles them | unit (teatest) | `go test ./internal/tui/screens/settings/ -run TestSettings_password_aging_days_cursor_visible -count=1` | NEW (Wave 0) |
| TUI-09 | Inline-edit + textinput round-trips via config.Save | unit (teatest) | `go test ./internal/tui/screens/settings/ -run TestSettings_password_aging_days_save_via_config -count=1` | NEW (Wave 0) |
| TUI-09 | Validation: positive int, max 3650, strict ordering | unit | `go test ./internal/config/ -run TestValidate_password_aging_strict_ordering -count=1` (extends existing test) | EXTENDS EXISTING |
| TUI-10 | Uppercase 'L' on S-USERS pushes M-USER-LOG | unit (teatest) | `go test ./internal/tui/screens/users/ -run TestUsers_uppercase_L_pushes_user_log_modal -count=1` | NEW (Wave 0) |
| TUI-10 | M-USER-LOG renders header strip + 5-column row table | unit (teatest) | `go test ./internal/tui/screens/userlog/ -run TestUserLog_renders_header_and_rows -count=1` | NEW (Wave 0) |
| TUI-10 | Empty state copy when no observations in window | unit (teatest) | `go test ./internal/tui/screens/userlog/ -run TestUserLog_empty_state_copy -count=1` | NEW (Wave 0) |
| TUI-10 | OSC 52 row copy via 'c' keybind | unit (teatest) | `go test ./internal/tui/screens/userlog/ -run TestUserLog_c_copies_row_via_OSC52 -count=1` | NEW (Wave 0) |
| TUI-10 | PerUserBreakdown SinceNs extension (signature change) | unit | `go test ./internal/store/ -run TestPerUserBreakdown_with_since_ns_filters -count=1` | NEW (Wave 0) |
| TUI-11 | sysops.Exec sets cmd.Cancel + cmd.WaitDelay = 2s | unit | `go test ./internal/sysops/ -run TestExec_cancel_sends_SIGTERM_then_SIGKILL_after_2s -count=1` | NEW (Wave 0) |
| TUI-11 | All 4 modals: Esc during async op invokes cancelFn | unit (teatest) | `go test ./internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/ -run TestEsc_during_async_invokes_cancel -count=1` | NEW (Wave 0) - 4 tests, one per modal |
| TUI-11 | Modal stays open during cancellation; closes on subprocess exit | unit (teatest) | `go test ./internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/ -run TestEsc_modal_stays_open_until_subprocess_exits -count=1` | NEW (Wave 0) |
| TUI-11 | All 9 context.Background() sites replaced with cancellable | smoke (CI grep) | `! git grep -n 'context.Background()' internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go | grep -v _test.go` | CI guard - NEW (Wave 0) |
| Phase | em-dash absent everywhere (project rule) | smoke (CI grep) | `! grep -rP '[—–]' --include='*.go' --include='*.md' internal/ docs/ .planning/phases/06-*/` | CI guard - SHOULD EXIST already; verify in Wave 0 |

### Sampling Rate
- **Per task commit:** RED test commit followed by GREEN implementation commit per D-22. Run `go test ./<changed-package>/... -count=1` (5-30 seconds typical).
- **Per wave merge:** Full target suite: `go test ./internal/firewall/... ./internal/txn/... ./internal/tui/... ./internal/sysops/... ./internal/config/... ./internal/store/... -race -count=1` (~60-90 seconds).
- **Phase gate:** Full suite green (`go test ./... -race -count=1`) before `/gsd:verify-work`. Plus the architectural CI guards: `bash scripts/check-no-exec-outside-sysops.sh`, em-dash grep, no-context.Background-in-modals grep.

### Wave 0 Gaps
- [ ] `internal/firewall/testdata/ufw-status-numbered-v6-only.txt` - new fixture file for v6-only-host enumerate testing
- [ ] `internal/txn/steps_test.go` - 1 new fixture function pair + 1 new test (`TestUfwDeleteCatchAllByEnumerate_v6_only_host_deletes_just_v6`)
- [ ] `internal/firewall/mutate_test.go` - 1 new test (v6-source AddRule round-trip)
- [ ] `internal/firewall/enumerate_test.go` - 1 new test (v6 source comment decode round-trip)
- [ ] `internal/store/queries.go` + `queries_test.go` - PerUserBreakdown signature extension to accept SinceNs (non-breaking: pass 0 to disable)
- [ ] `internal/tui/screens/userlog/userlog.go` - new package (model, Init, Update, View)
- [ ] `internal/tui/screens/userlog/userlog_test.go` - 4-5 teatest/v2 golden-file tests
- [ ] `internal/tui/screens/users/users.go` - 'L' keybind dispatch + factory seam
- [ ] `internal/tui/screens/users/users_test.go` - 1 new test for the 'L' dispatch
- [ ] `internal/tui/screens/settings/settings.go` - 2 new fieldKind cases + switch arms
- [ ] `internal/tui/screens/settings/settings_test.go` - 2-3 new teatest/v2 tests
- [ ] `internal/config/config.go` - max=3650 bound for PasswordAgingDays/PasswordStaleDays
- [ ] `internal/config/config_test.go` - extend strict-ordering test
- [ ] `internal/sysops/real.go` + `sysops_test.go` - Cancel + WaitDelay plumbing in Exec, with at least 1 test using `/bin/sleep` to verify SIGTERM-then-SIGKILL timing
- [ ] `internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` - 9 context.Background() replacements + cancelFn storage + Esc handling
- [ ] `internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*_test.go` - 1-2 new tests per modal for the cancel path (8 tests total)
- [ ] `docs/uat/06-fw09-uat.md` - new UAT runbook (≥10 numbered steps, dual-family + v6-only + evidence capture)
- [ ] `scripts/check-no-detached-context-in-modals.sh` (NEW CI guard, OPTIONAL) - greps for `context.Background()` in the 4 named modal files; fails build if found

*(If no gaps: not applicable - this is feature work, gaps listed above are the deliverables.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Phase 6 doesn't touch sshd PasswordAuthentication / SSH keys mutation contracts (those live in Phase 3). TUI-11 makes the disable flow Esc-cancellable but doesn't change the disable semantics or override gate. |
| V3 Session Management | no | No session state. TUI is single-admin-as-root. |
| V4 Access Control | partial | TUI-09 textinput inputs go through `config.Validate` (existing strict ordering + range checks). TUI-10 reads observations - no privilege boundary crossed (admin can read everything anyway). |
| V5 Input Validation | yes | TUI-09 numeric input via `strconv.Atoi(strings.TrimSpace(value))` - existing pattern. TUI-10 has no user input (read-only modal). FW-09 source-CIDR validation comes from caller (M-ADD-RULE upstream); FW-09 plan does not add new mutation surfaces. |
| V6 Cryptography | no | No crypto changes. SSH key handling untouched. |
| V7 Error Handling | yes | TUI-11 must NOT leak subprocess error details that reveal system internals beyond what existing patterns leak. The `committedMsg.err.Error()` strings already flow through; cancellation path adds `context.Canceled` which is benign. |
| V11 Business Logic | yes | TUI-11 cancellation MUST NOT bypass SAFE-04 revert windows. Verified: SAFE-04 timer is set in the txn batch BEFORE the cancellable subprocess; if the subprocess gets SIGTERM mid-flight, SAFE-04's reverse-cmd is what restores state. The cancellation does not run before SAFE-04 schedules. |
| V14 Configuration | yes | TUI-09 atomic-write contract (`config.Save` → `sysops.AtomicWriteFile`) - already in production. New rows inherit. |

### Known Threat Patterns for Go TUI + sysops + ufw stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Subprocess argv injection via username (TUI-09 / TUI-11) | Tampering | `ufwcomment.Encode` regex (existing) rejects shell metacharacters before any sysops call. Username regex `^[a-z][a-z0-9_-]{0,31}$` (existing) covers all sites. |
| TOCTOU on /etc/sftp-jailer/config.yaml (TUI-09) | Tampering | `config.Save` uses tmp+fsync+rename via `sysops.AtomicWriteFile` - POSIX atomic. No TOCTOU window. |
| Hung subprocess after Esc cancel (TUI-11) | DoS | `cmd.WaitDelay = 2s` triggers SIGKILL - hard upper bound on subprocess wall time post-cancel. D-08 documents the failure mode if SIGKILL itself doesn't release within 2s. |
| Information disclosure via cancellation error message (TUI-11) | Information Disclosure | `errors.Is(err, context.Canceled)` check renders neutral "cancelled" text instead of raw subprocess stderr - no system-path leakage. |
| Stale catch-all on dual-family or v6-only host (FW-09) | DoS / open-firewall | The position-independent loop (Phase 4 plan 04-12 / 04-13) already mitigates this on dual-family; FW-09 adds v6-only fixture coverage so the regression net catches future predicate drift. |
| Race between SIGTERM-receiver and txn.Compensate path (TUI-11) | Tampering | The txn package's Compensate hooks fire on Apply-error; ctx.Canceled IS an Apply-error so compensators run. Confirmed by reading `tx.Apply` contract (existing). FW-09 catch-all delete is intentional-noop Compensate (D-FW-07) - cancellation during the delete loop is rolled back via SAFE-04's reverse-cmd, not the step's Compensate. |

**Threat-modeling note:** TUI-11 specifically must NOT be analyzed as "introducing cancellability"; it's "tightening the contract" - the existing modals already cancel the modal frame on Esc but leave the subprocess running. TUI-11 closes a Denial-of-Service-by-orphaned-subprocess hole. This is a security improvement, not a regression risk.

## Sources

### Primary (HIGH confidence)
- `pkg.go.dev/os/exec` (WebFetch 2026-04-30) - `Cmd.Cancel` and `Cmd.WaitDelay` semantics; SIGTERM-then-SIGKILL canonical pattern
- `internal/sysops/real.go` (read directly) - existing Exec implementation; allowlist; cancellation seam
- `internal/firewall/{enumerate,mutate}.go` (read directly) - v6 detection, AddRule/DeleteRule writer surface
- `internal/txn/steps.go:782-866` (read directly) - NewUfwDeleteCatchAllByEnumerateStep with full BUG-04-A/B/C documentation
- `internal/txn/steps_test.go:1258-1411` (read directly) - existing dual-family fixture + 4 BUG-04-* tests
- `internal/store/queries.go:147-289` (read directly) - FilterEvents + PerUserBreakdown signatures and SQL
- `internal/tui/screens/observerun/observerun.go` (read directly) - production cancellable-subprocess pattern (M-OBSERVE)
- `internal/tui/screens/{addkey,deleteuser,applysetup,pwauthdisable}/*.go` (read directly) - the 4 TUI-11 sites; 9 context.Background() locations enumerated
- `internal/tui/screens/settings/settings.go` (read directly) - inline-edit pattern, fieldKind enum chain
- `internal/tui/screens/users/users.go` (read directly) - keybind dispatcher with W1 'D' (uppercase) precedent
- `internal/tui/screens/logs/logs.go` (read directly) - 5-column event row format, displayN/colorByTier helpers
- `internal/config/config.go` (read directly) - PasswordAgingDays/StaleDays/LockdownProposalWindowDays + Validate
- `docs/uat/05-ubuntu24-uat.md` (read directly) - UAT runbook template structure
- `.planning/phases/06-v1-1-carry-over-closure-firewall-edge-tui-polish/06-CONTEXT.md` (read directly) - 22 locked decisions D-01..D-22
- `.planning/REQUIREMENTS.md` (read directly) - FW-09 / TUI-09 / TUI-10 / TUI-11 definitions
- `.planning/ROADMAP.md` (read directly) - Phase 6 success criteria
- `CLAUDE.md` (read directly) - project constraints (em-dash forbidden; sysops invariant; Go 1.25; Bubble Tea v2 module path)

### Secondary (MEDIUM confidence)
- `https://help.ubuntu.com/community/UFW` (WebFetch 2026-04-30) - high-level ufw IPv6 guide; insufficient detail for IPv6 source rules
- `https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html` (WebFetch 2026-04-30) - confirms IPv6 source CIDR syntax `from 2001:db8::/32`; doesn't explicitly document `(v6)` marker on source rules but example syntax aligns with existing testdata
- `https://oneuptime.com/blog/post/2026-01-15-configure-ufw-ipv6-ubuntu/view` (WebSearch result 2026-04-30) - confirms IPv6 source addresses create v6-only rules (not dual-family); IPV6=yes default behavior on Ubuntu 24.04
- `https://victoriametrics.com/blog/go-graceful-shutdown/` (WebSearch result 2026-04-30) - confirms Go 1.20+ Cmd.Cancel/WaitDelay is the canonical pattern; reinforces stdlib choice

### Tertiary (LOW confidence)
- (None - all primary and secondary sources cross-verified.)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - every library is already pinned; no version research required.
- Architecture (Cmd.Cancel + WaitDelay): HIGH - stdlib since Go 1.20; documented at pkg.go.dev; existing M-OBSERVE pattern adapts cleanly.
- Architecture (modal patterns): HIGH - all 4 modals already implement the phase-machine; only context.Background() replacements are required.
- FW-09 dual-family + v6-only correctness: HIGH for code (existing test pins BUG-04-C); MEDIUM for empirical UAT (no IPv6 VM available - this is intentional per D-16).
- TUI-09 inline-edit pattern: HIGH - mechanical extension of fieldKind iota chain.
- TUI-10 data layer: HIGH for FilterEvents reuse; MEDIUM for PerUserBreakdown SinceNs extension (signature change is required - confirmed via code read).
- Pitfalls: HIGH - all 6 pitfalls have specific file/line citations and reproducible failure modes.
- ASVS / threat modeling: HIGH - feature scope is small; threat surface is well-bounded.

**Research date:** 2026-04-30
**Valid until:** 2026-05-30 (30 days; stable Phase - dependencies pinned, no fast-moving libs in scope)
