<!-- GSD:project-start source:PROJECT.md -->
## Project

**sftp-jailer**

`sftp-jailer` is an interactive, colorful terminal UI for Linux sysadmins who run a chrooted SFTP server on Ubuntu 24.04. It turns a scattered pile of `sshd_config` edits, filesystem permissions, user accounts, firewall rules, and log-grepping into a single TUI where you set up the chroot, manage users + passwords + SSH keys, browse SFTP transaction logs, and progressively tighten access from "open to the world" into per-user IP-allowlisted lockdown. Distributed as a single Go binary, GPL-3.0, aimed at the gap left by SFTP *clients* (termscp, lssh) — there's no equivalent admin tool for managing the server side.

**Core Value:** **One TUI takes a fresh Ubuntu 24.04 box from "no SFTP" to "hardened chrooted SFTP with per-user IP lockdown" — safely, interactively, with observable traffic intel driving every decision.** If everything else fails, this flow must work.

### Constraints

- **Tech stack**: Go 1.25+ (Bubble Tea v2 requirement), Bubble Tea v2 at `charm.land/bubbletea/v2` (framework), Bubbles (components), Lip Gloss (styling). Single static binary — no runtime dependencies beyond libc.
- **Platform**: Ubuntu 24.04 LTS, hard dependency. `apt`, `systemd` (journald + timers), `ufw` (nftables backend) all assumed present. No cron — scheduled jobs are systemd timer units.
- **Privilege**: must run as root/sudo — tool refuses to start otherwise. Modifies `sshd_config.d/` drop-ins, creates system users, writes firewall rules, reloads services.
- **Config ownership**: tool writes to `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` (a drop-in owned end-to-end by this tool). The main `/etc/ssh/sshd_config` stays admin-owned and is only read.
- **External process surface**: shells out to `adduser`/`usermod`/`chpasswd`/`passwd`/`chown`/`chmod`/`ufw`/`sshd -t`/`systemctl`/`journalctl`. Wrapped in typed Go functions; no raw string concatenation into shell.
- **Persistence**: SQLite via `modernc.org/sqlite` (pure Go — keeps the binary cgo-free) for the observation DB. No user↔IP state: that's in firewall rule comments.
- **Safety posture**: admin-trusted, minimal friction — but `sshd -t` validation before any sshd reload is mandatory (a typo there is self-DoS over SFTP). One rolling backup of any config drop-in on first edit per session, overwritten thereafter.
- **License**: GPL-3.0.
- **Distribution**: single Go binary, `.deb` package built via `nfpm`/`goreleaser`, hosted on GitHub (no Codeberg mirror for v1).
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## TL;DR — the exact pin list
## Recommended Stack
### Core Technologies
| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| **Go** | **1.25.x** (toolchain directive `go 1.25.0`; build with 1.25 or 1.26) | Implementation language | Bubble Tea v2 and Lip Gloss v2 both declare `go 1.25.0` in their `go.mod`. 1.24 and 1.25 are the currently-supported upstream Go releases (1.23 and earlier are EOL as of Feb 2026). See "Version Compatibility" — the `go 1.22+` constraint in PROJECT.md is obsolete and should be updated. |
| **Bubble Tea** | **v2.0.6** (module path: `charm.land/bubbletea/v2`) | TUI framework (Elm-architecture model/update/view) | The committed choice. v2 is the current stable line (v2.0.0 GA in Feb 2026). Note the module path moved from `github.com/charmbracelet/bubbletea` to `charm.land/bubbletea/v2` at v2 — an easy footgun for anyone copy-pasting older examples. |
| **Bubbles** | **v2.1.0** (`charm.land/bubbles/v2`) | Prebuilt TUI components (list, table, textinput, viewport, spinner, progress, paginator, help, key) | Every widget this project needs (user list, log viewer, IP-rule table, paginated user directory, modal textinputs for password/key paste) is already built and battle-tested. Matching major version with Bubble Tea v2 is mandatory — v2 components won't composite into a v1 program. |
| **Lip Gloss** | **v2.0.3** (`charm.land/lipgloss/v2`) | Terminal styling (colors, borders, padding, layout) | Pairs with Bubble Tea v2. The project spec calls for a "colorful" TUI and Lip Gloss v2 is the supported path. |
| **modernc.org/sqlite** | **v1.49.1** | Observation DB driver | **Pure Go, no cgo.** Aligns with the single-static-binary constraint. The cgo-based `mattn/go-sqlite3` is ~1.5–2× faster on inserts, but this project's write volume (weekly cron parsing journalctl, 20–100 users) is trivially small — performance is not the bottleneck, binary portability is. Exposes the standard `database/sql` interface so we can swap later if ever needed. |
| **systemd timer** (not a Go lib — packaging choice) | shipped as `.service`+`.timer` files | Schedule the weekly log-ingestion job | Ubuntu 24.04 has systemd as PID 1 and `journalctl` as the log backend. Dropping into `/etc/cron.weekly` works but inherits the cron env (minimal `$PATH`, no journal integration for the job's own stdout/stderr). A systemd timer logs job output straight into journald (where the same tool reads from), supports `Persistent=true` to catch up after reboots, and is the 2026-native way to schedule on Ubuntu. |
### Supporting Libraries
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/charmbracelet/x/exp/teatest/v2` | v2.0.0-20260422141420-a6cbdff8a7e2 (pseudo-version — this package has no tagged releases; pin to a specific commit) | TUI integration tests (golden-file model output) | All non-trivial screens. Charm themselves maintain and use it; it's the de facto answer. See "What NOT to Use" for alternatives. |
| `github.com/spf13/cobra` | v1.10.2 | CLI subcommand framework around the TUI entry point | `sftp-jailer` (opens TUI), `sftp-jailer ingest` (invoked by the systemd timer), `sftp-jailer version`, `sftp-jailer doctor`. Keeps the cron-callable entrypoints declarative. |
| `github.com/knadh/koanf/v2` | v2.3.4 | App config loader (`/etc/sftp-jailer/config.yaml` + env overrides) | Tool-level settings: DB path, retention days, chroot root path, log source. Chosen over Viper for a lighter dep tree (no MapStructure/HCL/etcd) and an explicit, composable API. Viper (v1.21.0) is fine but pulls a lot of transitive deps. |
| `golang.org/x/crypto/ssh` | v0.50.0 | Parse / validate / fingerprint SSH public keys for `authorized_keys` management | Any time the user pastes or uploads a key. Use `ssh.ParseAuthorizedKey` and `ssh.FingerprintSHA256`. |
| `golang.org/x/sys/unix` | v0.43.0 | Typed syscall wrappers (stat/chown/chmod, getuid, unix.Stat_t) | Chroot permission verification (is `/srv/sftp` root-owned, mode 0755?), resolving UID/GID from directory ownership for the orphan-user reconciliation flow. Prefer this over shelling out to `stat` where we need structured data. |
| `github.com/stretchr/testify` | v1.11.1 | Test assertions / suite | Unit tests throughout. Pairs with `teatest` for integration tests. |
### Development Tools
| Tool | Purpose | Notes |
|------|---------|-------|
| **goreleaser** (v2.15.4) | Cross-arch build + release orchestration + GitHub release publishing | Config pins `CGO_ENABLED=0`, `-trimpath`, `targets: ["go_first_class"]`. Calls nfpm under the hood for `.deb`. Same YAML drives local dev builds and CI releases. This is what Charm's own `bubbletea-app-template` uses. |
| **nfpm** (v2.46.3) | `.deb` packager (invoked by goreleaser) | Pure Go, zero external deps (no Ruby, no fpm). Declarative YAML. Handles `postinst`/`prerm` hooks for the systemd timer install and `/var/lib/sftp-jailer/` creation. |
| `golangci-lint` (latest stable) | Linter aggregator | Standard Go hygiene. Charm's bubbletea-app-template ships a config. |
| **Delve** | Debugger | Standard Go debugger. Relevant because TUIs are awkward to debug with print statements — tip: run `dlv` against a headless test harness, not a live TUI. |
| `golang.org/x/crypto` tooling for `ssh-keygen` parity | Public-key fingerprinting | Use in-process rather than shelling to `ssh-keygen -lf` — avoids a subprocess per key. |
## Per-question answers (keyed to the research prompt)
### 1. Go version
- **Choice:** Go **1.25.x** (toolchain `go 1.25.0`; any 1.25.x or 1.26.x compiler works).
- **Why:** Bubble Tea v2.0.6, Bubbles v2.1.0, and Lip Gloss v2.0.3 all declare `go 1.25.0` in their `go.mod`. Go 1.22 is **EOL** as of 2026. The original PROJECT.md constraint "Go 1.22+" is stale and should be updated to "Go 1.25+".
- **Ubuntu 24.04 implication:** The apt-shipped `golang-go` on Noble is currently pinned at **1.22.2** (even in `-updates`/`-security`). Developers building from source on a stock 24.04 cannot `apt install golang` and succeed. Document in README: use the official tarball from go.dev, `longsleep/golang-backports` PPA, or the `golang:1.25` docker image for dev. **End-users installing the `.deb` are unaffected** — the binary is pre-built and has no Go runtime dependency.
- **Confidence:** HIGH (versions read directly from upstream `go.mod` files and Launchpad).
### 2. Exact Bubble Tea / Bubbles / Lip Gloss versions
- `charm.land/bubbletea/v2 v2.0.6` (released 2026-04-16)
- `charm.land/bubbles/v2 v2.1.0` (released 2026-03-26)
- `charm.land/lipgloss/v2 v2.0.3` (released 2026-04-13)
- **Footgun:** the module paths moved from `github.com/charmbracelet/...` to `charm.land/...` at v2. Older blog posts and even Charm's own `bubbletea-app-template` (which still pins v1.3.10) will lead people astray. Pin v2 paths explicitly.
- **Alternative if v2 feels too fresh:** `github.com/charmbracelet/bubbletea v1.3.10` + `bubbles v1.0.0` + `lipgloss v1.1.0` are the stable v1 line (older, less active, but used in production by many tools). For a greenfield project in April 2026, v2 is the correct bet — it's been GA since February, has had 6 patch releases, and is where all feature work is happening.
- **Confidence:** HIGH.
### 3. SQLite driver — `modernc.org/sqlite` vs `mattn/go-sqlite3`
- **Choice:** **`modernc.org/sqlite` v1.49.1.**
- **Why for this project specifically:**
- **Trade acknowledged:** `modernc.org/sqlite` is slower (benchmarks in 2026 show ~1.5× slower inserts, comparable selects). For this tool's workload this is not observable.
- **Do NOT use `mattn/go-sqlite3`** — breaks the static-binary goal. See "What NOT to Use" table.
- **Confidence:** HIGH.
### 4. Config parsing for `/etc/ssh/sshd_config`
- **Finding:** There is **no mature Go library specifically for `sshd_config` (server-side)** in 2026. The libraries that search results surface (`kevinburke/ssh_config` v1.6.0, `mikkeloscar/sshconfig`, `k0sproject/rig/v2/sshconfig`, etc.) all parse **client-side `ssh_config`** with `Host` patterns. The directive set, `Match` conditional blocks, and `Include` globbing differ enough between the two files that you cannot safely reuse a client-side parser for server-side edits.
- **Choice:** **Hand-rolled, line-based, comment-preserving parser** tailored to sshd_config. Keep it small and targeted to the directives the tool actually cares about: `Subsystem`, `Match`, `ChrootDirectory`, `AllowUsers`, `PasswordAuthentication`, `PubkeyAuthentication`, `ForceCommand`, `Include`, plus pass-through of everything else.
- **Design:**
- **Alternative considered and rejected:** vendoring `kevinburke/ssh_config` and pretending it handles sshd_config. It doesn't — `Match User X Address Y` parsing is missing, `Subsystem` is not a known directive, and semantics of duplicate directives (last-wins vs first-wins) differ.
- **Confidence:** HIGH on the "no mature lib exists" finding (verified by reading the READMEs of the top 5 candidates); HIGH on the drop-in-file strategy (Debian/Ubuntu convention documented in `sshd_config(5)` on 24.04).
### 5. Shelling out safely
- **Choice:** **Standard library `os/exec` + a thin internal wrapper package.** Do not pull in a scripting DSL.
- **Pattern:**
- **Libraries considered and rejected:**
- **Confidence:** HIGH.
### 6. Log parsing — journalctl
- **Choice:** **Shell out to `journalctl --output=json --since=...` and parse with `encoding/json.Decoder` as newline-delimited JSON.**
- **Why:**
- **Pattern:**
- **Caveat:** fields >4096 bytes are encoded as `null` in JSON output unless `--all` is passed. sshd/sftp log lines are short, so this does not matter for this project — but document it.
- **Confidence:** HIGH.
### 7. Cron vs systemd timer on Ubuntu 24.04
- **Choice:** **systemd timer.** Ship two files in the `.deb`:
- **Why systemd timer over `/etc/cron.weekly`:**
- **Trade:** A systemd timer is two files instead of a one-liner in `/etc/cron.weekly`. nfpm handles this cleanly in YAML.
- **Confidence:** HIGH for the choice; MEDIUM that `cron.weekly` is worse — for a project with broader distro ambitions, cron is more portable. But PROJECT.md explicitly scopes v1 to Ubuntu 24.04 only, so "native to the target platform" wins.
### 8. Firewall library — nftables / ufw
- **Choice:** **Shell out to `ufw` (and fall back to `nft` for rule-comment inspection where ufw's own CLI is inadequate).**
- **Why not a native Go nftables library:**
- **Why not a Go `ufw` library:**
- **Pattern for the structured-comment contract (PROJECT.md line 51):**
- **Confidence:** HIGH for shell-out as the strategy; MEDIUM on the exact parse surface (`ufw status numbered` is easier to read than `nft -j list ...` but less structured — test both during Phase 0).
### 9. Packaging — `nfpm` vs `goreleaser` vs hand-rolled
- **Choice:** **Both, in a standard combination: `goreleaser` drives the build+release pipeline; `goreleaser` invokes `nfpm` for `.deb` output.**
- **Versions:** `goreleaser v2.15.4`, `nfpm v2.46.3`.
- **Why:** this is the standard Go packaging story in 2026. Charm's own `bubbletea-app-template` uses goreleaser. nfpm is explicitly designed as a pure-Go replacement for Ruby `fpm`. Configuration is a single YAML file that produces `.deb`, `.rpm`, `.apk` etc. from the same Go binary — future-proof if the project ever breaks its Ubuntu-only constraint.
- **`.deb` specifics to encode in `nfpm.yaml`:**
- **Do NOT hand-roll `dpkg-deb`:** painful, opaque, and you lose the multi-format future story.
- **Confidence:** HIGH.
### 10. TUI testing — `teatest`
- **Choice:** **`github.com/charmbracelet/x/exp/teatest/v2`** (pseudo-version `v2.0.0-20260422141420-a6cbdff8a7e2` — this module has no semantic tags; pin to a known-good commit and bump deliberately).
- **Status:** The package lives under `x/exp/` (experimental) and has for years, but Charm uses it internally, it's maintained alongside Bubble Tea, and in practice it's the only thing anyone uses. "Experimental" here means "API may rev with Bubble Tea major versions" not "unreliable." v2 track exists specifically for Bubble Tea v2.
- **What it gives you:** run a `tea.Model` in a test program, send synthetic keystrokes, assert on the final rendered frame via golden files, or read the `tea.Model` state directly.
- **Alternatives considered:**
- **Testing posture for this project:**
- **Confidence:** MEDIUM on "teatest is production-ready" (it lives in `x/exp`, which is a stated disclaimer; in practice it is widely used). HIGH on "it is the right choice anyway."
## Installation
# Dev environment (install Go 1.25+ first — do NOT `apt install golang-go` on Ubuntu 24.04, that's 1.22)
# Either: download from https://go.dev/dl/ or: sudo add-apt-repository ppa:longsleep/golang-backports && sudo apt install golang-1.25
# Bootstrap the module
# Core (module paths use charm.land/* for v2)
# SQLite (pure-Go, cgo-free)
# Supporting
# Dev dependencies
# Install CLI tooling (not go.mod deps — project-level tools)
# golangci-lint per their own install instructions (binary, not `go install`)
## Alternatives Considered
| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| `modernc.org/sqlite` | `github.com/mattn/go-sqlite3` v1.14.42 | Only if you abandon the static-binary constraint and measurement shows write throughput is actually bottlenecking you. Neither applies here. |
| Bubble Tea v2.0.6 | Bubble Tea v1.3.10 (`github.com/charmbracelet/bubbletea`) | If v2 proves to have a specific regression that blocks the project; v1 is the stable long-lived line. Not recommended for greenfield Apr 2026. |
| systemd timer | `/etc/cron.weekly/sftp-jailer` shell stub calling the binary | If the project ever drops the Ubuntu-24.04-only constraint and needs distro portability across systems that may lack systemd. |
| Shell-out to `ufw` | Direct netlink via `github.com/google/nftables` | If you need sub-millisecond rule operations or want to bypass ufw entirely for a high-rule-count deployment (>thousands of rules). Not this project. |
| Hand-rolled `sshd_config` parser | Vendor + extend `kevinburke/ssh_config` | Never — the grammars are close but the directive semantics diverge. Forking that library's internal AST is more work than writing a focused parser. |
| `goreleaser` + `nfpm` | Plain `nfpm` in a Makefile | If you want simpler CI without the changelog/release/publish orchestration. Fine but you'll end up re-implementing the wiring. |
| `teatest` | `knz/catwalk` | Personal API preference; no real technical difference. |
| `koanf/v2` | `spf13/viper` v1.21.0 | If you're already deep in the spf13 ecosystem and want tighter Cobra integration. Accept the bigger transitive dep tree. |
| `bitfield/script` (rejected) | — | Compelling for ad-hoc automation scripts. Wrong shape for a TUI with typed subprocess wrappers. |
## What NOT to Use
| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `github.com/mattn/go-sqlite3` | Requires `CGO_ENABLED=1`; dynamically links libc; kills the static-binary story and makes cross-compile painful. | `modernc.org/sqlite` |
| `github.com/coreos/go-systemd/v22/sdjournal` | Requires cgo (binds libsystemd). Same problem as above. | Shell out to `journalctl --output=json` and stream-parse with `encoding/json`. |
| `github.com/charmbracelet/bubbletea` (v1 import path) for a new v2 project | Module path moved to `charm.land/bubbletea/v2` at v2; mixing v1 and v2 imports silently compiles into two incompatible `tea.Model` types. | Import exclusively `charm.land/bubbletea/v2` (and matching `charm.land/bubbles/v2`, `charm.land/lipgloss/v2`). |
| `github.com/kevinburke/ssh_config` (or `mikkeloscar/sshconfig`, `k0sproject/rig/v2/sshconfig`, `petems/go-sshconfig`) **for sshd_config** | All parse client-side `ssh_config`. sshd_config has different directives (`Subsystem`, `Match Address`, `ChrootDirectory`) and semantics (`Include` globbing, drop-in precedence). | Hand-rolled comment-preserving parser targeted at sshd_config. Write to `sshd_config.d/50-sftp-jailer.conf` drop-in, not the main file. |
| `github.com/sbezverk/nftableslib` | Last commit 2023; effectively unmaintained. | Shell out to `ufw`; fall back to `nft` for queries `ufw` can't answer. |
| `gitlab.com/evolves-fr/go-ufw` v1.1.0 (2021) | Unmaintained. | Direct `exec.Command("ufw", ...)`. |
| `github.com/spf13/viper` | Works fine but hefty dep tree (HCL, etcd support, AWS SDK transitively). | `github.com/knadh/koanf/v2` — leaner. Viper remains acceptable; this is an opinionated lean, not a correctness issue. |
| Using cron (`/etc/cron.weekly`) on Ubuntu 24.04 | Not integrated with journald; no `Persistent=` semantics without adding anacron; noisier to debug. | systemd timer unit (`.service` + `.timer`). |
| `fpm` (Ruby) | Adds a Ruby runtime to CI; slow; nfpm exists specifically to replace it. | `nfpm`. |
| `github.com/magefile/mage` (for shelling out from the TUI) | Mage is a build automation tool, not a runtime shell library. Wrong category; not a tempting alternative once you look at it. | Standard `os/exec` with a typed wrapper. (Mage is fine for `/magefile.go` dev task runner if you want, separately from runtime code.) |
| Hand-rolled `dpkg-deb` invocation | Brittle, no multi-format path forward, reinvents what nfpm gives you. | `nfpm` (via `goreleaser`). |
| Go 1.22 or 1.23 | EOL. Bubble Tea v2 requires Go 1.25. | Go 1.25.x (or 1.26.x). |
## Stack Patterns by Variant
- Replace systemd-timer packaging with both timer-based and cron-based strategies, selected by presence of `/run/systemd/system`.
- Abstract the firewall layer behind an interface (already prudent — do this on day one even for v1). Add a `firewalld` backend alongside `ufw` for RHEL/Fedora.
- Swap `adduser`/`usermod` callsites for a distro-abstracted user-management interface.
- Partition `observations` table by month.
- Move to WAL mode explicitly (`PRAGMA journal_mode=WAL`) — both drivers support this through the `database/sql` path.
- Consider a compacted `noise_counters` table with `(source_ip, date) → count` so the full-fidelity `noise` tier can be trimmed aggressively.
- Use `viewport` component (from Bubbles) for virtual scrolling rather than rendering the full list.
- Profile with `pprof` on the `tea.Model` Update loop.
## Version Compatibility
| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `charm.land/bubbletea/v2 v2.0.6` | `charm.land/bubbles/v2 v2.1.0`, `charm.land/lipgloss/v2 v2.0.3` | Bubbles v2.1.0 requires Bubble Tea v2.0.2+. All three are on the same Go 1.25.0 toolchain floor. **Do not mix v1 and v2 imports in the same module** — they produce two incompatible `tea.Model` types, which compiles but will fail at runtime in confusing ways. |
| `charm.land/bubbletea/v2 v2.0.6` | Go `>= 1.25.0` | `go.mod` declares `go 1.25.0`. Building with 1.24 will fail at `go get`. |
| `modernc.org/sqlite v1.49.1` | Go `>= 1.22` (permissive), `CGO_ENABLED=0` | Works with 1.25. Confirm `CGO_ENABLED=0` is actually set in your build env — `go env CGO_ENABLED` should print `0`. |
| `github.com/charmbracelet/x/exp/teatest/v2` | `charm.land/bubbletea/v2 v2.x` | `v2` subpath is the Bubble Tea v2 variant. The non-versioned `teatest` is the Bubble Tea v1 variant. Easy to pick the wrong one. |
| `goreleaser v2.15.4` | `nfpm v2.46.3`, Go 1.24+ | goreleaser v2 yaml schema differs from v1; copy examples from the 2026-dated docs, not 2023 blog posts. |
| Ubuntu 24.04 `ufw` 0.36.2 | nftables backend | Default on 24.04 is nftables-backed ufw. Comments survive `ufw reload`. Verify in Phase 0 with `ufw --version` and `nft list ruleset` after adding a commented rule. |
## Project-specific design commitments that come out of this stack
- **Write sshd changes to `/etc/ssh/sshd_config.d/50-sftp-jailer.conf`, not to the main file.** Uses Ubuntu 24.04's drop-in convention; keeps the tool's footprint isolable; halves the parser's burden (only need to parse enough of the main file to confirm `Include sshd_config.d/*.conf` is present).
- **All subprocess invocations go through a single `internal/sysops` package** with: absolute-path lookup cached at startup, context timeouts mandatory, no `sh -c`, typed stdin handoff, structured error wrapping that includes the invoked argv for audit.
- **Firewall rule comment format:** `sftpj:user=<username>` (as PROJECT.md specifies). Define and commit a parser+serializer in one file, with fuzz tests — this is the load-bearing contract for the user↔IP mapping.
- **SQL schema migrations via embedded `//go:embed` + `modernc.org/sqlite`:** no external migration tool needed; track `PRAGMA user_version` and apply numbered .sql files from the binary.
- **Bubble Tea model structure:** one root model per screen (user list, log viewer, lockdown proposal, user detail); navigate between screens via a `tea.Cmd` returning the next model. Avoid a monolithic mega-model.
## Sources
- `/charmbracelet/bubbletea` (Context7, resolved) — versions, module path
- `https://proxy.golang.org/<module>/@latest` (Go module proxy) — exact semantic versions for every dep, verified 2026-04-24:
- `https://raw.githubusercontent.com/charmbracelet/bubbletea/v2.0.6/go.mod` — confirmed `go 1.25.0` floor
- `https://raw.githubusercontent.com/charmbracelet/bubbles/v2.1.0/go.mod` — confirmed transitive pins
- `https://raw.githubusercontent.com/charmbracelet/lipgloss/v2.0.3/go.mod` — confirmed `go 1.25.0` floor
- `https://api.github.com/repos/charmbracelet/bubbletea/releases` — release dates & tag list
- `https://api.launchpad.net/1.0/ubuntu/+archive/primary` — Ubuntu 24.04 `golang-1.22` 1.22.2-2ubuntu0.4 in noble-updates (no 1.24/1.25 in official repos as of research date)
- `https://go.dev/doc/devel/release` — 1.24 and 1.25 supported; 1.23 and earlier EOL
- `https://github.com/charmbracelet/bubbletea-app-template` — Charm's own reference template (note: still on v1 lineup, a decision point)
- `https://nfpm.goreleaser.com/docs/` — nfpm documentation
- `https://pkg.go.dev/github.com/charmbracelet/x/exp/teatest` — teatest package (experimental status confirmed)
- [Bubble Tea v2 upgrade guide](https://github.com/charmbracelet/bubbletea/blob/main/UPGRADE_GUIDE_V2.md) — module path change and v1→v2 migration notes
- [nftables Go lib comparison](https://pkg.go.dev/github.com/google/nftables), [knftables](https://github.com/kubernetes-sigs/knftables), [ngrok firewall_toolkit](https://github.com/ngrok/firewall_toolkit)
- [journalctl JSON output format](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html), [Journal Export Formats](https://systemd.io/JOURNAL_EXPORT_FORMATS/)
- HIGH: Go version floor, Bubble Tea/Bubbles/Lip Gloss pins, SQLite driver choice, packaging (goreleaser+nfpm), systemd timer choice, journalctl approach, sshd_config hand-roll verdict.
- MEDIUM: teatest "production-ready" claim (officially `x/exp`; de facto mature), ufw comment-preservation under `ufw reload` (expected, should be verified in Phase 0).
- LOW: none of the core recommendations.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:session-continuity-start source:GSD defaults -->
## Session Continuity

If `.planning/HANDOFF.json` exists at the start of a session, a previous session was interrupted (for example by `/compact` or `/gsd:pause-work`) and its state is captured there.

Run `/gsd:resume-work` immediately — before anything else, without waiting for user input. The resume skill will restore context, show project status, and clean up the handoff file.

This instruction is a backup path. When the SessionStart hook fires it emits the same directive via systemMessage; either trigger is sufficient.
<!-- GSD:session-continuity-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
