# Phase 5 Empirical UAT — Debian 13 Lab Host Runbook (DIST-10)

**Acceptance gate:** ROADMAP.md Phase 5 success criterion 7 (DIST-10)

---

## Operator sign-off header

| Field        | Value |
|-------------|-------|
| Operator name | ___________________________ |
| Date          | ___________________________ |
| Lab host      | `root@192.168.1.170` (Debian 13 "trixie") |
| .deb artifact path | ___________________________ |
| Debian version | `cat /etc/os-release` output: _______ |

---

## Preamble

> "Any apt/systemd/ufw/journald portability delta is filed as a finding;
> deltas that prevent the thesis flow from completing block the phase."
> — ROADMAP.md Phase 5 success criterion 7 (verbatim)

This runbook verifies that the Ubuntu 24.04 `.deb` artifact (single static
cgo-free binary) installs, runs the full thesis flow, and purges cleanly on the
Debian 13 lab host at `192.168.1.170`. The same `.deb` produced for Ubuntu
24.04 must run on Debian 13 — no Debian-specific build is produced in v1.2.

**Disclaimer:** Debian 13 is NOT committed as a tier-1 platform for sftp-jailer
v1.2. This UAT is an empirical portability gate only. The README explicitly
documents this scope limitation. Tier-1 Debian 13 support (CI matrix, README
parity, `.deb` metadata) is deferred to a future milestone.

**Why the same .deb works:** the binary is `CGO_ENABLED=0` static, with no
dynamic library dependencies. The `.deb` package depends on `openssh-server`,
`ufw`, and `init-system-helpers` — all present on Debian 13 trixie.

---

## Pre-flight Section

### D.0 — Confirm host is Debian 13 (trixie)

- [ ] **D.0** — Verify OS identity.

```bash
ssh root@192.168.1.170 'cat /etc/os-release | grep -E "^(ID|VERSION)="'
```

**EXPECTED:** `ID=debian` and `VERSION` mentions `trixie` or `13`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### D.1 — Capture system context (portability-delta baseline)

- [ ] **D.1** — Record system identification for evidence.

```bash
ssh root@192.168.1.170 '
  uname -a
  lsb_release -a 2>/dev/null || cat /etc/os-release
  dpkg --print-architecture
  systemctl --version | head -1
  ufw --version 2>&1 | head -1
'
```

**EXPECTED:** output recorded. Operator pastes verbatim into this runbook:

```
uname: ___________
dpkg_arch: ___________
systemd version: ___________
ufw version: ___________
```

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### D.2 — Confirm baseline tools available

- [ ] **D.2** — All required tools present.

```bash
ssh root@192.168.1.170 'command -v apt && command -v systemctl && command -v ufw && command -v journalctl && echo "ALL TOOLS PRESENT"'
```

**EXPECTED:** `ALL TOOLS PRESENT`

If `apt` or `systemctl` is missing → file as DIST-10-DELTA (severity: **block** — thesis flow CANNOT complete without these; phase blocks per ROADMAP.md).
If `ufw` is missing → file as DIST-10-DELTA (severity: **block** — lockdown step requires ufw).
If `journalctl` is missing → file as DIST-10-DELTA (severity: **block** — observe-fire step requires journalctl).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Copy artifacts to lab host

```bash
scp dist/sftp-jailer_*_amd64.deb root@192.168.1.170:/tmp/
scp ./bin/uat-05 root@192.168.1.170:/usr/local/bin/uat-05
ssh root@192.168.1.170 'chmod +x /usr/local/bin/uat-05'
```

---

## Step 1 — apt install (DIST-02 portability)

- [ ] **D.1.1** — Install the .deb.

```bash
ssh root@192.168.1.170 'apt install -y /tmp/sftp-jailer_*_amd64.deb'
```

**EXPECTED:** exits 0; postinst enables `sftp-jailer-observer.timer`; no unmet-dependency errors.

Deltas to capture:
- **apt config differences** — does Debian 13's apt behave differently with the Depends list (`init-system-helpers`, `openssh-server`, `ufw`)?
- **dpkg behaviour** — any `dpkg` errors or warnings specific to Debian 13?
- **lintian differences** — if you run `lintian --pedantic` on Debian 13's version of lintian, the tag set may differ from Ubuntu 22.04/24.04 lintian; note any new tags.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.1.2** — uat-05 install assertions.

```bash
ssh root@192.168.1.170 'uat-05 install'
```

**EXPECTED:** `[PASS] install`

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 2 — postinst side effects (DIST-04 portability)

- [ ] **D.2.1** — System group created; timer enabled + active; cursor pre-created.

```bash
ssh root@192.168.1.170 '
  getent group sftp-jailer
  systemctl is-enabled sftp-jailer-observer.timer
  systemctl is-active sftp-jailer-observer.timer
  stat -c "%a %U %G %s" /var/lib/sftp-jailer/observer.cursor
'
```

**EXPECTED:**
- `sftp-jailer:x:<GID>:` with GID < 1000
- `enabled`
- `active`
- `600 root root 0`

**Delta to capture:** Debian 13's `addgroup --system` GID range. Per Debian policy, system GIDs are typically in 100–999. Verify GID < 1000 holds; if the GID falls in 100–999 rather than Ubuntu's 100–999, this is still acceptable — file as DIST-10-DELTA (finding, not block) for documentation.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 3 — Diagnostic posture

- [ ] **D.3.1** — `sftp-jailer doctor` output on Debian 13.

```bash
ssh root@192.168.1.170 'sftp-jailer doctor'
```

**EXPECTED:** 6+ detector sections render; no panic; exit 0.

Likely deltas to watch:
- **AppArmor detector:** Debian 13 ships AppArmor preinstalled but status varies by image. If `aa-status` reports differently, the AppArmor detector section may show a different status than Ubuntu — file as finding if it does not error.
- **sshd config detector:** same parser; should be parity. Watch for sshd version differences (see Step 4 below).
- **systemd detector:** any version-specific output strings that differ from Ubuntu 24.04.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.3.2** — uat-05 doctor assertion.

```bash
ssh root@192.168.1.170 'uat-05 doctor'
```

**EXPECTED:** `[PASS] doctor`

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 4 — Canonical sshd drop-in apply (TUI-driven)

- [ ] **D.4.1** — Operator drives S-APPLY-SETUP via TUI.

```bash
ssh -t root@192.168.1.170 'sftp-jailer'
```

Navigate to S-APPLY-SETUP → confirm apply. Then run:

```bash
ssh root@192.168.1.170 'sshd -t && echo "sshd -t PASS"'
```

**EXPECTED:** `sshd -t PASS`

**Critical delta:** sshd version differences. Debian 13 ships OpenSSH 9.x; if any
directives in the drop-in template have been deprecated or renamed between Ubuntu's
bundled OpenSSH and Debian 13's version, `sshd -t` will fail. This would be a
**DIST-10-DELTA (block)** — exactly what this UAT is designed to surface.

File the specific error and the directive involved if `sshd -t` fails.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.4.2** — uat-05 apply-sshd post-condition.

```bash
ssh root@192.168.1.170 'uat-05 apply-sshd'
```

**EXPECTED:** `[PASS] apply-sshd`

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 5 — Per-user CRUD (TUI-driven)

Same as Ubuntu runbook Step 5.

- [ ] **D.5.1** — Create user "uattest" via TUI; verify passwd + shadow entries.

```bash
ssh root@192.168.1.170 'getent passwd uattest && getent shadow uattest | cut -d: -f1-2'
```

**EXPECTED:** entries present.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.5.2** — Add SSH key via TUI; verify authorized_keys.

```bash
ssh root@192.168.1.170 'cat /srv/sftp/uattest/.ssh/authorized_keys 2>/dev/null || cat /home/uattest/.ssh/authorized_keys 2>/dev/null'
```

**EXPECTED:** pasted key present.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.5.3** — Delete user via TUI; verify removal.

```bash
ssh root@192.168.1.170 '! getent passwd uattest && echo "user deleted"'
```

**EXPECTED:** `user deleted`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 6 — Observation timer fires + ingests (HIGHEST-RISK PORTABILITY SURFACE)

- [ ] **D.6.1** — Fire the observer service and poll for completion.

```bash
ssh root@192.168.1.170 'uat-05 observe-fire'
```

**EXPECTED:** `[PASS] observe-fire`; `observations_db_size_bytes > 0`.

**Critical delta — journalctl JSON output format:** Phase 2 plan 02-09 implements
`journalctl --output=json` parsing. If Debian 13's journalctl emits JSON with
different field names (e.g., `_HOSTNAME` casing, missing `__REALTIME_TIMESTAMP`,
renamed fields between systemd 255 and 257+), the observer parser may fail
silently or produce empty observation rows.

**This is the highest-risk DIST-10 portability surface.** If the observer
service exits `failed` AND the journal shows JSON parse errors, file as
DIST-10-DELTA (**block** if no observations are ingested despite sshd events
existing in the journal).

Check the journal if uat-05 observe-fire fails:

```bash
ssh root@192.168.1.170 'journalctl -u sftp-jailer-observer.service --no-pager -n 50'
```

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 7 — Lockdown commit + SAFE-04 auto-revert (TUI-driven)

- [ ] **D.7.1** — Capture pre-lockdown ufw state.

```bash
ssh root@192.168.1.170 'ufw status numbered'
```

**EXPECTED:** catch-all ALLOW rules present (OPEN mode).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.7.2** — Operator drives S-LOCKDOWN via TUI: Propose → Dry-run → Commit. DO NOT confirm the 3-minute revert window. Wait ~3 min, then check:

```bash
ssh root@192.168.1.170 'ufw status numbered'
```

**EXPECTED:** catch-all ALLOW rules restored (SAFE-04 revert fired).

**Critical delta — ufw backend on Debian 13:** Debian 13's ufw may use
`iptables-legacy` as its backend if the kernel was booted with the legacy
modules, rather than the nftables backend Ubuntu 24.04 uses by default.

Check the backend:

```bash
ssh root@192.168.1.170 'ufw --version'
```

The Phase 4 enumerate-based catch-all deletion (`ufw status numbered` parsing)
should still work regardless of backend, but if `ufw status numbered` output
format differs on Debian 13 (e.g., rule numbering, IPv6 suffix display), the
BUG-04-A position-shift fix may not correctly enumerate both v4 and v6 catch-alls.
File as DIST-10-DELTA if the lockdown commit leaves orphaned catch-all rules.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Step 8 — apt purge round-trip (DIST-05 portability)

- [ ] **D.8.1** — Purge the package.

```bash
ssh root@192.168.1.170 'apt purge -y sftp-jailer'
```

**EXPECTED:** exits 0; prerm cleans up the sshd drop-in; sshd remains running.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.8.2** — 5-condition teardown check.

```bash
ssh root@192.168.1.170 '
  test ! -f /usr/bin/sftp-jailer        && echo "binary gone" || echo "FAIL: binary present"
  test ! -f /lib/systemd/system/sftp-jailer-observer.service && echo "svc unit gone" || echo "FAIL: svc unit present"
  test ! -f /lib/systemd/system/sftp-jailer-observer.timer   && echo "tmr unit gone" || echo "FAIL: tmr unit present"
  test ! -d /var/lib/sftp-jailer         && echo "state dir gone" || echo "FAIL: state dir present"
  test ! -f /etc/ssh/sshd_config.d/50-sftp-jailer.conf && echo "drop-in gone" || echo "FAIL: drop-in present"
'
```

**EXPECTED:** all 5 lines print "gone".

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **D.8.3** — sshd still running; SSH session preserved.

```bash
ssh root@192.168.1.170 'systemctl is-active ssh.service || systemctl is-active ssh.socket'
```

**EXPECTED:** `active` — the SSH session running these commands is still live.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Portability Deltas Table

File each difference from Ubuntu 24.04 behaviour here. Per ROADMAP.md L52-L53:
- Deltas that PREVENT the thesis flow from completing → severity: **block** (phase blocks)
- Deltas that surface differences but don't block → severity: **finding** (documented; no phase block)

| Delta ID | Step | Description | Severity | Resolution / Workaround |
|----------|------|-------------|----------|------------------------|
| DIST-10-DELTA-01 | _(fill in)_ | _(fill in)_ | _(block / finding)_ | _(fill in)_ |
| DIST-10-DELTA-02 | _(fill in)_ | _(fill in)_ | _(block / finding)_ | _(fill in)_ |

---

## Sign-off

| Field | Value |
|-------|-------|
| Operator name | ___________________________ |
| Date | ___________________________ |

**Outcome (select one):**

- ☐ **ALL PASS** — DIST-10 empirically satisfied; portability deltas (if any) filed above as findings; none prevent thesis flow completion.
- ☐ **THESIS FLOW BLOCKED** — at least one delta listed above prevents thesis flow completion; phase blocks per ROADMAP.md. Gap-closure plan required before milestone close.

Notes:
___________________________________________________________________________
___________________________________________________________________________
