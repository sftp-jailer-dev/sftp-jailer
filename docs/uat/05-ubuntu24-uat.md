# Phase 5 Empirical UAT — Ubuntu 24.04 VM Runbook

**Acceptance gate:** ROADMAP.md Phase 5 success criteria 1 (DIST-02), 3 (DIST-04), 4 (DIST-05), 6 (DIST-09)

---

## Operator sign-off header

| Field        | Value |
|-------------|-------|
| Operator name | ___________________________ |
| Date          | ___________________________ |
| VM hostname   | ___________________________ |
| .deb artifact path | ___________________________ |
| Ubuntu version | `lsb_release -d` output: _______ |

---

## Preamble

This is the **load-bearing empirical acceptance gate** for Phase 5. CI alone is
insufficient: goreleaser can produce a syntactically valid .deb that still
mishandles postinst logic, fails to clean up on purge, or silently modifies the
admin's `/etc/ssh/sshd_config` on install. Only running the full thesis flow on a
real Ubuntu 24.04 VM catches these classes of bugs.

**Precedent:** Phase 4 plan 04-10 ran this same pattern — empirical UAT on a real
host discovered BUG-04-A (position-shift catch-all deletion), BUG-04-C (dual-family
catch-all), and BUG-04-D (timer-vs-service cancel bug) that CI had not caught.
Phase 5 carries the same standard forward.

**Two variants — run on separate VMs (or revert snapshots between runs):**
- **Variant A — Clean Install:** fresh Ubuntu 24.04 VM; covers criteria 1, 3, 4.
- **Variant B — Brownfield:** pre-edited `/etc/ssh/sshd_config`; covers criterion 6 (DIST-09).

---

## Pre-build: snapshot + helper binary

Build both the .deb and the uat-05 helper on your dev box before copying to VMs:

```bash
# Build the .deb (goreleaser snapshot — no publish)
goreleaser release --snapshot --clean --skip=publish --config packaging/goreleaser.yml

# Build uat-05 helper
CGO_ENABLED=0 go build -o ./bin/uat-05 ./cmd/uat-05
```

---

## Variant A — Clean Install (criteria 1, 3, 4)

### A.0 — Pre-flight: confirm VM is fresh

- [ ] **A.0** — Confirm no prior sftp-jailer install.

```bash
ssh root@<vm-ip> 'dpkg -l | grep sftp-jailer'
```

**EXPECTED:** empty output (no rows).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### A.1 — Copy .deb and uat-05 helper to VM

- [ ] **A.1** — Copy artifacts.

```bash
scp dist/sftp-jailer_*_amd64.deb root@<vm-ip>:/tmp/
scp ./bin/uat-05 root@<vm-ip>:/usr/local/bin/uat-05
ssh root@<vm-ip> 'chmod +x /usr/local/bin/uat-05'
```

**EXPECTED:** files transferred without error; `ls -la /tmp/sftp-jailer_*.deb` shows the .deb.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 1 — apt install (criterion 1, DIST-02)

- [ ] **1.1** — Install the .deb package.

```bash
ssh root@<vm-ip> 'apt install -y /tmp/sftp-jailer_*_amd64.deb'
```

**EXPECTED:** exits 0; postinst output mentions enabling `sftp-jailer-observer.timer`; no errors or dependency failures.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **1.2** — Run uat-05 install assertions.

```bash
ssh root@<vm-ip> 'uat-05 install'
```

**EXPECTED:** `[PASS] install`; receipt JSON at `/var/log/sftp-jailer-uat-05/install.json` shows 5 paths present and `timer_active=active`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **1.3** — Confirm cgo-free static binary.

```bash
ssh root@<vm-ip> 'ldd /usr/bin/sftp-jailer'
```

**EXPECTED:** `not a dynamic executable`

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 2 — postinst side effects (criterion 3, DIST-04)

- [ ] **2.1** — System group created with GID < 1000.

```bash
ssh root@<vm-ip> 'getent group sftp-jailer'
```

**EXPECTED:** `sftp-jailer:x:<GID>:` where GID < 1000 (system range).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **2.2** — Observer timer enabled and active.

```bash
ssh root@<vm-ip> 'systemctl is-enabled sftp-jailer-observer.timer && systemctl is-active sftp-jailer-observer.timer'
```

**EXPECTED:** two lines — `enabled` then `active`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **2.3** — observer.cursor pre-created with correct permissions.

```bash
ssh root@<vm-ip> 'stat -c "%a %U %G %s" /var/lib/sftp-jailer/observer.cursor'
```

**EXPECTED:** `600 root root 0`

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 3 — Diagnostic posture

- [ ] **3.1** — `sftp-jailer doctor` runs without panic.

```bash
ssh root@<vm-ip> 'sftp-jailer doctor'
```

**EXPECTED:** TUI renders 6+ detector sections; no panic traceback; exit 0. Operator visually confirms sections render correctly.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **3.2** — uat-05 doctor JSON assertion.

```bash
ssh root@<vm-ip> 'uat-05 doctor'
```

**EXPECTED:** `[PASS] doctor`; receipt JSON shows `report_keys >= 6`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 4 — Canonical sshd drop-in apply (operator drives TUI)

- [ ] **4.1** — Operator applies canonical sshd config via TUI.

Launch the TUI on the VM (or via SSH with terminal forwarding):

```bash
ssh -t root@<vm-ip> 'sftp-jailer'
```

Navigate to S-APPLY-SETUP → confirm apply.

Operator checklist (tick each after confirming in TUI):
- [ ] apply succeeded (no error toast)
- [ ] `sshd -t` passed (shown in TUI or verify manually below)
- [ ] sshd reload completed

```bash
ssh root@<vm-ip> 'sshd -t && echo "sshd -t PASS"'
```

**EXPECTED:** `sshd -t PASS` (config valid after drop-in write).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **4.2** — uat-05 apply-sshd post-flow assertion.

```bash
ssh root@<vm-ip> 'uat-05 apply-sshd'
```

**EXPECTED:** `[PASS] apply-sshd`; `sshd -T` shows `chrootdirectory` or `forcecommand`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 5 — Per-user CRUD (operator drives TUI)

This step is TUI-driven. The `user-crud` subcommand is a stub that directs to
this section; fill the PASS/FAIL columns manually after completing each TUI action.

- [ ] **5.1** — Create user "uattest" via TUI (S-USERS → New).

```bash
ssh root@<vm-ip> 'getent passwd uattest && getent shadow uattest | cut -d: -f1-2'
```

**EXPECTED:** passwd entry present; shadow entry shows `uattest:$6$...` (hashed password).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **5.2** — Add SSH key for "uattest" via TUI (S-USERS → select uattest → Add Key).

```bash
ssh root@<vm-ip> 'cat /srv/sftp/uattest/.ssh/authorized_keys 2>/dev/null || cat /home/uattest/.ssh/authorized_keys 2>/dev/null'
```

**EXPECTED:** the pasted public key is present in the file.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **5.3** — Delete user "uattest" via TUI (S-USERS → select uattest → Delete).

```bash
ssh root@<vm-ip> '! getent passwd uattest && echo "user deleted"'
```

**EXPECTED:** `user deleted` (user no longer in passwd db).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 6 — Observation timer fires and ingests (criterion 3)

- [ ] **6.1** — Fire the observer service and poll for completion.

```bash
ssh root@<vm-ip> 'uat-05 observe-fire'
```

**EXPECTED:** `[PASS] observe-fire`; receipt shows `final_state=inactive` (or `failed` with note); `observations_db_size_bytes > 0`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 7 — Lockdown commit + SAFE-04 rollback (operator drives TUI)

This step is TUI-driven. The `lockdown-cycle` subcommand is a stub; fill PASS/FAIL manually.

- [ ] **7.1** — Capture ufw state pre-lockdown.

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** catch-all ALLOW rules present (OPEN mode). Record output.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **7.2** — Operator drives S-LOCKDOWN via TUI: Propose → Dry-run → Commit. DO NOT confirm the 3-minute revert window — let SAFE-04 auto-revert fire. Wait ~3 minutes, then:

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** catch-all ALLOW rules restored (OPEN mode); sftpj per-user rules removed. The SAFE-04 timer fired and reverted the lockdown without operator intervention.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

### Step 8 — apt purge round-trip (criterion 4, DIST-05)

- [ ] **8.1** — Purge the package.

```bash
ssh root@<vm-ip> 'apt purge -y sftp-jailer'
```

**EXPECTED:** exits 0; prerm logs the `purge-sshd-cleanup` outcome; no errors; sshd remains running throughout.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **8.2** — Confirm complete teardown (5 conditions).

```bash
ssh root@<vm-ip> '
  test ! -f /usr/bin/sftp-jailer        && echo "binary gone" || echo "FAIL: binary present"
  test ! -f /lib/systemd/system/sftp-jailer-observer.service && echo "svc unit gone" || echo "FAIL: svc unit present"
  test ! -f /lib/systemd/system/sftp-jailer-observer.timer   && echo "tmr unit gone" || echo "FAIL: tmr unit present"
  test ! -d /var/lib/sftp-jailer         && echo "state dir gone" || echo "FAIL: state dir present"
  test ! -f /etc/ssh/sshd_config.d/50-sftp-jailer.conf && echo "drop-in gone" || echo "FAIL: drop-in present"
'
```

**EXPECTED:** all 5 lines print "gone" (no FAIL lines).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

- [ ] **8.3** — sshd still running and SSH session preserved.

```bash
ssh root@<vm-ip> 'systemctl is-active ssh.service || systemctl is-active ssh.socket'
```

**EXPECTED:** `active` — the SSH session running these commands is still live; that is proof sshd was not killed by the purge.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Variant B — Brownfield (criterion 6, DIST-09)

Run on a **SEPARATE** Ubuntu 24.04 VM (or revert to snapshot before this variant).

> **DIST-09 contract:** `apt install` and `apt purge sftp-jailer` MUST NOT
> modify `/etc/ssh/sshd_config` (the admin-owned main file). Only the
> tool-owned drop-in at `/etc/ssh/sshd_config.d/50-sftp-jailer.conf` is
> written/removed. Byte-identity of the main file is verified via sha256sum.

### B.0 — Pre-edit the main sshd_config with a UAT-MARKER

```bash
ssh root@<vm-ip-2> 'echo "# UAT-MARKER: do not delete (DIST-09 brownfield test)" >> /etc/ssh/sshd_config'
```

**EXPECTED:** exits 0.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.1 — Capture baseline sha256

```bash
ssh root@<vm-ip-2> 'sha256sum /etc/ssh/sshd_config'
```

**EXPECTED:** a 64-char hex hash and the filename. Record the hash:

```
BASELINE=<paste hash here>
```

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.2 — Install

```bash
ssh root@<vm-ip-2> 'apt install -y /tmp/sftp-jailer_*_amd64.deb'
```

**EXPECTED:** exits 0; postinst does NOT mention touching `/etc/ssh/sshd_config`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.3 — (Optional) Apply drop-in via TUI

Launch sftp-jailer TUI and drive S-APPLY-SETUP to write the drop-in. Even with
the drop-in written, the main `/etc/ssh/sshd_config` MUST remain byte-identical
to the pre-install baseline.

### B.4 — Purge

```bash
ssh root@<vm-ip-2> 'apt purge -y sftp-jailer'
```

**EXPECTED:** exits 0; prerm removes the drop-in; sshd remains running.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.5 — Re-hash and compare to BASELINE

```bash
ssh root@<vm-ip-2> "sha256sum /etc/ssh/sshd_config"
```

Record the post-purge hash. Compare manually:

```
BASELINE (from B.1): ___________________________________________
POST-PURGE:          ___________________________________________
Match? ☐ YES  ☐ NO
```

**EXPECTED:** hashes match exactly.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.6 — Run uat-05 brownfield-purge (DIST-09 gate)

```bash
ssh root@<vm-ip-2> "UAT_BASELINE_SHA256=$BASELINE uat-05 brownfield-purge"
```

**EXPECTED:** `[PASS] brownfield-purge`; receipt JSON shows `dist09_status=main_sshd_config_byte_identical` and `dropin_status=absent`.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

### B.7 — Confirm UAT-MARKER still present in main config

```bash
ssh root@<vm-ip-2> 'grep "UAT-MARKER" /etc/ssh/sshd_config'
```

**EXPECTED:** `# UAT-MARKER: do not delete (DIST-09 brownfield test)` printed.

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Lintian-overrides empirical fill (closes 05-04 task 4 deferred gap)

### L.1 — Build .debs and run lintian --pedantic

```bash
goreleaser release --snapshot --clean --skip=publish --config packaging/goreleaser.yml
for deb in dist/*.deb; do
  echo "==> $deb"
  lintian --pedantic "$deb" || true
done
```

Record every non-overridden warning in the table below:

| Warning tag | Package | Why acceptable |
|------------|---------|---------------|
| _(fill in)_ | _(fill in)_ | _(fill in)_ |

### L.2 — Add overrides to packaging/debian/lintian-overrides

For each warning from L.1, append an entry:

```
# WHY: <one-line rationale citing the source artifact decision or REQUIREMENTS.md>
sftp-jailer: <lintian-tag>
```

Each entry MUST carry the `# WHY:` rationale comment (per CONTEXT.md "Specific Ideas" L548-L550).

### L.3 — Re-run lintian to confirm zero non-overridden warnings

```bash
for deb in dist/*.deb; do
  echo "==> $deb"
  lintian --pedantic "$deb"
done
```

**EXPECTED:** empty stdout (clean — all warnings suppressed by overrides with rationale).

Result: ☐ PASS  ☐ FAIL  Notes: ___________

---

## Sign-off

| Field | Value |
|-------|-------|
| Operator name | ___________________________ |
| Date | ___________________________ |
| Variant A outcome | ☐ ALL PASS  ☐ FAILURES NOTED |
| Variant B (DIST-09) outcome | ☐ ALL PASS  ☐ FAILURES NOTED |
| Lintian clean | ☐ PASS  ☐ FAILURES NOTED |
| Phase may proceed | ☐ YES — all criteria met  ☐ NO — failures require gap-closure plan |

Notes / failures requiring follow-up:
___________________________________________________________________________
___________________________________________________________________________

**Phase cannot be marked complete until all PASS/FAIL columns are PASS or have a
recorded waiver approved by the operator.**
