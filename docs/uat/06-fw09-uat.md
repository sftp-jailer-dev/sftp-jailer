# Phase 6 Empirical UAT - FW-09 Dual-family + v6-only Runbook

**Acceptance gate:** ROADMAP.md Phase 6 success criterion 1 (FW-09: BUG-04-B closure on dual-family + v6-only ufw policies). REQUIREMENTS.md FW-09 line 28: "Empirical UAT on an IPv6-enabled VM."

---

## Operator sign-off header

| Field         | Value                  |
|---------------|------------------------|
| Operator name | TBD                    |
| Date          | TBD                    |
| VM hostname   | `<vm-ip>` (192.168.x.y) |
| .deb artifact path | `/tmp/sftp-jailer.deb` |
| Ubuntu version | `lsb_release -d` output: TBD |
| sftp-jailer version | `sftp-jailer version` output: TBD |

> **Identifier policy (D-17):** record only generic placeholders in this template (`<vm-ip>`, `192.168.x.y`). When a real run lands, fill the host fields here, but do NOT bake any specific hostname into the runbook source. The runbook is the empirical artifact, not a host registry.

---

## Preamble

This runbook is the **UAT-pending half of FW-09** per D-16: v1.2.0 ships with code-complete + teatest coverage and the runbook itself authored. Empirical execution becomes a v1.2.x checkbox flip when an IPv6-enabled VM is available; the closure of BUG-04-B does not block v1.2.0 release.

**Ship status (recorded only here and in 06-VERIFICATION.md frontmatter):** `verified-code, UAT-pending`.

The teatest + Go regression-net (plan 06-01 RED commits) proves on every CI run that:
- `NewUfwDeleteCatchAllByEnumerateStep` deletes exactly one v6 catch-all on a v6-only host (FW-09 v6-only edge).
- The dual-family path still deletes both v4 and v6 catch-alls in one pass (BUG-04-C regression guard preserved).
- `AddRule` round-trips an IPv6 source CIDR through ufw 0.36.2's auto-routed family detection.
- `ufwcomment.Decode` is protocol-agnostic on `sftpj:v=1:user=<name>` for v6 rules.

This document captures the runbook for the **empirical** half: the same flow exercised on a real Ubuntu 24.04 VM with IPV6=yes (Variant A) and on a real v6-only VM (Variant B).

**Two variants - run on separate VMs (or revert snapshots between runs):**
- **Variant A - Dual-family host:** stock Ubuntu 24.04 with IPV6=yes; covers the dual catch-all delete behavior at S-LOCKDOWN.
- **Variant B - v6-only host:** IPv6-only cloud VM (no v4 default policy enabling Anywhere); covers the single v6 catch-all delete edge.

---

## Pre-build: snapshot + helper binary

Build the .deb on your dev box before copying to VMs. (No new uat helper for FW-09; the existing `ufw status numbered` + `journalctl` are sufficient evidence.)

```bash
# Build the .deb (goreleaser snapshot - no publish)
goreleaser release --snapshot --clean --skip=publish --config packaging/goreleaser.yml
```

Confirm IPV6=yes on the target VM before starting:

```bash
ssh root@<vm-ip> 'grep "^IPV6=" /etc/default/ufw'
```

**EXPECTED:** `IPV6=yes`.

---

## Variant A - Dual-family host (BUG-04-C regression guard)

Run on a stock Ubuntu 24.04 VM with both v4 and v6 stacks enabled. Default ufw config has IPV6=yes; `ufw enable` produces both a v4 and v6 catch-all.

### A.0 - Pre-flight: confirm dual-family ufw state

- [ ] **A.0** - Confirm `ufw status numbered` shows BOTH a v4 catch-all AND a v6 catch-all.

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** at least two catch-all rows present:
- `[N] 22/tcp ALLOW IN Anywhere` (or `22 ALLOW IN Anywhere`)
- `[M] 22/tcp (v6) ALLOW IN Anywhere (v6)` (or `22 (v6) ALLOW IN Anywhere (v6)`)

Plus IPV6=yes confirmed by the pre-build check above.

Result: [ ] PASS  Notes: ___

---

### A.1 - Add IPv4 per-user rule via TUI (M-ADD-RULE)

- [ ] **A.1** - Operator drives sftp-jailer TUI: navigate to S-USERS, select a user (e.g. `uattest`), use M-ADD-RULE to add a per-user allow with an IPv4 source.

```bash
ssh -t root@<vm-ip> 'sftp-jailer'
```

Navigate: S-USERS -> uattest -> M-ADD-RULE -> source `203.0.113.7/32`, port `22`.

**EXPECTED:** the TUI reports success; M-ADD-RULE writes one ufw rule with comment `sftpj:v=1:user=uattest`.

Result: [ ] PASS  Notes: ___

---

### A.2 - Add IPv6 per-user rule via TUI (M-ADD-RULE)

- [ ] **A.2** - Repeat M-ADD-RULE for the same user with an IPv6 source CIDR.

In the TUI: S-USERS -> uattest -> M-ADD-RULE -> source `2001:db8::/32`, port `22`.

**EXPECTED:** ufw 0.36.2 auto-routes the family from the source CIDR; rule lands as `(v6)` with `# sftpj:v=1:user=uattest`. NO caller-side family flag; no error toast in the TUI.

Result: [ ] PASS  Notes: ___

---

### A.3 - Verify both per-user rules present with sftpj comments

- [ ] **A.3** - Confirm both rules carry the `sftpj:v=1:user=uattest` comment grammar.

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** four rows total:
- v4 catch-all `Anywhere`
- v6 catch-all `Anywhere (v6)`
- v4 per-user rule with `# sftpj:v=1:user=uattest`
- v6 per-user rule with `# sftpj:v=1:user=uattest`

Result: [ ] PASS  Notes: ___

---

### A.4 - Trigger S-LOCKDOWN commit (operator drives TUI)

- [ ] **A.4** - In the TUI, navigate to S-LOCKDOWN and Commit. Operator can either (a) confirm immediately, or (b) wait for the SAFE-04 3-minute revert window to lapse and then verify final state.

For this UAT we want to verify the LOCKDOWN final state - either confirm or wait through the revert window without revoking.

**EXPECTED:** S-LOCKDOWN runs `NewUfwDeleteCatchAllByEnumerateStep` which deletes BOTH catch-alls (v4 + v6) in one Apply pass per BUG-04-C regression guard.

Result: [ ] PASS  Notes: ___

---

### A.5 - Verify zero catch-alls remain post-lockdown

- [ ] **A.5** - After S-LOCKDOWN commit settles, both catch-alls must be gone.

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** ZERO `Anywhere` rows (no v4 or v6 catch-all). Both per-user rules from A.1/A.2 must remain (now the only ALLOW rules besides any system-default SSH rule).

Failure mode this gates: BUG-04-B regression. If only one catch-all is deleted (v4 OR v6 only), the v6 leak (or v4 leak on a brownfield host) means the box is still effectively open to the world over that family.

Result: [ ] PASS  Notes: ___

---

### A.6 - Capture evidence: full ufw output

- [ ] **A.6** - Capture full `ufw status numbered` stdout for the evidence section below.

```bash
ssh root@<vm-ip> 'ufw status numbered' | tee /tmp/fw09-variantA-postlockdown.txt
```

Paste the output into the Evidence Capture section below under "Variant A post-lockdown."

Result: [ ] PASS  Notes: ___

---

## Variant B - v6-only host (BUG-04-B closure)

Run on a SEPARATE Ubuntu 24.04 VM with an IPv6-only stack (no v4 default policy enabling Anywhere). Examples: a Hetzner / OVH / Vultr IPv6-only instance, or a local KVM guest with v4 disabled at the bridge.

### B.0 - Pre-flight: confirm v6-only ufw state

- [ ] **B.0** - Confirm `ufw status numbered` shows ONLY a v6 catch-all (no v4 `Anywhere` row).

```bash
ssh root@<vm-ip> 'ufw status numbered'
```

**EXPECTED:** at most one `Anywhere`-style catch-all row, and it must be `(v6) ALLOW IN Anywhere (v6)`. NO `[N] 22/tcp ALLOW IN Anywhere` (without `(v6)`) row.

If the host has both, this is the dual-family case - go run Variant A instead.

Result: [ ] PASS  Notes: ___

---

### B.1 - Add v6 per-user rule via TUI (M-ADD-RULE)

- [ ] **B.1** - In the TUI, S-USERS -> uattest -> M-ADD-RULE -> source `2001:db8::/32`, port `22`.

**EXPECTED:** rule lands; no error toast; `ufw status numbered` shows the new row with `# sftpj:v=1:user=uattest`.

Result: [ ] PASS  Notes: ___

---

### B.2 - Trigger S-LOCKDOWN commit (operator drives TUI)

- [ ] **B.2** - In the TUI, navigate to S-LOCKDOWN and Commit.

**EXPECTED:** `NewUfwDeleteCatchAllByEnumerateStep` deletes the single v6 catch-all in one pass and TERMINATES (no second pass needed). Per FW-09 Truth #1 and Test 1: count of `UfwDelete` calls equals exactly 1.

Result: [ ] PASS  Notes: ___

---

### B.3 - Verify exactly one delete occurred (audit trail)

- [ ] **B.3** - Confirm sftp-jailer issued exactly one ufw delete call for the catch-all step. Audit-trail source depends on installation:

```bash
# Option 1: journalctl audit (if sftp-jailer logs the txn step boundaries)
ssh root@<vm-ip> 'journalctl -u sftp-jailer-observer.service --since="-1h" | grep -iE "ufw.*delete|UfwDelete|catch-all"'

# Option 2: shell history / TUI screen capture if no journal entry exists
# (record screenshot of S-LOCKDOWN commit completion)
```

**EXPECTED:** evidence of exactly one ufw delete invocation between S-LOCKDOWN start and end. NOT zero (would mean the v6 catch-all leaked - regression of BUG-04-B). NOT more than one (would mean the loop did not terminate cleanly on the post-delete state).

Result: [ ] PASS  Notes: ___

---

### B.4 - Verify zero catch-alls remain post-lockdown

- [ ] **B.4** - The v6 catch-all must be gone; only the per-user v6 rule remains.

```bash
ssh root@<vm-ip> 'ufw status numbered' | tee /tmp/fw09-variantB-postlockdown.txt
```

**EXPECTED:** NO `Anywhere`-style row of any family. The per-user v6 rule from B.1 (with `# sftpj:v=1:user=uattest`) is the only ALLOW IN row besides any system SSH default.

Paste the output into the Evidence Capture section below under "Variant B post-lockdown."

Result: [ ] PASS  Notes: ___

---

## Evidence Capture

### Variant A pre-lockdown (`ufw status numbered`)

```text
(paste output from A.0 / A.3 here)
```

### Variant A post-lockdown (`ufw status numbered`)

```text
(paste output from A.6 here)
```

### Variant B pre-lockdown (`ufw status numbered`)

```text
(paste output from B.0 here)
```

### Variant B post-lockdown (`ufw status numbered`)

```text
(paste output from B.4 here)
```

### Anomaly notes

```text
(paste any unexpected behavior, error toasts, or follow-up bug observations here)
```

---

## Operator sign-off

| Field | Value |
|-------|-------|
| Operator name | TBD |
| Date          | TBD |
| Variant A outcome | [ ] PASS  [ ] FAIL  [ ] PASS-WITH-NOTES |
| Variant B outcome | [ ] PASS  [ ] FAIL  [ ] PASS-WITH-NOTES |
| FW-09 ship status moves from `verified-code, UAT-pending` to `verified` | [ ] YES  [ ] NO |

Operator signature: ___________________  Date: TBD

> **Phase 6 status note (D-16):** v1.2.0 shipped with `verified-code, UAT-pending` recorded ONLY in 06-VERIFICATION.md frontmatter (NOT ROADMAP, NOT changelog). When this runbook completes with both Variants PASS, update 06-VERIFICATION.md frontmatter to `verified` and reference this evidence in the FW-09 row of the traceability table.
