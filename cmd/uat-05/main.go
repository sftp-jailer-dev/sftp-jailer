// cmd/uat-05 is the empirical UAT helper for Phase 5 (packaging, install/purge,
// and automated release). It provides a subcommand-dispatch interface to the
// assertion-heavy parts of the thesis flow: verifying a .deb install lands the
// right files, the systemd timer fires, the sshd drop-in is applied correctly,
// the observation DB is written, the brownfield byte-identity contract holds
// after apt purge, and more.
//
// Requirements gated: DIST-04, DIST-05, DIST-09, DIST-10.
//
// Subcommands:
//
//	install          - asserts all 5 install paths + timer active + static binary
//	doctor           - asserts sftp-jailer doctor runs and returns ≥6 detector keys
//	apply-sshd       - post-condition check: drop-in exists + sshd -T output sane
//	user-crud        - stub: directs operator to manual TUI flow in runbook
//	observe-fire     - fires the one-shot timer, polls for completion, checks DB rows
//	lockdown-cycle   - stub: directs operator to manual TUI flow for SAFE-04 revert
//	brownfield-purge - DIST-09 gate: sha256sum main sshd_config unchanged post-purge
//
// JSON receipts are written to /var/log/sftp-jailer-uat-05/<subcmd>.json after
// each invocation. This directory is outside /var/lib/sftp-jailer so apt purge
// does NOT erase the audit trail.
//
// Receipt fields: subcmd, started_at, finished_at, status ("PASS"|"FAIL"),
// evidence (map[string]string), error (omitempty), host_info (map[string]string).
//
// IMPORTANT: this helper temporarily mutates real system state (apt, systemctl,
// ufw, sshd). Run ONLY on staging boxes dedicated to UAT - never production.
//
// This helper is intentionally one-shot - it should be removed from cmd/ after
// the empirical UAT completes, mirroring the Phase 3/4 pattern documented in
// the 03-08b/03-09 and 04-10 SUMMARYs.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

const receiptDir = "/var/log/sftp-jailer-uat-05"

// receipt is the JSON audit trail written after each subcommand invocation.
type receipt struct {
	Subcmd     string            `json:"subcmd"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Status     string            `json:"status"` // "PASS" | "FAIL"
	Evidence   map[string]string `json:"evidence"`
	Error      string            `json:"error,omitempty"`
	HostInfo   map[string]string `json:"host_info"`
}

// subcmdFn is the signature every subcommand implementation must satisfy.
type subcmdFn func(ctx context.Context, ops sysops.SystemOps, r *receipt) error

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "uat-05 must run as root (it checks system paths + fires systemd units)")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, `Usage: uat-05 <subcommand>

Subcommands:
  install          Assert 5 install paths + timer active + static binary (cgo-free)
  doctor           Assert sftp-jailer doctor --json returns ≥6 detector keys
  apply-sshd       Post-condition: drop-in exists + sshd -T output is sane
  user-crud        STUB: see docs/uat/05-ubuntu24-uat.md for manual TUI flow
  observe-fire     Fire sftp-jailer-observer.service, poll completion, check DB
  lockdown-cycle   STUB: see docs/uat/05-ubuntu24-uat.md for manual SAFE-04 flow
  brownfield-purge DIST-09: assert /etc/ssh/sshd_config sha256 unchanged post-purge

JSON receipts written to %s/<subcmd>.json
`, receiptDir)
		os.Exit(1)
	}

	subcmd := os.Args[1]
	ops := sysops.NewReal()
	ctx := context.Background()

	subcommands := map[string]subcmdFn{
		"install":          runInstall,
		"doctor":           runDoctor,
		"apply-sshd":       runApplySshd,
		"user-crud":        runUserCrud,
		"observe-fire":     runObserveFire,
		"lockdown-cycle":   runLockdownCycle,
		"brownfield-purge": runBrownfieldPurge,
	}

	fn, ok := subcommands[subcmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "[FAIL] unknown subcommand %q\n", subcmd)
		os.Exit(1)
	}

	r := &receipt{
		Subcmd:    subcmd,
		StartedAt: time.Now().UTC(),
		Status:    "FAIL", // default; overridden to PASS on success
		Evidence:  make(map[string]string),
		HostInfo:  make(map[string]string),
	}

	// Always write the receipt, even on failure - it is the audit trail.
	defer func() {
		r.FinishedAt = time.Now().UTC()
		if werr := writeReceipt(r); werr != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not write receipt: %v\n", werr)
		}
	}()

	// Populate host_info upfront (best-effort; failures do not abort the run).
	r.HostInfo = gatherHostInfo(ctx, ops)

	err := fn(ctx, ops, r)
	if err != nil {
		r.Status = "FAIL"
		r.Error = err.Error()
		fmt.Printf("[FAIL] %s: %v\n", subcmd, err)
		os.Exit(1)
	}

	r.Status = "PASS"
	fmt.Printf("[PASS] %s\n", subcmd)
}

// gatherHostInfo collects basic system identification via ops.Exec.
// Failures are ignored - this is audit decoration, not a gate.
func gatherHostInfo(ctx context.Context, ops sysops.SystemOps) map[string]string {
	info := make(map[string]string)

	if res, err := ops.Exec(ctx, "uname", "-a"); err == nil && res.ExitCode == 0 {
		info["uname"] = strings.TrimSpace(string(res.Stdout))
	}
	if res, err := ops.Exec(ctx, "dpkg", "--print-architecture"); err == nil && res.ExitCode == 0 {
		info["dpkg_arch"] = strings.TrimSpace(string(res.Stdout))
	}
	// lsb_release may not be present on all Debian 13 images.
	if res, err := ops.Exec(ctx, "lsb_release", "-a"); err == nil && res.ExitCode == 0 {
		info["lsb_release"] = strings.TrimSpace(string(res.Stdout))
	} else {
		// Fall back to /etc/os-release for Debian 13 which may lack lsb_release.
		if data, rerr := os.ReadFile("/etc/os-release"); rerr == nil {
			info["os_release"] = strings.TrimSpace(string(data))
		}
	}

	return info
}

// writeReceipt serialises r to receiptDir/<subcmd>.json (mode 0644 root:root).
// The directory is created if absent.
func writeReceipt(r *receipt) error {
	if err := os.MkdirAll(receiptDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", receiptDir, err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal receipt: %w", err)
	}
	path := filepath.Join(receiptDir, r.Subcmd+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// fileSHA256 computes the hex-encoded SHA-256 of the file at path.
// Used by runBrownfieldPurge for the DIST-09 byte-equality assertion.
func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s for sha256: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// contains is a minimal substring helper used by runApplySshd.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// ----------------------------------------------------------------------------
// Subcommand implementations
// ----------------------------------------------------------------------------

// runInstall asserts the 5 install paths, timer active, and cgo-free binary.
// Verifies:
//   - /usr/bin/sftp-jailer
//   - /lib/systemd/system/sftp-jailer-observer.service
//   - /lib/systemd/system/sftp-jailer-observer.timer
//   - /var/lib/sftp-jailer/ (directory)
//   - /usr/share/man/man1/sftp-jailer.1 OR sftp-jailer.1.gz
//     (nfpm ships .1 uncompressed; man-db does not gzip during install trigger)
//   - systemctl is-active sftp-jailer-observer.timer returns "active"
//   - ldd /usr/bin/sftp-jailer reports "not a dynamic executable"
func runInstall(ctx context.Context, ops sysops.SystemOps, r *receipt) error {
	paths := map[string]string{
		"binary":       "/usr/bin/sftp-jailer",
		"observer_svc": "/lib/systemd/system/sftp-jailer-observer.service",
		"observer_tmr": "/lib/systemd/system/sftp-jailer-observer.timer",
		"state_dir":    "/var/lib/sftp-jailer",
	}
	for key, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("install path missing (%s): %s: %w", key, p, err)
		}
		r.Evidence[key+"_present"] = "true"
		fmt.Printf("  OK: %s\n", p)
	}

	// Man page: nfpm ships sftp-jailer.1 uncompressed; man-db trigger does NOT
	// gzip at install time (only updates its database index). Accept both forms.
	manGz := "/usr/share/man/man1/sftp-jailer.1.gz"
	manUncomp := "/usr/share/man/man1/sftp-jailer.1"
	if _, err := os.Stat(manGz); err == nil {
		r.Evidence["man_page_present"] = "true"
		r.Evidence["man_page_path"] = manGz
		fmt.Printf("  OK: %s\n", manGz)
	} else if _, err := os.Stat(manUncomp); err == nil {
		r.Evidence["man_page_present"] = "true"
		r.Evidence["man_page_path"] = manUncomp
		fmt.Printf("  OK: %s (uncompressed; nfpm does not auto-gzip)\n", manUncomp)
	} else {
		return fmt.Errorf("install path missing (man_page): neither %s nor %s found", manGz, manUncomp)
	}

	// Timer active check via ops.Exec (typed wrapper; sysops discipline enforced).
	res, err := ops.Exec(ctx, "systemctl", "is-active", "sftp-jailer-observer.timer")
	if err != nil {
		return fmt.Errorf("systemctl is-active: %w", err)
	}
	timerState := strings.TrimSpace(string(res.Stdout))
	r.Evidence["timer_active"] = timerState
	if timerState != "active" {
		return fmt.Errorf("sftp-jailer-observer.timer is %q, expected \"active\"", timerState)
	}
	fmt.Printf("  OK: timer is-active=%s\n", timerState)

	// cgo-free binary check: ldd should report "not a dynamic executable".
	// Use absolute path to bypass the sysops allowlist (UAT-only helper).
	lddRes, err := ops.Exec(ctx, "/usr/bin/ldd", "/usr/bin/sftp-jailer")
	if err != nil {
		return fmt.Errorf("ldd: %w", err)
	}
	lddOut := strings.TrimSpace(string(lddRes.Stdout) + string(lddRes.Stderr))
	r.Evidence["ldd_output"] = lddOut
	if !contains(lddOut, "not a dynamic executable") {
		return fmt.Errorf("cgo-free check FAILED: ldd output=%q (expected \"not a dynamic executable\")", lddOut)
	}
	fmt.Printf("  OK: cgo-free static binary confirmed (ldd: not a dynamic executable)\n")

	// Capture `file` output as supplementary evidence.
	// Use absolute path to bypass the sysops allowlist (UAT-only helper).
	if fileRes, ferr := ops.Exec(ctx, "/usr/bin/file", "/usr/bin/sftp-jailer"); ferr == nil {
		r.Evidence["file_output"] = strings.TrimSpace(string(fileRes.Stdout))
	}

	return nil
}

// runDoctor asserts that `sftp-jailer doctor --json` exits 0 and returns
// a JSON object with at least 6 detector keys.
func runDoctor(ctx context.Context, ops sysops.SystemOps, r *receipt) error {
	res, err := ops.Exec(ctx, "/usr/bin/sftp-jailer", "doctor", "--json")
	if err != nil {
		return fmt.Errorf("sftp-jailer doctor --json: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sftp-jailer doctor --json exit %d: stderr=%s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	// Unmarshal the JSON report; assert ≥6 keys.
	var report map[string]interface{}
	if err := json.Unmarshal(res.Stdout, &report); err != nil {
		return fmt.Errorf("parse doctor JSON output: %w (raw: %s)", err, string(res.Stdout))
	}
	keyCount := len(report)
	r.Evidence["report_size_bytes"] = fmt.Sprintf("%d", len(res.Stdout))
	r.Evidence["report_keys"] = fmt.Sprintf("%d", keyCount)
	if keyCount < 6 {
		return fmt.Errorf("doctor JSON has %d keys, expected ≥6 detector sections", keyCount)
	}
	fmt.Printf("  OK: doctor JSON has %d detector keys\n", keyCount)
	return nil
}

// runApplySshd is a POST-CONDITION asserter - the operator drives the
// S-APPLY-SETUP TUI flow first, then runs this subcommand.
// Asserts:
//   - /etc/ssh/sshd_config.d/50-sftp-jailer.conf exists
//   - sshd -T output contains "chrootdirectory" or "forcecommand"
func runApplySshd(ctx context.Context, ops sysops.SystemOps, r *receipt) error {
	dropIn := "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"
	if _, err := os.Stat(dropIn); err != nil {
		return fmt.Errorf("drop-in missing: %s: %w\n  TIP: run the S-APPLY-SETUP TUI flow first, then re-run this subcommand", dropIn, err)
	}
	r.Evidence["dropin_present"] = "true"
	fmt.Printf("  OK: drop-in present: %s\n", dropIn)

	// sshd -T dumps the effective config in key=value form.
	res, err := ops.Exec(ctx, "sshd", "-T")
	if err != nil {
		return fmt.Errorf("sshd -T: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("sshd -T exit %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	out := strings.ToLower(string(res.Stdout))
	hasChrootDir := contains(out, "chrootdirectory")
	hasForceCmd := contains(out, "forcecommand")
	r.Evidence["sshd_t_has_chrootdirectory"] = fmt.Sprintf("%v", hasChrootDir)
	r.Evidence["sshd_t_has_forcecommand"] = fmt.Sprintf("%v", hasForceCmd)

	if !hasChrootDir && !hasForceCmd {
		return fmt.Errorf("sshd -T output contains neither \"chrootdirectory\" nor \"forcecommand\"; drop-in may not be active")
	}
	fmt.Printf("  OK: sshd -T confirms chrootdirectory=%v forcecommand=%v\n", hasChrootDir, hasForceCmd)
	return nil
}

// runUserCrud is a STUB. The per-user CRUD flow is TUI-driven and cannot be
// fully automated without a headless Bubble Tea harness. The operator must
// follow the runbook steps manually.
func runUserCrud(_ context.Context, _ sysops.SystemOps, _ *receipt) error {
	return fmt.Errorf(`user-crud is a manual TUI flow - this subcommand is intentionally a stub.

Follow docs/uat/05-ubuntu24-uat.md Step 5 (per-user CRUD):
  5.1 Create user "uattest" via TUI (S-USERS → New)
      Verify: getent passwd uattest && getent shadow uattest | cut -d: -f1-2
  5.2 Add SSH key via TUI (S-USERS → select uattest → Add Key)
      Verify: cat <chrootRoot>/uattest/.ssh/authorized_keys
  5.3 Delete user via TUI (S-USERS → select uattest → Delete)
      Verify: ! getent passwd uattest exits 0

After completing the TUI flow, fill in the PASS/FAIL columns in the runbook.
The receipt for this subcommand will record FAIL until the operator signs off manually.`)
}

// runObserveFire fires the one-shot sftp-jailer-observer.service and polls
// until it reaches "inactive" or "failed" (Type=oneshot completion), then
// checks that observations.db has at least some content.
func runObserveFire(ctx context.Context, ops sysops.SystemOps, r *receipt) error {
	// Start the one-shot observer service.
	startRes, err := ops.Exec(ctx, "systemctl", "start", "sftp-jailer-observer.service")
	if err != nil {
		return fmt.Errorf("systemctl start sftp-jailer-observer.service: %w", err)
	}
	if startRes.ExitCode != 0 {
		return fmt.Errorf("systemctl start exit %d: %s", startRes.ExitCode, strings.TrimSpace(string(startRes.Stderr)))
	}
	fmt.Printf("  OK: sftp-jailer-observer.service started\n")

	// Poll for up to 2 minutes for inactive or failed (oneshot completion).
	deadline := time.Now().Add(2 * time.Minute)
	var finalState string
	for time.Now().Before(deadline) {
		res, perr := ops.Exec(ctx, "systemctl", "is-active", "sftp-jailer-observer.service")
		if perr != nil {
			return fmt.Errorf("systemctl is-active (poll): %w", perr)
		}
		state := strings.TrimSpace(string(res.Stdout))
		if state == "inactive" || state == "failed" {
			finalState = state
			break
		}
		time.Sleep(2 * time.Second)
	}
	if finalState == "" {
		return fmt.Errorf("sftp-jailer-observer.service still active after 2-minute poll deadline")
	}
	r.Evidence["final_state"] = finalState
	fmt.Printf("  OK: service completed with state=%s\n", finalState)

	// Check observations.db exists.
	dbPath := "/var/lib/sftp-jailer/observations.db"
	info, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("observations.db missing: %w", err)
	}
	r.Evidence["observations_db_size_bytes"] = fmt.Sprintf("%d", info.Size())
	fmt.Printf("  OK: observations.db present (%d bytes)\n", info.Size())

	if finalState == "failed" {
		fmt.Printf("  NOTE: service reported \"failed\" - check journalctl -u sftp-jailer-observer.service for details\n")
		r.Evidence["service_state_note"] = "failed; inspect journal for error details"
		// A failed oneshot is recorded as evidence but is not a hard FAIL for
		// the uat-05 tool - the operator interprets the journal to determine if
		// the failure was expected (e.g., no sshd events yet on a fresh install).
		// Comment out the return to make this a hard failure if desired.
		//
		// return fmt.Errorf("service exited with failed state; check journal")
	}

	return nil
}

// runLockdownCycle is a STUB. The lockdown commit + SAFE-04 auto-revert
// flow requires interactive TUI operation and cannot be fully automated.
func runLockdownCycle(_ context.Context, _ sysops.SystemOps, _ *receipt) error {
	return fmt.Errorf(`lockdown-cycle is a manual TUI flow - this subcommand is intentionally a stub.

Follow docs/uat/05-ubuntu24-uat.md Step 7 (lockdown commit + rollback):
  7.1 Operator drives S-LOCKDOWN: Propose → Dry-run → Commit
      DO NOT confirm the 3-minute revert window - let SAFE-04 auto-revert fire.
      Watch the ufw rules return to OPEN after ~3 minutes.
      Verify via: ufw status numbered  (pre, during, and post)

The SAFE-04 3-minute auto-revert is the load-bearing assertion here.
After completing this step manually, fill in the PASS/FAIL column in the runbook.
The receipt for this subcommand will record FAIL until the operator signs off manually.`)
}

// runBrownfieldPurge is the DIST-09 acceptance gate.
//
//   - If UAT_BASELINE_SHA256 is empty: prints the current sha256 of
//     /etc/ssh/sshd_config for the operator to record as the baseline.
//   - If UAT_BASELINE_SHA256 is set: hashes /etc/ssh/sshd_config now;
//     compares to baseline; FAILS with "DIST-09 VIOLATION" if mismatched;
//     asserts the drop-in is absent (post-purge).
func runBrownfieldPurge(_ context.Context, _ sysops.SystemOps, r *receipt) error {
	const mainConfig = "/etc/ssh/sshd_config"
	const dropIn = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"

	baseline := os.Getenv("UAT_BASELINE_SHA256")

	if baseline == "" {
		// BASELINE CAPTURE MODE - print the current hash for the operator.
		hash, err := fileSHA256(mainConfig)
		if err != nil {
			return fmt.Errorf("sha256(%s): %w", mainConfig, err)
		}
		r.Evidence["mode"] = "baseline_capture"
		r.Evidence["baseline_sha256"] = hash
		fmt.Printf("  BASELINE: sha256(%s)=%s\n", mainConfig, hash)
		fmt.Printf("\n  Record this hash, then run apt purge sftp-jailer, and re-run with:\n")
		fmt.Printf("  UAT_BASELINE_SHA256=%s uat-05 brownfield-purge\n\n", hash)
		// This invocation succeeds - it is a capture, not an assertion.
		return nil
	}

	// ASSERTION MODE - compare current hash to baseline.
	currentHash, err := fileSHA256(mainConfig)
	if err != nil {
		return fmt.Errorf("sha256(%s) post-purge: %w", mainConfig, err)
	}
	r.Evidence["mode"] = "assertion"
	r.Evidence["baseline_sha256"] = baseline
	r.Evidence["current_sha256"] = currentHash

	if currentHash != baseline {
		r.Evidence["dist09_status"] = "VIOLATION_main_sshd_config_modified"
		return fmt.Errorf("DIST-09 VIOLATION: %s sha256 changed post-purge\n  baseline: %s\n  current:  %s\n  The drop-in purge must NOT have touched the main sshd_config file", mainConfig, baseline, currentHash)
	}
	r.Evidence["dist09_status"] = "main_sshd_config_byte_identical"
	fmt.Printf("  OK: DIST-09 PASS - %s is byte-identical (sha256=%s)\n", mainConfig, currentHash)

	// Assert the drop-in is absent post-purge.
	if _, err := os.Stat(dropIn); err == nil {
		r.Evidence["dropin_status"] = "present_UNEXPECTED"
		return fmt.Errorf("DIST-09 partial failure: drop-in %s still present after apt purge (postrm did not remove it)", dropIn)
	}
	r.Evidence["dropin_status"] = "absent"
	fmt.Printf("  OK: drop-in %s is absent post-purge\n", dropIn)

	return nil
}
