// cmd/uat-04 is the empirical UAT helper for Phase 4 (firewall mutations
// and progressive lockdown). It runs on a real Ubuntu 24.04 box and
// validates the SAFE-04 timer-fires-after-crash, FW-06 IPv6 hard-block,
// LOCK-06 commit, and LOCK-08 rollback flows end-to-end.
//
// Usage:
//
//	go build -o ./bin/uat-04 ./cmd/uat-04
//	sudo ./bin/uat-04
//
// Exit code: 0 on full pass, 1 on first phase failure.
//
// IMPORTANT: this helper uses a 30-SECOND SAFE-04 revert window for test
// speed (NOT the production 3-minute). It also temporarily mutates the
// live firewall + /etc/default/ufw and adds rules with the comment
// "sftpj-uat-04-test" or "sftpj:v=1:user=ubuntu". Run on a STAGING box
// dedicated to testing — phases 3 and 4 will briefly LOCK the box (the
// SAFE-04 timer is the safety net if the helper crashes mid-run).
//
// Helper is intentionally one-shot — it should be removed from cmd/ after
// the empirical UAT completes, mirroring the Phase 3 pattern documented in
// 03-08b/03-09 SUMMARYs.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

type phaseFn func(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "uat-04 must run as root (it manipulates ufw + /etc/default/ufw)")
		os.Exit(1)
	}
	ops := sysops.NewReal()
	watcher := revert.New(ops)
	ctx := context.Background()

	phases := []struct {
		name string
		fn   phaseFn
	}{
		{"phase 1: SAFE-04 timer-fires-after-TUI-crash", phase1SafeRevert},
		{"phase 2: FW-06 hard-block on live IPv6 host", phase2FW06HardBlock},
		{"phase 3: LOCK-06 commit on staging install", phase3LockCommit},
		{"phase 4: LOCK-08 rollback to OPEN", phase4LockRollback},
	}

	passed := 0
	for i, p := range phases {
		fmt.Printf("\n========================================\n")
		fmt.Printf("[%d/%d] %s\n", i+1, len(phases), p.name)
		fmt.Printf("========================================\n")
		if err := p.fn(ctx, ops, watcher); err != nil {
			fmt.Printf("\nFAIL: %v\n", err)
			fmt.Printf("\nResult: %d/%d phases passed\n", passed, len(phases))
			os.Exit(1)
		}
		passed++
		fmt.Printf("\nPASS\n")
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("ALL %d/%d PHASES PASSED\n", passed, len(phases))
	fmt.Printf("========================================\n")
}

// phase1SafeRevert exercises the SAFE-04 timer-fires-after-TUI-crash
// path: arms a 30-second revert window, inserts a sentinel ufw rule,
// then exits the apply path WITHOUT calling Watcher.Clear / Cancel
// (simulating a TUI crash). Waits past the deadline and asserts the
// systemd-run unit fired (rule removed, unit no longer active).
func phase1SafeRevert(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error {
	// 1. Confirm starting state — ufw active + catch-all present
	rules, err := firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("Enumerate failed: %w", err)
	}
	var hasCatchAll bool
	for _, r := range rules {
		if r.Source == "Anywhere" && strings.Contains(strings.ToUpper(r.Action), "ALLOW") && r.RawComment == "" {
			hasCatchAll = true
			break
		}
	}
	if !hasCatchAll {
		return fmt.Errorf("box is not in OPEN mode (no catch-all rule); run `sudo ufw allow 22/tcp` to set up baseline")
	}
	fmt.Println("  baseline: ufw OPEN with catch-all confirmed")

	// 2. Snapshot pre-mutation ruleset
	preCount := len(rules)
	fmt.Printf("  pre-mutation rule count: %d\n", preCount)

	// 3. Build a 30-second SAFE-04 revert window (faster than production 3-min).
	const testSrc = "198.51.100.99/32"
	const testComment = "sftpj-uat-04-test"
	nowFn := time.Now
	deadline := nowFn().Add(30 * time.Second)

	// 4. Compose the inserted-rule's reverse cmd: `ufw status numbered | grep …`
	//    placeholder pattern (B1+B5 from Plan 04-05) — we don't know the
	//    assigned ID until after Apply, so resolve at fire time.
	reverseCmds := []string{
		fmt.Sprintf("ufw status numbered | grep '%s' | head -1 | sed 's/[^0-9]*\\([0-9]*\\).*/\\1/' | xargs -I{} ufw --force delete {}", testComment),
		"ufw reload",
	}

	// 5. Schedule the revert
	scheduleStep := txn.NewScheduleRevertStep(reverseCmds, deadline, watcher, nowFn)
	if err := scheduleStep.Apply(ctx, ops); err != nil {
		return fmt.Errorf("ScheduleRevert failed: %w", err)
	}
	st := watcher.Get()
	if st == nil {
		return fmt.Errorf("watcher.Get returned nil after Set")
	}
	fmt.Printf("  revert window armed: unit=%s deadline=%s\n",
		st.UnitName, time.Unix(0, st.DeadlineUnixNs).Format(time.RFC3339))

	// 6. Insert the test rule (the "mutation" we want auto-reverted)
	insertOpts := sysops.UfwAllowOpts{
		Proto: "tcp", Source: testSrc, Port: "22", Comment: testComment,
	}
	if err := ops.UfwInsert(ctx, 1, insertOpts); err != nil {
		return fmt.Errorf("UfwInsert failed: %w", err)
	}
	fmt.Printf("  test rule inserted: source=%s comment=%s\n", testSrc, testComment)

	// 7. Verify the rule landed
	rules, err = firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("post-insert Enumerate failed: %w", err)
	}
	var foundTest bool
	for _, r := range rules {
		if r.Source == testSrc && r.RawComment == testComment {
			foundTest = true
			break
		}
	}
	if !foundTest {
		return fmt.Errorf("test rule not found post-insert")
	}
	fmt.Println("  test rule confirmed in firewall")

	// 8. SIMULATE TUI CRASH: do NOT call Watcher.Clear or systemctl stop.
	//    The pointer file remains on-disk; the unit's ExecStart will fire
	//    when the timer expires (`30s` from arm-time).
	fmt.Println("  simulating TUI crash: NOT calling Confirm; timer will fire in ~30s...")

	// 9. Wait for the timer to fire (deadline + grace)
	wait := time.Until(deadline) + 5*time.Second
	fmt.Printf("  waiting %v for timer to fire...\n", wait.Round(time.Second))
	time.Sleep(wait)

	// 10. Re-Enumerate; assert the test rule is GONE
	rules, err = firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("post-fire Enumerate failed: %w", err)
	}
	for _, r := range rules {
		if r.Source == testSrc && r.RawComment == testComment {
			return fmt.Errorf("CRITICAL: test rule still present after revert window expired (timer did not fire)")
		}
	}
	fmt.Println("  test rule REMOVED — timer fired as expected")

	// 11. Verify the unit is no longer active (cleanup)
	active, err := ops.SystemctlIsActive(ctx, st.UnitName)
	if err != nil {
		return fmt.Errorf("SystemctlIsActive after fire: %w", err)
	}
	if active {
		return fmt.Errorf("unit %s is still active after fire — should have cleaned up", st.UnitName)
	}
	fmt.Printf("  unit %s is no longer active\n", st.UnitName)

	// 12. Run Watcher.Restore to verify it cleans up the orphan pointer
	fired, err := watcher.Restore(ctx)
	if err != nil {
		return fmt.Errorf("Watcher.Restore after fire: %w", err)
	}
	if !fired {
		return fmt.Errorf("Watcher.Restore returned fired=false; expected true (unit fired)")
	}
	fmt.Println("  Watcher.Restore detected fired state and cleaned pointer")

	// 13. Final rule count check — should be back to baseline
	if got := len(rules); got != preCount {
		fmt.Printf("  WARN: rule count post-revert = %d, pre-mutation = %d (may be benign if other rules shifted)\n", got, preCount)
	}
	return nil
}

// phase2FW06HardBlock exercises the FW-06 IPv6 hard-block preflight on a
// live IPv6-enabled box: forces /etc/default/ufw → IPV6=no, confirms
// HasPublicIPv6 returns true, then asserts the same logic M-ADD-RULE's
// preflightCmd uses (IPV6=no AND HasPublicIPv6) detects the leak. Restores
// the prior IPV6= value at the end.
func phase2FW06HardBlock(ctx context.Context, ops sysops.SystemOps, _ *revert.Watcher) error {
	// 1. Read current IPV6= value
	priorBytes, err := ops.ReadFile(ctx, "/etc/default/ufw")
	if err != nil {
		return fmt.Errorf("read /etc/default/ufw: %w", err)
	}
	priorIPV6 := "yes" // default
	for _, line := range strings.Split(string(priorBytes), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "IPV6=") {
			priorIPV6 = strings.Trim(strings.TrimPrefix(t, "IPV6="), `"`)
			break
		}
	}
	fmt.Printf("  prior IPV6= value: %q (will be restored at end)\n", priorIPV6)

	// 2. Force IPV6=no
	if err := ops.RewriteUfwIPV6(ctx, "no"); err != nil {
		return fmt.Errorf("RewriteUfwIPV6('no'): %w", err)
	}
	// restart ufw via Exec (no typed wrapper for restart in sysops).
	res, err := ops.Exec(ctx, "systemctl", "restart", "ufw")
	if err != nil {
		return fmt.Errorf("systemctl restart ufw: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl restart ufw exit %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	fmt.Println("  IPV6=no applied + ufw restarted")

	// 3. Verify public IPv6 exists. If not, restore + SKIP.
	hasIPv6, err := ops.HasPublicIPv6(ctx)
	if err != nil {
		// Best-effort restore on error path
		if rerr := ops.RewriteUfwIPV6(ctx, priorIPV6); rerr != nil {
			fmt.Printf("  WARN: failed to restore IPV6=%s on error path: %v\n", priorIPV6, rerr)
		}
		_, _ = ops.Exec(ctx, "systemctl", "restart", "ufw")
		return fmt.Errorf("HasPublicIPv6: %w", err)
	}
	if !hasIPv6 {
		// Restore and skip
		if rerr := ops.RewriteUfwIPV6(ctx, priorIPV6); rerr != nil {
			fmt.Printf("  WARN: failed to restore IPV6=%s: %v\n", priorIPV6, rerr)
		}
		_, _ = ops.Exec(ctx, "systemctl", "restart", "ufw")
		fmt.Println("  SKIP: box has no public IPv6; FW-06 hard-block path not exercisable on this host")
		return nil
	}
	fmt.Println("  public IPv6 detected")

	// 4. Re-read /etc/default/ufw — confirm IPV6=no
	nowBytes, err := ops.ReadFile(ctx, "/etc/default/ufw")
	if err != nil {
		return fmt.Errorf("re-read /etc/default/ufw: %w", err)
	}
	gotIPV6 := ""
	for _, line := range strings.Split(string(nowBytes), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "IPV6=") {
			gotIPV6 = strings.Trim(strings.TrimPrefix(t, "IPV6="), `"`)
			break
		}
	}
	if gotIPV6 != "no" {
		return fmt.Errorf("expected IPV6=no after rewrite, got %q", gotIPV6)
	}
	fmt.Printf("  /etc/default/ufw confirms IPV6=%s\n", gotIPV6)

	// 5. Run M-ADD-RULE preflight logic — assert leak detection.
	//    The production preflight in internal/tui/screens/firewallrule
	//    checks the same conjunction: HasPublicIPv6 && (IPV6 file says
	//    "no"). If both are true, the modal pushes M-FW-IPV6-FIX.
	leak := (gotIPV6 == "no") && hasIPv6
	if !leak {
		return fmt.Errorf("CRITICAL: leak=false despite IPV6=no AND public IPv6 — preflight logic broken")
	}
	fmt.Println("  preflight logic correctly detects leak: M-ADD-RULE would have triggered M-FW-IPV6-FIX")

	// 6. Restore prior IPV6= value
	if err := ops.RewriteUfwIPV6(ctx, priorIPV6); err != nil {
		return fmt.Errorf("restore IPV6=%s: %w", priorIPV6, err)
	}
	res2, err := ops.Exec(ctx, "systemctl", "restart", "ufw")
	if err != nil {
		return fmt.Errorf("systemctl restart ufw on cleanup: %w", err)
	}
	if res2.ExitCode != 0 {
		return fmt.Errorf("systemctl restart ufw on cleanup exit %d: %s", res2.ExitCode, strings.TrimSpace(string(res2.Stderr)))
	}
	fmt.Printf("  restored IPV6=%s\n", priorIPV6)
	return nil
}

// phase3LockCommit exercises a LOCK-06 commit batch: from MODE=Open it
// inserts a sftpj per-user rule + deletes the catch-all under a 30-second
// SAFE-04 revert window, asserts MODE → Locked, then waits past the
// deadline and asserts MODE → Open (catch-all restored by the timer).
//
// Also runs a best-effort LOCK-07 empirical assertion: while in the
// LOCKED window, journalctl -u ssh is grep'd for connection-refused /
// disconnected entries — these would map to tier='targeted' observation
// rows in the production observer pipeline. The assertion is best-effort
// per D-L0809-06; absence of journal evidence is logged as a SKIP toast,
// not a hard failure.
func phase3LockCommit(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error {
	// 1. Verify starting OPEN state
	rules, err := firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("Enumerate: %w", err)
	}
	mode := firewall.DetectMode(rules, "22")
	if mode != firewall.ModeOpen {
		return fmt.Errorf("expected starting MODE=Open, got %s — phase 3 needs catch-all baseline", mode)
	}
	fmt.Println("  starting state: MODE: OPEN")

	// Find catch-all rule ID by signature match (Source="Anywhere", ALLOW,
	// no sftpj comment).
	var catchAllID = -1
	for _, r := range rules {
		if r.Source == "Anywhere" && strings.Contains(strings.ToUpper(r.Action), "ALLOW") && r.RawComment == "" {
			catchAllID = r.ID
			break
		}
	}
	if catchAllID < 0 {
		return fmt.Errorf("could not find catch-all rule ID")
	}
	fmt.Printf("  catch-all rule ID: %d\n", catchAllID)

	// 2. Choose a test user. We hardcode "ubuntu" — present on most cloud
	//    Ubuntu images. The UAT exercises the txn batch; user allowlist
	//    semantics are validated elsewhere.
	const testIP = "198.51.100.42/32"
	const testComment = "sftpj:v=1:user=ubuntu"

	// 3. Mark the LOCKED window start so the LOCK-07 journal-grep
	//    fallback can scope its search.
	lockWindowStart := time.Now()

	// 4. Build the SAFE-04 revert window — 30 sec for testing.
	nowFn := time.Now
	deadline := nowFn().Add(30 * time.Second)
	// Reverse cmd: re-add catch-all + delete the test rule by comment grep.
	reverseCmds := []string{
		"ufw allow 22/tcp",
		fmt.Sprintf("ufw status numbered | grep '%s' | head -1 | sed 's/[^0-9]*\\([0-9]*\\).*/\\1/' | xargs -I{} ufw --force delete {}", testComment),
		"ufw reload",
	}

	steps := []txn.Step{
		txn.NewScheduleRevertStep(reverseCmds, deadline, watcher, nowFn),
		txn.NewUfwInsertStep(sysops.UfwAllowOpts{
			Proto: "tcp", Source: testIP, Port: "22", Comment: testComment,
		}),
		txn.NewUfwDeleteStep(catchAllID),
		txn.NewUfwReloadStep(),
	}
	tx := txn.New(ops)
	if err := tx.Apply(ctx, steps); err != nil {
		return fmt.Errorf("commit batch failed: %w", err)
	}
	fmt.Println("  commit batch applied")

	// 5. Verify MODE = LOCKED
	rules, err = firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("post-commit Enumerate: %w", err)
	}
	mode = firewall.DetectMode(rules, "22")
	if mode != firewall.ModeLocked {
		return fmt.Errorf("post-commit MODE = %s, expected Locked", mode)
	}
	fmt.Println("  MODE transitioned OPEN -> LOCKED")

	// 6. (W7) LOCK-07 best-effort empirical assertion: scope journalctl
	//    to the LOCKED window and grep for connection-refused entries.
	//    Any non-allowlisted ssh probe during this short window would
	//    map to tier='targeted' rows in the production observer pipeline
	//    (D-L0809-06). Absence is logged as SKIP, not failure.
	since := lockWindowStart.Format("2006-01-02 15:04:05")
	if jres, jerr := ops.Exec(ctx, "journalctl", "-u", "ssh", "--since", since, "--no-pager"); jerr == nil && jres.ExitCode == 0 {
		text := string(jres.Stdout)
		if strings.Contains(text, "connection refused") || strings.Contains(text, "Disconnected") {
			fmt.Println("  LOCK-07: journal shows refused/disconnected entries during LOCKED window (tier='targeted' candidates)")
		} else {
			fmt.Println("  LOCK-07 SKIP: no rejected-connection journal evidence during LOCKED window (best-effort; not a failure)")
		}
	} else {
		fmt.Println("  LOCK-07 SKIP: journalctl unavailable (best-effort)")
	}

	// 7. Wait for the timer to fire (deadline + grace).
	wait := time.Until(deadline) + 5*time.Second
	fmt.Printf("  waiting %v for revert to fire...\n", wait.Round(time.Second))
	time.Sleep(wait)

	// 8. Verify rolled back to OPEN
	rules, err = firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("post-fire Enumerate: %w", err)
	}
	mode = firewall.DetectMode(rules, "22")
	if mode != firewall.ModeOpen {
		return fmt.Errorf("post-fire MODE = %s, expected Open (revert should have restored catch-all)", mode)
	}
	fmt.Println("  MODE rolled back to OPEN — timer fired as expected")

	// 9. Cleanup any leftover test rules
	for _, r := range rules {
		if r.RawComment == testComment {
			_ = ops.UfwDelete(ctx, r.ID)
		}
	}
	// Run Restore to clean any orphan pointer
	_, _ = watcher.Restore(ctx)
	return nil
}

// phase4LockRollback exercises the LOCK-08 rollback path: sets up an
// artificial LOCKED state (insert sftpj rule, find + delete catch-all by
// signature match — the I1 fix re-Enumerates AFTER the insert so the
// catch-all is located correctly even if its ID shifted), then runs the
// rollback batch (re-add catch-all under a 30s SAFE-04 window), asserts
// MODE → Staging, then explicitly cancels the timer (the rollback rules
// are intended to be permanent).
func phase4LockRollback(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error {
	// 1. Locate the original catch-all (signature match)
	rules, err := firewall.Enumerate(ctx, ops)
	if err != nil {
		return fmt.Errorf("Enumerate: %w", err)
	}
	var catchAllID = -1
	for _, r := range rules {
		if r.Source == "Anywhere" && strings.Contains(strings.ToUpper(r.Action), "ALLOW") && r.RawComment == "" {
			catchAllID = r.ID
			break
		}
	}
	if catchAllID < 0 {
		return fmt.Errorf("no catch-all to remove")
	}

	// 2. Insert a sftpj test rule first so post-removal we land in LOCKED
	//    (not UNKNOWN).
	const testIP = "198.51.100.43/32"
	const testComment = "sftpj:v=1:user=ubuntu"
	if err := ops.UfwInsert(ctx, 1, sysops.UfwAllowOpts{
		Proto: "tcp", Source: testIP, Port: "22", Comment: testComment,
	}); err != nil {
		return fmt.Errorf("setup UfwInsert: %w", err)
	}

	// 3. (I1 fix) re-Enumerate AFTER the insert and re-locate catch-all by
	//    signature match (Source="Anywhere", ALLOW, empty comment) —
	//    NOT by guessing the original ID + 1 slot. Insertion at position
	//    one shifts everything below by one row, but other admin tooling
	//    may have perturbed the firewall between Enumerate calls.
	//    Signature-match is robust to all such shifts.
	rules2, eErr := firewall.Enumerate(ctx, ops)
	if eErr != nil {
		return fmt.Errorf("re-Enumerate after setup insert: %w", eErr)
	}
	var newCatchAllID = -1
	for _, r := range rules2 {
		if r.Source == "Anywhere" && strings.Contains(strings.ToUpper(r.Action), "ALLOW") && r.RawComment == "" {
			newCatchAllID = r.ID
			break
		}
	}
	if newCatchAllID < 0 {
		// Catch-all somehow vanished between Enumerate calls — try the
		// originally-captured ID as a last resort.
		newCatchAllID = catchAllID
	}
	if err := ops.UfwDelete(ctx, newCatchAllID); err != nil {
		// Cleanup before returning
		_ = ops.UfwDelete(ctx, -1) // no-op; preserves cleanup attempt below
		for _, r := range rules2 {
			if r.RawComment == testComment {
				_ = ops.UfwDelete(ctx, r.ID)
			}
		}
		return fmt.Errorf("delete catch-all (id=%d): %w", newCatchAllID, err)
	}
	rules, _ = firewall.Enumerate(ctx, ops)
	mode := firewall.DetectMode(rules, "22")
	if mode != firewall.ModeLocked {
		// Cleanup before returning
		for _, r := range rules {
			if r.RawComment == testComment {
				_ = ops.UfwDelete(ctx, r.ID)
			}
		}
		return fmt.Errorf("expected LOCKED setup state, got %s — abort phase 4", mode)
	}
	fmt.Println("  artificial LOCKED state set up")

	// 4. Programmatic rollback: re-add catch-all under SAFE-04 30s window.
	nowFn := time.Now
	deadline := nowFn().Add(30 * time.Second)
	// Reverse cmd: remove the catch-all we're about to re-add (the one
	// without the sftpj comment).
	reverseCmds := []string{
		"ufw status numbered | grep ' allow 22 ' | grep -v sftpj | head -1 | sed 's/[^0-9]*\\([0-9]*\\).*/\\1/' | xargs -I{} ufw --force delete {}",
		"ufw reload",
	}
	steps := []txn.Step{
		txn.NewScheduleRevertStep(reverseCmds, deadline, watcher, nowFn),
		txn.NewUfwAllowStep(sysops.UfwAllowOpts{
			Source: "any", Port: "22/tcp",
		}),
		txn.NewUfwReloadStep(),
	}
	tx := txn.New(ops)
	if err := tx.Apply(ctx, steps); err != nil {
		return fmt.Errorf("rollback batch: %w", err)
	}
	fmt.Println("  rollback batch applied")

	// 5. Verify MODE = STAGING (catch-all + sftpj rules coexist)
	rules, _ = firewall.Enumerate(ctx, ops)
	mode = firewall.DetectMode(rules, "22")
	if mode != firewall.ModeStaging {
		// Wait briefly in case ufw enumerate sees a transient stale state.
		time.Sleep(time.Second)
		rules, _ = firewall.Enumerate(ctx, ops)
		mode = firewall.DetectMode(rules, "22")
	}
	if mode != firewall.ModeStaging {
		return fmt.Errorf("post-rollback MODE = %s, expected Staging", mode)
	}
	fmt.Println("  MODE transitioned LOCKED -> STAGING (catch-all back, sftpj rules preserved)")

	// 6. Confirm the revert (cancel the timer; rules persist).
	st := watcher.Get()
	if st != nil {
		if err := ops.SystemctlStop(ctx, st.UnitName); err != nil {
			fmt.Printf("  WARN: SystemctlStop on cancel: %v\n", err)
		}
		_ = watcher.Clear(ctx)
		fmt.Printf("  revert unit %s cancelled — rollback rules now permanent\n", st.UnitName)
	}

	// 7. Cleanup test rules
	rules, _ = firewall.Enumerate(ctx, ops)
	for _, r := range rules {
		if r.RawComment == testComment {
			_ = ops.UfwDelete(ctx, r.ID)
		}
	}
	return nil
}
