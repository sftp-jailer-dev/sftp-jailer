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

// phase2FW06HardBlock implements phase 2 — see Task 2.
func phase2FW06HardBlock(ctx context.Context, ops sysops.SystemOps, _ *revert.Watcher) error {
	return fmt.Errorf("not yet implemented (Task 2)")
}

// phase3LockCommit implements phase 3 — see Task 3.
func phase3LockCommit(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error {
	return fmt.Errorf("not yet implemented (Task 3)")
}

// phase4LockRollback implements phase 4 — see Task 4.
func phase4LockRollback(ctx context.Context, ops sysops.SystemOps, watcher *revert.Watcher) error {
	return fmt.Errorf("not yet implemented (Task 4)")
}
