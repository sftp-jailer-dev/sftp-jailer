// ipv6_preflight.go is the M-FW-IPV6-FIX modal landed by Plan 04-05
// Task 2. It is the FW-06 leak remediation — when M-ADD-RULE / M-DELETE-
// RULE / S-LOCKDOWN preflight detects /etc/default/ufw IPV6=no AND
// HasPublicIPv6=true, it pushes this modal (D-FW-03 step 3).
//
// State machine:
//
//	ipv6PhaseConfirm  → banner + [A]pply / [C]ancel
//	ipv6PhaseApplying → tx.Apply running ([Schedule, WriteIPV6=yes, RestartUfw])
//	ipv6PhaseDone     → success; tea.Tick(500ms) → nav.PopCmd
//	ipv6PhaseError    → surface error; esc to pop
//
// Commit batch (D-S04-09 step 3 + D-FW-03 step 3):
//
//	[NewScheduleRevertStep, NewWriteUfwIPV6Step("yes"), NewSystemctlRestartUfwStep]
//
// The reverse-cmd payload restores IPV6=no + restarts ufw — the box is
// returned to its prior state if admin doesn't Confirm in 3 min. The
// SAFE-04 wrapper means even a wrong rewrite is auto-rolled back.
//
// Threat model (mirror 04-05-PLAN <threat_model>):
//   - T-04-05-05 (tampering, /etc/default/ufw rewrite): the
//     NewWriteUfwIPV6Step Compensate restores the prior bytes captured
//     at Apply time. AtomicWriteFile path-allowlist prevents writes
//     outside /etc/default/ufw. SAFE-04 schedule covers any subsequent
//     observability gap.
//   - T-04-05-06 (info disclosure, leakDetail): accept — the IPv6 is
//     already in `ip -6 addr show` output; reading it requires root.
package firewallrule

import (
	"context"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// ipv6FixApplyTimeout bounds the SAFE-04-wrapped txn batch.
const ipv6FixApplyTimeout = 60 * time.Second

// ipv6FixRevertWindow is the SAFE-04 deadline for the FW-06 fix —
// 3 min, mirroring the M-ADD-RULE window.
const ipv6FixRevertWindow = 3 * time.Minute

// ipv6Phase tracks the M-FW-IPV6-FIX state-machine position.
type ipv6Phase int

const (
	ipv6PhaseConfirm ipv6Phase = iota
	ipv6PhaseApplying
	ipv6PhaseDone
	ipv6PhaseError
)

// IPv6FixModel is M-FW-IPV6-FIX. Constructed when M-ADD-RULE / M-DELETE-RULE
// / S-LOCKDOWN preflight detects IPV6=no + public IPv6 (D-FW-03).
type IPv6FixModel struct {
	ops        sysops.SystemOps
	watcher    *revert.Watcher
	leakDetail string // human-readable line for the banner

	phase    ipv6Phase
	applyErr error
	nowFn    func() time.Time
	keys     ipv6FixKeyMap
}

// ipv6AppliedMsg carries the tx.Apply outcome back to Update.
type ipv6AppliedMsg struct{ err error }

// ipv6AutoPopMsg pops the modal after a successful apply.
type ipv6AutoPopMsg struct{}

// NewIPv6Fix constructs M-FW-IPV6-FIX. ops / watcher MAY be nil in
// unit-test paths.
func NewIPv6Fix(ops sysops.SystemOps, watcher *revert.Watcher, leakDetail string) *IPv6FixModel {
	return &IPv6FixModel{
		ops:        ops,
		watcher:    watcher,
		leakDetail: leakDetail,
		phase:      ipv6PhaseConfirm,
		nowFn:      time.Now,
		keys:       defaultIPv6FixKeyMap(),
	}
}

// ---- nav.Screen interface ---------------------------------------------------

// Title implements nav.Screen.
func (m *IPv6FixModel) Title() string { return "fix ufw IPv6 leak (FW-06)" }

// KeyMap implements nav.Screen.
func (m *IPv6FixModel) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — false, this is a single-action
// confirm modal with no textinput.
func (m *IPv6FixModel) WantsRawKeys() bool { return false }

// Init implements nav.Screen.
func (m *IPv6FixModel) Init() tea.Cmd { return nil }

// Update implements nav.Screen.
func (m *IPv6FixModel) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch v := msg.(type) {
	case tea.KeyPressMsg:
		switch v.String() {
		case "a", "A":
			if m.phase == ipv6PhaseConfirm {
				m.phase = ipv6PhaseApplying
				return m, m.applyCmd()
			}
		case "c", "C", "esc":
			// Cancel from confirm → return to caller. Esc from done /
			// error also pops.
			return m, nav.PopCmd()
		}
	case ipv6AppliedMsg:
		if v.err != nil {
			m.phase = ipv6PhaseError
			m.applyErr = v.err
			return m, nil
		}
		m.phase = ipv6PhaseDone
		return m, tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return ipv6AutoPopMsg{} })
	case ipv6AutoPopMsg:
		return m, nav.PopCmd()
	}
	return m, nil
}

// applyCmd runs the SAFE-04-wrapped batch:
//
//	[NewScheduleRevertStep(reverseCmds, now+3min), NewWriteUfwIPV6Step("yes"), NewSystemctlRestartUfwStep]
//
// reverseCmds restores IPV6=no + restarts ufw. Both halves of the pair
// are idempotent on a re-run.
func (m *IPv6FixModel) applyCmd() tea.Cmd {
	if m.ops == nil {
		// Test path — surface a benign error.
		return func() tea.Msg {
			return ipv6AppliedMsg{err: fmt.Errorf("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	watcher := m.watcher
	nowFn := m.nowFn

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), ipv6FixApplyTimeout)
		defer cancel()

		reverseCmds := []string{
			"sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw",
			"systemctl restart ufw",
			"ufw reload",
		}

		steps := []txn.Step{
			txn.NewScheduleRevertStep(
				reverseCmds, nowFn().Add(ipv6FixRevertWindow), watcher, nowFn),
			txn.NewWriteUfwIPV6Step("yes", nowFn),
			txn.NewSystemctlRestartUfwStep(),
		}
		tx := txn.New(ops)
		err := tx.Apply(ctx, steps)
		return ipv6AppliedMsg{err: err}
	}
}

// View renders per phase.
func (m *IPv6FixModel) View() string {
	switch m.phase {
	case ipv6PhaseConfirm:
		body := styles.Critical.Render("⚠ FW-06 IPv6 LEAK") + "\n\n"
		body += m.leakDetail + "\n\n"
		body += "[A]pply fix — rewrites /etc/default/ufw IPV6=yes + restarts ufw\n"
		body += "             (3-min auto-revert armed under SAFE-04)\n"
		body += "[C]ancel — return to caller; FW mutation blocked until fixed"
		return wrapModal(body)
	case ipv6PhaseApplying:
		return wrapModal("Applying IPv6 fix…")
	case ipv6PhaseDone:
		return wrapModal(styles.Success.Render(
			"✓ ufw IPV6=yes applied — restart succeeded; 3-min revert armed"))
	case ipv6PhaseError:
		return wrapModal(
			styles.Critical.Render(fmt.Sprintf("Failed to apply fix: %v", m.applyErr)) +
				"\n\n[esc] back")
	}
	return ""
}

// ---- KeyMap ----------------------------------------------------------------

type ipv6FixKeyMap struct {
	Apply  nav.KeyBinding
	Cancel nav.KeyBinding
}

func defaultIPv6FixKeyMap() ipv6FixKeyMap {
	return ipv6FixKeyMap{
		Apply:  nav.KeyBinding{Keys: []string{"a", "A"}, Help: "apply fix"},
		Cancel: nav.KeyBinding{Keys: []string{"c", "C", "esc"}, Help: "cancel"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k ipv6FixKeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Apply}
}

// FullHelp implements nav.KeyMap.
func (k ipv6FixKeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Apply},
	}
}

// ---- Test seams ------------------------------------------------------------

// IPv6PhaseConfirmForTest etc. expose the unexported phase ints to tests.
const (
	IPv6PhaseConfirmForTest  = int(ipv6PhaseConfirm)
	IPv6PhaseApplyingForTest = int(ipv6PhaseApplying)
	IPv6PhaseDoneForTest     = int(ipv6PhaseDone)
	IPv6PhaseErrorForTest    = int(ipv6PhaseError)
)

// PhaseForTest exposes the current phase as int.
func (m *IPv6FixModel) PhaseForTest() int { return int(m.phase) }

// FeedAppliedMsgForTest delivers a synthesized ipv6AppliedMsg to Update.
func (m *IPv6FixModel) FeedAppliedMsgForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(ipv6AppliedMsg{err: err})
}

// SetNowFnForTest pins the time-source for deterministic deadlines.
func (m *IPv6FixModel) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }

// LeakDetailForTest exposes the banner text.
func (m *IPv6FixModel) LeakDetailForTest() string { return m.leakDetail }
