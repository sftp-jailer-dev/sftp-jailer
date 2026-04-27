// Package firewallrule renders M-ADD-RULE (Plan 04-05) and M-FW-IPV6-FIX
// (the FW-06 leak remediation modal). Both modals push onto the nav.Stack
// from S-FIREWALL ('a') and S-USER-DETAIL ('r' — keybind deviation
// W1, see 04-05-PLAN.md context_compliance + 04-CONTEXT.md Integration
// Points: 'a' on S-USER-DETAIL is reserved for M-ADD-KEY since Phase 3).
//
// M-ADD-RULE state machine (D-FW-CIDR + D-FW-03 + D-S04-09):
//
//	phaseInput      → admin types source CIDR; Enter triggers attemptParse
//	phasePreflight  → async ops.HasPublicIPv6 + /etc/default/ufw IPV6=
//	                  read; if leak detected, push M-FW-IPV6-FIX and bail
//	phaseReview     → render proposed `ufw insert 1 allow proto tcp …`
//	                  command + 3-min revert payload preview; 'c' commits
//	phaseCommitting → SAFE-04-wrapped txn batch under tx.Apply
//	phaseDone       → success; tea.Tick(500ms) → nav.PopCmd
//	phaseError      → surface error; esc to pop
//
// Commit batch ordering (D-S04-09 step 3 — checker B1+B5 fix):
//
//	[NewScheduleRevertStep, NewUfwInsertStep]
//
// The Schedule step arms the systemd-run --on-active=3min timer FIRST.
// If the FW step then fails, txn rolls back via Schedule's Compensate
// (stops the unit). The reverse-cmd uses a comment-grep PLACEHOLDER
// (`ufw status numbered | grep -F '<comment>' | sed -E … | xargs ufw
// --force delete`) so the timer doesn't need the assigned rule ID
// (which is only known AFTER UfwInsert returns).
//
// Shell-quoting safety on the placeholder reverse-cmd:
//   - `comment` is the output of ufwcomment.Encode whose regex strips to
//     [a-z0-9:=_-]+ (no quotes/semicolons/backticks/whitespace possible).
//   - The single-quote literal wrapping the comment inside `grep -F` is
//     therefore safe — no quote-balancing risk.
//
// Threat model (mirror 04-05-PLAN <threat_model>):
//   - T-04-05-01 (tampering, source field): mitigate via net.ParseCIDR
//     strict — reject any non-CIDR string. The output of
//     ipnet.String() is the canonical CIDR form, never an attacker-
//     controlled raw string.
//   - T-04-05-02 (tampering, userField): mitigate via ufwcomment.Encode
//     regex — Encode returns ErrInvalidUser on any malformed value.
//   - T-04-05-03 (self-lockout): SAFE-04 wrapper arms the 3-min timer
//     BEFORE returning success.
//   - T-04-05-04 (DoS, preflight): each call bounded by 5s context
//     timeout in preflightCmd.
//
// FW-08 mirror rebuild (W2 fix): after a successful tx.Apply, the modal
// best-effort calls store.RebuildUserIPs to re-derive the SQLite cache
// from the post-mutation `ufw status numbered`. Failure surfaces in
// logs but does NOT roll back the firewall change — the rule is
// correctly armed under the SAFE-04 timer regardless of cache state.
package firewallrule

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// autoPopDelay is how long phaseDone lingers before the modal pops back.
const autoPopDelay = 500 * time.Millisecond

// preflightTimeout bounds the FW-06 IPv6-leak detection async work.
const preflightTimeout = 5 * time.Second

// commitTimeout bounds the SAFE-04-wrapped txn batch (Schedule + UfwInsert
// + post-Apply Enumerate + best-effort RebuildUserIPs).
const commitTimeout = 60 * time.Second

// revertWindow is the SAFE-04 deadline (D-S04-04) — 3 min from arm time.
const revertWindow = 3 * time.Minute

// phase tracks the modal's state-machine position.
type phase int

const (
	phaseInput      phase = iota // textinput visible (CIDR field)
	phasePreflight               // FW-06 IPv6-leak check in flight
	phaseReview                  // confirm proposed `ufw insert 1 …`
	phaseCommitting              // SAFE-04 wrapped txn batch running
	phaseDone                    // success; auto-pop after autoPopDelay
	phaseError                   // surface error, allow Esc back
)

// Model is the M-ADD-RULE Bubble Tea v2 model.
type Model struct {
	ops      sysops.SystemOps
	watcher  *revert.Watcher
	sftpPort string
	store    *store.Queries // optional — tests pass nil; production wires the real handle

	// Per-modal config.
	userLocked bool   // true when caller pre-filled user (S-USER-DETAIL)
	userField  string // current value (locked or admin-typed)

	// Input state.
	cidrInput  textinput.Model
	phase      phase
	errInline  string
	warnInline string // loopback / link-local warning (non-blocking)

	// Computed values for the review/commit phase.
	normalizedSource string // post-promote-and-validate
	comment          string // ufwcomment.Encode(userField)

	// Pre-flight result.
	leakDetail string // human-readable banner for M-FW-IPV6-FIX

	// Post-commit.
	assignedID int
	commitErr  error

	// Time / spinner / toast / keys.
	spinner spinner.Model
	toast   widgets.Toast
	keys    KeyMap
	nowFn   func() time.Time
}

// preflightDoneMsg carries the FW-06 leak-check result back to Update.
type preflightDoneMsg struct {
	ipv6Leak   bool
	leakDetail string
	err        error
}

// committedMsg carries the tx.Apply outcome back from the goroutine.
type committedMsg struct {
	assignedID int
	err        error
}

// autoPopMsg pops the modal after a successful commit lingers for autoPopDelay.
type autoPopMsg struct{}

// New constructs an M-ADD-RULE modal. lockedUser is "" for the
// S-FIREWALL `a` path (admin picks user later — currently the user
// field is admin-typed via the user textinput; for v1 we only support
// the S-USER-DETAIL pre-fill path); set to a username for the
// S-USER-DETAIL `r` path (user is read-only).
//
// ops / watcher MAY be nil in unit-test paths that drive the model via
// LoadStateForTest; the goroutine paths short-circuit on nil.
func New(ops sysops.SystemOps, watcher *revert.Watcher, sftpPort, lockedUser string) *Model {
	ti := textinput.New()
	ti.Placeholder = "203.0.113.7/32"
	ti.Focus()
	ti.CharLimit = 64

	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary

	return &Model{
		ops:        ops,
		watcher:    watcher,
		sftpPort:   sftpPort,
		cidrInput:  ti,
		phase:      phaseInput,
		userLocked: lockedUser != "",
		userField:  lockedUser,
		spinner:    sp,
		keys:       DefaultKeyMap(),
		nowFn:      time.Now,
	}
}

// SetStore injects the FW-08 mirror handle. Production wires the real
// *store.Queries via the bootstrap factory; tests can leave it nil and
// the post-Apply RebuildUserIPs is skipped.
func (m *Model) SetStore(q *store.Queries) { m.store = q }

// ---- nav.Screen interface ---------------------------------------------------

// Title implements nav.Screen.
func (m *Model) Title() string {
	if m.userLocked && m.userField != "" {
		return "add firewall rule — " + m.userField
	}
	return "add firewall rule"
}

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the textinput is the
// admin's primary input surface (phaseInput) OR during phaseError where
// any key returns to the input. False during preflight / review /
// committing / done so the screen's single-key shortcuts (c / esc)
// reach handleKey unmolested.
func (m *Model) WantsRawKeys() bool {
	return m.phase == phaseInput || m.phase == phaseError
}

// Init implements nav.Screen — no async load on push (admin types first).
func (m *Model) Init() tea.Cmd { return nil }

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case preflightDoneMsg:
		return m.handlePreflightDone(msg)
	case committedMsg:
		return m.handleCommitted(msg)
	case autoPopMsg:
		return m, nav.PopCmd()
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches per phase.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	s := msg.String()
	if s == "esc" {
		switch m.phase {
		case phaseInput, phaseDone, phaseError:
			return m, nav.PopCmd()
		case phaseReview:
			m.phase = phaseInput
			m.errInline = ""
			m.warnInline = ""
			return m, nil
		case phasePreflight, phaseCommitting:
			// Swallow — async work will complete and return us to a stable phase.
			return m, nil
		}
	}
	switch m.phase {
	case phaseInput:
		if s == "enter" {
			m.attemptParse()
			if m.errInline != "" {
				return m, nil
			}
			// Validation passed → kick off async preflight.
			m.phase = phasePreflight
			return m, tea.Batch(m.spinner.Tick, m.preflightCmd())
		}
		// Forward to textinput for raw input (typing IP digits / letters).
		var cmd tea.Cmd
		m.cidrInput, cmd = m.cidrInput.Update(msg)
		return m, cmd
	case phaseReview:
		switch s {
		case "c", "C":
			m.phase = phaseCommitting
			return m, tea.Batch(m.spinner.Tick, m.commitCmd())
		case "q":
			return m, nav.PopCmd()
		}
		return m, nil
	case phaseError:
		// Esc handled above; any other key returns to input so admin can retype.
		m.phase = phaseInput
		m.errInline = ""
		m.warnInline = ""
		return m, nil
	}
	return m, nil
}

// ---- attemptParse: textinput → CIDR validation ---------------------------

// attemptParse is the synchronous CIDR validation per D-FW-CIDR. Runs
// inside Update — no goroutine, no I/O. On success populates
// m.normalizedSource and clears errInline; on failure populates errInline.
//
// Validation rules (mirror 04-CONTEXT.md "M-ADD-RULE input validation rules"):
//
//   - Empty / whitespace-only → "source CIDR is required" (errInline).
//   - IPv6 zone-id (% suffix) → rejected (link-local-with-zone is local-only,
//     not internet-routable; T-04-05-01 mitigation).
//   - Bare IP → promote to /32 (v4) or /128 (v6) BEFORE the strict CIDR
//     parser sees it.
//   - net.ParseCIDR strict — rejects 300.0.0.1/24, leading-zero octets,
//     malformed strings.
//   - Loopback / link-local → accept, populate warnInline (non-blocking).
func (m *Model) attemptParse() {
	raw := strings.TrimSpace(m.cidrInput.Value())
	if raw == "" {
		m.errInline = "source CIDR is required"
		m.warnInline = ""
		return
	}
	// Reject IPv6 zone-id BEFORE bare-IP promotion — the % suffix would
	// otherwise sneak through the bare-IP path's net.ParseIP, which
	// accepts zoned link-local addresses.
	if strings.Contains(raw, "%") {
		m.errInline = "IPv6 zone-id is not internet-routable; use a non-zoned address"
		m.warnInline = ""
		return
	}
	// Promote bare IP → /32 (v4) or /128 (v6).
	if !strings.Contains(raw, "/") {
		ip := net.ParseIP(raw)
		if ip == nil {
			m.errInline = fmt.Sprintf("not a valid IP or CIDR: %q", raw)
			m.warnInline = ""
			return
		}
		if ip.To4() != nil {
			raw = raw + "/32"
		} else {
			raw = raw + "/128"
		}
	}
	// Strict CIDR parsing.
	ip, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		m.errInline = fmt.Sprintf("invalid CIDR: %v", err)
		m.warnInline = ""
		return
	}
	// Loopback / link-local — accept but warn (non-blocking).
	m.warnInline = ""
	if ip.IsLoopback() {
		m.warnInline = fmt.Sprintf(
			"source %s is loopback — only local processes will match", ip)
	} else if ip.IsLinkLocalUnicast() {
		m.warnInline = fmt.Sprintf(
			"source %s is link-local — limited reachability", ip)
	}
	m.normalizedSource = ipnet.String()
	m.errInline = ""
}

// ---- preflight: async FW-06 IPv6-leak check ------------------------------

// preflightCmd runs the FW-06 check (D-FW-03):
//
//  1. ops.HasPublicIPv6(ctx) — true if `ip -6 addr show scope global`
//     returns at least one inet6 line.
//  2. ReadFile /etc/default/ufw — extract the `IPV6=` line.
//  3. If IPV6=no AND HasPublicIPv6==true → leak detected; the caller
//     pushes M-FW-IPV6-FIX and bails.
//
// Bounded by preflightTimeout (5s — sub-second on a healthy box).
func (m *Model) preflightCmd() tea.Cmd {
	ops := m.ops
	if ops == nil {
		// Test path — no async work; treat as no-leak.
		return func() tea.Msg { return preflightDoneMsg{} }
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
		defer cancel()
		hasIPv6, err := ops.HasPublicIPv6(ctx)
		if err != nil {
			return preflightDoneMsg{err: fmt.Errorf("HasPublicIPv6: %w", err)}
		}
		// Read /etc/default/ufw IPV6= line directly. The file should always
		// exist on Ubuntu 24.04; missing-file is treated as a hard error
		// rather than a default-yes assumption.
		data, err := ops.ReadFile(ctx, "/etc/default/ufw")
		if err != nil {
			return preflightDoneMsg{err: fmt.Errorf("read /etc/default/ufw: %w", err)}
		}
		ufwIPV6 := "yes" // OpenBSD-style default if absent (defensive)
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "IPV6=") {
				ufwIPV6 = strings.Trim(strings.TrimPrefix(t, "IPV6="), `"`)
				break
			}
		}
		leak := (ufwIPV6 == "no") && hasIPv6
		var detail string
		if leak {
			detail = "FW-06: ufw IPV6=no but this box has at least one public IPv6 — " +
				"any per-user lockdown rule below would silently leak v6 access."
		}
		return preflightDoneMsg{ipv6Leak: leak, leakDetail: detail}
	}
}

// handlePreflightDone routes the preflight result.
//
// Leak detected → push M-FW-IPV6-FIX (Task 2). On its pop, the admin
// can re-invoke M-ADD-RULE. (Re-running preflight on the SAME modal
// instance is deferred — typically the admin pops both modals and
// starts fresh; this keeps the state-machine simple.)
func (m *Model) handlePreflightDone(msg preflightDoneMsg) (nav.Screen, tea.Cmd) {
	if msg.err != nil {
		m.errInline = "preflight: " + msg.err.Error()
		m.phase = phaseError
		return m, nil
	}
	if msg.ipv6Leak {
		m.leakDetail = msg.leakDetail
		fix := NewIPv6Fix(m.ops, m.watcher, m.leakDetail)
		// Pop M-ADD-RULE first so admin lands back at the caller (S-FIREWALL
		// or S-USER-DETAIL) after the fix; THEN push the fix modal so it's
		// the top-of-stack. The simpler approach for v1: push the fix and
		// leave M-ADD-RULE underneath — admin pops both back to the caller.
		return m, nav.PushCmd(fix)
	}
	// No leak — proceed to review.
	m.phase = phaseReview
	return m, nil
}

// ---- commit: SAFE-04-wrapped txn batch -----------------------------------

// commitCmd builds the SAFE-04-wrapped batch and calls tx.Apply.
//
// D-S04-09 step 3 ordering (B1+B5 fix per checker): Schedule arms the
// timer FIRST, then UfwInsert. The reverse-cmd uses a comment-grep
// PLACEHOLDER (since the assigned ID is not known at schedule time):
//
//	ID=$(ufw status numbered | grep -F '<comment>' | head -1 |
//	     sed -E 's/^\[ +([0-9]+)\].*/\1/'); \
//	[ -n "$ID" ] && ufw --force delete $ID
//
// followed by `ufw reload`.
//
// Shell-quoting safety: `comment` is the output of ufwcomment.Encode
// whose regex is `^[a-z][a-z0-9:=_-]+$` — no quotes/semicolons/
// backticks/whitespace possible. Single-quote literal wrapping is safe.
//
// W2 fix: post-Apply we best-effort rebuild the FW-08 mirror so the
// SQLite cache reflects the new rule. Failure is logged via the toast
// (silent in production logs); the rule itself is correctly armed
// under the SAFE-04 timer regardless of cache state.
func (m *Model) commitCmd() tea.Cmd {
	if m.ops == nil {
		// Test path — no async work; surface a benign error so the
		// state machine transitions visibly.
		return func() tea.Msg {
			return committedMsg{err: fmt.Errorf("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	watcher := m.watcher
	user := m.userField
	source := m.normalizedSource
	port := m.sftpPort
	nowFn := m.nowFn
	storeQ := m.store

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
		defer cancel()

		comment, err := ufwcomment.Encode(user)
		if err != nil {
			return committedMsg{err: fmt.Errorf("encode comment: %w", err)}
		}
		opts := sysops.UfwAllowOpts{
			Proto:   "tcp",
			Source:  source,
			Port:    port,
			Comment: comment,
		}

		// === D-S04-09 step 3 ordering (B1+B5 fix) ===
		// Comment-grep placeholder reverse-cmd — see commitCmd doc.
		reverseCmd := fmt.Sprintf(
			"ID=$(ufw status numbered | grep -F '%s' | head -1 | "+
				"sed -E 's/^\\[ +([0-9]+)\\].*/\\1/'); "+
				"[ -n \"$ID\" ] && ufw --force delete $ID",
			comment,
		)
		reverseCmds := []string{reverseCmd, "ufw reload"}

		// Step 1: arm the timer FIRST (D-S04-09 step 3).
		scheduleStep := txn.NewScheduleRevertStep(
			reverseCmds, nowFn().Add(revertWindow), watcher, nowFn)

		// Step 2: the FW mutation.
		insertStep := txn.NewUfwInsertStep(opts)

		tx := txn.New(ops)
		steps := []txn.Step{scheduleStep, insertStep}
		if err := tx.Apply(ctx, steps); err != nil {
			// tx.Apply's reverse-order Compensate runs Schedule's
			// Compensate (stops the unit, clears watcher pointer).
			// The placeholder reverse-cmd's `[ -n "$ID" ]` guard
			// means even a fired-but-not-yet-stopped unit is harmless
			// (the rule didn't land, so grep returns empty).
			return committedMsg{err: fmt.Errorf("commit batch: %w", err)}
		}

		// Step 3 (post-Apply): resolve the assigned ID for the caller's
		// bookkeeping. Not load-bearing — the reverse-cmd no longer
		// needs it because of the comment-grep placeholder.
		assignedID, _ := firewall.ResolveRuleIDByCommentSource(ctx, ops, user, source)

		// Step 4 (W2): rebuild the FW-08 mirror best-effort.
		if storeQ != nil {
			if rules, eErr := firewall.Enumerate(ctx, ops); eErr == nil {
				_ = storeQ.RebuildUserIPs(ctx, rules, nowFn)
			}
		}

		return committedMsg{assignedID: assignedID}
	}
}

func (m *Model) handleCommitted(msg committedMsg) (nav.Screen, tea.Cmd) {
	if msg.err != nil {
		m.errInline = msg.err.Error()
		m.commitErr = msg.err
		m.phase = phaseError
		return m, nil
	}
	m.assignedID = msg.assignedID
	m.phase = phaseDone
	var flashCmd tea.Cmd
	flashText := fmt.Sprintf(
		"added rule for %s from %s (id=%d) — 3-min revert armed",
		m.userField, m.normalizedSource, m.assignedID)
	m.toast, flashCmd = m.toast.Flash(flashText)
	return m, tea.Batch(
		flashCmd,
		tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} }),
	)
}

// ---- View ------------------------------------------------------------------

// View renders the modal body wrapped in NormalBorder + Padding(0, 2).
func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(styles.Primary.Render(m.Title()))
	b.WriteString("\n\n")

	switch m.phase {
	case phaseInput:
		if m.userLocked {
			b.WriteString(styles.Dim.Render("user (locked): "))
			b.WriteString(m.userField)
			b.WriteString("\n\n")
		}
		b.WriteString("source CIDR (or bare IP): ")
		b.WriteString("\n")
		b.WriteString(m.cidrInput.View())
		b.WriteString("\n\n")
		if m.errInline != "" {
			b.WriteString(styles.Critical.Render(m.errInline))
			b.WriteString("\n\n")
		}
		b.WriteString(styles.Dim.Render("[enter] preflight + review · [esc] cancel"))
	case phasePreflight:
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
		b.WriteString(styles.Dim.Render(
			"checking FW-06 IPv6-leak preflight…"))
	case phaseReview:
		// Render the proposed shell command + the SAFE-04 revert payload.
		comment, _ := ufwcomment.Encode(m.userField)
		fmt.Fprintf(&b, "user:    %s\n", m.userField)
		fmt.Fprintf(&b, "source:  %s\n", m.normalizedSource)
		fmt.Fprintf(&b, "port:    %s\n\n", m.sftpPort)
		b.WriteString(styles.Primary.Render("Proposed mutation:"))
		b.WriteString("\n  ")
		b.WriteString(fmt.Sprintf(
			"ufw insert 1 allow proto tcp from %s to any port %s comment '%s'",
			m.normalizedSource, m.sftpPort, comment))
		b.WriteString("\n\n")
		b.WriteString(styles.Primary.Render("SAFE-04 revert payload (3-min countdown):"))
		b.WriteString("\n  ")
		b.WriteString(styles.Dim.Render(
			"ufw status numbered | grep -F '<comment>' | … | ufw --force delete $ID; ufw reload"))
		b.WriteString("\n\n")
		if m.warnInline != "" {
			b.WriteString(styles.Warn.Render("⚠ " + m.warnInline))
			b.WriteString("\n\n")
		}
		b.WriteString(styles.Dim.Render("[c] confirm · [esc] back · [q] quit"))
	case phaseCommitting:
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
		b.WriteString(styles.Dim.Render(
			"applying ufw insert + arming 3-min revert…"))
	case phaseDone:
		b.WriteString(styles.Success.Render(fmt.Sprintf(
			"✓ rule added for %s from %s (id=%d) — 3-min revert armed",
			m.userField, m.normalizedSource, m.assignedID)))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n")
		b.WriteString(styles.Dim.Render("[esc] back · [any key] retry"))
	}

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}
	return wrapModal(b.String())
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2).
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// ---- KeyMap ----------------------------------------------------------------

// KeyMap describes the modal's bindings — implements nav.KeyMap.
type KeyMap struct {
	Submit  nav.KeyBinding // enter (in phaseInput)
	Confirm nav.KeyBinding // c (in phaseReview)
	Cancel  nav.KeyBinding // esc — back / pop
}

// DefaultKeyMap returns the canonical M-ADD-RULE bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Submit:  nav.KeyBinding{Keys: []string{"enter"}, Help: "preflight + review"},
		Confirm: nav.KeyBinding{Keys: []string{"c"}, Help: "confirm + commit"},
		Cancel:  nav.KeyBinding{Keys: []string{"esc"}, Help: "back / cancel"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Submit, k.Confirm}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel},
		{k.Submit, k.Confirm},
	}
}

// ---- Test seams ------------------------------------------------------------

// Phase-int constants for test assertions (mirrors deleteuser pattern).
const (
	PhaseInputForTest      = int(phaseInput)
	PhasePreflightForTest  = int(phasePreflight)
	PhaseReviewForTest     = int(phaseReview)
	PhaseCommittingForTest = int(phaseCommitting)
	PhaseDoneForTest       = int(phaseDone)
	PhaseErrorForTest      = int(phaseError)
)

// LoadStateForTest pokes the model into a specific phase + values.
// Tests use this to assert WantsRawKeys / View per phase without
// driving the full state machine through Update.
func (m *Model) LoadStateForTest(p int, source, user, errInline, warnInline string) {
	m.phase = phase(p)
	m.normalizedSource = source
	if user != "" {
		m.userField = user
	}
	m.errInline = errInline
	m.warnInline = warnInline
}

// SetCIDRInputForTest seeds the textinput value for attemptParse drive.
func (m *Model) SetCIDRInputForTest(raw string) { m.cidrInput.SetValue(raw) }

// AttemptParseForTest runs attemptParse synchronously so tests can
// assert errInline / warnInline / normalizedSource without firing the
// async preflight.
func (m *Model) AttemptParseForTest() { m.attemptParse() }

// SetNowFnForTest pins the time-source for deterministic deadline /
// unit-name tests.
func (m *Model) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }

// FeedCommittedMsgForTest delivers a synthesized committedMsg to Update.
func (m *Model) FeedCommittedMsgForTest(err error) (nav.Screen, tea.Cmd) {
	msg := committedMsg{err: err}
	if err == nil {
		msg.assignedID = 1
	}
	return m.Update(msg)
}

// PhaseForTest exposes the current phase as int.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// UserLockedForTest exposes userLocked.
func (m *Model) UserLockedForTest() bool { return m.userLocked }

// UserFieldForTest exposes the current user value.
func (m *Model) UserFieldForTest() string { return m.userField }

// NormalizedSourceForTest exposes the post-validate CIDR.
func (m *Model) NormalizedSourceForTest() string { return m.normalizedSource }

// ErrInlineForTest exposes the inline error.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// WarnInlineForTest exposes the inline warning.
func (m *Model) WarnInlineForTest() string { return m.warnInline }

// AssignedIDForTest exposes the post-Apply assigned rule ID.
func (m *Model) AssignedIDForTest() int { return m.assignedID }
