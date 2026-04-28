// Package lockdown is the S-LOCKDOWN screen — the progressive-lockdown
// flow's flagship surface. Two-pane editor: managed users on the left
// (cursor source); IPs of the selected user on the right.
//
// The screen runs at MODE: OPEN, MODE: STAGING, or MODE: LOCKED
// (D-L0809-02). In LOCKED mode it offers rollback (R). In OPEN mode it
// offers commit (C). In STAGING it offers both (commit removes the
// catch-all; rollback re-adds it).
//
// Plan 04-08 ships in two tasks:
//   - Task 1a (this commit + tests): screen frame, state machine, async
//     load (Init → goroutine → proposalsLoadedMsg), admin-IP guard
//     (DetectAdminIP + adminIPCovered), augmentWithZeroConnUsers, View()
//     rendering, and the keybind dispatch table.
//   - Task 1b: commit + rollback paths — composeCommitReverseCmds,
//     detectAddrFamily, RebuildUserIPs wiring + tests.
//
// Test seams (LoadProposalsForTest, SetAdminIPForTest, etc.) bypass
// Init's async load so unit tests can assert on dispatch + render
// without spinning up the goroutine.
package lockdown

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// commitTimeout bounds the SAFE-04-wrapped commit batch (Schedule + N
// mutations + Reload + post-Apply Enumerate + RebuildUserIPs). Same
// budget as M-ADD-RULE / M-DELETE-RULE.
const commitTimeout = 120 * time.Second

// rollbackTimeout bounds the rollback batch (Schedule + UfwAllow +
// Reload + post-Apply Enumerate + RebuildUserIPs).
const rollbackTimeout = 60 * time.Second

// revertWindow is the SAFE-04 deadline (D-S04-04) — 3 min from arm time.
const revertWindow = 3 * time.Minute

// loadTimeout bounds the async generator + enumerator + admin-IP detect
// chain at Init-time.
const loadTimeout = 30 * time.Second

// screenPhase tracks the screen's state-machine position.
type screenPhase int

const (
	screenLoading    screenPhase = iota // async load in flight
	screenEditing                       // editor active; admin can navigate / mutate proposals
	screenCommitting                    // commit txn batch running
	screenDone                          // commit/rollback success — auto-pop after delay
	screenError                         // commit/rollback / load failure — esc to pop
)

// proposalsLoadedMsg carries the load goroutine's result back to Update.
// Includes the admin's source IP (DetectAdminIP) so the LOCK-03 banner
// can render on first View().
type proposalsLoadedMsg struct {
	proposals []lockdown.Proposal
	allUsers  []users.Row
	rules     []firewall.Rule
	adminIP   string
	err       error
}

// proposalUpdateMsg is the response to a per-user re-Generate (toggle
// include-targeted). Replaces just the IPs of the named user.
type proposalUpdateMsg struct {
	User string
	IPs  []lockdown.ProposedIP
	Err  error
}

// committedMsg / rollbackDoneMsg carry the commit/rollback async results
// back from the goroutine. Defined here so Task 1a's test file builds;
// Task 1b adds the commitCmd / rollbackCmd implementations.
type committedMsg struct{ err error }
type rollbackDoneMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that pops the screen after a
// successful commit / rollback lingers for the autoPopDelay.
type autoPopMsg struct{}

// autoPopDelay is how long screenDone lingers before popping.
const autoPopDelay = time.Second

// Model is the S-LOCKDOWN screen state.
type Model struct {
	ops      sysops.SystemOps
	watcher  *revert.Watcher
	gen      *lockdown.Generator
	userEnum *users.Enumerator
	sftpPort string

	phase screenPhase

	// Loaded by Init — populated by proposalsLoadedMsg handler.
	proposals    []lockdown.Proposal
	currentRules []firewall.Rule
	currentMode  firewall.Mode
	adminIP      string

	// Editor state.
	cursor             int                              // selected user (left pane)
	windowDays         int                              // editable; default from config
	includeTargetedFor map[string]bool                  // per-user include-targeted toggle
	manualAdds         map[string][]lockdown.ProposedIP // per-user — admin-typed IPs (Task 1b textinput sub-modal)

	// Per-screen ephemerals.
	toast     widgets.Toast
	commitErr error
	loadErr   error
	nowFn     func() time.Time
	width     int

	// FW-08 mirror handle (Task 1b — rebuilt post-mutation success).
	// Set via SetStoreForTest / SetStore from bootstrap. nil-safe at
	// all callsites.
	store storeQ
}

// storeQ is the narrow interface the screen consumes from
// *store.Queries — only RebuildUserIPs is needed (FW-08 mirror).
// Defined as an interface so tests can inject a fake without importing
// the full store package + tmp-DB seeding shape.
type storeQ interface {
	RebuildUserIPs(ctx context.Context, rules []firewall.Rule, nowFn func() time.Time) error
}

// New constructs the S-LOCKDOWN screen. ops/watcher/gen/userEnum may be
// nil in unit-test paths that drive the model via LoadProposalsForTest.
// The goroutine paths short-circuit on nil.
func New(
	ops sysops.SystemOps,
	watcher *revert.Watcher,
	gen *lockdown.Generator,
	userEnum *users.Enumerator,
	sftpPort string,
	windowDays int,
) *Model {
	return &Model{
		ops:                ops,
		watcher:            watcher,
		gen:                gen,
		userEnum:           userEnum,
		sftpPort:           sftpPort,
		phase:              screenLoading,
		windowDays:         windowDays,
		includeTargetedFor: map[string]bool{},
		manualAdds:         map[string][]lockdown.ProposedIP{},
		nowFn:              time.Now,
	}
}

// Title implements nav.Screen.
func (m *Model) Title() string { return "Progressive lockdown" }

// KeyMap implements nav.Screen — minimal for v1 (the help overlay reads
// this; the screen's own key dispatch lives in handleKey).
func (m *Model) KeyMap() nav.KeyMap { return emptyKeyMap{} }

// WantsRawKeys implements nav.Screen — false (no textinput at the top
// level; per-IP add textinput is a sub-modal in Task 1b).
func (m *Model) WantsRawKeys() bool { return false }

// Init kicks off the async generator + enumerator + admin-IP detect.
// Returns nil if any required dep is nil (test path; tests seed via
// LoadProposalsForTest).
func (m *Model) Init() tea.Cmd {
	if m.gen == nil || m.userEnum == nil || m.ops == nil {
		return nil
	}
	gen := m.gen
	userEnum := m.userEnum
	ops := m.ops
	windowDays := m.windowDays
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		proposals, perr := gen.Generate(ctx, windowDays, false)
		if perr != nil {
			return proposalsLoadedMsg{err: fmt.Errorf("generate proposals: %w", perr)}
		}
		allRows, _, uerr := userEnum.Enumerate(ctx)
		if uerr != nil {
			return proposalsLoadedMsg{err: fmt.Errorf("enumerate users: %w", uerr)}
		}
		rules, rerr := firewall.Enumerate(ctx, ops)
		if rerr != nil {
			return proposalsLoadedMsg{err: fmt.Errorf("enumerate firewall: %w", rerr)}
		}
		adminIP := lockdown.DetectAdminIP(ctx, ops)
		return proposalsLoadedMsg{
			proposals: proposals,
			allUsers:  allRows,
			rules:     rules,
			adminIP:   adminIP,
		}
	}
}

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		return m, nil

	case proposalsLoadedMsg:
		if v.err != nil {
			m.phase = screenError
			m.loadErr = v.err
			return m, nil
		}
		m.proposals = augmentWithZeroConnUsers(v.proposals, v.allUsers)
		m.currentRules = v.rules
		m.currentMode = firewall.DetectMode(v.rules, m.sftpPort)
		m.adminIP = v.adminIP
		m.phase = screenEditing
		return m, nil

	case proposalUpdateMsg:
		if v.Err != nil {
			// Best-effort: toast + ignore (don't block the editor).
			var flashCmd tea.Cmd
			m.toast, flashCmd = m.toast.Flash("regenerate failed: " + v.Err.Error())
			return m, flashCmd
		}
		for i := range m.proposals {
			if m.proposals[i].User == v.User {
				m.proposals[i].IPs = v.IPs
				m.proposals[i].ZeroConn = len(v.IPs) == 0
				break
			}
		}
		return m, nil

	case committedMsg:
		if v.err != nil {
			m.phase = screenError
			m.commitErr = v.err
			return m, nil
		}
		m.phase = screenDone
		return m, tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case rollbackDoneMsg:
		if v.err != nil {
			m.phase = screenError
			m.commitErr = v.err
			return m, nil
		}
		m.phase = screenDone
		return m, tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case autoPopMsg:
		return m, nav.PopCmd()

	case tea.KeyPressMsg:
		return m.handleKey(v)
	}

	// Toast TTL.
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches the screen's key bindings. Outside the editing
// phase, only `esc` is honoured (back-to-home).
func (m *Model) handleKey(k tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	if m.phase != screenEditing {
		if k.String() == "esc" {
			return m, nav.PopCmd()
		}
		return m, nil
	}
	switch k.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "j", "down":
		if m.cursor < len(m.proposals)-1 {
			m.cursor++
		}
		return m, nil
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case "a":
		// Task 1b: push a small textinput sub-modal that on submit
		// appends to manualAdds[user]. Skipped for Task 1a — flash an
		// info toast so the keybind isn't mysteriously dead.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("manual-add IP — Task 1b sub-modal")
		return m, flashCmd
	case "d":
		// Task 1b: remove selected IP from current user's manual adds.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("remove IP — Task 1b sub-modal")
		return m, flashCmd
	case "c":
		return m.handleCopyURL()
	case "i":
		// Toggle include-targeted for selected user; re-Generate
		// scoped to that user.
		if u, ok := m.selectedUser(); ok {
			m.includeTargetedFor[u] = !m.includeTargetedFor[u]
			return m, m.regenerateForUser(u)
		}
		return m, nil
	case "w":
		// Task 1b sub-modal: prompt for window-days override.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("window override — Task 1b sub-modal")
		return m, flashCmd
	case "D":
		// Push M-DRY-RUN modal (Task 2).
		return m, nav.PushCmd(NewDryRunModal(m.ops, m.buildPendingMutations(), m.currentRules))
	case "C":
		// Commit — admin-IP guard gate.
		if !m.adminIPCovered() && m.adminIP != "" {
			return m, m.flashErr("admin IP not in any user's allowlist — commit refused")
		}
		m.phase = screenCommitting
		return m, m.commitCmd()
	case "R":
		// Rollback to OPEN — only valid in LOCKED / STAGING modes.
		if m.currentMode == firewall.ModeLocked || m.currentMode == firewall.ModeStaging {
			m.phase = screenCommitting
			return m, m.rollbackCmd()
		}
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("rollback only valid in LOCKED / STAGING mode")
		return m, flashCmd
	}
	return m, nil
}

// selectedUser returns the username at the current cursor position, or
// "", false if the cursor is out of range (e.g. empty proposals slice).
func (m *Model) selectedUser() (string, bool) {
	if m.cursor < 0 || m.cursor >= len(m.proposals) {
		return "", false
	}
	return m.proposals[m.cursor].User, true
}

// adminIPCovered returns true when the admin's source IP is contained
// by at least one proposed CIDR (or manual-added CIDR) across all users.
// Console session (adminIP == "") returns true unconditionally — the
// LOCK-03 guard is intentionally fail-open in that case (D-L0204-05).
func (m *Model) adminIPCovered() bool {
	if m.adminIP == "" {
		return true // console session — guard inactive
	}
	for _, p := range m.proposals {
		for _, ip := range p.IPs {
			if ipMatchesCIDR(m.adminIP, ip.Source) {
				return true
			}
		}
		if extra, ok := m.manualAdds[p.User]; ok {
			for _, ip := range extra {
				if ipMatchesCIDR(m.adminIP, ip.Source) {
					return true
				}
			}
		}
	}
	return false
}

// ipMatchesCIDR reports whether ipStr (a single IP) is contained by
// cidrStr (a CIDR or a single IP). Falls back to IP-equality when
// cidrStr lacks a `/` (treats it as /32 or /128).
//
// Both IPv4 and IPv6 are supported. Returns false on any parse failure
// (defensive — never panics, never throws).
func ipMatchesCIDR(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Accept bare IP (no `/`): promote to /32 or /128 for comparison.
	if !strings.Contains(cidrStr, "/") {
		bare := net.ParseIP(cidrStr)
		if bare == nil {
			return false
		}
		return ip.Equal(bare)
	}
	_, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil || ipnet == nil {
		return false
	}
	return ipnet.Contains(ip)
}

// handleCopyURL emits the OSC 52 SetClipboard for the public-IP
// discovery URL (D-L0204-03) and flashes a toast. Admins can share this
// URL with their SFTP customers ("visit this URL, tell me the IP, I'll
// add it to your allowlist").
func (m *Model) handleCopyURL() (nav.Screen, tea.Cmd) {
	const url = "https://ifconfig.me"
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied https://ifconfig.me via OSC 52")
	return m, tea.Batch(tea.SetClipboard(url), flashCmd)
}

// regenerateForUser re-runs Generate with includeTargeted=true and
// patches just the named user's IP slice. Returns a no-op command if
// the generator is nil (test path).
func (m *Model) regenerateForUser(user string) tea.Cmd {
	if m.gen == nil {
		return nil
	}
	gen := m.gen
	windowDays := m.windowDays
	includeTargeted := m.includeTargetedFor[user]
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		all, err := gen.Generate(ctx, windowDays, includeTargeted)
		if err != nil {
			return proposalUpdateMsg{User: user, Err: err}
		}
		for _, p := range all {
			if p.User == user {
				return proposalUpdateMsg{User: user, IPs: p.IPs}
			}
		}
		return proposalUpdateMsg{User: user, IPs: nil}
	}
}

// flashErr surfaces a transient error toast on the editor.
func (m *Model) flashErr(text string) tea.Cmd {
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash(text)
	return flashCmd
}

// buildPendingMutations composes the txn batch's mutation list from the
// current proposals (per-user IPs + manualAdds). One UfwInsert per IP
// per user. Plus a UfwDelete for the catch-all if MODE=OPEN.
//
// Detail: the catch-all rule we want to delete is identified by an
// empty RawComment + Anywhere source + matching SFTP port. Picks the
// first match — there should never be more than one in normal
// operation (the firewall enforces uniqueness by content).
func (m *Model) buildPendingMutations() []lockdown.PendingMutation {
	var muts []lockdown.PendingMutation
	for _, p := range m.proposals {
		allIPs := append([]lockdown.ProposedIP(nil), p.IPs...)
		allIPs = append(allIPs, m.manualAdds[p.User]...)
		for _, ip := range allIPs {
			muts = append(muts, lockdown.PendingMutation{
				Op: lockdown.OpAdd,
				Rule: firewall.Rule{
					User:   p.User,
					Source: ip.Source,
					Port:   m.sftpPort,
					Proto:  detectAddrFamily(ip.Source),
				},
			})
		}
	}
	if m.currentMode == firewall.ModeOpen || m.currentMode == firewall.ModeStaging {
		// Find the catch-all rule (empty comment + Anywhere source on
		// the SFTP port) and emit a delete for it. In STAGING mode
		// the commit is "remove the catch-all"; in OPEN mode the
		// commit is "add per-user rules + remove the catch-all".
		for _, r := range m.currentRules {
			if !portMatchesSFTP(r.Port, m.sftpPort) {
				continue
			}
			if r.RawComment != "" {
				continue
			}
			if !strings.EqualFold(r.Source, "Anywhere") {
				continue
			}
			if !strings.Contains(strings.ToUpper(r.Action), "ALLOW") {
				continue
			}
			muts = append(muts, lockdown.PendingMutation{
				Op:   lockdown.OpDelete,
				Rule: r,
			})
			break
		}
	}
	return muts
}

// portMatchesSFTP reports whether a Rule.Port string matches sftpPort.
// Accepts "22", "22/tcp", "22/udp" against "22". Local helper rather
// than depending on firewall.portMatches (unexported).
func portMatchesSFTP(rulePort, sftpPort string) bool {
	if rulePort == sftpPort {
		return true
	}
	for _, suffix := range []string{"/tcp", "/udp"} {
		if rulePort == sftpPort+suffix {
			return true
		}
	}
	return false
}

// commitCmd composes the SAFE-04-wrapped txn batch for the LOCK-06
// commit and runs it under tx.Apply. Ordering follows D-S04-09 step 3:
// Schedule first (arms the 3-min revert), then N mutations, then a
// trailing UfwReload finalizer. Cancel is NOT in the batch — it runs
// only on explicit admin Confirm in the countdown UI (D-S04-09 step 5).
//
// Reverse-cmd composition (composeCommitReverseCmds):
//   - OpAdd entries: comment-grep placeholder (the rule's AssignedID is
//     not known pre-Apply; the placeholder resolves it via
//     `ufw status numbered | grep -F '<comment>'`).
//   - OpDelete entries: lockdown.RenderReverseCommands rebuilds the
//     full `ufw insert <originalID> allow proto tcp from <src> to any
//     port <port> [comment '<c>']` line.
//
// Post-Apply: best-effort RebuildUserIPs from the post-mutation
// firewall.Enumerate output (FW-08 mirror, W2). Failure logs but does
// NOT roll back the commit — the rules are armed under the SAFE-04
// timer regardless of cache state.
func (m *Model) commitCmd() tea.Cmd {
	if m.ops == nil {
		return func() tea.Msg {
			return committedMsg{err: fmt.Errorf("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	// Avoid the typed-nil-pointer-as-non-nil-interface gotcha (mirrors
	// deleterule.go pattern): if the concrete *Watcher is nil (test
	// paths), pass an explicit nil interface to NewScheduleRevertStep
	// so its `if s.watcher != nil` guard fires correctly. Production
	// paths always supply a non-nil *Watcher (main.go::runTUI
	// constructs the singleton).
	var watcher txn.RevertWatcher
	if m.watcher != nil {
		watcher = m.watcher
	}
	nowFn := m.nowFn
	storeQ := m.store
	port := m.sftpPort
	muts := m.buildPendingMutations()

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
		defer cancel()

		if len(muts) == 0 {
			return committedMsg{err: fmt.Errorf("commit batch is empty — nothing to apply")}
		}

		reverseCmds := composeCommitReverseCmds(muts, port)
		if len(reverseCmds) == 0 {
			return committedMsg{err: fmt.Errorf("internal: composeCommitReverseCmds returned empty for non-empty mutations")}
		}

		// D-S04-09 step 3 ordering: Schedule first, then mutations, then
		// reload finalizer.
		steps := []txn.Step{
			txn.NewScheduleRevertStep(reverseCmds, nowFn().Add(revertWindow), watcher, nowFn),
		}
		for _, mut := range muts {
			switch mut.Op {
			case lockdown.OpAdd:
				comment, err := ufwcomment.Encode(mut.Rule.User)
				if err != nil {
					return committedMsg{err: fmt.Errorf("encode comment for %s: %w", mut.Rule.User, err)}
				}
				steps = append(steps, txn.NewUfwInsertStep(sysops.UfwAllowOpts{
					Proto:   "tcp",
					Source:  mut.Rule.Source,
					Port:    mut.Rule.Port,
					Comment: comment,
				}))
			case lockdown.OpDelete:
				steps = append(steps, txn.NewUfwDeleteStep(mut.Rule.ID))
			}
		}
		steps = append(steps, txn.NewUfwReloadStep())

		tx := txn.New(ops)
		if err := tx.Apply(ctx, steps); err != nil {
			return committedMsg{err: fmt.Errorf("commit batch: %w", err)}
		}

		// W2: best-effort FW-08 mirror rebuild post-Apply.
		if storeQ != nil {
			if rules, eErr := firewall.Enumerate(ctx, ops); eErr == nil {
				_ = storeQ.RebuildUserIPs(ctx, rules, nowFn)
			}
		}

		return committedMsg{err: nil}
	}
}

// rollbackCmd re-adds the catch-all `allow port <p> from any` under a
// SAFE-04 revert window (D-L0809-04). Per-user sftpj rules stay in
// place — they're operationally redundant once the catch-all overrides
// them, but visible as STAGING-mode rules for re-promotion later. The
// new MODE auto-derives to STAGING (or OPEN if there are no per-user
// rules) on the next Enumerate.
//
// Reverse-cmd shape (B3): the rollback's reverse re-deletes the
// catch-all by signature (`allow <port>/tcp.*Anywhere`) AND comment
// absence (`grep -v sftpj`) — there can be only one such rule at any
// given time. The pattern is documented inline so future readers
// understand why we don't use RenderReverseCommands here (the catch-
// all has no fixed ID pre-Apply; signature-grep is the deterministic
// resolver for a single rule).
func (m *Model) rollbackCmd() tea.Cmd {
	if m.ops == nil {
		return func() tea.Msg {
			return rollbackDoneMsg{err: fmt.Errorf("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	// Avoid the typed-nil-pointer-as-non-nil-interface gotcha — see
	// commitCmd's nil-check comment above for the rationale.
	var watcher txn.RevertWatcher
	if m.watcher != nil {
		watcher = m.watcher
	}
	nowFn := m.nowFn
	storeQ := m.store
	port := m.sftpPort

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()

		// Reverse: locate the catch-all by signature (`allow <port>/tcp` +
		// Anywhere) AND absence of sftpj comment; delete by ID. The
		// extended-regex matches either bare-port or proto-prefixed forms
		// ufw might emit.
		reverseCmd := fmt.Sprintf(
			"ID=$(ufw status numbered | grep -E 'allow +%s/tcp.*Anywhere' | "+
				"grep -v sftpj | head -1 | "+
				"sed -E 's/^\\[ +([0-9]+)\\].*/\\1/'); "+
				"[ -n \"$ID\" ] && ufw --force delete $ID",
			port,
		)
		reverseCmds := []string{reverseCmd, "ufw reload"}

		steps := []txn.Step{
			txn.NewScheduleRevertStep(reverseCmds, nowFn().Add(revertWindow), watcher, nowFn),
			txn.NewUfwAllowStep(sysops.UfwAllowOpts{
				Proto:   "tcp",
				Source:  "any",
				Port:    port,
				Comment: "", // catch-all has no comment
			}),
			txn.NewUfwReloadStep(),
		}

		tx := txn.New(ops)
		if err := tx.Apply(ctx, steps); err != nil {
			return rollbackDoneMsg{err: fmt.Errorf("rollback batch: %w", err)}
		}

		// W2: best-effort FW-08 mirror rebuild post-Apply.
		if storeQ != nil {
			if rules, eErr := firewall.Enumerate(ctx, ops); eErr == nil {
				_ = storeQ.RebuildUserIPs(ctx, rules, nowFn)
			}
		}

		return rollbackDoneMsg{err: nil}
	}
}

// composeCommitReverseCmds builds the SAFE-04 reverse payload for a
// multi-mutation commit batch. Each OpAdd contributes a comment-grep
// placeholder reverse (the assigned rule ID is not known pre-Apply);
// each OpDelete contributes a canonical `ufw insert <originalID> ...`
// reverse via lockdown.RenderReverseCommands (which knows the pre-
// delete state byte-for-byte). The output is a flat []string suitable
// for handing to NewScheduleRevertStep — `strings.Join(out, "; ")` is
// the systemd-run ExecStart shell body.
//
// The trailing `ufw reload` finalizer is appended exactly ONCE
// (W3 contract): RenderReverseCommands appends its own reload, which
// we strip before adding our own. This avoids `ufw reload; ufw reload`
// pairs which would be benign but ugly in `systemctl cat` output.
//
// Returns nil for an empty input — no spurious reload line.
//
// Threat-model commitments (T-04-08-04 / T-04-08-05): the OpAdd
// placeholder's `[ -n "$ID" ]` guard prevents `ufw delete <empty>`
// invocations when the rule has already been removed (e.g. by an
// earlier reverse cmd in the same batch). The comment is single-quoted
// inside `grep -F`; ufwcomment.Encode rejects all shell metacharacters
// in the user portion (the regex's `^[a-z][a-z0-9:=_-]+$`), so the
// quote-balancing safety holds.
func composeCommitReverseCmds(muts []lockdown.PendingMutation, _port string) []string {
	if len(muts) == 0 {
		return nil
	}

	var out []string
	var deletes []lockdown.PendingMutation

	for _, mut := range muts {
		switch mut.Op {
		case lockdown.OpAdd:
			// ufwcomment.Encode is the load-bearing safety net for the
			// shell-quote-free systemd-run ExecStart per D-S04-08. If
			// Encode fails (invalid user), surface it via the special
			// SQL-NULL placeholder; the SAFE-04 timer will fire but
			// `grep -F ''` matches nothing → harmless no-op.
			comment, err := ufwcomment.Encode(mut.Rule.User)
			if err != nil {
				comment = "" // benign — grep -F '' matches everything but `[ -n "$ID" ]` guards
			}
			out = append(out, fmt.Sprintf(
				"ID=$(ufw status numbered | grep -F '%s' | head -1 | "+
					"sed -E 's/^\\[ +([0-9]+)\\].*/\\1/'); "+
					"[ -n \"$ID\" ] && ufw --force delete $ID",
				comment,
			))
		case lockdown.OpDelete:
			deletes = append(deletes, mut)
		}
	}

	if len(deletes) > 0 {
		// RenderReverseCommands returns OpDelete inserts + a trailing
		// "ufw reload". Strip the trailing reload so we only emit it
		// once at the end (W3 contract).
		rendered := lockdown.RenderReverseCommands(deletes)
		for _, line := range rendered {
			if line == "ufw reload" {
				continue
			}
			out = append(out, line)
		}
	}

	if len(out) == 0 {
		return nil
	}
	out = append(out, "ufw reload")
	return out
}

// detectAddrFamily returns "v4" or "v6" for a CIDR or bare IP. Falls
// back to "v4" on any parse failure (defensive — never panics, never
// throws). The Rule.Proto field carries this value and is the address
// family marker used by RebuildUserIPs to populate the user_ips mirror.
func detectAddrFamily(cidr string) string {
	if cidr == "" {
		return "v4"
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		if bare := net.ParseIP(cidr); bare != nil {
			if bare.To4() != nil {
				return "v4"
			}
			return "v6"
		}
		return "v4"
	}
	if ip.To4() != nil {
		return "v4"
	}
	return "v6"
}

// augmentWithZeroConnUsers adds empty Proposal entries for users in
// allUsers but not in proposals (D-L0204-03 zero-connection surface).
// Returns the augmented slice sorted ASC by username for deterministic
// rendering.
func augmentWithZeroConnUsers(proposals []lockdown.Proposal, allUsers []users.Row) []lockdown.Proposal {
	seen := map[string]bool{}
	for _, p := range proposals {
		seen[p.User] = true
	}
	out := append([]lockdown.Proposal(nil), proposals...)
	for _, u := range allUsers {
		if !seen[u.Username] {
			out = append(out, lockdown.Proposal{
				User:     u.Username,
				IPs:      nil,
				ZeroConn: true,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// ---- Test seams -----------------------------------------------------------

// LoadProposalsForTest seeds the editor without running Init's async
// load. Mirrors users.LoadRowsForTest. currentMode defaults to
// firewall.ModeOpen if zero — pass an explicit value when testing
// rollback paths in MODE: LOCKED.
func (m *Model) LoadProposalsForTest(props []lockdown.Proposal, currentMode firewall.Mode) {
	m.proposals = props
	m.currentMode = currentMode
	m.phase = screenEditing
}

// SetAdminIPForTest pokes the detected admin IP. Pass "" to simulate a
// console session (LOCK-03 guard inactive).
func (m *Model) SetAdminIPForTest(ip string) { m.adminIP = ip }

// AdminIPCoveredForTest exposes the gate decision for assertions.
func (m *Model) AdminIPCoveredForTest() bool { return m.adminIPCovered() }

// Phase exposes the current screenPhase for assertions.
func (m *Model) Phase() screenPhase { return m.phase }

// SetCursorForTest sets the editor cursor index (left pane).
func (m *Model) SetCursorForTest(idx int) { m.cursor = idx }

// SetCurrentRulesForTest seeds the current ruleset (for buildPendingMutations).
func (m *Model) SetCurrentRulesForTest(rules []firewall.Rule) { m.currentRules = rules }

// ProposalsForTest exposes the loaded proposals slice.
func (m *Model) ProposalsForTest() []lockdown.Proposal { return m.proposals }

// SetStore registers the FW-08 mirror handle. Production wiring passes
// *store.Queries; tests inject a recording fake. nil-safe at all
// callsites (commitCmd / rollbackCmd skip the rebuild on nil).
func (m *Model) SetStore(s storeQ) { m.store = s }

// SetNowFnForTest pins the time source for deterministic deadline
// math in commitCmd / rollbackCmd (Task 1b).
func (m *Model) SetNowFnForTest(fn func() time.Time) {
	if fn == nil {
		m.nowFn = time.Now
		return
	}
	m.nowFn = fn
}

// ---- View -----------------------------------------------------------------

// View renders the screen body. Layout: top banner (mode + readiness +
// admin-IP) → two-pane (users left, IPs right) → footer.
func (m *Model) View() string {
	switch m.phase {
	case screenLoading:
		return styles.Dim.Render("loading lockdown proposal…")
	case screenError:
		errText := "(no error)"
		if m.loadErr != nil {
			errText = m.loadErr.Error()
		} else if m.commitErr != nil {
			errText = m.commitErr.Error()
		}
		return styles.Critical.Render("error: "+errText) +
			"\n\n" + styles.Dim.Render("(esc to return)")
	case screenDone:
		return styles.Success.Render("✓ committed — popping…")
	}

	var b strings.Builder
	b.WriteString(styles.Primary.Render("Progressive lockdown"))
	b.WriteString("\n\n")

	// Top banner — readiness signal + admin-IP guard banner.
	b.WriteString(m.renderReadinessBanner())
	b.WriteString("\n")
	b.WriteString(m.renderAdminIPBanner())
	b.WriteString("\n\n")

	// Mode line.
	b.WriteString(styles.Dim.Render(
		fmt.Sprintf("MODE: %s · port %s · window %dd · %d users",
			strings.ToUpper(m.currentMode.String()), m.sftpPort, m.windowDays, len(m.proposals))))
	b.WriteString("\n\n")

	// Two-pane render.
	b.WriteString(m.renderTwoPane())
	b.WriteString("\n\n")

	// Footer.
	b.WriteString(styles.Dim.Render(
		"↑↓·move  a·add IP  d·remove  i·include-targeted  c·copy URL  w·window  D·dry-run  C·commit  R·rollback  esc·back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}
	return b.String()
}

func (m *Model) renderReadinessBanner() string {
	zeroConnCount := 0
	totalUsers := len(m.proposals)
	for _, p := range m.proposals {
		if p.ZeroConn || len(p.IPs) == 0 {
			zeroConnCount++
		}
	}
	if zeroConnCount == 0 && totalUsers > 0 {
		return styles.Success.Render(
			fmt.Sprintf("✓ Ready for lockdown — all %d managed users have observed source IPs", totalUsers))
	}
	return styles.Warn.Render(
		fmt.Sprintf("⚠ %d of %d managed users have no observed connections — they will be locked out unless you add IPs manually",
			zeroConnCount, totalUsers))
}

func (m *Model) renderAdminIPBanner() string {
	if m.adminIP == "" {
		return styles.Dim.Render("Console session — self-lockout guard inactive")
	}
	if m.adminIPCovered() {
		// Find which user covers it (first match wins for the banner).
		coveringUser := "(some user)"
		for _, p := range m.proposals {
			for _, ip := range p.IPs {
				if ipMatchesCIDR(m.adminIP, ip.Source) {
					coveringUser = p.User
					goto found
				}
			}
			if extra, ok := m.manualAdds[p.User]; ok {
				for _, ip := range extra {
					if ipMatchesCIDR(m.adminIP, ip.Source) {
						coveringUser = p.User
						goto found
					}
				}
			}
		}
	found:
		return styles.Success.Render(
			fmt.Sprintf("✓ Your IP %s is covered by %s's allowlist", m.adminIP, coveringUser))
	}
	return styles.Critical.Render(
		fmt.Sprintf("⚠ Your IP %s isn't in any user's allowlist — add it before commit (commit will be refused)", m.adminIP))
}

func (m *Model) renderTwoPane() string {
	if len(m.proposals) == 0 {
		return styles.Dim.Render("(no managed users)")
	}

	// Left pane — users list with cursor marker.
	var left strings.Builder
	left.WriteString(styles.Primary.Render("users"))
	left.WriteString("\n")
	for i, p := range m.proposals {
		marker := "  "
		if i == m.cursor {
			marker = "▌ "
		}
		readinessGlyph := "✓"
		if p.ZeroConn || len(p.IPs) == 0 {
			readinessGlyph = "⚠"
		}
		manual := len(m.manualAdds[p.User])
		row := fmt.Sprintf("%s%s %-12s  obs:%2d  manual:%d",
			marker, readinessGlyph, truncate(p.User, 12), len(p.IPs), manual)
		if i == m.cursor {
			row = styles.Primary.Render(row)
		}
		left.WriteString(row)
		left.WriteString("\n")
	}

	// Right pane — IPs of selected user.
	var right strings.Builder
	right.WriteString(styles.Primary.Render("IPs (selected user)"))
	right.WriteString("\n")
	if u, ok := m.selectedUser(); ok {
		// Find proposal for selected user.
		var sel *lockdown.Proposal
		for i := range m.proposals {
			if m.proposals[i].User == u {
				sel = &m.proposals[i]
				break
			}
		}
		if sel == nil || (len(sel.IPs) == 0 && len(m.manualAdds[u]) == 0) {
			right.WriteString(styles.Warn.Render(
				fmt.Sprintf("⚠ %s — no observations in last %dd", u, m.windowDays)))
			right.WriteString("\n")
			right.WriteString(styles.Dim.Render(
				"add at least one IP via [a], or " + u + " will be locked out after commit"))
			right.WriteString("\n\n")
			right.WriteString(styles.Dim.Render(
				"hint: tell your customer to visit https://ifconfig.me — copy the IP shown there"))
		} else {
			right.WriteString(fmt.Sprintf("  %-22s %5s  %-7s  %s\n",
				"source", "conns", "tier", "last-seen"))
			for _, ip := range sel.IPs {
				lastSeen := "—"
				if ip.LastSeenNs > 0 {
					lastSeen = time.Unix(0, ip.LastSeenNs).Format("2006-01-02")
				}
				right.WriteString(fmt.Sprintf("  %-22s %5d  %-7s  %s\n",
					truncate(ip.Source, 22), ip.ConnCount, ip.Tier, lastSeen))
			}
			for _, ip := range m.manualAdds[u] {
				right.WriteString(fmt.Sprintf("  %-22s %5s  %-7s  %s\n",
					truncate(ip.Source, 22), "—", "manual", "—"))
			}
		}
	}

	// Side-by-side render via lipgloss.JoinHorizontal.
	leftStyled := lipgloss.NewStyle().Width(40).Render(left.String())
	rightStyled := lipgloss.NewStyle().Width(60).Render(right.String())
	return lipgloss.JoinHorizontal(lipgloss.Top, leftStyled, "  ", rightStyled)
}

// truncate clips s to width with a trailing "…" marker.
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

// emptyKeyMap implements nav.KeyMap with no bindings — the screen's own
// help text is rendered inline in View().
type emptyKeyMap struct{}

func (emptyKeyMap) ShortHelp() []nav.KeyBinding  { return nil }
func (emptyKeyMap) FullHelp() [][]nav.KeyBinding { return nil }
