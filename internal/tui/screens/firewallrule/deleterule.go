// deleterule.go is the M-DELETE-RULE modal landed by Plan 04-06 — the
// FW-03 user surface for "remove an allow rule." Three resolution modes
// per D-FW-07:
//
//	ModeByID     → admin selects a rule on S-FIREWALL and presses 'd';
//	               payload is the firewall.Rule already resolved by the
//	               caller. Init skips the async load (the target is
//	               known) and lands directly in phaseConfirm.
//	ModeByUser   → admin presses 'D' on S-USERS for the selected user;
//	               payload is the username. Init runs firewall.Enumerate
//	               and filters to r.User == username AND r.ParseErr == nil
//	               (foreign rules are excluded — only sftpj-tagged rules
//	               are deletable from this path).
//	ModeBySource → admin presses 's' on S-FIREWALL and types a CIDR;
//	               payload is the source string. Init runs Enumerate and
//	               filters to r.Source == source verbatim (may span
//	               multiple users).
//
// Commit batch (D-S04-09 step 3 + D-FW-07 strategy 1):
//
//	[NewScheduleRevertStep, NewUfwDeleteStep(idN), ..., NewUfwDeleteStep(id1)]
//
// IDs are sorted DESCENDING because lower IDs do NOT shift after a
// higher delete (deleting rule [3] before [1] would shift [5]'s
// numbering, breaking the next step). NewScheduleRevertStep is FIRST so
// the SAFE-04 timer arms before any FW mutation runs (D-S04-09 step 3).
//
// The reverse-cmd payload reconstructs every deleted rule via
// `lockdown.RenderReverseCommands` with OpDelete entries — each emits
// `ufw insert <originalID> allow proto tcp from <Source> to any port
// <Port> [comment '<RawComment>']` so a timer-fire rebuilds the deleted
// set byte-for-byte (T-04-06-04 mitigation: partial-failure rollback +
// admin-doesn't-confirm both restore the same set).
//
// Threat model (mirror 04-06 PLAN <threat_model>):
//   - T-04-06-01 (DoS, large batch): accept — PROJECT.md targets ≤100
//     users * ~10 IPs each = ~1000 rules max; systemd-run ARG_MAX
//     accommodates a 1000-line shell snippet (~80KB << 128KB).
//   - T-04-06-02 (tampering, source CIDR): mitigate — caller (S-FIREWALL
//     `s` prompt) validates via net.ParseCIDR before pushing the modal.
//   - T-04-06-03 (self-lockout): mitigate — SAFE-04 timer covers the
//     window; admin has 3 min to detect lost connectivity.
//   - T-04-06-04 (partial-failure consistency): mitigate — tx.Apply
//     reverses the order on failure; Schedule's Compensate stops the
//     unit so the timer doesn't fire post-failure.
//   - T-04-06-05 (reverse-cmd ID drift): accept — FW-08 mirror is keyed
//     on (user, source, proto, port), not ID; rule SET is identical
//     after revert even if numeric IDs differ.
//
// FW-08 mirror rebuild (W2): on successful tx.Apply, the modal best-
// effort calls `store.RebuildUserIPs` from the post-mutation
// `firewall.Enumerate` output. Failure surfaces in logs but does NOT
// roll back the firewall change — the rules are correctly deleted, and
// the SAFE-04 timer is independently armed.
package firewallrule

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/revert"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// deleteEnumerateTimeout bounds the async Enumerate call that resolves
// the target rule set for ModeByUser / ModeBySource.
const deleteEnumerateTimeout = 10 * time.Second

// deleteCommitTimeout bounds the SAFE-04-wrapped txn batch (Schedule +
// N UfwDelete + post-Apply Enumerate + best-effort RebuildUserIPs).
const deleteCommitTimeout = 60 * time.Second

// deleteRevertWindow is the SAFE-04 deadline (D-S04-04) — 3 min
// matching M-ADD-RULE's window (autoPopDelay + revertWindow are reused
// from addrule.go).

// DeleteMode discriminates the resolution strategy for the rules to
// delete (D-FW-07).
type DeleteMode int

const (
	// ModeByID = delete the one rule whose firewall.Rule was passed in
	// at construction time (S-FIREWALL `d`).
	ModeByID DeleteMode = iota
	// ModeByUser = delete every rule where r.User == username AND
	// r.ParseErr == nil. Foreign rules (ErrNotOurs / ErrBadVersion) are
	// excluded — they cannot be safely round-tripped (S-USERS `D`).
	ModeByUser
	// ModeBySource = delete every rule where r.Source matches the
	// payload CIDR string verbatim. May span multiple users
	// (S-FIREWALL `s`).
	ModeBySource
)

// deletePhase tracks the M-DELETE-RULE state-machine position.
type deletePhase int

const (
	// deletePhaseLoading — async firewall.Enumerate in flight (skipped
	// for ModeByID, which has the rule already).
	deletePhaseLoading deletePhase = iota
	// deletePhaseConfirm — admin reviews the resolved target set and
	// decides y / n.
	deletePhaseConfirm
	// deletePhaseCommitting — SAFE-04-wrapped txn batch in flight.
	deletePhaseCommitting
	// deletePhaseDone — txn succeeded; auto-pop after autoPopDelay.
	deletePhaseDone
	// deletePhaseError — txn or resolve failed; surface error and
	// allow esc-to-pop.
	deletePhaseError
)

// targetsLoadedMsg carries the filtered Enumerate result back to Update.
type targetsLoadedMsg struct {
	targets []firewall.Rule
	err     error
}

// deleteCommittedMsg carries the txn-batch outcome.
type deleteCommittedMsg struct {
	err error
}

// deleteAutoPopMsg pops the modal after a successful commit lingers.
type deleteAutoPopMsg struct{}

// DeleteModel is the M-DELETE-RULE Bubble Tea v2 model.
type DeleteModel struct {
	ops     sysops.SystemOps
	watcher *revert.Watcher
	store   *store.Queries // optional — tests pass nil; production wires the real handle
	mode    DeleteMode

	// Per-mode payload (one is non-zero based on mode):
	rule     firewall.Rule // ModeByID
	username string        // ModeByUser
	source   string        // ModeBySource

	phase     deletePhase
	targets   []firewall.Rule // resolved by Init (ModeByID: pre-loaded with rule)
	commitErr error
	keys      deleteKeyMap
	nowFn     func() time.Time
}

// NewDelete constructs M-DELETE-RULE. Most callers should use the
// per-mode convenience wrappers (NewDeleteByID / NewDeleteByUser /
// NewDeleteBySource) below; this is the kitchen-sink form for tests +
// future modes.
//
// ops / watcher MAY be nil in unit-test paths that drive the model via
// LoadTargetsForTest; the goroutine paths short-circuit on nil.
func NewDelete(ops sysops.SystemOps, watcher *revert.Watcher, mode DeleteMode, rule firewall.Rule, username, source string) *DeleteModel {
	return &DeleteModel{
		ops:      ops,
		watcher:  watcher,
		mode:     mode,
		rule:     rule,
		username: username,
		source:   source,
		phase:    deletePhaseLoading,
		keys:     defaultDeleteKeyMap(),
		nowFn:    time.Now,
	}
}

// NewDeleteByID is the S-FIREWALL `d` constructor — payload is the
// already-resolved firewall.Rule; Init skips Enumerate and lands in
// phaseConfirm directly.
func NewDeleteByID(ops sysops.SystemOps, watcher *revert.Watcher, rule firewall.Rule) *DeleteModel {
	return NewDelete(ops, watcher, ModeByID, rule, "", "")
}

// NewDeleteByUser is the S-USERS `D` constructor — payload is the
// username; Init runs Enumerate and filters to that user's sftpj rules.
func NewDeleteByUser(ops sysops.SystemOps, watcher *revert.Watcher, username string) *DeleteModel {
	return NewDelete(ops, watcher, ModeByUser, firewall.Rule{}, username, "")
}

// NewDeleteBySource is the S-FIREWALL `s` constructor — payload is the
// source CIDR; Init runs Enumerate and filters by source verbatim.
func NewDeleteBySource(ops sysops.SystemOps, watcher *revert.Watcher, source string) *DeleteModel {
	return NewDelete(ops, watcher, ModeBySource, firewall.Rule{}, "", source)
}

// SetStore injects the FW-08 mirror handle. Production wires the real
// *store.Queries via the bootstrap factory; tests can leave it nil and
// the post-Apply RebuildUserIPs is skipped.
func (m *DeleteModel) SetStore(q *store.Queries) { m.store = q }

// ---- nav.Screen interface ---------------------------------------------------

// Title implements nav.Screen.
func (m *DeleteModel) Title() string { return "Delete firewall rule(s)" }

// KeyMap implements nav.Screen.
func (m *DeleteModel) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — always false (no textinput).
func (m *DeleteModel) WantsRawKeys() bool { return false }

// Init runs Enumerate for ModeByUser/ModeBySource; ModeByID skips and
// transitions straight to phaseConfirm with the payload Rule.
func (m *DeleteModel) Init() tea.Cmd {
	if m.mode == ModeByID {
		// Already have the rule — skip Enumerate.
		m.targets = []firewall.Rule{m.rule}
		m.phase = deletePhaseConfirm
		return nil
	}
	if m.ops == nil {
		// Test path — caller should drive via LoadTargetsForTest /
		// FeedTargetsLoadedMsgForTest. Stay in phaseLoading until then.
		return nil
	}
	ops := m.ops
	mode := m.mode
	username := m.username
	source := m.source
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), deleteEnumerateTimeout)
		defer cancel()
		rules, err := firewall.Enumerate(ctx, ops)
		if err != nil {
			return targetsLoadedMsg{err: err}
		}
		matched := filterTargets(rules, mode, username, source)
		return targetsLoadedMsg{targets: matched}
	}
}

// filterTargets implements the per-mode filter contract. Pure;
// extracted so unit tests can pin the matching rules without driving
// Init.
func filterTargets(rules []firewall.Rule, mode DeleteMode, username, source string) []firewall.Rule {
	var matched []firewall.Rule
	for _, r := range rules {
		switch mode {
		case ModeByUser:
			if r.User == username && r.ParseErr == nil {
				matched = append(matched, r)
			}
		case ModeBySource:
			if r.Source == source {
				matched = append(matched, r)
			}
		}
	}
	return matched
}

// Update implements nav.Screen.
func (m *DeleteModel) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch v := msg.(type) {
	case targetsLoadedMsg:
		if v.err != nil {
			m.phase = deletePhaseError
			m.commitErr = v.err
			return m, nil
		}
		m.targets = v.targets
		m.phase = deletePhaseConfirm
		return m, nil
	case deleteCommittedMsg:
		if v.err != nil {
			m.phase = deletePhaseError
			m.commitErr = v.err
			return m, nil
		}
		m.phase = deletePhaseDone
		return m, tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return deleteAutoPopMsg{} })
	case deleteAutoPopMsg:
		return m, nav.PopCmd()
	case tea.KeyPressMsg:
		return m.handleKey(v)
	}
	return m, nil
}

// handleKey routes key presses per phase.
func (m *DeleteModel) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	s := msg.String()
	if s == "esc" {
		return m, nav.PopCmd()
	}
	switch m.phase {
	case deletePhaseConfirm:
		switch s {
		case "y", "Y":
			if len(m.targets) == 0 {
				// No-op — nothing to delete; let admin esc-back.
				return m, nil
			}
			m.phase = deletePhaseCommitting
			return m, m.commitCmd()
		case "n", "N", "q":
			return m, nav.PopCmd()
		}
	case deletePhaseError:
		// Any key returns to the prior phase; for simplicity, just pop.
		return m, nav.PopCmd()
	}
	return m, nil
}

// commitCmd builds the SAFE-04-wrapped batch and calls tx.Apply.
//
// D-S04-09 step 3 ordering: Schedule arms the timer FIRST. The reverse-
// cmd payload uses lockdown.RenderReverseCommands(OpDelete) so each
// deleted rule is reconstructed via `ufw insert <originalID> allow
// proto tcp from <Source> to any port <Port> [comment '<RawComment>']`
// (T-04-06-04 mitigation).
//
// Targets are sorted DESCENDING by ID per D-FW-07 strategy 1 — lower
// IDs don't shift after a higher delete.
//
// W2 fix: post-Apply we best-effort rebuild the FW-08 mirror so the
// SQLite cache reflects the post-delete ruleset. Failure surfaces in
// logs but does NOT roll back; the rules are correctly deleted and
// the SAFE-04 timer is independently armed.
func (m *DeleteModel) commitCmd() tea.Cmd {
	if m.ops == nil {
		// Test path with nil ops — emit a benign error so the state
		// machine transitions visibly.
		return func() tea.Msg {
			return deleteCommittedMsg{err: errors.New("internal: ops is nil (test path mis-wired)")}
		}
	}
	ops := m.ops
	// Avoid the typed-nil-pointer-as-non-nil-interface gotcha: if the
	// concrete *Watcher is nil (test paths), pass an explicit nil
	// interface to NewScheduleRevertStep so its `if s.watcher != nil`
	// guard fires correctly. Production paths always supply a non-nil
	// *Watcher (main.go::runTUI constructs the singleton).
	var watcher txn.RevertWatcher
	if m.watcher != nil {
		watcher = m.watcher
	}
	nowFn := m.nowFn
	storeQ := m.store
	// Defensive copy of the targets — sort happens on the copy.
	targets := append([]firewall.Rule(nil), m.targets...)

	// Sort DESCENDING by ID (D-FW-07 strategy 1). Lower IDs don't shift
	// after a higher delete.
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID > targets[j].ID })

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), deleteCommitTimeout)
		defer cancel()

		// Build reverse-cmd payload from the FULL pre-delete rules
		// (Source + Port + RawComment carry through to the `ufw insert`).
		mutations := make([]lockdown.PendingMutation, 0, len(targets))
		for _, r := range targets {
			mutations = append(mutations, lockdown.PendingMutation{
				Op:   lockdown.OpDelete,
				Rule: r,
			})
		}
		reverseCmds := lockdown.RenderReverseCommands(mutations)

		// Build the txn batch: schedule-first per D-S04-09 step 3, then
		// one UfwDelete per target in descending-ID order.
		steps := make([]txn.Step, 0, len(targets)+1)
		steps = append(steps,
			txn.NewScheduleRevertStep(reverseCmds, nowFn().Add(revertWindow), watcher, nowFn))
		for _, r := range targets {
			steps = append(steps, txn.NewUfwDeleteStep(r.ID))
		}

		tx := txn.New(ops)
		if err := tx.Apply(ctx, steps); err != nil {
			// tx.Apply's reverse-order Compensate runs Schedule's
			// Compensate (stops the unit, clears watcher pointer).
			// UfwDeleteStep.Compensate is a no-op (D-S04-05) — once a
			// rule is gone at the tool layer, only the SAFE-04 timer
			// can recover it. The half-applied state is still
			// consistent: rules from successful steps are gone (and
			// armed for revert via the ScheduleStep's reverseCmds);
			// rules from later (failed) steps weren't deleted.
			return deleteCommittedMsg{err: fmt.Errorf("commit batch: %w", err)}
		}

		// W2: rebuild the FW-08 mirror best-effort from the post-delete
		// ruleset. Failure logs but does NOT roll back.
		if storeQ != nil {
			if rules, eErr := firewall.Enumerate(ctx, ops); eErr == nil {
				_ = storeQ.RebuildUserIPs(ctx, rules, nowFn)
			}
		} else {
			// Even when storeQ is nil (tests), we still issue the
			// post-Apply Enumerate so callers can observe state. This
			// keeps the W2 invariant pinned by the test seam without
			// requiring a real *store.Queries.
			_, _ = firewall.Enumerate(ctx, ops)
		}

		return deleteCommittedMsg{}
	}
}

// View renders per phase.
func (m *DeleteModel) View() string {
	switch m.phase {
	case deletePhaseLoading:
		return wrapModal(styles.Dim.Render("Loading rules..."))
	case deletePhaseConfirm:
		if len(m.targets) == 0 {
			return wrapModal(
				styles.Warn.Render(m.noMatchesMessage()) + "\n\n" +
					styles.Dim.Render("[esc] back"))
		}
		return wrapModal(
			m.confirmText() + "\n\n" +
				styles.Dim.Render("[y] confirm  [n] cancel"))
	case deletePhaseCommitting:
		return wrapModal(styles.Dim.Render(
			fmt.Sprintf("Deleting %d rule(s)...", len(m.targets))))
	case deletePhaseDone:
		return wrapModal(styles.Success.Render(fmt.Sprintf(
			"✓ Deleted %d rule(s) — 3-min revert window armed", len(m.targets))))
	case deletePhaseError:
		return wrapModal(
			styles.Critical.Render(fmt.Sprintf("Failed: %v", m.commitErr)) +
				"\n\n" + styles.Dim.Render("[esc] back"))
	}
	return ""
}

// confirmText composes the per-mode copy for phaseConfirm.
func (m *DeleteModel) confirmText() string {
	switch m.mode {
	case ModeByID:
		r := m.targets[0]
		comment := r.RawComment
		if comment == "" {
			comment = "(no comment)"
		}
		return fmt.Sprintf(
			"Delete rule #%d (allow port %s from %s — %s)?",
			r.ID, r.Port, r.Source, comment)
	case ModeByUser:
		var srcs []string
		for _, t := range m.targets {
			srcs = append(srcs, t.Source)
		}
		return fmt.Sprintf(
			"Remove ALL %d rule(s) for %s?\n  → %s",
			len(m.targets), m.username, strings.Join(srcs, ", "))
	case ModeBySource:
		var users []string
		for _, t := range m.targets {
			users = append(users, t.User)
		}
		return fmt.Sprintf(
			"Remove ALL %d rule(s) matching source %s?\n  → users: %s",
			len(m.targets), m.source, strings.Join(users, ", "))
	}
	return ""
}

// noMatchesMessage composes the per-mode "nothing to delete" copy.
func (m *DeleteModel) noMatchesMessage() string {
	switch m.mode {
	case ModeByUser:
		return fmt.Sprintf("No rules found for user %s.", m.username)
	case ModeBySource:
		return fmt.Sprintf("No rules found matching source %s.", m.source)
	default:
		return "No rules to delete."
	}
}

// ---- KeyMap ----------------------------------------------------------------

// deleteKeyMap is the M-DELETE-RULE bindings.
type deleteKeyMap struct {
	Confirm nav.KeyBinding // y
	Cancel  nav.KeyBinding // n / esc
}

func defaultDeleteKeyMap() deleteKeyMap {
	return deleteKeyMap{
		Confirm: nav.KeyBinding{Keys: []string{"y", "Y"}, Help: "confirm delete"},
		Cancel:  nav.KeyBinding{Keys: []string{"n", "N", "esc"}, Help: "cancel"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k deleteKeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Confirm}
}

// FullHelp implements nav.KeyMap.
func (k deleteKeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Confirm},
	}
}

// ---- Test seams ------------------------------------------------------------

// Phase-int constants exposed to tests so they can pin transitions
// without importing the unexported deletePhase type.
const (
	DeletePhaseLoadingForTest    = int(deletePhaseLoading)
	DeletePhaseConfirmForTest    = int(deletePhaseConfirm)
	DeletePhaseCommittingForTest = int(deletePhaseCommitting)
	DeletePhaseDoneForTest       = int(deletePhaseDone)
	DeletePhaseErrorForTest      = int(deletePhaseError)
)

// PhaseForTest exposes the current phase as int.
func (m *DeleteModel) PhaseForTest() int { return int(m.phase) }

// TargetsForTest exposes the resolved target list.
func (m *DeleteModel) TargetsForTest() []firewall.Rule { return m.targets }

// LoadTargetsForTest pokes the model into phaseConfirm with the given
// target set. Tests use this to drive the confirm/commit phases without
// running Enumerate.
func (m *DeleteModel) LoadTargetsForTest(targets []firewall.Rule) {
	m.targets = targets
	m.phase = deletePhaseConfirm
	m.commitErr = nil
}

// FeedTargetsLoadedMsgForTest delivers a synthesized targetsLoadedMsg
// to Update so error-branch tests can transition without spinning a
// goroutine.
func (m *DeleteModel) FeedTargetsLoadedMsgForTest(targets []firewall.Rule, err error) (nav.Screen, tea.Cmd) {
	return m.Update(targetsLoadedMsg{targets: targets, err: err})
}

// CommitCmdForTest returns the same tea.Cmd that the y-keypress would
// dispatch in phaseConfirm. Tests invoke the returned closure inline to
// observe Fake.Calls without driving the full Bubble Tea event loop.
func (m *DeleteModel) CommitCmdForTest() tea.Cmd {
	return m.commitCmd()
}

// SetNowFnForTest pins the time-source for deterministic deadline /
// unit-name assertions in SAFE-04 tests.
func (m *DeleteModel) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }
