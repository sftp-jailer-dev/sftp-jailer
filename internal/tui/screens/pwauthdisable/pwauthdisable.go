// Package pwauthdisable renders M-DISABLE-PWAUTH — the USER-13 / D-16
// safety-rail modal that gates the "globally disable password auth" flow
// behind a managed-user pre-flight + a typed-string override.
//
// Lifecycle phases:
//
//	phasePreflight          — Init runs the asynchronous preflight: read the
//	                          existing canonical drop-in, enumerate sftp-group
//	                          users via internal/users.Enumerator, run
//	                          chrootcheck.CheckAuthKeysFile per user, collect
//	                          the keyless-or-strict-modes-broken set.
//	phaseReview             — admin reviews the proposal. For ActionDisable
//	                          with no keyless users → Enter starts submit
//	                          immediately. For ActionDisable with keyless
//	                          users → Enter advances to phaseConfirmingOverride.
//	                          For ActionEnable → Enter starts submit (no
//	                          preflight gate; re-enabling password auth has
//	                          no lockout risk per D-16).
//	phaseConfirmingOverride — admin types `I understand` verbatim. Match is
//	                          exact-string and case-sensitive (T-03-09-02).
//	                          Enter on a non-matching value sets errInline
//	                          and stays in phase.
//	phaseSubmitting         — txn batch in flight inside an off-loop tea.Cmd:
//	                          (1) WriteSshdDropIn (backup + atomic write),
//	                          (2) SshdValidate (`sshd -t`),
//	                          (3) SystemctlReload (PasswordAuthentication is
//	                              NOT socket-affecting per pitfall 4 → use
//	                              ReloadService, NOT RestartSocket),
//	                          (4) post-reload sshd -T verifier (inline, NOT
//	                              the SshdVerifyChrootDirective step — that
//	                              one checks for chrootdirectory/forcecommand,
//	                              not the directive we just changed).
//	phaseDone               — apply succeeded; modal lingers briefly then
//	                          auto-pops back to S-SETTINGS.
//	phaseError              — apply failed (txn rolled back) OR preflight
//	                          error; inline Critical errInline; Esc back.
//
// The setTopLevelPasswordAuthentication helper handles all four cases of
// the directive's lifecycle:
//   - ADD: directive absent + ActionDisable → append `passwordauthentication no`
//     at top level.
//   - REMOVE: directive present + ActionEnable → delete (preferred over
//     setting `yes` — keeps the drop-in minimal; OpenSSH defaults to yes
//     so the absence is functionally equivalent).
//   - UPDATE: directive present with stale value + ActionDisable → overwrite
//     Value to "no" AND clear RawLine so Render emits the canonical form.
//   - STRIP-FROM-MATCH: defensive against an admin who hand-edited the
//     directive into a Match block (pitfall A3) — strip from MatchBlock.Body
//     so the top-level write is the single source of truth.
//
// Architectural invariants:
//   - This package never imports os or os/exec. Every shell-out flows
//     through ops via the txn batch (CI guard:
//     scripts/check-no-exec-outside-sysops.sh).
//   - Drop-in writes flow through txn.NewWriteSshdDropInStep →
//     ops.AtomicWriteFile (CI guard: scripts/check-no-raw-config-write.sh).
//   - Single bubble-tea program per process is enforced at main.go (pitfall
//     E1); this modal is only ever pushed onto the existing program's nav
//     stack via nav.PushCmd, never via a fresh program constructor.
package pwauthdisable

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/applysetup"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// AutoPopDelay is how long the modal lingers in phaseDone before auto-popping
// back to S-SETTINGS. Mirrors applysetup.AutoPopDelay for UX consistency.
const AutoPopDelay = 500 * time.Millisecond

// OverrideText is the exact phrase the admin must type verbatim to override
// the keyless-user safety gate. Case-sensitive, exact string match per
// T-03-09-02 (lowercase "i understand" must NOT bypass).
const OverrideText = "I understand"

// Action discriminates the two directions the modal can drive.
type Action int

const (
	// ActionDisable adds `PasswordAuthentication no` at top level. Has the
	// keyless-user preflight gate.
	ActionDisable Action = iota
	// ActionEnable removes the directive (or no-op if absent). No preflight
	// gate — re-enabling password auth has no lockout risk per D-16.
	ActionEnable
)

// String returns a human label used in View copy + error messages.
func (a Action) String() string {
	if a == ActionEnable {
		return "enable"
	}
	return "disable"
}

// phase tracks the modal's state-machine position. Rendered in View.
type phase int

const (
	phasePreflight phase = iota
	phaseReview
	phaseConfirmingOverride
	phaseSubmitting
	phaseDone
	phaseError
)

// Model is the M-DISABLE-PWAUTH Bubble Tea v2 model. Constructed via New
// and pushed onto the nav stack from S-SETTINGS when the admin presses
// enter on the PasswordAuthentication row.
type Model struct {
	ops        sysops.SystemOps
	enum       *users.Enumerator
	chrootRoot string
	dropInPath string
	action     Action

	// preflight outputs
	currentDropIn []byte
	keylessUsers  []string

	// override gate
	confirmTI textinput.Model

	// runtime state
	phase     phase
	errInline string
	errFatal  bool
	spinner   spinner.Model
	toast     widgets.Toast
	keyMap    KeyMap

	// time source seam — production binds time.Now; tests pin via
	// SetNowFnForTest so the WriteSshdDropIn backup-path timestamp is
	// deterministic across runs.
	nowFn func() time.Time
}

// preflightLoadedMsg carries the result of the asynchronous preflight load
// from Init's tea.Cmd back into Update.
type preflightLoadedMsg struct {
	currentDropIn []byte
	keylessUsers  []string
	err           error
}

// submitDoneMsg carries the txn.Tx.Apply outcome (plus the post-reload
// sshd -T verifier outcome) from the off-loop goroutine back into Update.
// err == nil → phaseDone; err != nil → phaseError + Critical errInline.
type submitDoneMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that fires AutoPopDelay after a
// successful apply, telling Update to emit nav.PopCmd + the success toast.
type autoPopMsg struct{}

// New constructs the modal seeded with the admin's chosen direction. The
// caller (S-SETTINGS) picks ActionDisable when the live sshd value is "yes"
// and ActionEnable when it is "no".
func New(ops sysops.SystemOps, enum *users.Enumerator, chrootRoot string, action Action) *Model {
	confirmTI := textinput.New()
	confirmTI.Prompt = ""
	confirmTI.CharLimit = 64
	confirmTI.Placeholder = OverrideText
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	return &Model{
		ops:        ops,
		enum:       enum,
		chrootRoot: chrootRoot,
		dropInPath: applysetup.DropInPath,
		action:     action,
		confirmTI:  confirmTI,
		spinner:    sp,
		phase:      phasePreflight,
		nowFn:      time.Now,
		keyMap:     DefaultKeyMap(),
	}
}

// SetNowFnForTest pins the time-source seam used by the WriteSshdDropIn
// step's backup-path timestamp. Tests call this before LoadPreflightForTest
// so any subsequent submit() invocation produces deterministic args.
func (m *Model) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }

// LoadPreflightForTest bypasses Init's async preflight and seeds the model
// in phaseReview directly. Mirrors applysetup.LoadProposalForTest.
func (m *Model) LoadPreflightForTest(currentDropIn []byte, keylessUsers []string) {
	m.currentDropIn = currentDropIn
	m.keylessUsers = keylessUsers
	m.phase = phaseReview
}

// SetConfirmTextForTest pokes the confirm textinput's value (avoids
// having to drive char-by-char keypresses through the bubbles textinput).
// Mirrors deleteuser.SetConfirmTextForTest.
func (m *Model) SetConfirmTextForTest(s string) { m.confirmTI.SetValue(s) }

// FeedSubmitDoneForTest delivers a synthesized submitDoneMsg to Update.
func (m *Model) FeedSubmitDoneForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(submitDoneMsg{err: err})
}

// PhaseForTest exposes the unexported phase as an int for assertions.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// ErrInlineForTest exposes the inline error string for assertions.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// Phase constants exported under the For-Test suffix so tests can reference
// the state-machine values without leaking the private phase type.
const (
	PhasePreflightForTest          = int(phasePreflight)
	PhaseReviewForTest             = int(phaseReview)
	PhaseConfirmingOverrideForTest = int(phaseConfirmingOverride)
	PhaseSubmittingForTest         = int(phaseSubmitting)
	PhaseDoneForTest               = int(phaseDone)
	PhaseErrorForTest              = int(phaseError)
)

// KeyMap describes the modal's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Cancel  nav.KeyBinding
	Proceed nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-DISABLE-PWAUTH bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel:  nav.KeyBinding{Keys: []string{"esc"}, Help: "cancel"},
		Proceed: nav.KeyBinding{Keys: []string{"enter"}, Help: "proceed"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding { return []nav.KeyBinding{k.Cancel, k.Proceed} }

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{{k.Cancel, k.Proceed}}
}

// Title implements nav.Screen.
func (m *Model) Title() string {
	if m.action == ActionEnable {
		return "enable password authentication"
	}
	return "disable password authentication"
}

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keyMap }

// WantsRawKeys implements nav.Screen — true while the override-text
// textinput is focused so the root App forwards every key (including
// space + 'q') into the input rather than acting on global bindings.
func (m *Model) WantsRawKeys() bool { return m.phase == phaseConfirmingOverride }

// Init starts the spinner ticker and the asynchronous preflight load. In
// unit tests where ops is nil the test seam (LoadPreflightForTest) drives
// the model directly.
func (m *Model) Init() tea.Cmd {
	tickCmd := func() tea.Msg { return m.spinner.Tick() }
	if m.ops == nil || m.enum == nil {
		return tickCmd
	}
	ops, enum, chrootRoot, dropInPath := m.ops, m.enum, m.chrootRoot, m.dropInPath
	return tea.Batch(
		tickCmd,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return runPreflight(ctx, ops, enum, chrootRoot, dropInPath)
		},
	)
}

// runPreflight performs the synchronous preflight: read the current drop-in
// (best-effort — a missing file is normal on a fresh install and yields
// an empty currentDropIn), enumerate sftp-group users, and run
// chrootcheck.CheckAuthKeysFile per user to populate the keylessUsers set.
//
// "Keyless" here means "fails sshd's StrictModes prerequisites" — either
// the authorized_keys file is missing OR exists with wrong perms / owner.
// Either way the user cannot SSH-key in, so disabling password auth would
// lock them out (D-16 step 2).
func runPreflight(ctx context.Context, ops sysops.SystemOps, enum *users.Enumerator, chrootRoot, dropInPath string) preflightLoadedMsg {
	current, err := ops.ReadFile(ctx, dropInPath)
	if err != nil && !isNotExist(err) {
		return preflightLoadedMsg{err: fmt.Errorf("read drop-in %s: %w", dropInPath, err)}
	}
	rows, _, err := enum.Enumerate(ctx)
	if err != nil {
		return preflightLoadedMsg{err: fmt.Errorf("enumerate sftp users: %w", err)}
	}
	var keyless []string
	for _, r := range rows {
		vios, verr := chrootcheck.CheckAuthKeysFile(ctx, ops, r.Username, chrootRoot)
		if verr != nil {
			// A single user's lookup failure (e.g. user vanished mid-walk)
			// is treated as "no working key" for safety — the override gate
			// will surface this and let the admin decide.
			keyless = append(keyless, fmt.Sprintf("%s (lookup error: %v)", r.Username, verr))
			continue
		}
		if len(vios) > 0 {
			keyless = append(keyless, fmt.Sprintf("%s (%s)", r.Username, summarizeViolations(vios)))
		}
	}
	return preflightLoadedMsg{currentDropIn: current, keylessUsers: keyless}
}

// summarizeViolations joins the first violation Reason for compactness
// (and indicates "+N more" when several are present). The full detail is
// always recoverable via the doctor / S-USER-DETAIL screens — the modal's
// keyless list is meant to be at-a-glance.
func summarizeViolations(vios []chrootcheck.Violation) string {
	if len(vios) == 0 {
		return ""
	}
	first := vios[0].Reason
	// Truncate verbose reasons (e.g. the long chmod hint) at the first ';'
	// or '—' to keep the bullet line readable.
	if idx := strings.IndexAny(first, ";—"); idx > 0 {
		first = strings.TrimSpace(first[:idx])
	}
	if len(vios) > 1 {
		return fmt.Sprintf("%s; +%d more", first, len(vios)-1)
	}
	return first
}

// isNotExist returns true iff err signals "file does not exist" through
// fs.ErrNotExist or any wrapped equivalent. Used to treat a missing
// drop-in as a clean-slate (current bytes == nil) rather than an error.
func isNotExist(err error) bool {
	return err != nil && errors.Is(err, fs.ErrNotExist)
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over the modal's message types +
// per-phase keypress routing.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case preflightLoadedMsg:
		if msg.err != nil {
			m.errInline = "preflight error: " + msg.err.Error()
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		m.currentDropIn = msg.currentDropIn
		m.keylessUsers = msg.keylessUsers
		m.phase = phaseReview
		return m, nil

	case submitDoneMsg:
		if msg.err != nil {
			m.errInline = m.action.String() + " failed (rolled back): " + msg.err.Error()
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		m.phase = phaseDone
		return m, tea.Tick(AutoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} })

	case autoPopMsg:
		var flashCmd tea.Cmd
		toastText := "password authentication " + m.action.String() + "d"
		m.toast, flashCmd = m.toast.Flash(toastText)
		return m, tea.Batch(nav.PopCmd(), flashCmd)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches per phase.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch m.phase {
	case phaseReview:
		return m.handleReviewKey(msg)
	case phaseConfirmingOverride:
		return m.handleConfirmKey(msg)
	case phaseError:
		if msg.String() == "esc" || msg.String() == "q" {
			return m, nav.PopCmd()
		}
		return m, nil
	case phasePreflight, phaseSubmitting, phaseDone:
		// Esc still backs out fast — admins should be able to bail at any
		// time even if the spinner is still running.
		if msg.String() == "esc" {
			return m, nav.PopCmd()
		}
		return m, nil
	}
	return m, nil
}

// handleReviewKey routes keys while the modal is in phaseReview.
func (m *Model) handleReviewKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "enter":
		// ActionEnable: no preflight gate — re-enabling password auth has
		// no lockout risk per D-16.
		if m.action == ActionEnable {
			return m, m.startSubmit()
		}
		// ActionDisable: if any users are keyless, advance to the override
		// gate; otherwise start submit immediately.
		if len(m.keylessUsers) > 0 {
			m.phase = phaseConfirmingOverride
			m.errInline = ""
			return m, m.confirmTI.Focus()
		}
		return m, m.startSubmit()
	}
	return m, nil
}

// handleConfirmKey routes keys while the admin is typing the override text.
func (m *Model) handleConfirmKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Back out of override to review. The confirm field is intentionally
		// preserved — admin can re-focus and continue if they Esc by accident.
		m.phase = phaseReview
		m.errInline = ""
		m.confirmTI.Blur()
		return m, nil
	case "enter":
		// T-03-09-02: exact case-sensitive match. Lowercase "i understand"
		// MUST NOT bypass — that's the point of the gate.
		if m.confirmTI.Value() != OverrideText {
			m.errInline = fmt.Sprintf("type %q verbatim to override (case-sensitive)", OverrideText)
			return m, nil
		}
		return m, m.startSubmit()
	}
	var cmd tea.Cmd
	m.confirmTI, cmd = m.confirmTI.Update(msg)
	return m, cmd
}

// startSubmit returns the tea.Cmd that runs the txn batch + the post-reload
// sshd -T verifier inline. Failure surfaces via submitDoneMsg → phaseError
// + Critical errInline (rolled-back state per txn.Apply contract).
func (m *Model) startSubmit() tea.Cmd {
	m.phase = phaseSubmitting
	if m.ops == nil {
		// Test path — caller drives FeedSubmitDoneForTest manually.
		return func() tea.Msg { return m.spinner.Tick() }
	}
	ops, action, current, dropInPath, now := m.ops, m.action, m.currentDropIn, m.dropInPath, m.nowFn
	return tea.Batch(
		func() tea.Msg { return m.spinner.Tick() },
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			// Build the proposed drop-in: parse current, splice or strip
			// the top-level PasswordAuthentication directive, render. Per
			// pitfall A3 / D-16 step 5, the directive lives at TOP LEVEL —
			// putting it inside a Match block would scope it to that block
			// only and miss every other connection.
			d, _ := sshdcfg.ParseDropIn(current)
			d = setTopLevelPasswordAuthentication(d, action == ActionDisable)
			proposed := sshdcfg.Render(d)

			// W-02 + T-03-06-06: ensure backup dir exists before the txn
			// batch's first step (WriteSshdDropIn writes its backup into
			// BackupDir; the dir must exist).
			if err := ops.MkdirAll(ctx, applysetup.BackupDir, 0o700); err != nil {
				return submitDoneMsg{err: fmt.Errorf("ensure backup dir: %w", err)}
			}

			steps := []txn.Step{
				txn.NewWriteSshdDropInStep(dropInPath, applysetup.BackupDir, proposed, 0o644, now),
				txn.NewSshdValidateStep(),
				// Pitfall 4: PasswordAuthentication is NOT socket-affecting
				// (only Port / ListenAddress / AddressFamily are). Use
				// ReloadService — NEVER RestartSocket here.
				txn.NewSystemctlReloadStep(txn.ReloadService),
			}
			tx := txn.New(ops)
			if err := tx.Apply(ctx, steps); err != nil {
				return submitDoneMsg{err: err}
			}

			// Inline post-reload verifier — sshd -T reports the active
			// global value of passwordauthentication. We read it back and
			// confirm the change actually took effect (catches the case
			// where the drop-in was overwritten by a higher-precedence
			// admin-edit between our write and reload, or where the
			// directive landed inside a stale Match block we missed).
			//
			// Note: `sshd -T` (no -C) only reports global directives — for
			// our top-level directive that is exactly what we want. If a
			// future plan ever moves PasswordAuthentication into a Match
			// block (D-16 explicitly forbids this), the verifier would
			// need to switch to sysops.SshdTWithContext.
			cfg, err := ops.SshdDumpConfig(ctx)
			if err != nil {
				return submitDoneMsg{err: fmt.Errorf("post-reload sshd -T: %w", err)}
			}
			got := strings.ToLower(strings.Join(cfg["passwordauthentication"], " "))
			want := "no"
			if action == ActionEnable {
				want = "yes"
			}
			if !strings.Contains(got, want) {
				return submitDoneMsg{err: fmt.Errorf("sshd -T reports passwordauthentication=%q after reload, expected %q", got, want)}
			}
			return submitDoneMsg{err: nil}
		},
	)
}

// setTopLevelPasswordAuthentication implements the four-case decision
// matrix for the directive's lifecycle. Returns the modified DropIn —
// caller passes the result to sshdcfg.Render.
//
// Decision matrix:
//
//	disable=true,  directive absent  → ADD top-level `passwordauthentication no`
//	disable=true,  directive present → UPDATE Value to "no", clear RawLine
//	                                   (forces Render to emit canonical form
//	                                   instead of the original line — protects
//	                                   against admin-authored exotic spacing
//	                                   or trailing comments)
//	disable=false, directive present → REMOVE (cleaner than setting "yes" —
//	                                   OpenSSH defaults to yes so absence is
//	                                   functionally equivalent and keeps the
//	                                   drop-in minimal)
//	disable=false, directive absent  → no-op
//
// Defensive case (independent of disable flag): any passwordauthentication
// directive found INSIDE a MatchBlock.Body is stripped. Per pitfall A3 the
// top-level directive is the single source of truth; a stray Match-scoped
// directive would scope to that block only and create surprising behaviour.
// This tool never writes inside Match blocks for this directive, but an
// admin hand-edit could land one — we strip defensively.
func setTopLevelPasswordAuthentication(d sshdcfg.DropIn, disable bool) sshdcfg.DropIn {
	const keyword = "passwordauthentication"

	// Top-level pass: ADD / UPDATE / REMOVE per the matrix above.
	newDirs := make([]sshdcfg.Directive, 0, len(d.Directives)+1)
	found := false
	for _, dir := range d.Directives {
		if dir.Keyword == keyword {
			found = true
			if disable {
				// UPDATE: rewrite Value to "no" and clear RawLine so
				// Render emits the canonical form. Preserving RawLine
				// would silently keep an admin-authored "PasswordAuthentication yes"
				// in the file and ignore our intent.
				newDirs = append(newDirs, sshdcfg.Directive{
					Keyword: keyword,
					Value:   "no",
					RawLine: "",
				})
			}
			// disable=false → skip (REMOVE).
			continue
		}
		newDirs = append(newDirs, dir)
	}
	if disable && !found {
		// ADD.
		newDirs = append(newDirs, sshdcfg.Directive{
			Keyword: keyword,
			Value:   "no",
			RawLine: "",
		})
	}
	d.Directives = newDirs

	// Defensive Match-block strip (pitfall A3). Independent of disable flag —
	// the top-level directive is the single source of truth; any same-keyword
	// directive inside a Match.Body is removed regardless.
	for i := range d.Matches {
		filtered := make([]sshdcfg.Directive, 0, len(d.Matches[i].Body))
		for _, dir := range d.Matches[i].Body {
			if dir.Keyword == keyword {
				continue
			}
			filtered = append(filtered, dir)
		}
		d.Matches[i].Body = filtered
	}
	return d
}

// SetTopLevelPasswordAuthenticationForTest exposes the helper for unit
// tests so the four-case matrix can be pinned without driving the modal's
// state machine.
func SetTopLevelPasswordAuthenticationForTest(d sshdcfg.DropIn, disable bool) sshdcfg.DropIn {
	return setTopLevelPasswordAuthentication(d, disable)
}

// View renders the modal body wrapped in the M-OBSERVE-style border.
//
//nolint:gocyclo // per-phase rendering switch
func (m *Model) View() string {
	var b strings.Builder
	switch m.phase {
	case phasePreflight:
		b.WriteString(m.spinner.View() + " checking sftp users for working SSH keys…")
	case phaseReview:
		m.renderReview(&b)
	case phaseConfirmingOverride:
		m.renderConfirm(&b)
	case phaseSubmitting:
		b.WriteString(m.spinner.View() + " writing drop-in → sshd -t → systemctl reload → sshd -T verify…")
	case phaseDone:
		toastText := "password authentication " + m.action.String() + "d"
		b.WriteString(styles.Success.Render("✓ " + toastText))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n[esc] back to settings")
	}
	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n" + ts)
	}
	return wrapModal(b.String())
}

// renderReview renders the phaseReview surface. ActionDisable + keyless
// users → BLOCKED list with override prompt; ActionDisable + clean → simple
// confirm; ActionEnable → re-enable confirm (no preflight gate).
func (m *Model) renderReview(b *strings.Builder) {
	b.WriteString(styles.Primary.Render("M-DISABLE-PWAUTH — PasswordAuthentication " + m.action.String()))
	b.WriteString("\n\n")
	switch m.action {
	case ActionEnable:
		b.WriteString("Re-enable PasswordAuthentication globally? Removes the directive from\n")
		b.WriteString("the canonical drop-in (OpenSSH defaults to yes when absent).\n\n")
		b.WriteString("[enter] proceed   [esc] cancel")
		return
	case ActionDisable:
		if len(m.keylessUsers) == 0 {
			b.WriteString("All sftp-group users have working SSH keys (StrictModes prerequisites OK).\n")
			b.WriteString("Disable PasswordAuthentication globally? Adds `PasswordAuthentication no`\n")
			b.WriteString("at the top of the canonical drop-in.\n\n")
			b.WriteString("[enter] proceed   [esc] cancel")
			return
		}
		b.WriteString(styles.Critical.Render("BLOCKED: these managed users have no working SSH key —"))
		b.WriteString("\n")
		b.WriteString(styles.Critical.Render("disabling password auth will lock them out:"))
		b.WriteString("\n\n")
		for _, u := range m.keylessUsers {
			b.WriteString("  • " + u + "\n")
		}
		b.WriteString("\n[enter] override   [esc] cancel")
	}
}

// renderConfirm renders the phaseConfirmingOverride surface — the typed-
// string gate. `OverrideText` is rendered verbatim AS WELL AS quoted in
// the prompt to avoid the "what exactly do I type?" guessing game.
func (m *Model) renderConfirm(b *strings.Builder) {
	b.WriteString(styles.Critical.Render("Override gate — irreversible to the affected users until you re-enable"))
	b.WriteString("\n\n")
	fmt.Fprintf(b, "Type %q verbatim (case-sensitive) to confirm:\n  ", OverrideText)
	b.WriteString(m.confirmTI.View())
	if m.errInline != "" {
		b.WriteString("\n\n  ")
		b.WriteString(styles.Critical.Render(m.errInline))
	}
	b.WriteString("\n\n[enter] confirm   [esc] back")
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2). Per
// UI-SPEC line 46 modals carry this border; non-modal screens do not.
// Mirrors applysetup.wrapModal.
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}
