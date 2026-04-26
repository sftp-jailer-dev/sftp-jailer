// Package newuser renders the M-NEW-USER modal — the multi-textinput form
// that creates a chrooted SFTP user via the D-12 useradd batch and (on
// success) chains into M-PASSWORD per D-11.
//
// Two construction paths:
//
//   - New(ops, chrootRoot): fresh-create. UID auto-pick starts at 2000;
//     home auto-derives as <chrootRoot>/<username>; primary group defaults
//     to the username (UPG); sftp-jailer membership default-checked. The
//     useradd opts use CreateHome=true and GID=0 (UPG — useradd creates
//     a same-name group).
//
//   - NewFromOrphan(ops, chrootRoot, orphan): D-14 orphan reconcile path.
//     Pre-populates fields from the orphan dir's existing UID AND GID
//     (B-03 fix — preserves the dir's existing same-name group rather
//     than letting useradd create a fresh group with a new GID and
//     causing silent ownership drift). useradd opts use CreateHome=false
//     (the dir already exists) and GID=orphan.GID (`-u <uid> -g <gid>`).
//     The Chmod / Chown txn steps are SKIPPED in the orphan path — the
//     directory already has correct ownership and re-applying could drift
//     if Lookup ever returned a different gid.
//
// Lifecycle phases:
//
//	phasePreflight — Init runs B4 (/etc/shells contains /usr/sbin/nologin)
//	                 + chrootcheck.WalkRoot(chrootRoot) asynchronously.
//	                 Block with errInline if either fails.
//	phaseEditing   — admin navigates the field list (j/k), enters a field
//	                 (e/Enter on a textinput), types into it, commits with
//	                 Enter, exits edit-of-field with Esc.
//	phaseSubmitting — txn batch in flight (Useradd + GpasswdAdd [+ Chmod
//	                  + Chown for fresh-create only]).
//	phaseDone      — txn succeeded; auto-push M-PASSWORD via tea.Batch
//	                 (nav.PopCmd, nav.PushCmd(password.New(...))).
//	phaseError     — preflight failure OR txn-Apply failure (rolled back
//	                 by the txn substrate); errInline carries the message;
//	                 admin presses Esc to back out.
//
// Test seams:
//   - LoadPreflightForTest(shellsHasNologin, walkViolations): bypasses
//     Init's async preflight and seeds the model directly into phaseEditing
//     (or phaseError if either gate fails).
//   - SetUserLookupForTest / ResetUserLookupForTest: swap the os/user.LookupId
//     seam that powers the UID-collision check (USER-04 reserved-range
//     handling already lives in pure validate code).
//   - FeedSubmitDoneForTest: synthesizes a submitDoneMsg without spinning
//     up the off-loop tea.Cmd. Drives test 9 (rollback) and test 14 (push
//     M-PASSWORD on success).
//
// Architectural invariants:
//   - This package issues zero direct subprocess calls — every mutation
//     flows through internal/txn → internal/sysops (CI guard
//     scripts/check-no-exec-outside-sysops.sh).
//   - This package never writes to /etc/sftp-jailer/config.yaml — the only
//     write surface is the txn batch (CI guard
//     scripts/check-no-raw-config-write.sh).
package newuser

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// USER-04 reserved-UID range floor + ceiling. UIDs in 60000..65535 are
// reserved on Ubuntu 24.04 (60000-64999 = anonymous, 65534=nobody, 65535=
// kernel sentinel). The modal rejects anything in this range explicitly
// rather than let useradd surface a confusing error. UIDs >= 65536 are
// allowed at the modal layer (useradd will decide; some sites use 65536+
// for federated pools — N-04 boundary tests pin this).
const (
	uidFloor    = 2000
	uidReserved = 60000 // first reserved UID (USER-04)
	uidCeiling  = 59999 // last allowed UID below the reserved range
)

// usernameRegex enforces the POSIX-portable shape per N-04: starts with
// lowercase letter, then letters/digits/underscore/hyphen, max 32 chars.
// Excludes uppercase (LDAP convention), dot (Win32 NAMES), leading hyphen
// (avoids -flag confusion in argv).
var usernameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// fieldKind enumerates the editable rows. The cursor cycle goes top-to-
// bottom; the last "field" is the [Create] action button.
type fieldKind int

const (
	fieldUsername fieldKind = iota
	fieldUID
	fieldHome
	fieldPrimaryGroup
	fieldSftpJailer
	fieldCreate

	fieldKindCount
)

func (k fieldKind) label() string {
	switch k {
	case fieldUsername:
		return "username"
	case fieldUID:
		return "uid"
	case fieldHome:
		return "home"
	case fieldPrimaryGroup:
		return "primary group"
	case fieldSftpJailer:
		return "sftp-jailer membership"
	case fieldCreate:
		return "[create]"
	}
	return "?"
}

// phase tracks the modal's state-machine position.
type phase int

const (
	phasePreflight phase = iota
	phaseEditing
	phaseSubmitting
	phaseDone
	phaseError
)

// preflightLoadedMsg carries B4 + chrootcheck.WalkRoot results back into
// Update.
type preflightLoadedMsg struct {
	shellsOK       bool
	walkViolations []chrootcheck.Violation
	err            error
}

// submitDoneMsg carries the txn.Apply outcome.
type submitDoneMsg struct{ err error }

// userLookupFn is the os/user.LookupId seam — production uses
// internal/sysops-equivalent stdlib lookups; tests stub via
// SetUserLookupForTest. Returns true if a user with the given UID exists.
type userLookupFn func(uid int) bool

// Model is the M-NEW-USER Bubble Tea v2 model.
type Model struct {
	ops        sysops.SystemOps
	chrootRoot string

	// Field state — one textinput per typed input plus two booleans.
	usernameTI       textinput.Model
	uidTI            textinput.Model
	homeTI           textinput.Model
	primaryGroupTI   textinput.Model
	sftpJailerMember bool
	createHome       bool // true for fresh-create (default); false for orphan reconcile

	// Cursor + edit state.
	cursor    fieldKind
	editing   bool
	errInline string
	errFatal  bool

	// Async-load state.
	phase   phase
	spinner spinner.Model
	toast   widgets.Toast

	// Orphan-reconcile metadata (B-03 — UID and GID both pinned so submit
	// can route the right useradd opts and SKIP the chmod/chown steps).
	isOrphan  bool
	orphanGID int

	// Test seams.
	lookupFn userLookupFn

	keys KeyMap
}

// New constructs the modal in fresh-create mode. UID auto-pick starts at
// uidFloor (2000) and increments until LookupId returns false. Home
// auto-fills as <chrootRoot>/<username> and tracks username changes until
// the admin manually edits it (tracked implicitly by leaving it empty
// until commit). Primary group defaults to the username; sftp-jailer
// membership defaults TRUE.
func New(ops sysops.SystemOps, chrootRoot string) *Model {
	m := newBase(ops, chrootRoot)
	m.usernameTI.Placeholder = "alice"
	m.usernameTI.SetValue("")
	m.uidTI.SetValue(strconv.Itoa(autoPickUID(m.lookupFn)))
	// Home + primary group derive from the username at submit time when the
	// admin has not edited them; for now leave them blank with placeholders.
	m.homeTI.Placeholder = chrootRoot + "/<username>"
	m.homeTI.SetValue("")
	m.primaryGroupTI.Placeholder = "<username>"
	m.primaryGroupTI.SetValue("")
	m.sftpJailerMember = true
	m.createHome = true
	m.isOrphan = false
	return m
}

// NewFromOrphan constructs the modal in D-14 orphan-reconcile mode.
// B-03 (the central fix this constructor encodes): we pin BOTH UID AND
// GID from the orphan InfoRow so the eventual useradd invocation passes
// `-u <uid> -g <gid>` and reuses the existing same-name group. We also
// flip createHome=false so useradd uses `-M` (the dir already exists), and
// set isOrphan=true / orphanGID=orphan.GID so attemptSubmit routes onto
// the SKIP-chmod-chown branch. Re-running chmod/chown on an already-owned
// dir is correctness-equivalent in the happy path but creates a drift
// window if Lookup ever resolves to a different gid than the dir actually
// has — the orphan-path SKIP defends against that.
func NewFromOrphan(ops sysops.SystemOps, chrootRoot string, orphan users.InfoRow) *Model {
	m := newBase(ops, chrootRoot)
	name := filepath.Base(orphan.Dir)
	m.usernameTI.SetValue(name)
	m.uidTI.SetValue(strconv.Itoa(orphan.UID))
	m.homeTI.SetValue(orphan.Dir)
	m.primaryGroupTI.SetValue(name)
	m.sftpJailerMember = true
	m.createHome = false
	m.isOrphan = true
	m.orphanGID = orphan.GID
	return m
}

// newBase wires the textinputs + spinner + lookup seam shared between the
// two constructors.
func newBase(ops sysops.SystemOps, chrootRoot string) *Model {
	mk := func(charLimit int) textinput.Model {
		ti := textinput.New()
		ti.Prompt = ""
		ti.CharLimit = charLimit
		return ti
	}
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	return &Model{
		ops:            ops,
		chrootRoot:     chrootRoot,
		usernameTI:     mk(32),
		uidTI:          mk(6),
		homeTI:         mk(255),
		primaryGroupTI: mk(32),
		spinner:        sp,
		phase:          phasePreflight,
		lookupFn:       defaultUserLookup,
		keys:           DefaultKeyMap(),
	}
}

// Title implements nav.Screen.
func (m *Model) Title() string {
	if m.isOrphan {
		return "new user (orphan reconcile)"
	}
	return "new user"
}

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while editing a textinput so
// the root App forwards every key (including 'q', 'a', '/', digits) into
// the input rather than acting on global bindings.
func (m *Model) WantsRawKeys() bool {
	return m.editing && m.cursor != fieldSftpJailer && m.cursor != fieldCreate
}

// Init starts the spinner + asynchronous preflight (B4 + chrootcheck).
func (m *Model) Init() tea.Cmd {
	tickCmd := func() tea.Msg { return m.spinner.Tick() }
	if m.ops == nil {
		return tickCmd
	}
	ops, root := m.ops, m.chrootRoot
	return tea.Batch(
		tickCmd,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return runPreflight(ctx, ops, root)
		},
	)
}

// runPreflight reads /etc/shells and walks the chroot chain. Returns a
// preflightLoadedMsg.
func runPreflight(ctx context.Context, ops sysops.SystemOps, chrootRoot string) preflightLoadedMsg {
	shellsOK := false
	if b, err := ops.ReadFile(ctx, "/etc/shells"); err == nil {
		// /etc/shells is a list of valid login shells, one per line. We
		// require /usr/sbin/nologin to be present so useradd's `-s
		// /usr/sbin/nologin` does not produce a user with an unlisted shell
		// (B4 / pitfall). A line-prefix match handles trailing whitespace.
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "/usr/sbin/nologin" {
				shellsOK = true
				break
			}
		}
	}
	v, err := chrootcheck.WalkRoot(ctx, ops, chrootRoot)
	return preflightLoadedMsg{shellsOK: shellsOK, walkViolations: v, err: err}
}

// LoadPreflightForTest bypasses Init's async tea.Cmd and drives the model
// into phaseEditing (clean preflight) or phaseError (failed preflight).
// shellsHasNologin=true + walkViolations empty + err==nil → phaseEditing.
func (m *Model) LoadPreflightForTest(shellsHasNologin bool, walkViolations []chrootcheck.Violation, err error) {
	m.applyPreflight(preflightLoadedMsg{
		shellsOK: shellsHasNologin, walkViolations: walkViolations, err: err,
	})
}

// FeedSubmitDoneForTest delivers a synthesized submitDoneMsg to Update.
// Drives test 9 (rollback) and test 14 (push M-PASSWORD on success).
func (m *Model) FeedSubmitDoneForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(submitDoneMsg{err: err})
}

// PhaseForTest exposes the unexported phase for assertions. Test-only.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// IsOrphanForTest / OrphanGIDForTest expose the orphan-pin metadata so
// B-03 tests can assert the constructor wiring.
func (m *Model) IsOrphanForTest() bool { return m.isOrphan }

// OrphanGIDForTest exposes the captured orphan GID for B-03 assertions.
func (m *Model) OrphanGIDForTest() int { return m.orphanGID }

// ErrInlineForTest exposes the inline error string for assertions.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// CreateHomeForTest exposes the createHome flag for assertions.
func (m *Model) CreateHomeForTest() bool { return m.createHome }

// FieldValuesForTest returns a snapshot of the current field values for
// assertions across the two constructors.
func (m *Model) FieldValuesForTest() (username, uid, home, primaryGroup string, sftpJailer bool) {
	return m.usernameTI.Value(),
		m.uidTI.Value(),
		m.homeTI.Value(),
		m.primaryGroupTI.Value(),
		m.sftpJailerMember
}

// PhaseEditing / PhaseError / etc. — int-typed exports for tests so the
// test file does not need to import the unexported phase type.
const (
	PhasePreflightForTest  = int(phasePreflight)
	PhaseEditingForTest    = int(phaseEditing)
	PhaseSubmittingForTest = int(phaseSubmitting)
	PhaseDoneForTest       = int(phaseDone)
	PhaseErrorForTest      = int(phaseError)
)

// SetUserLookupForTest swaps the os/user.LookupId seam. Pass a function
// that returns true for UIDs the test wants to claim are taken.
func (m *Model) SetUserLookupForTest(fn userLookupFn) { m.lookupFn = fn }

// applyPreflight is the Update branch shared between the async tea.Cmd
// and the LoadPreflightForTest seam.
func (m *Model) applyPreflight(msg preflightLoadedMsg) {
	if msg.err != nil {
		m.errInline = "preflight error: " + msg.err.Error()
		m.errFatal = true
		m.phase = phaseError
		return
	}
	if !msg.shellsOK {
		m.errInline = "/etc/shells does not list /usr/sbin/nologin — useradd would create a user with an unlisted shell (B4). Add the line and retry."
		m.errFatal = true
		m.phase = phaseError
		return
	}
	if len(msg.walkViolations) > 0 {
		var bld strings.Builder
		bld.WriteString("chroot chain violations — fix before creating users:")
		for _, v := range msg.walkViolations {
			bld.WriteString("\n  • ")
			bld.WriteString(v.Reason)
		}
		m.errInline = bld.String()
		m.errFatal = true
		m.phase = phaseError
		return
	}
	m.phase = phaseEditing
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over async messages + per-phase keypress
// routing. Each branch is small; the spread is in the message types.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case preflightLoadedMsg:
		m.applyPreflight(msg)
		return m, nil

	case submitDoneMsg:
		if msg.err != nil {
			m.errInline = "create failed (rolled back): " + msg.err.Error()
			m.errFatal = true
			m.phase = phaseError
			return m, nil
		}
		m.phase = phaseDone
		// D-11 chained-modal pattern: pop self, push M-PASSWORD with the
		// just-created username + AutoGenerateMode. The handoff is a
		// single tea.Batch so the nav stack mutates atomically.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("user " + m.username() + " created — set password")
		return m, tea.Batch(
			nav.PopCmd(),
			nav.PushCmd(password.New(m.ops, m.username(), password.AutoGenerateMode)),
			flashCmd,
		)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	if m.editing {
		return m, m.routeEditingMsg(msg)
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// routeEditingMsg forwards a non-keypress message into the active textinput.
func (m *Model) routeEditingMsg(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch m.cursor {
	case fieldUsername:
		m.usernameTI, cmd = m.usernameTI.Update(msg)
	case fieldUID:
		m.uidTI, cmd = m.uidTI.Update(msg)
	case fieldHome:
		m.homeTI, cmd = m.homeTI.Update(msg)
	case fieldPrimaryGroup:
		m.primaryGroupTI, cmd = m.primaryGroupTI.Update(msg)
	}
	return cmd
}

// handleKey dispatches by phase. phaseEditing splits further between
// in-textinput-edit and field-list-navigation.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	if m.phase != phaseEditing && m.phase != phaseError {
		// Spinner phases ignore keypresses; let Esc back-out from error.
		if m.phase == phaseError && (msg.String() == "esc" || msg.String() == "q") {
			return m, nav.PopCmd()
		}
		return m, nil
	}
	if m.phase == phaseError {
		switch msg.String() {
		case "esc", "q":
			return m, nav.PopCmd()
		}
		return m, nil
	}
	if m.editing {
		return m.handleEditKey(msg)
	}
	return m.handleNavKey(msg)
}

// handleNavKey routes keys when NOT editing a textinput.
func (m *Model) handleNavKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "j", "down", "tab":
		if m.cursor < fieldKindCount-1 {
			m.cursor++
		}
		return m, nil
	case "k", "up", "shift+tab":
		if m.cursor > fieldUsername {
			m.cursor--
		}
		return m, nil
	case "n":
		if m.cursor == fieldSftpJailer {
			m.sftpJailerMember = !m.sftpJailerMember
		}
		return m, nil
	case " ", "space":
		if m.cursor == fieldSftpJailer {
			m.sftpJailerMember = !m.sftpJailerMember
		}
		return m, nil
	case "enter":
		if m.cursor == fieldCreate {
			return m, m.attemptSubmit()
		}
		// Enter on a non-create row enters edit mode for that field.
		return m.beginEdit()
	case "e":
		// Same as Enter for non-create rows.
		if m.cursor == fieldCreate {
			return m, nil
		}
		return m.beginEdit()
	}
	return m, nil
}

// beginEdit focuses the textinput corresponding to the current cursor.
//
// Mirrors the settings.go edit-mode placeholder-not-seed discipline: the
// current value moves to the placeholder slot and the textinput is cleared
// so subsequent keys REPLACE rather than APPEND. textinput.Focus places
// the cursor at end-of-content, so SetValue(prior) + Focus would extend
// rather than overwrite — this clearing makes the typing match what the
// admin expects ("type a fresh value"). The plan calls this out as the
// canonical pattern in 02-07's edit-mode summary.
func (m *Model) beginEdit() (nav.Screen, tea.Cmd) {
	if m.cursor == fieldSftpJailer || m.cursor == fieldCreate {
		// Booleans + the action button don't have textinput edit mode.
		return m, nil
	}
	m.editing = true
	m.errInline = ""
	switch m.cursor {
	case fieldUsername:
		m.usernameTI.Placeholder = m.usernameTI.Value()
		m.usernameTI.SetValue("")
		return m, m.usernameTI.Focus()
	case fieldUID:
		m.uidTI.Placeholder = m.uidTI.Value()
		m.uidTI.SetValue("")
		return m, m.uidTI.Focus()
	case fieldHome:
		m.homeTI.Placeholder = m.homeTI.Value()
		m.homeTI.SetValue("")
		return m, m.homeTI.Focus()
	case fieldPrimaryGroup:
		m.primaryGroupTI.Placeholder = m.primaryGroupTI.Value()
		m.primaryGroupTI.SetValue("")
		return m, m.primaryGroupTI.Focus()
	}
	return m, nil
}

// handleEditKey routes keys when editing a textinput. Esc cancels edit;
// Enter commits (re-enters nav mode); other keys forward to the textinput.
func (m *Model) handleEditKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		m.blurAll()
		return m, nil
	case "enter":
		m.editing = false
		m.blurAll()
		return m, nil
	}
	cmd := m.routeEditingMsg(msg)
	return m, cmd
}

func (m *Model) blurAll() {
	m.usernameTI.Blur()
	m.uidTI.Blur()
	m.homeTI.Blur()
	m.primaryGroupTI.Blur()
}

// username returns the current username value (trimmed). Used by the
// chained-modal handoff so it doesn't have to depend on the textinput
// internals.
func (m *Model) username() string {
	return strings.TrimSpace(m.usernameTI.Value())
}

// derivedHome returns the home path the modal will use at submit. Falls
// back to <chrootRoot>/<username> when the admin left the home textinput
// blank (D-12).
func (m *Model) derivedHome() string {
	if v := strings.TrimSpace(m.homeTI.Value()); v != "" {
		return v
	}
	return strings.TrimRight(m.chrootRoot, "/") + "/" + m.username()
}

// derivedPrimaryGroup returns the primary group at submit. Defaults to
// the username (UPG convention) when blank.
func (m *Model) derivedPrimaryGroup() string {
	if v := strings.TrimSpace(m.primaryGroupTI.Value()); v != "" {
		return v
	}
	return m.username()
}

// parsedUID returns the textinput's UID as int. Validation lives in
// validate(); parsedUID only handles the conversion.
func (m *Model) parsedUID() (int, error) {
	v := strings.TrimSpace(m.uidTI.Value())
	uid, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("uid %q is not a number", v)
	}
	return uid, nil
}

// validate runs synchronous form validation BEFORE attempting to submit.
// Returns ("", nil) on success or (errMsg, nil) on failure (the caller
// surfaces errMsg as errInline). N-04 boundary cases at uidReserved=60000
// + 65535 (rejected) and 65536+ (allowed via the !inReserved check).
func (m *Model) validate() string {
	uname := m.username()
	if !usernameRegex.MatchString(uname) {
		return "username must match ^[a-z][a-z0-9_-]{0,31}$ (lowercase, no dot, no leading hyphen, 1-32 chars)"
	}
	uid, err := m.parsedUID()
	if err != nil {
		return err.Error()
	}
	if uid < uidFloor {
		return fmt.Sprintf("uid %d too low — pick %d or above (system UID range below)", uid, uidFloor)
	}
	if uid >= uidReserved && uid <= 65535 {
		// USER-04 reserved-range: 60000-65535. N-04 boundary tests pin
		// both 60000 and 65535 as rejected. 65536+ is allowed (some sites
		// use federated UID pools above the kernel sentinel).
		return fmt.Sprintf("uid %d is in the reserved Ubuntu range %d-65535 — pick %d-%d (USER-04)", uid, uidReserved, uidFloor, uidCeiling)
	}
	if m.lookupFn != nil && m.lookupFn(uid) {
		return fmt.Sprintf("uid %d is already in use — pick a different uid", uid)
	}
	home := m.derivedHome()
	if !filepath.IsAbs(home) {
		return fmt.Sprintf("home %q must be an absolute path", home)
	}
	return ""
}

// attemptSubmit validates the form, builds the txn batch, and returns a
// tea.Cmd that runs the batch off the main loop. Validation failures set
// errInline and return nil (no submit).
//
// B-03 BRANCHING (the central correctness contract this modal encodes):
//
//	if m.isOrphan:
//	    UseraddOpts{UID, GID: orphanGID, CreateHome: false, ...}
//	    steps = [Useradd, GpasswdAdd]   // SKIP Chmod + Chown
//	else (fresh-create):
//	    UseraddOpts{UID, GID: 0, CreateHome: true, ...}
//	    steps = [Useradd, GpasswdAdd, Chmod(home, 0o750), Chown(home, uid, uid)]
//
// The orphan path SKIPS Chmod + Chown because the dir already has correct
// ownership; re-applying with the resolved gid risks drift if Lookup ever
// returned a different value than the dir's actual gid (defensive).
func (m *Model) attemptSubmit() tea.Cmd {
	if errMsg := m.validate(); errMsg != "" {
		m.errInline = errMsg
		m.errFatal = true
		return nil
	}
	uname := m.username()
	uid, _ := m.parsedUID()
	home := m.derivedHome()
	memberOfSftpJailer := m.sftpJailerMember

	gid := uid
	var opts sysops.UseraddOpts
	if m.isOrphan {
		gid = m.orphanGID
		opts = sysops.UseraddOpts{
			Username:           uname,
			UID:                uid,
			GID:                gid,
			Home:               home,
			Shell:              "/usr/sbin/nologin",
			CreateHome:         false,
			MemberOfSftpJailer: memberOfSftpJailer,
		}
	} else {
		opts = sysops.UseraddOpts{
			Username:           uname,
			UID:                uid,
			GID:                0, // UPG — useradd creates same-name group
			Home:               home,
			Shell:              "/usr/sbin/nologin",
			CreateHome:         true,
			MemberOfSftpJailer: memberOfSftpJailer,
		}
	}

	steps := []txn.Step{txn.NewUseraddStep(opts)}
	if memberOfSftpJailer {
		steps = append(steps, txn.NewGpasswdAddStep(uname, "sftp-jailer"))
	}
	if !m.isOrphan {
		// Fresh-create: own + secure the home dir useradd just created.
		// SKIPPED for orphan path per B-03 (see godoc).
		steps = append(steps,
			txn.NewChmodStep(home, 0o750),
			txn.NewChownStep(home, uid, gid),
		)
	}

	m.phase = phaseSubmitting
	m.errInline = ""
	ops := m.ops
	if ops == nil {
		// Test path: the test will FeedSubmitDoneForTest manually.
		return m.spinner.Tick
	}
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			tx := txn.New(ops)
			return submitDoneMsg{err: tx.Apply(ctx, steps)}
		},
	)
}

// View renders the modal body.
func (m *Model) View() string {
	var b strings.Builder
	switch m.phase {
	case phasePreflight:
		b.WriteString(m.spinner.View() + " preflight: /etc/shells + chroot chain…")
	case phaseSubmitting:
		b.WriteString(m.spinner.View() + " creating user (useradd → gpasswd → chmod → chown)…")
	case phaseDone:
		b.WriteString(styles.Success.Render("✓ user created — opening password modal…"))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n[esc] back")
	case phaseEditing:
		title := "M-NEW-USER — fresh create"
		if m.isOrphan {
			title = "M-NEW-USER — orphan reconcile"
		}
		b.WriteString(styles.Primary.Render(title))
		b.WriteString("\n\n")
		if m.isOrphan {
			b.WriteString(styles.Warn.Render(
				"orphan reconcile mode — UID and GID inferred from existing directory; useradd will use -u/-g and SKIP the chmod/chown steps to preserve current ownership."))
			b.WriteString("\n\n")
		}
		// Render each field row.
		for k := fieldUsername; k < fieldKindCount; k++ {
			marker := "  "
			if k == m.cursor {
				marker = "▌ "
			}
			label := k.label()
			var value string
			switch k {
			case fieldUsername:
				value = m.fieldRender(k, m.usernameTI, m.usernameTI.Value(), "(letters/digits/_/-, 1-32 chars)")
			case fieldUID:
				value = m.fieldRender(k, m.uidTI, m.uidTI.Value(), fmt.Sprintf("(%d-%d)", uidFloor, uidCeiling))
			case fieldHome:
				v := m.homeTI.Value()
				if !m.editing && strings.TrimSpace(v) == "" {
					v = styles.Dim.Render(m.derivedHome() + " (auto-derived)")
				}
				value = m.fieldRender(k, m.homeTI, v, "")
			case fieldPrimaryGroup:
				v := m.primaryGroupTI.Value()
				if !m.editing && strings.TrimSpace(v) == "" {
					v = styles.Dim.Render(m.derivedPrimaryGroup() + " (auto-derived)")
				}
				value = m.fieldRender(k, m.primaryGroupTI, v, "")
			case fieldSftpJailer:
				if m.sftpJailerMember {
					value = "[✓] add to sftp-jailer group"
				} else {
					value = "[ ] add to sftp-jailer group"
				}
			case fieldCreate:
				if m.isOrphan {
					value = styles.Primary.Render("[create — orphan reconcile]")
				} else {
					value = styles.Primary.Render("[create]")
				}
			}
			row := fmt.Sprintf("%s%-22s %s", marker, label+":", value)
			b.WriteString(row)
			b.WriteString("\n")
			if k == m.cursor && m.errInline != "" {
				style := styles.Warn
				if m.errFatal {
					style = styles.Critical
				}
				b.WriteString("    ")
				b.WriteString(style.Render(m.errInline))
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
		if m.editing {
			b.WriteString(styles.Dim.Render("enter·commit  esc·cancel-edit"))
		} else {
			b.WriteString(styles.Dim.Render("↑↓·move  enter·edit  enter-on-[create]·submit  esc·back"))
		}
	}
	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n" + ts)
	}
	return wrapModal(b.String())
}

// fieldRender returns the per-row value cell — textinput.View when editing
// the row, plain string otherwise.
func (m *Model) fieldRender(k fieldKind, ti textinput.Model, plainValue, hint string) string {
	if m.editing && k == m.cursor {
		v := ti.View()
		if hint != "" {
			v += "  " + styles.Dim.Render(hint)
		}
		return v
	}
	if plainValue == "" {
		plainValue = styles.Dim.Render("(empty)")
	}
	if hint != "" {
		return plainValue + "  " + styles.Dim.Render(hint)
	}
	return plainValue
}

// wrapModal applies the M-OBSERVE-style border (UI-SPEC line 46).
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// KeyMap describes the modal's bindings. Implements nav.KeyMap.
type KeyMap struct {
	Cancel  nav.KeyBinding
	Move    nav.KeyBinding
	Edit    nav.KeyBinding
	Toggle  nav.KeyBinding
	Submit  nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-NEW-USER bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel: nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		Move:   nav.KeyBinding{Keys: []string{"↑", "↓", "j", "k", "tab"}, Help: "move"},
		Edit:   nav.KeyBinding{Keys: []string{"enter", "e"}, Help: "edit field"},
		Toggle: nav.KeyBinding{Keys: []string{"n", "space"}, Help: "toggle checkbox"},
		Submit: nav.KeyBinding{Keys: []string{"enter"}, Help: "create (on [create] row)"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Move, k.Edit, k.Submit}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Move},
		{k.Edit, k.Toggle, k.Submit},
	}
}

// autoPickUID returns the lowest UID >= uidFloor not currently in use
// (per the lookup seam). Caps at uidCeiling so the picker never lands in
// the reserved range. If no slot found, returns uidFloor (the modal's
// validate() will catch this on submit and let the admin pick manually).
func autoPickUID(lookup userLookupFn) int {
	if lookup == nil {
		return uidFloor
	}
	for uid := uidFloor; uid <= uidCeiling; uid++ {
		if !lookup(uid) {
			return uid
		}
	}
	return uidFloor
}
