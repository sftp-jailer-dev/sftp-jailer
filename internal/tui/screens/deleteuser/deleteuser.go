// Package deleteuser renders M-DELETE-USER — the D-15 destructive
// modal pushed from S-USERS via 'd' (plan 03-08a).
//
// Two paths, both running as a single internal/txn batch:
//
//   - PERMANENT (default focus per D-15 — admin types the username
//     verbatim into the confirm field as the irreversibility gate, then
//     submits a 1-step txn: [Userdel(removeHome=true)]). The
//     type-username gate is the deliberate friction; once the username
//     matches, Enter activates the [Permanent] button.
//
//   - ARCHIVE (admin tabs to it; Enter starts immediately — no
//     type-username gate). Runs a 3-step txn:
//     [MkdirAll(/var/lib/sftp-jailer/archive 0700),
//      Tar(<archive>/<user>-<ISO>.tar.gz, source=<home>),
//      Userdel(removeHome=false)]. On Tar failure, the Tar step's
//     compensator removes the partial tarball (NewTarStep.Compensate →
//     ops.RemoveAll). MkdirAll's compensator removes the archive dir
//     iff it didn't exist before the batch (W-02).
//
// Async metadata load: on Init, the modal walks the user's home dir
// (via ops.ReadDir + ops.Lstat — strictly through the sysops seam, no
// raw os.Walk per the architectural invariant) to compute total bytes
// and a count of authorized_keys. The result drives the review-phase
// View ("3.4 MiB · 2 keys") so admins know what they're about to
// destroy.
//
// Test seams (LoadMetaForTest, FeedSubmitDoneForTest) bypass the async
// loaders so unit tests assert on phase transitions and txn-step
// composition without spinning up goroutines.
package deleteuser

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/dustin/go-humanize"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// ArchiveDir is the canonical destination for D-15 Archive tarballs.
// Per plan 02-09 README the parent /var/lib/sftp-jailer/ is mode 0700
// owned root:root; this subdir inherits + is created mode 0700 by the
// MkdirAll txn step (T-03-08a-05 mitigation).
const ArchiveDir = "/var/lib/sftp-jailer/archive"

// AutoPopDelay is how long the modal lingers in phaseDone before
// auto-popping back to S-USERS.
const AutoPopDelay = 500 * time.Millisecond

// Mode discriminates the two delete strategies.
type Mode int

const (
	// ModePermanent runs userdel -r (irreversible — deletes the home
	// dir). Default focus per D-15. Requires typing the username verbatim
	// into the confirm field before [Permanent] activates.
	ModePermanent Mode = iota
	// ModeArchive runs MkdirAll + Tar + Userdel (no -r). The home
	// directory survives only as the tarball at
	// /var/lib/sftp-jailer/archive/<user>-<ISO>.tar.gz.
	ModeArchive
)

// phase tracks the modal's state-machine position.
type phase int

const (
	// phaseLoading — async meta-load (size + key count) in flight.
	phaseLoading phase = iota
	// phaseReview — admin reviews size + keys count, picks Permanent or
	// Archive, then either presses Enter to submit (Archive) OR enters
	// the type-username confirm (Permanent).
	phaseReview
	// phaseConfirmingPermanent — admin is typing the username verbatim
	// into the confirm textinput. Submit gated on
	// strings.TrimSpace(confirmTI.Value()) == username.
	phaseConfirmingPermanent
	// phaseSubmitting — txn batch in flight.
	phaseSubmitting
	// phaseDone — txn succeeded; auto-pop after AutoPopDelay.
	phaseDone
	// phaseError — txn rolled back; errInline carries the error.
	phaseError
)

// metaLoadedMsg carries the async meta-load result back to Update.
type metaLoadedMsg struct {
	size      int64
	keysCount int
	err       error
}

// submitDoneMsg carries the txn-batch outcome.
type submitDoneMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that pops after a successful submit.
type autoPopMsg struct{}

// Model is the M-DELETE-USER Bubble Tea v2 model.
type Model struct {
	ops        sysops.SystemOps
	chrootRoot string
	username   string
	home       string

	// Loaded meta.
	dirSize   int64
	keysCount int

	mode      Mode
	confirmTI textinput.Model

	phase     phase
	errInline string
	spinner   spinner.Model
	toast     widgets.Toast
	keyMap    KeyMap

	// nowFn is the time-source seam for the archive ISO timestamp.
	// Production binds time.Now; tests inject a frozen clock so the
	// archive path is deterministic.
	nowFn func() time.Time
}

// New constructs the modal for username at home under chrootRoot. ops
// may be nil in unit tests that drive Update via test seams.
func New(ops sysops.SystemOps, chrootRoot, username, home string) *Model {
	confirmTI := textinput.New()
	confirmTI.Prompt = ""
	confirmTI.CharLimit = 64
	confirmTI.Placeholder = username
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	return &Model{
		ops:        ops,
		chrootRoot: chrootRoot,
		username:   username,
		home:       home,
		mode:       ModePermanent, // D-15: default focus
		confirmTI:  confirmTI,
		phase:      phaseLoading,
		spinner:    sp,
		keyMap:     DefaultKeyMap(),
		nowFn:      time.Now,
	}
}

// LoadMetaForTest bypasses the async meta-load and seeds the model
// directly. Mirrors the LoadXForTest pattern from users.go.
func (m *Model) LoadMetaForTest(size int64, keysCount int) {
	m.dirSize = size
	m.keysCount = keysCount
	m.phase = phaseReview
	m.errInline = ""
}

// SetNowFnForTest pins the time-source for deterministic archive paths.
func (m *Model) SetNowFnForTest(fn func() time.Time) { m.nowFn = fn }

// FeedSubmitDoneForTest delivers a synthesized submitDoneMsg to Update.
func (m *Model) FeedSubmitDoneForTest(err error) (nav.Screen, tea.Cmd) {
	return m.Update(submitDoneMsg{err: err})
}

// ModeForTest exposes the mode field for assertions.
func (m *Model) ModeForTest() Mode { return m.mode }

// PhaseForTest exposes the unexported phase as an int for assertions.
func (m *Model) PhaseForTest() int { return int(m.phase) }

// ErrInlineForTest exposes the inline error string for assertions.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// SetConfirmTextForTest pokes the confirm textinput's value (avoids
// having to drive char-by-char keypresses through the bubbles textinput).
func (m *Model) SetConfirmTextForTest(s string) { m.confirmTI.SetValue(s) }

// Phase constants exported under the For-Test suffix so tests can
// reference state-machine values without importing the private type.
const (
	PhaseLoadingForTest             = int(phaseLoading)
	PhaseReviewForTest              = int(phaseReview)
	PhaseConfirmingPermanentForTest = int(phaseConfirmingPermanent)
	PhaseSubmittingForTest          = int(phaseSubmitting)
	PhaseDoneForTest                = int(phaseDone)
	PhaseErrorForTest               = int(phaseError)
)

// Title implements nav.Screen.
func (m *Model) Title() string { return "delete user — " + m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keyMap }

// WantsRawKeys implements nav.Screen — true while in the
// type-username-to-confirm phase so the root App forwards every
// keystroke (including 'q', 's') into the textinput.
func (m *Model) WantsRawKeys() bool { return m.phase == phaseConfirmingPermanent }

// Init kicks off the spinner ticker + the async meta-load. Returns
// only the spinner ticker if ops is nil (test path).
func (m *Model) Init() tea.Cmd {
	tickCmd := func() tea.Msg { return m.spinner.Tick() }
	if m.ops == nil {
		return tickCmd
	}
	return tea.Batch(tickCmd, m.startMetaLoad())
}

// startMetaLoad walks the user's home dir to compute total bytes and
// counts the authorized_keys file. Returns metaLoadedMsg.
func (m *Model) startMetaLoad() tea.Cmd {
	ops, home, root, user := m.ops, m.home, m.chrootRoot, m.username
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		size, err := walkSize(ctx, ops, home)
		if err != nil {
			return metaLoadedMsg{err: err}
		}
		// Count keys in <chrootRoot>/<user>/.ssh/authorized_keys (D-17
		// canonical path). 0 if file missing or unparseable — the keys
		// count is informational, not gating.
		keysCount := countAuthorizedKeys(ctx, ops, root, user)
		return metaLoadedMsg{size: size, keysCount: keysCount}
	}
}

// walkSize sums Lstat sizes of every regular file rooted at dir,
// purely through the sysops seam (ops.ReadDir + ops.Lstat). Symlinks
// are NOT followed (Lstat-not-Stat semantics). Returns 0 + nil if dir
// is missing — empty-home users are valid (no UX block).
func walkSize(ctx context.Context, ops sysops.SystemOps, dir string) (int64, error) {
	if dir == "" {
		return 0, nil
	}
	fi, err := ops.Lstat(ctx, dir)
	if err != nil {
		// Missing home → 0 size, no error. Admin sees "0 B" and
		// proceeds (the dir genuinely has nothing to delete).
		return 0, nil
	}
	if !fi.IsDir {
		// Not a directory — degenerate case, return 0.
		return 0, nil
	}
	var total int64
	var walk func(path string) error
	walk = func(path string) error {
		entries, err := ops.ReadDir(ctx, path)
		if err != nil {
			// Skip unreadable subdirs without aborting the whole walk —
			// we surface a best-effort size, not an exact one.
			return nil
		}
		for _, e := range entries {
			child := filepath.Join(path, e.Name())
			cfi, lerr := ops.Lstat(ctx, child)
			if lerr != nil {
				continue
			}
			if cfi.IsDir {
				_ = walk(child)
				continue
			}
			if cfi.IsLink {
				continue // don't follow symlinks; their target is owned by another tree
			}
			// FileInfo has no size field — approximate by reading the
			// file. For sftp home dirs (typically a handful of small
			// files at most) this is acceptable. Future plan can add
			// FileInfo.Size if a sftp home ever grows large enough to
			// notice the read overhead.
			b, rerr := ops.ReadFile(ctx, child)
			if rerr != nil {
				continue
			}
			total += int64(len(b))
		}
		return nil
	}
	_ = walk(dir)
	return total, nil
}

// countAuthorizedKeys reads the user's authorized_keys file and counts
// non-blank, non-comment lines. 0 on any error (file missing,
// unreadable). Result is informational — never gates the delete.
func countAuthorizedKeys(ctx context.Context, ops sysops.SystemOps, chrootRoot, username string) int {
	authPath := filepath.Join(chrootRoot, username, ".ssh", "authorized_keys")
	content, err := ops.ReadFile(ctx, authPath)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		count++
	}
	return count
}

// Update implements nav.Screen.
//
//nolint:gocyclo // top-level dispatch over async messages + per-phase keypress routing
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case metaLoadedMsg:
		if msg.err != nil {
			m.errInline = "could not load metadata: " + msg.err.Error()
			m.phase = phaseError
			return m, nil
		}
		m.dirSize = msg.size
		m.keysCount = msg.keysCount
		m.phase = phaseReview
		return m, nil

	case submitDoneMsg:
		if msg.err != nil {
			m.errInline = "delete failed: " + msg.err.Error()
			m.phase = phaseError
			return m, nil
		}
		m.phase = phaseDone
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("deleted user " + m.username)
		return m, tea.Batch(
			flashCmd,
			tea.Tick(AutoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} }),
		)

	case autoPopMsg:
		return m, nav.PopCmd()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	if m.phase == phaseConfirmingPermanent {
		var cmd tea.Cmd
		m.confirmTI, cmd = m.confirmTI.Update(msg)
		return m, cmd
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches per phase.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch m.phase {
	case phaseReview:
		return m.handleReviewKey(msg)
	case phaseConfirmingPermanent:
		return m.handleConfirmKey(msg)
	case phaseError:
		return m.handleErrorKey(msg)
	case phaseLoading, phaseSubmitting, phaseDone:
		// Esc still backs out from done / loading / submitting so admins
		// can leave fast.
		if msg.String() == "esc" || msg.String() == "q" {
			return m, nav.PopCmd()
		}
		return m, nil
	}
	return m, nil
}

// handleReviewKey dispatches keys while the modal is showing the review
// surface. Tab toggles mode; Enter starts the next step (confirm typing
// for Permanent, immediate submit for Archive); Esc cancels.
func (m *Model) handleReviewKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "tab":
		if m.mode == ModePermanent {
			m.mode = ModeArchive
		} else {
			m.mode = ModePermanent
		}
		m.errInline = ""
		return m, nil
	case "enter":
		switch m.mode {
		case ModePermanent:
			// Move into the type-username confirm phase.
			m.phase = phaseConfirmingPermanent
			m.errInline = ""
			return m, m.confirmTI.Focus()
		case ModeArchive:
			return m, m.startSubmit()
		}
	}
	return m, nil
}

// handleConfirmKey dispatches keys while the admin is typing the
// username confirm field for the Permanent path.
func (m *Model) handleConfirmKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Back out of confirm to review without losing the typed text;
		// admin can tab to Archive or re-enter confirm.
		m.phase = phaseReview
		m.errInline = ""
		m.confirmTI.Blur()
		return m, nil
	case "enter":
		typed := strings.TrimSpace(m.confirmTI.Value())
		if typed != m.username {
			m.errInline = "type the username verbatim to confirm — irreversible"
			return m, nil
		}
		return m, m.startSubmit()
	}
	var cmd tea.Cmd
	m.confirmTI, cmd = m.confirmTI.Update(msg)
	return m, cmd
}

// handleErrorKey lets admin Esc out of the error surface.
func (m *Model) handleErrorKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	if msg.String() == "esc" || msg.String() == "q" {
		return m, nav.PopCmd()
	}
	return m, nil
}

// startSubmit returns the tea.Cmd that runs the chosen path's txn batch.
func (m *Model) startSubmit() tea.Cmd {
	m.phase = phaseSubmitting
	if m.ops == nil {
		// Test path — caller drives FeedSubmitDoneForTest manually.
		return func() tea.Msg { return m.spinner.Tick() }
	}
	steps := m.composeSteps()
	ops := m.ops
	return tea.Batch(
		func() tea.Msg { return m.spinner.Tick() },
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			tx := txn.New(ops)
			if err := tx.Apply(ctx, steps); err != nil {
				return submitDoneMsg{err: err}
			}
			return submitDoneMsg{err: nil}
		},
	)
}

// composeSteps builds the txn step list for the current mode.
//
//   - ModePermanent: 1-step batch [Userdel(removeHome=true)]
//   - ModeArchive:   3-step batch [MkdirAll(0o700), Tar(czf <archive>),
//                                   Userdel(removeHome=false)]
//
// ArchivePath uses an ISO-8601 compact UTC timestamp (matches plan
// 03-05's NewWriteSshdDropInStep convention).
func (m *Model) composeSteps() []txn.Step {
	switch m.mode {
	case ModePermanent:
		return []txn.Step{
			txn.NewUserdelStep(m.username, true),
		}
	case ModeArchive:
		ts := m.nowFn().UTC().Format("20060102T150405Z")
		archive := filepath.Join(ArchiveDir, m.username+"-"+ts+".tar.gz")
		return []txn.Step{
			// W-02: MkdirAll uses ops.MkdirAll typed wrapper. uid=0,
			// gid=0 (root:root) per T-03-08a-05 mitigation.
			txn.NewMkdirAllStep(ArchiveDir, 0o700, 0, 0),
			txn.NewTarStep(sysops.TarOpts{
				Mode:        sysops.TarCreateGzip,
				ArchivePath: archive,
				SourceDir:   m.home,
			}),
			// removeHome=false because the tar already preserved the
			// content; keeping the dir-residue on disk lets the admin
			// inspect leftovers without restoring from the archive.
			txn.NewUserdelStep(m.username, false),
		}
	}
	return nil
}

// ComposeStepsForTest exposes composeSteps for assertions on the txn
// batch shape per-mode (test 7 + 8).
func (m *Model) ComposeStepsForTest() []txn.Step { return m.composeSteps() }

// View renders the modal body wrapped in the M-OBSERVE-style border.
//
//nolint:gocyclo // per-phase rendering switch
func (m *Model) View() string {
	var b strings.Builder
	switch m.phase {
	case phaseLoading:
		b.WriteString(m.spinner.View() + " loading user metadata…")
	case phaseReview:
		m.renderReview(&b)
	case phaseConfirmingPermanent:
		m.renderConfirm(&b)
	case phaseSubmitting:
		b.WriteString(m.spinner.View() + " " + m.submittingLabel())
	case phaseDone:
		b.WriteString(styles.Success.Render("✓ deleted user " + m.username))
	case phaseError:
		b.WriteString(styles.Critical.Render(m.errInline))
		b.WriteString("\n\n[esc] back")
	}
	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n" + ts)
	}
	return wrapModal(b.String())
}

func (m *Model) submittingLabel() string {
	if m.mode == ModeArchive {
		return "archiving + deleting…"
	}
	return "deleting…"
}

func (m *Model) renderReview(b *strings.Builder) {
	b.WriteString(styles.Primary.Render("M-DELETE-USER — " + m.username))
	b.WriteString("\n\n")
	b.WriteString("chroot path:  " + m.home)
	b.WriteString("\n")
	// dirSize is always >= 0 (walkSize accumulates non-negative file
	// sizes); the gosec G115 conversion guard is satisfied by the
	// max(0, ...) clamp.
	size := m.dirSize
	if size < 0 {
		size = 0
	}
	fmt.Fprintf(b, "contents:     %s · %d keys", humanize.IBytes(uint64(size)), m.keysCount) //nolint:gosec // G115: clamped to >= 0 above
	b.WriteString("\n")
	if m.mode == ModeArchive {
		ts := m.nowFn().UTC().Format("20060102T150405Z")
		archive := filepath.Join(ArchiveDir, m.username+"-"+ts+".tar.gz")
		b.WriteString("archive will land at: " + archive)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.modeButtonsRow())
	b.WriteString("\n\n")
	b.WriteString(styles.Dim.Render("[tab] toggle mode   [enter] proceed   [esc] cancel"))
}

func (m *Model) modeButtonsRow() string {
	permLabel := "[Permanent]"
	archLabel := "[Archive]"
	if m.mode == ModePermanent {
		permLabel = styles.Primary.Render("▶ " + permLabel)
		archLabel = styles.Dim.Render("  " + archLabel)
	} else {
		permLabel = styles.Dim.Render("  " + permLabel)
		archLabel = styles.Primary.Render("▶ " + archLabel)
	}
	return permLabel + "    " + archLabel
}

func (m *Model) renderConfirm(b *strings.Builder) {
	b.WriteString(styles.Primary.Render("M-DELETE-USER — " + m.username))
	b.WriteString("\n\n")
	b.WriteString(styles.Critical.Render("⚠ Permanent deletion is IRREVERSIBLE."))
	b.WriteString("\n\n")
	b.WriteString("Type the username verbatim to confirm:\n  ")
	b.WriteString(m.confirmTI.View())
	if m.errInline != "" {
		b.WriteString("\n  " + styles.Critical.Render(m.errInline))
	}
	b.WriteString("\n\n")
	b.WriteString(styles.Dim.Render("[enter] confirm + delete   [esc] back"))
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2).
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// KeyMap describes the modal's bindings — implements nav.KeyMap.
type KeyMap struct {
	Cancel  nav.KeyBinding
	Toggle  nav.KeyBinding
	Submit  nav.KeyBinding
	Confirm nav.KeyBinding
}

// DefaultKeyMap returns the canonical M-DELETE-USER bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Cancel:  nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "cancel"},
		Toggle:  nav.KeyBinding{Keys: []string{"tab"}, Help: "toggle Permanent/Archive"},
		Submit:  nav.KeyBinding{Keys: []string{"enter"}, Help: "proceed (Permanent → confirm; Archive → submit)"},
		Confirm: nav.KeyBinding{Keys: []string{"enter"}, Help: "type username to confirm Permanent"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Toggle, k.Submit}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Toggle},
		{k.Submit, k.Confirm},
	}
}
