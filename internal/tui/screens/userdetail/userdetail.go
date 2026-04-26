// Package userdetail renders S-USER-DETAIL — the per-user authorized-keys
// surface pushed from S-USERS via 'k' or Enter on a real row (plan 03-08a
// per phase 03 D-22).
//
// Capabilities:
//
//   - Async-loads the user's authorized_keys file via ops.ReadFile +
//     ops.Lstat (FileInfo.ModTime per plan 03-01 B-06 — the "added on"
//     column).
//   - Renders one row per key with algorithm / SHA256 fingerprint /
//     comment / wire-byte size / humanized "added X ago" timestamp
//     (single-source ModTime — sshd reads the file before chroot, so the
//     mtime IS the upload time for the most recent key).
//   - Key delete (D-22) via single-key txn batch:
//     [WriteAuthorizedKeys, VerifyAuthKeys] using the chrootcheck
//     CheckAuthKeysFile verifier wrapped in [txn.NewVerifyAuthKeysStep].
//     On verify failure, the WriteAuthorizedKeysStep compensator restores
//     the prior file content automatically.
//   - 'p' pushes M-PASSWORD for this user (plan 03-07's password.New).
//   - 'c' copies the selected key's fingerprint via OSC 52 + toast.
//   - 'a' pushes M-ADD-KEY (addkey.New) — single-textarea entry surface
//     that auto-detects per-line source (paste / gh:user / file path)
//     per D-19, surfaces a mandatory review table per D-20, and commits
//     via the four-step StrictModes verifier with rollback per D-21.
//
// Test seams (LoadKeysForTest, etc.) bypass Init's async load so unit
// tests assert on render + dispatch without spinning up the goroutine.
package userdetail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/dustin/go-humanize"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/addkey"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// keysLoadedMsg carries the async-load result back to Update.
type keysLoadedMsg struct {
	exists bool
	keys   []keys.ParsedKey
	mtime  time.Time
	err    error
}

// keyDeletedMsg carries the result of the single-key delete txn back to
// Update. On success, the model re-loads the authorized_keys file (so the
// table reflects the new state and the mtime updates).
type keyDeletedMsg struct {
	deletedFingerprint string
	err                error
}

// Model is the S-USER-DETAIL Bubble Tea v2 model.
type Model struct {
	ops        sysops.SystemOps
	chrootRoot string
	username   string

	keys           []keys.ParsedKey
	keysFileExists bool
	keysFileMtime  time.Time

	cursor    int
	loading   bool
	errText   string
	toast     widgets.Toast
	keyMap    KeyMap

	// verifierFn is the chrootcheck.CheckAuthKeysFile seam — production
	// binds the real verifier; tests can override via SetVerifierForTest
	// to script a violation slice for the rollback-on-verify-failure path.
	verifierFn func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]txn.VerifyViolation, error)
}

// New constructs the screen for username + chrootRoot. ops may be nil in
// unit tests that call LoadKeysForTest directly.
func New(ops sysops.SystemOps, chrootRoot, username string) *Model {
	return &Model{
		ops:        ops,
		chrootRoot: chrootRoot,
		username:   username,
		loading:    true,
		keyMap:     DefaultKeyMap(),
		verifierFn: defaultVerifier,
	}
}

// defaultVerifier wraps chrootcheck.CheckAuthKeysFile and adapts its
// []chrootcheck.Violation return into []txn.VerifyViolation so the txn
// VerifyAuthKeys step doesn't pull chrootcheck transitively.
func defaultVerifier(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]txn.VerifyViolation, error) {
	vios, err := chrootcheck.CheckAuthKeysFile(ctx, ops, username, chrootRoot)
	if err != nil {
		return nil, err
	}
	out := make([]txn.VerifyViolation, len(vios))
	for i, v := range vios {
		out[i] = txn.VerifyViolation{Path: v.Path, Reason: v.Reason}
	}
	return out, nil
}

// LoadKeysForTest bypasses Init's async load and seeds the model
// directly. Mirrors users.LoadRowsForTest. mtime is the FileInfo.ModTime
// the screen would otherwise read via Lstat (B-06 plumbing).
func (m *Model) LoadKeysForTest(parsed []keys.ParsedKey, mtime time.Time) {
	m.loading = false
	m.keys = parsed
	m.keysFileExists = true
	m.keysFileMtime = mtime
	m.errText = ""
}

// LoadEmptyForTest seeds the "no authorized_keys file yet" fresh-user
// state. From this state, pressing 'a' pushes M-ADD-KEY (addkey.New).
func (m *Model) LoadEmptyForTest() {
	m.loading = false
	m.keys = nil
	m.keysFileExists = false
	m.errText = ""
}

// SetVerifierForTest overrides the chrootcheck.CheckAuthKeysFile seam.
// Tests use this to script a violation slice for the
// "verifier-fails-rolls-back-write" path (test 7).
func (m *Model) SetVerifierForTest(fn func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]txn.VerifyViolation, error)) {
	m.verifierFn = fn
}

// SetCursorForTest exposes a direct cursor poke so unit tests don't
// need to drive j/k navigation.
func (m *Model) SetCursorForTest(idx int) { m.cursor = idx }

// CursorForTest exposes the cursor index for assertions.
func (m *Model) CursorForTest() int { return m.cursor }

// KeysCountForTest exposes the loaded key count.
func (m *Model) KeysCountForTest() int { return len(m.keys) }

// MtimeForTest exposes the loaded file mtime so tests can confirm the
// B-06 FileInfo.ModTime plumbing populated it.
func (m *Model) MtimeForTest() time.Time { return m.keysFileMtime }

// UsernameForTest exposes the username for cross-modal handoff
// assertions (e.g. 'p' push to M-PASSWORD).
func (m *Model) UsernameForTest() string { return m.username }

// Title implements nav.Screen.
func (m *Model) Title() string { return "user detail — " + m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keyMap }

// WantsRawKeys implements nav.Screen — false (no textinput on this
// screen; every key is either a single-letter binding or navigation).
func (m *Model) WantsRawKeys() bool { return false }

// Init kicks off the async authorized_keys load. Returns nil if ops is
// nil (test path; LoadKeysForTest seeds state directly).
func (m *Model) Init() tea.Cmd {
	if m.ops == nil {
		return nil
	}
	ops, root, user := m.ops, m.chrootRoot, m.username
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return loadKeys(ctx, ops, root, user)
	}
}

// loadKeys reads + parses the authorized_keys file for username under
// chrootRoot and returns a keysLoadedMsg. Missing file → exists=false
// (fresh-user state).
func loadKeys(ctx context.Context, ops sysops.SystemOps, chrootRoot, username string) keysLoadedMsg {
	authPath := filepath.Join(chrootRoot, username, ".ssh", "authorized_keys")
	content, err := ops.ReadFile(ctx, authPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return keysLoadedMsg{exists: false}
		}
		return keysLoadedMsg{err: err}
	}
	parsed, _ := keys.Parse(string(content))
	// Lstat the file so we can render the "added on" column with the
	// real mtime per plan 03-01 B-06 (FileInfo.ModTime).
	var mtime time.Time
	if fi, lerr := ops.Lstat(ctx, authPath); lerr == nil {
		mtime = fi.ModTime
	}
	return keysLoadedMsg{
		exists: true,
		keys:   parsed,
		mtime:  mtime,
	}
}

// Update implements nav.Screen.
func (m *Model) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case keysLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.errText = msg.err.Error()
			return m, nil
		}
		m.keysFileExists = msg.exists
		m.keys = msg.keys
		m.keysFileMtime = msg.mtime
		// Clamp cursor when the new key set shrinks below the prior
		// position (e.g. after a delete reload).
		if m.cursor >= len(m.keys) {
			m.cursor = 0
		}
		return m, nil

	case keyDeletedMsg:
		if msg.err != nil {
			m.errText = "delete failed: " + msg.err.Error()
			return m, nil
		}
		// Toast the deletion and re-load via the same async path so the
		// table reflects post-delete state + the mtime updates.
		var flashCmd tea.Cmd
		m.toast, flashCmd = m.toast.Flash("deleted " + msg.deletedFingerprint)
		m.loading = true
		ops, root, user := m.ops, m.chrootRoot, m.username
		reloadCmd := func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return loadKeys(ctx, ops, root, user)
		}
		return m, tea.Batch(flashCmd, reloadCmd)

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleKey dispatches the screen's key bindings.
func (m *Model) handleKey(msg tea.KeyPressMsg) (nav.Screen, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		return m, nav.PopCmd()
	case "j", "down":
		if m.cursor < len(m.keys)-1 {
			m.cursor++
		}
		return m, nil
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case "a":
		// 'a' pushes M-ADD-KEY (addkey.New). ops==nil is the unit-test
		// path where LoadKeysForTest seeded state without a Fake —
		// there's nothing to commit against, so return cleanly.
		if m.ops == nil {
			return m, nil
		}
		return m, nav.PushCmd(addkey.New(m.ops, m.chrootRoot, m.username))
	case "d":
		return m, m.startDeleteSelectedKey()
	case "p":
		if m.ops == nil {
			return m, nil
		}
		return m, nav.PushCmd(password.New(m.ops, m.username, password.AutoGenerateMode))
	case "c":
		return m.handleCopy()
	}
	return m, nil
}

// handleCopy emits the OSC 52 SetClipboard for the selected key's
// fingerprint and flashes a toast. No-op when there is no selection.
func (m *Model) handleCopy() (nav.Screen, tea.Cmd) {
	k := m.selectedKey()
	if k == nil {
		return m, nil
	}
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied fingerprint via OSC 52")
	return m, tea.Batch(tea.SetClipboard(k.Fingerprint), flashCmd)
}

// selectedKey returns the currently-selected ParsedKey, or nil if there
// is no selection.
func (m *Model) selectedKey() *keys.ParsedKey {
	if m.cursor < 0 || m.cursor >= len(m.keys) {
		return nil
	}
	return &m.keys[m.cursor]
}

// startDeleteSelectedKey returns the tea.Cmd that runs the D-22
// single-key delete txn batch:
//
//  1. Read current authorized_keys content (via ops.ReadFile).
//  2. Filter out the selected key's line by fingerprint match (re-parse
//     each line; keep lines whose fingerprint != target).
//  3. Run [txn.NewAtomicWriteAuthorizedKeysStep] to atomic-write the
//     reduced content.
//  4. Run [txn.NewVerifyAuthKeysStep] (chrootcheck.CheckAuthKeysFile);
//     on failure the WriteAuthorizedKeysStep compensator restores the
//     prior file content.
//
// On success returns keyDeletedMsg{deletedFingerprint: fp}; on failure
// returns keyDeletedMsg{err}.
func (m *Model) startDeleteSelectedKey() tea.Cmd {
	target := m.selectedKey()
	if target == nil || m.ops == nil {
		return nil
	}
	ops, root, user, fp := m.ops, m.chrootRoot, m.username, target.Fingerprint
	verifier := m.verifierFn
	if verifier == nil {
		verifier = defaultVerifier
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		authPath := filepath.Join(root, user, ".ssh", "authorized_keys")
		content, err := ops.ReadFile(ctx, authPath)
		if err != nil {
			return keyDeletedMsg{deletedFingerprint: fp, err: fmt.Errorf("read authorized_keys: %w", err)}
		}
		filtered, removed := filterOutFingerprint(string(content), fp)
		if !removed {
			return keyDeletedMsg{deletedFingerprint: fp, err: fmt.Errorf("fingerprint %s not found in authorized_keys", fp)}
		}
		steps := []txn.Step{
			txn.NewAtomicWriteAuthorizedKeysStep(user, root, []byte(filtered)),
			txn.NewVerifyAuthKeysStep(user, root, verifier),
		}
		tx := txn.New(ops)
		if err := tx.Apply(ctx, steps); err != nil {
			return keyDeletedMsg{deletedFingerprint: fp, err: err}
		}
		return keyDeletedMsg{deletedFingerprint: fp}
	}
}

// filterOutFingerprint walks the authorized_keys content line-by-line,
// re-parses each line via keys.Parse, and drops lines whose fingerprint
// matches target. Returns the filtered content and a bool indicating
// whether the target was found+removed (false → caller surfaces a "not
// found" error to avoid running an empty txn batch).
//
// Comment / blank lines are preserved verbatim (they don't carry
// fingerprints; they survive the filter).
func filterOutFingerprint(content, target string) (string, bool) {
	var out strings.Builder
	removed := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		parsed, _ := keys.Parse(line)
		if len(parsed) == 1 && parsed[0].Fingerprint == target {
			removed = true
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	// Drop the trailing newline we always append in the loop so
	// round-trip-empty content stays empty.
	result := out.String()
	result = strings.TrimRight(result, "\n")
	if result != "" {
		result += "\n"
	}
	return result, removed
}

// View renders the screen body wrapped in the modal-style border (the
// screen pushes from S-USERS so it visually nests inside the parent).
func (m *Model) View() string {
	if m.loading {
		return styles.Dim.Render("loading authorized keys…")
	}
	if m.errText != "" {
		return styles.Critical.Render("Could not load keys: "+m.errText) +
			"\n\n" + styles.Dim.Render("(esc to return)")
	}

	var b strings.Builder
	b.WriteString(styles.Primary.Render("user detail — " + m.username))
	b.WriteString("\n\n")

	if !m.keysFileExists || len(m.keys) == 0 {
		// Fresh-user empty state — [a] opens M-ADD-KEY (addkey.New).
		b.WriteString("no authorized_keys file yet — press [a] to add the first key")
		b.WriteString("\n\n")
		b.WriteString(styles.Dim.Render(
			"a·add key   p·set password   esc·back"))
		if ts := m.toast.View(); ts != "" {
			b.WriteString("\n")
			b.WriteString(ts)
		}
		return b.String()
	}

	// Header.
	b.WriteString(styles.Primary.Render(fmt.Sprintf(
		"  %-18s  %-50s  %-24s  %5s  %s",
		"algorithm", "fingerprint", "comment", "bytes", "added")))
	b.WriteString("\n")

	now := time.Now()
	for i, k := range m.keys {
		marker := "  "
		if i == m.cursor {
			marker = "▌ "
		}
		// Per-key "added on" — the sshd authorized_keys file has a single
		// mtime; we render the same timestamp for every row (the most-
		// recent add is what the mtime actually represents). This is
		// honest UX: we can't distinguish per-key add times from the
		// FS metadata alone.
		added := "—"
		if !m.keysFileMtime.IsZero() {
			added = humanize.RelTime(m.keysFileMtime, now, "ago", "from now")
		}
		comment := k.Comment
		if comment == "" {
			comment = "—"
		}
		row := fmt.Sprintf(
			"%s%-18s  %-50s  %-24s  %5d  %s",
			marker,
			truncate(k.Algorithm, 18),
			truncate(k.Fingerprint, 50),
			truncate(comment, 24),
			k.ByteSize,
			added,
		)
		if i == m.cursor {
			row = styles.Primary.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(
		"↑↓·move   a·add key   d·delete key   p·set password   c·copy fp   esc·back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return wrapModal(b.String())
}

// truncate clips s to width with a trailing "…" marker. Pure-display
// helper — never called on data destined for the clipboard.
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

// wrapModal applies the M-OBSERVE-style NormalBorder + Padding(0, 2).
// S-USER-DETAIL is technically a screen rather than a modal, but the
// visual nesting (pushed from S-USERS via 'k') reads better with the
// modal-style border so admins see the focus shift.
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// KeyMap describes the screen's bindings — implements nav.KeyMap.
type KeyMap struct {
	Back     nav.KeyBinding
	AddKey   nav.KeyBinding
	Delete   nav.KeyBinding
	Password nav.KeyBinding
	Copy     nav.KeyBinding
}

// DefaultKeyMap returns the canonical S-USER-DETAIL bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Back:     nav.KeyBinding{Keys: []string{"esc", "q"}, Help: "back"},
		AddKey:   nav.KeyBinding{Keys: []string{"a"}, Help: "add key (M-ADD-KEY)"},
		Delete:   nav.KeyBinding{Keys: []string{"d"}, Help: "delete selected key"},
		Password: nav.KeyBinding{Keys: []string{"p"}, Help: "set password"},
		Copy:     nav.KeyBinding{Keys: []string{"c"}, Help: "copy fingerprint via OSC 52"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Back, k.AddKey, k.Delete, k.Password, k.Copy}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Back, k.Copy},
		{k.AddKey, k.Delete, k.Password},
	}
}
