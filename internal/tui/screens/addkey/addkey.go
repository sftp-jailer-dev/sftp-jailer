// Package addkey renders the M-ADD-KEY modal: a single-textarea entry
// surface that auto-detects per-line source per D-19 (direct paste / gh:
// import / file path), fetches gh: keys via internal/keys.FetchGitHub
// (5s timeout, no auto-retry — surface 429 Retry-After verbatim), and
// routes ALL keys (regardless of source) through a mandatory review
// table per D-20 before committing as a single internal/txn batch.
//
// Commit batch (D-20 step 5 + D-21 four-step verifier):
//
//	1. txn.NewAtomicWriteAuthorizedKeysStep — atomic write + chown + chmod
//	2. txn.NewVerifyAuthKeysStep with verifier closure that runs:
//	     2a. chrootcheck.CheckAuthKeysFile (D-21 steps 1-2: perms + path-walk)
//	     2b. re-read authorized_keys via ops.ReadFile, re-parse with keys.Parse (D-21 step 3)
//	     2c. ops.SshdTWithContext(user=<u>,host=localhost,addr=127.0.0.1) (D-21 step 4)
//
// Any non-empty violation list at any step aborts the batch, triggering
// the AtomicWriteAuthorizedKeys compensator to restore prior content.
//
// The review table is MANDATORY even for gh:<user> returning a single
// key — D-20 explicitly forbids an auto-commit-on-fetch path. The gh
// account-compromise threat motivates the friction (T-03-08b-03).
//
// Pre-fetch validation: per 03-04 SUMMARY T-03-04-02 call-site invariant,
// gh: usernames are validated against `^[A-Za-z0-9-]+$` (GitHub's
// username charset) before any HTTP call.
//
// Partial-batch policy: ANY ssh.ParseAuthorizedKey error (in keys.Parse
// output OR in post-fetch parse) rejects the WHOLE batch with the
// verbatim error string. Admin keeps textarea content and can edit-retry.
package addkey

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/txn"
)

// ghUsernameRegex is the GitHub username charset per docs.github.com.
// Source: 03-04 SUMMARY T-03-04-02 / T-03-04-07 call-site invariant.
// Validated client-side BEFORE FetchGitHub to prevent URL-injection.
var ghUsernameRegex = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// verifierTimeout bounds the per-step verifier closure run time.
// chrootcheck + re-parse are filesystem-fast; sshd -t -C is the slow
// step (~100-500ms on a real box). 10s is generous.
const verifierTimeout = 10 * time.Second

// fetchTimeout duplicates the 5s declared by internal/keys.FetchGitHub
// so the screen's overall context can be derived from a single budget.
// Per D-19: NO auto-retry on 429 — the timeout is per-attempt, not a
// window over multiple attempts. Adds 1s headroom for goroutine plumbing.
const fetchTimeout = 6 * time.Second

// commitTimeout bounds the txn batch (write + verifier).
const commitTimeout = 30 * time.Second

// autoPopDelay is how long phaseDone lingers before the modal pops back.
// Locally redeclared (rather than imported from observerunscreen) to
// avoid pulling the observerun package transitively.
const autoPopDelay = 500 * time.Millisecond

// phase tracks the modal's state-machine position.
type phase int

const (
	phaseInput      phase = iota // textarea visible; admin types/pastes
	phaseFetching                // gh: lookups in flight; spinner shown
	phaseReview                  // review table visible; admin can toggle/copy/commit
	phaseCommitting              // txn batch running; spinner shown
	phaseDone                    // success; auto-pop after autoPopDelay
	phaseError                   // surface error, allow Esc back to input or pop
)

// ReviewRow is one row in the D-20 review table. Per-source resolution
// populates Algorithm/Fingerprint/Comment/ByteSize from the resolved
// ssh.PublicKey; Raw is the verbatim authorized_keys-format line we'll
// append on commit.
type ReviewRow struct {
	Algorithm   string
	Fingerprint string // SHA256:base64-no-padding
	Comment     string
	ByteSize    int
	Raw         []byte      // verbatim line written on commit
	Source      keys.Source // for footer label "via gh:alice" etc.
	SourceLabel string      // human-readable: "paste", "gh:alice", "gh:alice/12345", "/etc/keys/x.pub"
}

// Model is the M-ADD-KEY Bubble Tea v2 model.
type Model struct {
	ops        sysops.SystemOps
	chrootRoot string
	username   string

	ta      textarea.Model
	phase   phase
	spinner spinner.Model
	toast   widgets.Toast
	keys    KeyMap

	// Review-table state — populated after parse + (optional) async resolve.
	review    []ReviewRow
	reviewSel []bool
	reviewCur int

	// Last keys.Parse errors for post-mortem (surfaced verbatim in errInline).
	parseErrs []keys.ParseErr

	// Error surfacing.
	errInline string
	errFatal  bool
}

// fetchedMsg carries the resolved review rows back from the goroutine
// spawned by attemptParse on a textarea containing gh: / file: markers.
type fetchedMsg struct {
	rows []ReviewRow
	err  error
}

// committedMsg carries the txn.Apply outcome back from the goroutine
// spawned by attemptCommit.
type committedMsg struct{ err error }

// autoPopMsg is the tea.Tick payload that pops the modal after a
// successful commit lingers for autoPopDelay.
type autoPopMsg struct{}

// New constructs the M-ADD-KEY modal for the given user. The chrootRoot
// is needed for the path <chrootRoot>/<username>/.ssh/authorized_keys
// (D-17). ops may be nil in unit tests that drive Update directly.
func New(ops sysops.SystemOps, chrootRoot, username string) *Model {
	ta := textarea.New()
	ta.Placeholder = "ssh-ed25519 AAAA... or gh:alice or /etc/keys/x.pub (one per line)"
	ta.Focus()
	ta.SetHeight(8)
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = styles.Primary
	return &Model{
		ops: ops, chrootRoot: chrootRoot, username: username,
		ta: ta, phase: phaseInput, spinner: sp, keys: DefaultKeyMap(),
	}
}

// ---- nav.Screen interface ---------------------------------------------------

// Title implements nav.Screen.
func (m *Model) Title() string { return "add ssh key — " + m.username }

// KeyMap implements nav.Screen.
func (m *Model) KeyMap() nav.KeyMap { return m.keys }

// WantsRawKeys implements nav.Screen — true while the textarea is the
// admin's primary input surface (phaseInput) OR during phaseError where
// any key returns to the input. False during fetching/review/committing/
// done so the screen's single-key shortcuts (j/k/space/c/enter) reach
// handleKey unmolested.
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
	case fetchedMsg:
		return m.handleFetched(msg)
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
			m.review = nil
			m.reviewSel = nil
			m.reviewCur = 0
			m.errInline = ""
			m.errFatal = false
			return m, nil
		case phaseFetching, phaseCommitting:
			// Swallow — async work will complete and return us to a stable phase.
			return m, nil
		}
	}
	switch m.phase {
	case phaseInput:
		if s == "enter" {
			return m, m.attemptParse()
		}
		// Forward to textarea for raw input (multi-line paste, editing).
		var cmd tea.Cmd
		m.ta, cmd = m.ta.Update(msg)
		return m, cmd
	case phaseReview:
		switch s {
		case "j", "down":
			if m.reviewCur < len(m.review)-1 {
				m.reviewCur++
			}
			return m, nil
		case "k", "up":
			if m.reviewCur > 0 {
				m.reviewCur--
			}
			return m, nil
		case " ", "space":
			if m.reviewCur >= 0 && m.reviewCur < len(m.reviewSel) {
				m.reviewSel[m.reviewCur] = !m.reviewSel[m.reviewCur]
			}
			return m, nil
		case "c":
			if m.reviewCur >= 0 && m.reviewCur < len(m.review) {
				fp := m.review[m.reviewCur].Fingerprint
				var flashCmd tea.Cmd
				m.toast, flashCmd = m.toast.Flash("copied fingerprint via OSC 52")
				return m, tea.Batch(tea.SetClipboard(fp), flashCmd)
			}
			return m, nil
		case "enter":
			return m, m.attemptCommit()
		case "q":
			return m, nav.PopCmd()
		}
		return m, nil
	case phaseError:
		// Esc handled above; any other key returns to input so admin can retype.
		m.phase = phaseInput
		m.errInline = ""
		m.errFatal = false
		return m, nil
	}
	return m, nil
}

// ---- attemptParse: textarea → parse + dispatch ----------------------------

// attemptParse executes the D-19 dispatch over the textarea content.
// Pure-string lines feed directly into the review-table builder; gh: and
// file: markers spawn an async resolution goroutine. ANY ssh.ParseAuthorizedKey
// error from keys.Parse (or in any subsequently-resolved gh:/file: bytes)
// rejects the whole batch — admin sees the verbatim error and can retry.
func (m *Model) attemptParse() tea.Cmd {
	text := m.ta.Value()
	parsed, errs := keys.Parse(text)
	if len(errs) > 0 {
		m.parseErrs = errs
		m.errInline = "parse failed: " + errs[0].Error()
		if len(errs) > 1 {
			m.errInline = fmt.Sprintf("parse failed (%d errors): %s", len(errs), errs[0].Error())
		}
		m.errFatal = true
		m.phase = phaseError
		return nil
	}
	if len(parsed) == 0 {
		m.errInline = "no keys found — paste at least one key, or gh:user, or path"
		m.errFatal = false
		m.phase = phaseError
		return nil
	}
	// Validate gh: usernames synchronously per T-03-04-02 BEFORE any HTTP call.
	for _, p := range parsed {
		if p.Source == keys.SourceGithubAll || p.Source == keys.SourceGithubByID {
			if !ghUsernameRegex.MatchString(p.GithubUser) {
				m.errInline = fmt.Sprintf(
					"invalid GitHub username %q — must match [A-Za-z0-9-]+",
					p.GithubUser)
				m.errFatal = true
				m.phase = phaseError
				return nil
			}
		}
	}
	// Direct-paste keys can populate review rows immediately; gh: + file:
	// require async resolution. If ALL keys are direct, skip phaseFetching.
	if !hasUnresolvedSource(parsed) {
		m.review = directReviewRows(parsed)
		m.reviewSel = allTrue(len(m.review))
		m.reviewCur = 0
		m.phase = phaseReview
		return nil
	}
	m.phase = phaseFetching
	return tea.Batch(m.spinner.Tick, m.resolveAsync(parsed))
}

func hasUnresolvedSource(ps []keys.ParsedKey) bool {
	for _, p := range ps {
		if p.Source != keys.SourceDirect {
			return true
		}
	}
	return false
}

func directReviewRows(ps []keys.ParsedKey) []ReviewRow {
	rows := make([]ReviewRow, 0, len(ps))
	for _, p := range ps {
		rows = append(rows, ReviewRow{
			Algorithm: p.Algorithm, Fingerprint: p.Fingerprint,
			Comment: p.Comment, ByteSize: p.ByteSize, Raw: p.Raw,
			Source: p.Source, SourceLabel: "paste",
		})
	}
	return rows
}

func allTrue(n int) []bool {
	s := make([]bool, n)
	for i := range s {
		s[i] = true
	}
	return s
}

// resolveAsync resolves all non-Direct ParsedKeys (gh: + file:) and
// emits a fetchedMsg back to Update. Per D-19: NO auto-retry on 429;
// FetchGitHub's 5s timeout is the entire window. File reads use ops.ReadFile.
//
// Each resolved key's bytes are re-parsed with keys.Parse to populate
// Fingerprint/Algorithm; ANY parse error rejects the whole batch with
// the verbatim ssh.ParseAuthorizedKey error.
func (m *Model) resolveAsync(parsed []keys.ParsedKey) tea.Cmd {
	ops := m.ops
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()
		var rows []ReviewRow
		for _, p := range parsed {
			switch p.Source {
			case keys.SourceDirect:
				rows = append(rows, ReviewRow{
					Algorithm: p.Algorithm, Fingerprint: p.Fingerprint,
					Comment: p.Comment, ByteSize: p.ByteSize, Raw: p.Raw,
					Source: p.Source, SourceLabel: "paste",
				})
			case keys.SourceGithubAll:
				lines, err := keys.FetchGitHub(ctx, p.GithubUser)
				if err != nil {
					return fetchedMsg{err: fmt.Errorf("gh:%s: %w", p.GithubUser, err)}
				}
				for _, line := range lines {
					rr, perr := parseLineToRow(line, fmt.Sprintf("gh:%s", p.GithubUser))
					if perr != nil {
						return fetchedMsg{err: perr}
					}
					rows = append(rows, rr)
				}
			case keys.SourceGithubByID:
				line, err := keys.FetchGitHubByID(ctx, p.GithubUser, p.GithubKeyID)
				if err != nil {
					return fetchedMsg{err: fmt.Errorf("gh:%s/%d: %w", p.GithubUser, p.GithubKeyID, err)}
				}
				rr, perr := parseLineToRow(line, fmt.Sprintf("gh:%s/%d", p.GithubUser, p.GithubKeyID))
				if perr != nil {
					return fetchedMsg{err: perr}
				}
				rows = append(rows, rr)
			case keys.SourceFile:
				path := p.FilePath
				if strings.HasPrefix(path, "~/") {
					home, herr := os.UserHomeDir()
					if herr != nil {
						return fetchedMsg{err: fmt.Errorf("expand ~: %w", herr)}
					}
					path = filepath.Join(home, path[2:])
				}
				if ops == nil {
					return fetchedMsg{err: fmt.Errorf("file %s: ops is nil (test path mis-wired)", path)}
				}
				body, err := ops.ReadFile(ctx, path)
				if err != nil {
					return fetchedMsg{err: fmt.Errorf("read %s: %w", path, err)}
				}
				sub, subErrs := keys.Parse(string(body))
				if len(subErrs) > 0 {
					return fetchedMsg{err: fmt.Errorf("file %s: %s", path, subErrs[0].Error())}
				}
				for _, sp := range sub {
					rows = append(rows, ReviewRow{
						Algorithm: sp.Algorithm, Fingerprint: sp.Fingerprint,
						Comment: sp.Comment, ByteSize: sp.ByteSize, Raw: sp.Raw,
						Source: sp.Source, SourceLabel: path,
					})
				}
			}
		}
		return fetchedMsg{rows: rows}
	}
}

// parseLineToRow re-parses an authorized_keys-format byte slice into a
// ReviewRow, surfacing ssh.ParseAuthorizedKey errors verbatim per the
// partial-batch-rejects-whole policy.
func parseLineToRow(line []byte, sourceLabel string) (ReviewRow, error) {
	sub, subErrs := keys.Parse(string(line))
	if len(subErrs) > 0 {
		return ReviewRow{}, fmt.Errorf("parse %s: %s", sourceLabel, subErrs[0].Error())
	}
	if len(sub) != 1 {
		return ReviewRow{}, fmt.Errorf("parse %s: expected 1 key, got %d", sourceLabel, len(sub))
	}
	p := sub[0]
	return ReviewRow{
		Algorithm: p.Algorithm, Fingerprint: p.Fingerprint,
		Comment: p.Comment, ByteSize: p.ByteSize, Raw: p.Raw,
		Source: p.Source, SourceLabel: sourceLabel,
	}, nil
}

func (m *Model) handleFetched(msg fetchedMsg) (nav.Screen, tea.Cmd) {
	if msg.err != nil {
		m.errInline = msg.err.Error()
		m.errFatal = true
		m.phase = phaseError
		return m, nil
	}
	m.review = msg.rows
	m.reviewSel = allTrue(len(m.review))
	m.reviewCur = 0
	m.phase = phaseReview
	return m, nil
}

// ---- attemptCommit: review → txn batch (write + verifier) ----------------

// attemptCommit assembles the selected keys' Raw bytes (one line each,
// newline-terminated) into a single []byte payload, prepends any
// existing authorized_keys content (D-20 step 2 "append new keys"), and
// dispatches a single internal/txn batch:
//
//  1. NewAtomicWriteAuthorizedKeysStep(username, chrootRoot, newContent)
//  2. NewVerifyAuthKeysStep(username, chrootRoot, verify) where verify
//     runs chrootcheck.CheckAuthKeysFile → re-read+keys.Parse → SshdTWithContext.
func (m *Model) attemptCommit() tea.Cmd {
	var selectedRows []ReviewRow
	for i, sel := range m.reviewSel {
		if sel {
			selectedRows = append(selectedRows, m.review[i])
		}
	}
	if len(selectedRows) == 0 {
		m.errInline = "no keys selected — at least one row must be checked"
		m.errFatal = false
		// Stay in review (don't transition to error — admin just needs to toggle).
		return nil
	}
	if m.ops == nil {
		// Test path: tests that don't seed a Fake should not reach here.
		m.errInline = "internal error: ops is nil"
		m.errFatal = true
		m.phase = phaseError
		return nil
	}
	ops, user, root := m.ops, m.username, m.chrootRoot
	m.phase = phaseCommitting
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
		defer cancel()
		// Read prior content (if any) for append.
		authPath := filepath.Join(root, user, ".ssh", "authorized_keys")
		prior, _ := ops.ReadFile(ctx, authPath) // ErrNotExist → empty prior
		var buf bytes.Buffer
		if len(prior) > 0 {
			buf.Write(prior)
			if !bytes.HasSuffix(prior, []byte("\n")) {
				buf.WriteByte('\n')
			}
		}
		for _, r := range selectedRows {
			buf.Write(r.Raw)
			buf.WriteByte('\n')
		}
		tx := txn.New(ops)
		steps := []txn.Step{
			txn.NewAtomicWriteAuthorizedKeysStep(user, root, buf.Bytes()),
			txn.NewVerifyAuthKeysStep(user, root, buildVerifier()),
		}
		err := tx.Apply(ctx, steps)
		return committedMsg{err: err}
	})
}

// buildVerifier returns the D-21 four-step closure injected into
// NewVerifyAuthKeysStep. Step ordering is mandatory per CONTEXT.md D-21:
//
//	1+2: chrootcheck.CheckAuthKeysFile (perms + path-walk)
//	3:   re-read authorized_keys via ops.ReadFile + keys.Parse (catches partial writes / BOM)
//	4:   ops.SshdTWithContext(user=<u>,host=localhost,addr=127.0.0.1)
//
// Any non-empty violation list at any step short-circuits and returns.
func buildVerifier() func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]txn.VerifyViolation, error) {
	return func(ctx context.Context, ops sysops.SystemOps, username, chrootRoot string) ([]txn.VerifyViolation, error) {
		ctx, cancel := context.WithTimeout(ctx, verifierTimeout)
		defer cancel()

		// Step 1+2: perms + path-walk via chrootcheck.
		vios, err := chrootcheck.CheckAuthKeysFile(ctx, ops, username, chrootRoot)
		if err != nil {
			return nil, fmt.Errorf("chrootcheck: %w", err)
		}
		if len(vios) > 0 {
			return adaptViolations(vios), nil
		}
		// Step 3: re-read + re-parse. Catches partial writes / BOM / corruption
		// that the perms check would not see.
		authPath := filepath.Join(chrootRoot, username, ".ssh", "authorized_keys")
		content, err := ops.ReadFile(ctx, authPath)
		if err != nil {
			return nil, fmt.Errorf("re-read %s: %w", authPath, err)
		}
		_, parseErrs := keys.Parse(string(content))
		if len(parseErrs) > 0 {
			return []txn.VerifyViolation{{
				Path:   authPath,
				Reason: fmt.Sprintf("post-write re-parse failed: %s", parseErrs[0].Error()),
			}}, nil
		}
		// Step 4: sshd -t -C user=<u>,host=localhost,addr=127.0.0.1 — confirms
		// the chrooted Match block actually resolves under the just-written file.
		stderr, err := ops.SshdTWithContext(ctx, sysops.SshdTContextOpts{
			User: username, Host: "localhost", Addr: "127.0.0.1",
		})
		if err != nil {
			return []txn.VerifyViolation{{
				Path: authPath,
				Reason: fmt.Sprintf(
					"sshd -t -C user=%s failed: %s",
					username, strings.TrimSpace(string(stderr))),
			}}, nil
		}
		return nil, nil
	}
}

func adaptViolations(in []chrootcheck.Violation) []txn.VerifyViolation {
	out := make([]txn.VerifyViolation, len(in))
	for i, v := range in {
		out[i] = txn.VerifyViolation{Path: v.Path, Reason: v.Reason}
	}
	return out
}

func (m *Model) handleCommitted(msg committedMsg) (nav.Screen, tea.Cmd) {
	if msg.err != nil {
		m.errInline = msg.err.Error()
		m.errFatal = true
		m.phase = phaseError
		return m, nil
	}
	m.phase = phaseDone
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash(fmt.Sprintf("added %d key(s)", countSelected(m.reviewSel)))
	return m, tea.Batch(
		flashCmd,
		tea.Tick(autoPopDelay, func(time.Time) tea.Msg { return autoPopMsg{} }),
	)
}

func countSelected(sel []bool) int {
	n := 0
	for _, s := range sel {
		if s {
			n++
		}
	}
	return n
}

// ---- View ------------------------------------------------------------------

// View renders the modal body wrapped in NormalBorder + Padding(0, 2)
// (M-OBSERVE-style modal frame). Per phase:
//
//   - phaseInput: textarea + footer.
//   - phaseFetching: spinner + "fetching keys…" + Esc footer.
//   - phaseReview: D-20 review table (algorithm | sha256-fp | comment | bytes | source) + footer "N of M keys to add · …".
//   - phaseCommitting: spinner + "writing authorized_keys + verifying…".
//   - phaseDone: Success "added N key(s); auto-closing…".
//   - phaseError: Critical/Warn errInline + "Esc back · any key retry".
func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(styles.Primary.Render("M-ADD-KEY — " + m.username))
	b.WriteString("\n\n")

	switch m.phase {
	case phaseInput:
		b.WriteString(m.ta.View())
		b.WriteString("\n\n")
		if m.errInline != "" {
			b.WriteString(m.styledErr(m.errInline))
			b.WriteString("\n\n")
		}
		b.WriteString(styles.Dim.Render(
			"[enter] parse · [esc] cancel"))
	case phaseFetching:
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
		b.WriteString(styles.Dim.Render("fetching keys…   [esc] cancel"))
	case phaseReview:
		b.WriteString(m.renderReviewTable())
		b.WriteString("\n")
		if m.errInline != "" {
			b.WriteString(m.styledErr(m.errInline))
			b.WriteString("\n")
		}
		sel := countSelected(m.reviewSel)
		b.WriteString(styles.Dim.Render(fmt.Sprintf(
			"%d of %d keys to add · [space] toggle · [c] copy fp · [enter] commit · [esc] back",
			sel, len(m.review))))
	case phaseCommitting:
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
		b.WriteString(styles.Dim.Render("writing authorized_keys + verifying…"))
	case phaseDone:
		b.WriteString(styles.Success.Render(fmt.Sprintf(
			"✓ added %d key(s); auto-closing…", countSelected(m.reviewSel))))
	case phaseError:
		b.WriteString(m.styledErr(m.errInline))
		b.WriteString("\n\n")
		b.WriteString(styles.Dim.Render("[esc] back · [any key] retry"))
	}

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}
	return wrapModal(b.String())
}

func (m *Model) styledErr(s string) string {
	if m.errFatal {
		return styles.Critical.Render(s)
	}
	return styles.Warn.Render(s)
}

// renderReviewTable renders the D-20 column order verbatim:
// `[✓] | algorithm | sha256-fp | comment | bytes | source`.
// The 'source' column is appended after 'bytes' as a Dim-styled label.
//
// T-03-08b-02 column-order regression guard: the test
// TestAddKey_review_columns_match_D20_order asserts the substring order
// `algorithm` < `sha256-fp` < `comment` < `bytes` in the rendered output.
func (m *Model) renderReviewTable() string {
	var b strings.Builder
	// Header.
	b.WriteString(styles.Primary.Render(fmt.Sprintf(
		"  %-3s  %-18s  %-50s  %-20s  %5s  %s",
		"[ ]", "algorithm", "sha256-fp", "comment", "bytes", "source")))
	b.WriteString("\n")
	for i, r := range m.review {
		marker := "  "
		if i == m.reviewCur {
			marker = "▌ "
		}
		check := "[ ]"
		if i < len(m.reviewSel) && m.reviewSel[i] {
			check = "[✓]"
		}
		comment := r.Comment
		if comment == "" {
			comment = "—"
		}
		row := fmt.Sprintf("%s%-3s  %-18s  %-50s  %-20s  %5d  %s",
			marker, check,
			truncate(r.Algorithm, 18),
			truncate(r.Fingerprint, 50),
			truncate(comment, 20),
			r.ByteSize,
			styles.Dim.Render(r.SourceLabel),
		)
		if i == m.reviewCur {
			row = styles.Primary.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}
	return b.String()
}

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
func wrapModal(content string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 2).
		Render(content)
}

// ---- KeyMap ----------------------------------------------------------------

// KeyMap describes the modal's bindings — implements nav.KeyMap.
type KeyMap struct {
	Submit nav.KeyBinding // Enter (in phaseInput / phaseReview)
	Toggle nav.KeyBinding // space (in phaseReview)
	CopyFP nav.KeyBinding // c (in phaseReview)
	Cursor nav.KeyBinding // j/k/up/down (in phaseReview)
	Cancel nav.KeyBinding // esc — back to input or pop
}

// DefaultKeyMap returns the canonical M-ADD-KEY bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Submit: nav.KeyBinding{Keys: []string{"enter"}, Help: "parse / commit"},
		Toggle: nav.KeyBinding{Keys: []string{"space"}, Help: "toggle row"},
		CopyFP: nav.KeyBinding{Keys: []string{"c"}, Help: "copy fingerprint via OSC 52"},
		Cursor: nav.KeyBinding{Keys: []string{"j", "k", "↑", "↓"}, Help: "move cursor"},
		Cancel: nav.KeyBinding{Keys: []string{"esc"}, Help: "back / cancel"},
	}
}

// ShortHelp implements nav.KeyMap.
func (k KeyMap) ShortHelp() []nav.KeyBinding {
	return []nav.KeyBinding{k.Cancel, k.Submit, k.Toggle, k.CopyFP}
}

// FullHelp implements nav.KeyMap.
func (k KeyMap) FullHelp() [][]nav.KeyBinding {
	return [][]nav.KeyBinding{
		{k.Cancel, k.Submit},
		{k.Cursor, k.Toggle, k.CopyFP},
	}
}

// ---- Test seams ------------------------------------------------------------

// LoadReviewForTest seeds the review table directly, bypassing parse/fetch.
// Tests use this when they want to assert review-table behavior in isolation.
func (m *Model) LoadReviewForTest(rows []ReviewRow) {
	m.review = rows
	m.reviewSel = allTrue(len(rows))
	m.reviewCur = 0
	m.phase = phaseReview
}

// SetTextareaForTest replaces the textarea content with a known string.
func (m *Model) SetTextareaForTest(s string) { m.ta.SetValue(s) }

// TextareaValueForTest exposes the textarea content for assertions
// (e.g. the "Esc preserves textarea" regression).
func (m *Model) TextareaValueForTest() string { return m.ta.Value() }

// SetReviewSelForTest overrides the per-row selection vector. Used by
// the no-selection-blocks test to deselect every row before commit.
func (m *Model) SetReviewSelForTest(sel []bool) {
	cp := make([]bool, len(sel))
	copy(cp, sel)
	m.reviewSel = cp
}

// PhaseForTest returns the current phase as a string for assertions.
func (m *Model) PhaseForTest() string {
	switch m.phase {
	case phaseInput:
		return "input"
	case phaseFetching:
		return "fetching"
	case phaseReview:
		return "review"
	case phaseCommitting:
		return "committing"
	case phaseDone:
		return "done"
	case phaseError:
		return "error"
	}
	return "?"
}

// ErrInlineForTest exposes the inline-error string for assertions.
func (m *Model) ErrInlineForTest() string { return m.errInline }

// ReviewLenForTest exposes len(m.review) for assertions.
func (m *Model) ReviewLenForTest() int { return len(m.review) }

// ReviewRowForTest returns the ReviewRow at index i for assertions.
func (m *Model) ReviewRowForTest(i int) ReviewRow { return m.review[i] }

// ReviewSelForTest exposes the selection vector for assertions.
func (m *Model) ReviewSelForTest() []bool {
	cp := make([]bool, len(m.reviewSel))
	copy(cp, m.reviewSel)
	return cp
}

// ReviewCursorForTest exposes the cursor index for assertions.
func (m *Model) ReviewCursorForTest() int { return m.reviewCur }
