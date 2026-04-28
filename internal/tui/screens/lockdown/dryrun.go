// Package lockdown's dryrun.go implements M-DRY-RUN — read-only preview
// of the proposed LOCK-06 commit batch (D-L0809-05). Two scrollable
// sections:
//
//  1. Rule diff — current `ufw status numbered` ruleset side-by-side
//     with the predicted post-commit listing. Added rules show `+`,
//     deleted rules show `- ` prefix, unchanged are dim.
//  2. Command plan — verbatim shell sequence the txn batch will run,
//     including the `systemd-run --on-active=180sec
//     --unit=sftpj-revert-<unix-ns>.service /bin/sh -c '<reverse>'`
//     line and the per-step revert payload baked into it.
//
// Keys: `c`/`C` copy entire plan via OSC 52; `Tab` switch sections;
// j/k scroll within active section; esc pop without applying. NO commit
// action — this is preview only.
package lockdown

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	lpkg "github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/widgets"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/ufwcomment"
)

// dryRunSection is the section discriminator (Tab cycles between
// dryRunSectionDiff and dryRunSectionCommands).
type dryRunSection int

const (
	dryRunSectionDiff dryRunSection = iota
	dryRunSectionCommands
)

// dryRunSectionCount is used by the Tab modulo to cycle through the
// two sections.
const dryRunSectionCount = 2

// DryRunModel is M-DRY-RUN. Read-only preview of the proposed commit;
// no apply path. Constructed via NewDryRunModal from the S-LOCKDOWN
// editor's `D`-keybind handler.
type DryRunModel struct {
	ops          sysops.SystemOps
	mutations    []lpkg.PendingMutation
	currentRules []firewall.Rule

	section dryRunSection
	scrollY int
	toast   widgets.Toast
	width   int
}

// NewDryRunModal constructs the modal. ops is captured for OSC 52
// dispatch (tea.SetClipboard does not require ops, but keeping the
// signature parallel to the screens that DO need ops prevents
// future-refactor friction).
func NewDryRunModal(ops sysops.SystemOps, mutations []lpkg.PendingMutation, currentRules []firewall.Rule) *DryRunModel {
	return &DryRunModel{
		ops:          ops,
		mutations:    mutations,
		currentRules: currentRules,
		section:      dryRunSectionDiff,
	}
}

// Title implements nav.Screen.
func (m *DryRunModel) Title() string { return "Dry-run preview" }

// WantsRawKeys implements nav.Screen — false (no textinput).
func (m *DryRunModel) WantsRawKeys() bool { return false }

// KeyMap implements nav.Screen — minimal; the screen renders its own
// help inline in View().
func (m *DryRunModel) KeyMap() nav.KeyMap { return emptyKeyMap{} }

// Init implements nav.Screen — no async work; the dry-run is fully
// derivable from the constructor inputs.
func (m *DryRunModel) Init() tea.Cmd { return nil }

// Update implements nav.Screen.
func (m *DryRunModel) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		return m, nil
	case tea.KeyPressMsg:
		switch v.String() {
		case "c", "C":
			return m.handleCopy()
		case "tab":
			m.section = (m.section + 1) % dryRunSectionCount
			m.scrollY = 0
			return m, nil
		case "j", "down":
			m.scrollY++
			return m, nil
		case "k", "up":
			if m.scrollY > 0 {
				m.scrollY--
			}
			return m, nil
		case "esc", "q":
			return m, nav.PopCmd()
		}
	}
	m.toast = m.toast.Update(msg)
	return m, nil
}

// handleCopy emits OSC 52 SetClipboard for the full plan (both
// sections concatenated) + flashes a confirmation toast.
func (m *DryRunModel) handleCopy() (nav.Screen, tea.Cmd) {
	text := m.RenderPlanText()
	var flashCmd tea.Cmd
	m.toast, flashCmd = m.toast.Flash("copied dry-run plan via OSC 52")
	return m, tea.Batch(tea.SetClipboard(text), flashCmd)
}

// RenderPlanText returns the full plan as plain text (no ANSI escapes)
// suitable for OSC 52 paste. Format: rule-diff section + command-plan
// section, separated by blank lines.
//
// Pure: zero side effects; safe to call from tests + the OSC 52 copy
// handler. Output is stable for a given (mutations, currentRules)
// input.
func (m *DryRunModel) RenderPlanText() string {
	var b strings.Builder
	b.WriteString("=== Rule diff ===\n")
	b.WriteString(m.renderDiff())
	b.WriteString("\n=== Command plan ===\n")
	b.WriteString(m.renderCommands())
	return b.String()
}

// renderDiff produces the rule-diff section. Layout:
//
//	Current ruleset:
//	  [N] <port> ALLOW <source>  # <comment>
//	- [N] ...                            ← marked for deletion
//
//	Proposed additions:
//	+ ufw insert 1 allow proto tcp from <src> to any port <port> comment '<c>'
//
// Plain-text-only — the View() rendering wraps in styles for the TUI;
// this function is the source of truth for both display and OSC 52
// copy.
func (m *DryRunModel) renderDiff() string {
	var b strings.Builder

	// Build deleted-IDs set so we can mark current-ruleset rows.
	deletedIDs := map[int]bool{}
	for _, mut := range m.mutations {
		if mut.Op == lpkg.OpDelete {
			deletedIDs[mut.Rule.ID] = true
		}
	}

	b.WriteString("Current ruleset:\n")
	if len(m.currentRules) == 0 {
		b.WriteString("  (no rules)\n")
	}
	for _, r := range m.currentRules {
		commentDisplay := r.RawComment
		if commentDisplay == "" {
			commentDisplay = "(none)"
		}
		line := fmt.Sprintf("  [%d] %s %s %s  # %s",
			r.ID, r.Port, r.Action, r.Source, commentDisplay)
		if deletedIDs[r.ID] {
			line = "- " + strings.TrimPrefix(line, "  ")
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\nProposed additions:\n")
	hasAdds := false
	for _, mut := range m.mutations {
		if mut.Op != lpkg.OpAdd {
			continue
		}
		hasAdds = true
		// Display the canonical forward `ufw insert` line including
		// the comment. ufwcomment.Encode is the canonical user-grammar
		// gate; we re-encode here so the displayed line matches what
		// would actually run (no drift between dry-run and commit).
		comment, err := ufwcomment.Encode(mut.Rule.User)
		if err != nil {
			// Defensive — shouldn't happen because buildPendingMutations
			// only emits well-formed users. Display a clear marker.
			comment = "(invalid: " + err.Error() + ")"
		}
		b.WriteString(fmt.Sprintf("+ ufw insert 1 allow proto tcp from %s to any port %s comment '%s'\n",
			mut.Rule.Source, mut.Rule.Port, comment))
	}
	if !hasAdds {
		b.WriteString("  (none)\n")
	}

	return b.String()
}

// renderCommands produces the command-plan section. Layout:
//
//	# SAFE-04 schedule (3-min revert):
//	systemd-run --on-active=180sec --unit=sftpj-revert-<unix-ns>.service /bin/sh -c '<reverse>'
//
//	# Forward batch:
//	ufw insert 1 allow proto tcp from <src> to any port <port> comment '<c>'
//	...
//	ufw reload
//
// The reverse-cmd body comes from lockdown.RenderReverseCommands —
// note that for OpAdd entries with AssignedID==0 (commit-time, before
// the rules are assigned), RenderReverseCommands skips them rather
// than emitting a malformed reverse. The S-LOCKDOWN commit path uses
// composeCommitReverseCmds (which emits the comment-grep placeholder
// instead) — this dry-run renders the simpler RenderReverseCommands
// shape because the unit-name / pre-assigned-ID is purely informational
// here. If admin presses 'C' from the dry-run modal (NOT possible —
// 'c' copies; 'C' is only on S-LOCKDOWN), they'd see different reverse
// shapes; documented limitation acknowledged.
func (m *DryRunModel) renderCommands() string {
	var b strings.Builder

	b.WriteString("# SAFE-04 schedule (3-min revert):\n")
	if len(m.mutations) > 0 {
		// Use composeCommitReverseCmds for the preview — the canonical
		// commit-time composer that emits the comment-grep placeholder
		// for OpAdd entries (where AssignedID is unknown pre-Apply) +
		// RenderReverseCommands for OpDelete entries. This matches what
		// would actually run via NewScheduleRevertStep at commit time.
		reverseCmds := composeCommitReverseCmds(m.mutations, "")
		b.WriteString(fmt.Sprintf(
			"systemd-run --on-active=180sec --unit=sftpj-revert-<unix-ns>.service /bin/sh -c '%s'\n",
			strings.Join(reverseCmds, "; ")))
	} else {
		b.WriteString("  (no commands — empty mutation set)\n")
	}

	b.WriteString("\n# Forward batch:\n")
	for _, mut := range m.mutations {
		switch mut.Op {
		case lpkg.OpAdd:
			comment, err := ufwcomment.Encode(mut.Rule.User)
			if err != nil {
				comment = "(invalid)"
			}
			b.WriteString(fmt.Sprintf("ufw insert 1 allow proto tcp from %s to any port %s comment '%s'\n",
				mut.Rule.Source, mut.Rule.Port, comment))
		case lpkg.OpDelete:
			b.WriteString(fmt.Sprintf("ufw --force delete %d\n", mut.Rule.ID))
		}
	}
	if len(m.mutations) > 0 {
		b.WriteString("ufw reload\n")
	}

	return b.String()
}

// View implements nav.Screen.
func (m *DryRunModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Primary.Render("Dry-run preview"))
	b.WriteString("\n\n")

	if m.section == dryRunSectionDiff {
		b.WriteString(styles.Primary.Render("[Rule diff]"))
		b.WriteString("  ")
		b.WriteString(styles.Dim.Render("[Tab] command plan"))
		b.WriteString("\n\n")
		b.WriteString(m.renderDiff())
	} else {
		b.WriteString(styles.Dim.Render("[Rule diff]"))
		b.WriteString("  ")
		b.WriteString(styles.Primary.Render("[Command plan]"))
		b.WriteString("  ")
		b.WriteString(styles.Dim.Render("[Tab] back"))
		b.WriteString("\n\n")
		b.WriteString(m.renderCommands())
	}

	b.WriteString("\n")
	b.WriteString(styles.Dim.Render(
		"[c] copy plan via OSC 52  [Tab] switch section  [j/k] scroll  [esc] back"))

	if ts := m.toast.View(); ts != "" {
		b.WriteString("\n")
		b.WriteString(ts)
	}

	return b.String()
}

// SectionForTest exposes the active section for assertions.
func (m *DryRunModel) SectionForTest() dryRunSection { return m.section }
