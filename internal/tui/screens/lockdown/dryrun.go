package lockdown

import (
	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	lpkg "github.com/sftp-jailer-dev/sftp-jailer/internal/lockdown"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
)

// DryRunModel is the M-DRY-RUN modal — read-only preview of the proposed
// commit batch. Task 1a ships a minimal stub so the lockdown screen's
// `D`-keybind handler compiles; Task 2 replaces this file with the full
// two-section diff + command-plan rendering + OSC 52 copy.
type DryRunModel struct {
	ops          sysops.SystemOps
	mutations    []lpkg.PendingMutation
	currentRules []firewall.Rule
}

// NewDryRunModal constructs the modal. Task 2 replaces this stub.
func NewDryRunModal(ops sysops.SystemOps, mutations []lpkg.PendingMutation, currentRules []firewall.Rule) *DryRunModel {
	return &DryRunModel{
		ops:          ops,
		mutations:    mutations,
		currentRules: currentRules,
	}
}

func (m *DryRunModel) Title() string      { return "Dry-run preview" }
func (m *DryRunModel) WantsRawKeys() bool { return false }
func (m *DryRunModel) KeyMap() nav.KeyMap { return emptyKeyMap{} }
func (m *DryRunModel) Init() tea.Cmd      { return nil }

func (m *DryRunModel) Update(msg tea.Msg) (nav.Screen, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		return m, nav.PopCmd()
	}
	return m, nil
}

func (m *DryRunModel) View() string {
	return "Dry-run preview — Task 2 implementation pending\n\n(esc to return)"
}
