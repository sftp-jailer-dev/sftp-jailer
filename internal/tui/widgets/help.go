package widgets

import (
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// HelpOverlay wraps bubbles/v2/help to render a `?`-triggered help panel
// below the current screen's body. Each screen supplies its own FullHelp
// columns; this widget adapts nav.KeyBinding → key.Binding and renders via
// help.Model.FullHelpView.
type HelpOverlay struct {
	m help.Model
}

// NewHelpOverlay constructs a HelpOverlay with sensible defaults.
func NewHelpOverlay() HelpOverlay {
	return HelpOverlay{m: help.New()}
}

// Overlay returns the caller's `body` with a bordered help panel appended
// below, rendered from the supplied columns of key bindings. If fullHelp is
// empty, body is returned unchanged (no panel).
func (h HelpOverlay) Overlay(body string, fullHelp [][]nav.KeyBinding) string {
	if len(fullHelp) == 0 {
		return body
	}

	columns := make([][]key.Binding, 0, len(fullHelp))
	for _, col := range fullHelp {
		cb := make([]key.Binding, 0, len(col))
		for _, kb := range col {
			cb = append(cb, key.NewBinding(
				key.WithKeys(kb.Keys...),
				key.WithHelp(strings.Join(kb.Keys, "/"), kb.Help),
			))
		}
		columns = append(columns, cb)
	}
	panel := h.m.FullHelpView(columns)
	panel = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		Padding(0, 1).
		Render(panel)
	return body + "\n" + styles.Dim.Render("— help —") + "\n" + panel
}
