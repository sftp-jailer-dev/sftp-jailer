package widgets

import (
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/sahilm/fuzzy"
)

// Search is the reusable fuzzy-search widget. Any list-rendering screen
// composes a Search; when Active, its textinput is focused and the parent
// screen's WantsRawKeys() should return true so the root App forwards
// letters to the input instead of quitting.
type Search struct {
	ti      textinput.Model
	Active  bool
	Matches fuzzy.Matches
}

// NewSearch constructs a Search widget. Prompt `/ `, placeholder `fuzzy…`.
func NewSearch() Search {
	ti := textinput.New()
	ti.Placeholder = "fuzzy…"
	ti.Prompt = "/ "
	return Search{ti: ti}
}

// Activate focuses the underlying textinput and flips Active=true. Returns
// the focus tea.Cmd for the cursor blink (callers must thread it through
// their Update return). Use this from screen `/` handlers instead of
// poking `s.Active = true` directly — without Focus() the textinput
// silently swallows keystrokes (see internal/tui/screens/users for the
// canonical caller).
func (s Search) Activate() (Search, tea.Cmd) {
	s.Active = true
	cmd := s.ti.Focus()
	return s, cmd
}

// Deactivate blurs and clears. Returned for the (Search, tea.Cmd) value-
// pattern; the cmd is always nil today but the signature mirrors Activate
// so future cursor-stop animations don't break callers.
func (s Search) Deactivate() (Search, tea.Cmd) {
	s.Active = false
	s.ti.SetValue("")
	s.ti.Blur()
	s.Matches = nil
	return s, nil
}

// Update processes key / blur messages. When Active, esc dismisses; any
// other key forwards to the underlying textinput. When inactive it's a
// no-op.
func (s Search) Update(msg tea.Msg) (Search, tea.Cmd) {
	if !s.Active {
		return s, nil
	}
	if k, ok := msg.(tea.KeyPressMsg); ok {
		if k.String() == "esc" {
			s.Active = false
			s.ti.SetValue("")
			s.Matches = nil
			return s, nil
		}
	}
	var cmd tea.Cmd
	s.ti, cmd = s.ti.Update(msg)
	return s, cmd
}

// Filter populates Matches by running the current query against `rows`.
// Empty query OR inactive search produces nil Matches.
func (s *Search) Filter(rows []string) {
	q := s.ti.Value()
	if !s.Active || q == "" {
		s.Matches = nil
		return
	}
	s.Matches = fuzzy.Find(q, rows)
}

// View returns the textinput's rendered view when active, empty otherwise.
func (s Search) View() string {
	if !s.Active {
		return ""
	}
	return s.ti.View()
}

// Value returns the current query string (useful for tests and for screens
// that want to show the query in their header).
func (s Search) Value() string { return s.ti.Value() }

// SetValue is a test seam; parent screens don't need it in Phase 1.
func (s *Search) SetValue(v string) { s.ti.SetValue(v) }
