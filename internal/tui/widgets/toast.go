package widgets

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// Toast is a short ephemeral confirmation shown at the bottom of the frame
// (e.g. "copied to clipboard"). It self-expires after a fixed TTL. The
// value-return pattern (C6 fix) makes state transitions explicit — calls
// look like:
//
//	a.toast, cmd = a.toast.Flash("copied")
//
// Pointer-receivers would silently drop mutations because Bubble Tea values
// are often passed by copy through tea.Cmd closures.
type Toast struct {
	text    string
	expires time.Time
}

// toastExpireMsg is emitted by the Flash tick to clear the toast.
type toastExpireMsg struct{}

// View renders the toast; empty string if inactive or expired.
func (t Toast) View() string {
	if t.text == "" || time.Now().After(t.expires) {
		return ""
	}
	return styles.Success.Render("✓ " + t.text)
}

// Flash returns a new Toast showing `text` for 2 seconds plus the tea.Cmd
// that will deliver the expire message. Caller site:
//
//	a.toast, cmd = a.toast.Flash("copied")
//	return a, cmd
func (t Toast) Flash(text string) (Toast, tea.Cmd) {
	t.text = text
	t.expires = time.Now().Add(2 * time.Second)
	return t, tea.Tick(2*time.Second, func(time.Time) tea.Msg { return toastExpireMsg{} })
}

// Update consumes toastExpireMsg to clear the toast; any other msg passes
// through. Returns a new Toast value (C6 pattern).
func (t Toast) Update(msg tea.Msg) Toast {
	if _, ok := msg.(toastExpireMsg); ok {
		t.text = ""
	}
	return t
}
