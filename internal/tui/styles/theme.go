// Package styles holds the lipgloss style primitives used across screens.
// TUI-07 graceful color degradation is handled automatically by lipgloss v2
// via the colorprofile integration — hex colors fall back to 256 / 16 /
// monochrome based on the detected terminal profile.
//
// Note: Lip Gloss v2 removed the v1 `lipgloss.AdaptiveColor` type. The v2
// replacement for light/dark switching is the `lipgloss.LightDark(isDark)`
// helper wrapped around individual styles; for Phase 1 we use plain Colors
// — the palette was chosen to read acceptably on both light and dark
// backgrounds and the downsampler handles everything else. Revisit in Phase 2
// if specific screens need per-background tuning.
package styles

import "charm.land/lipgloss/v2"

var (
	// Primary — neutral blue used for headings and accents.
	Primary = lipgloss.NewStyle().Foreground(lipgloss.Color("#4a9eff"))
	// Success — green used for positive confirmations (e.g. copied to clipboard).
	Success = lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e"))
	// Warn — amber used for warnings.
	Warn = lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b"))
	// Critical — red + bold used for errors and destructive warnings.
	Critical = lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Bold(true)
	// Dim — faint style used for subtle labels (e.g. "— help —").
	Dim = lipgloss.NewStyle().Faint(true)
	// Info — cyan token added in Phase 2 plan 02-04. Used by S-USERS for
	// D-12 INFO pseudo-rows (orphan / missing-match / missing-chroot
	// breadcrumbs) and by S-LOGS (02-06) for the `noise` log tier. See
	// UI-SPEC §Color row "info (NEW)".
	Info = lipgloss.NewStyle().Foreground(lipgloss.Color("#06b6d4"))
)
