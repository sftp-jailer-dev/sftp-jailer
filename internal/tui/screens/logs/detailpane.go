// Package logsscreen — detailpane.go renders the per-event key/value
// detail block consumed by (a) the wide-mode right pane and (b) the
// narrow-mode modal. Pure-string output; no Lip Gloss styling here —
// the parent View applies width / padding.
//
// Mirrors the doctor service's `RenderText`-as-single-source-of-truth
// pattern: this helper is the byte-identity producer for both the
// wide-mode pane (split layout) and the narrow-mode detail modal
// (deferred to v1.x). Tests exercise the helper directly so neither
// layout has to recompute the key/value shape.
package logsscreen

import (
	"fmt"
	"strings"
	"time"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
)

// RenderDetail produces a multi-line key/value block describing one event.
//
// width is the target render width. The current implementation does not
// hard-wrap because Lip Gloss applies hard width clipping at the parent
// layer; long lines will overflow at the data layer and the parent style
// truncates with ellipsis if configured to do so. Soft wrapping is
// deliberately deferred — see UI-SPEC §S-LOGS detail-pane spec which
// allows the raw MESSAGE to overflow into a horizontal-scroll viewport
// in v1.x.
func RenderDetail(e store.Event, width int) string {
	_ = width // reserved for future soft-wrap; kept in signature for API stability.
	var b strings.Builder
	ts := time.Unix(0, e.TsUnixNs).UTC().Format("2006-01-02 15:04:05")
	fmt.Fprintf(&b, "timestamp:  %s\n", ts)
	fmt.Fprintf(&b, "user:       %s\n", displayOrDash(e.User))
	fmt.Fprintf(&b, "source:     %s\n", displayOrDash(e.SourceIP))
	fmt.Fprintf(&b, "event:      %s\n", displayOrDash(e.EventType))
	fmt.Fprintf(&b, "tier:       %s %s\n", e.Tier, tierGlyph(e.Tier))
	b.WriteString("\n")
	b.WriteString("raw MESSAGE:\n")
	b.WriteString(e.RawMessage)
	return b.String()
}

// displayOrDash returns "—" for the empty string so missing values are
// visibly distinct from intentional blanks. Used by both the detail
// pane and the flat-list cell renderer.
func displayOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// tierGlyph maps the 4-tier classifier output to its UI-SPEC line 432
// glyph. Unknown tiers render `?` so a future v=2 schema with a 5th tier
// degrades visibly rather than silently. Matches the in-package
// classification taxonomy from internal/observe/classifier.
func tierGlyph(tier string) string {
	switch tier {
	case "success":
		return "✓"
	case "targeted":
		return "!"
	case "noise":
		return "i"
	case "unmatched":
		return "⚠"
	}
	return "?"
}
