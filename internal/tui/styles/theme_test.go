// Package styles tests for the Phase 2 Info color token (D-12 INFO rows
// in S-USERS, noise tier in S-LOGS).
package styles_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/styles"
)

// TestTheme_Info_defined asserts the Info style exists and renders its
// argument. We intentionally do NOT assert exact ANSI bytes (fragile across
// terminal profile changes) — only that the rendered string contains the
// input substring and is non-empty.
func TestTheme_Info_defined(t *testing.T) {
	out := styles.Info.Render("noise")
	require.NotEmpty(t, out, "styles.Info.Render must produce a non-empty string")
	require.True(t, strings.Contains(out, "noise"),
		"styles.Info.Render output must contain its input; got %q", out)
}
