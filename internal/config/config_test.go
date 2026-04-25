// Package config_test exercises the koanf-based load + atomic save of
// /etc/sftp-jailer/config.yaml plus the inline Validate ruleset (D-07).
package config_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/config"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

const settingsPath = "/etc/sftp-jailer/config.yaml"

// TestLoad_missing_file_returns_defaults: no file in Fake.Files → ReadFile
// returns fs.ErrNotExist; Load must return Defaults() with nil error.
func TestLoad_missing_file_returns_defaults(t *testing.T) {
	f := sysops.NewFake()
	got, err := config.Load(context.Background(), f, settingsPath)
	require.NoError(t, err)
	require.Equal(t, config.Defaults(), got)
	require.Equal(t, 90, got.DetailRetentionDays)
	require.Equal(t, 500, got.DBMaxSizeMB)
	require.Equal(t, 90, got.CompactAfterDays)
}

// TestLoad_partial_yaml_overlays_defaults: only db_max_size_mb is set;
// the other two fields fall back to Defaults().
func TestLoad_partial_yaml_overlays_defaults(t *testing.T) {
	f := sysops.NewFake()
	f.Files[settingsPath] = []byte("db_max_size_mb: 1000\n")
	got, err := config.Load(context.Background(), f, settingsPath)
	require.NoError(t, err)
	require.Equal(t, 90, got.DetailRetentionDays, "default applies when field absent")
	require.Equal(t, 1000, got.DBMaxSizeMB)
	require.Equal(t, 90, got.CompactAfterDays, "default applies when field absent")
}

// TestLoad_full_yaml: all three keys set explicitly → Settings reflects them.
func TestLoad_full_yaml(t *testing.T) {
	f := sysops.NewFake()
	f.Files[settingsPath] = []byte(`detail_retention_days: 30
db_max_size_mb: 250
compact_after_days: 14
`)
	got, err := config.Load(context.Background(), f, settingsPath)
	require.NoError(t, err)
	require.Equal(t, 30, got.DetailRetentionDays)
	require.Equal(t, 250, got.DBMaxSizeMB)
	require.Equal(t, 14, got.CompactAfterDays)
}

// TestLoad_invalid_yaml_returns_error: malformed YAML must wrap a parse error.
// Validation does NOT run on Load — that's a Save concern; bad bytes on disk
// must surface as an explicit error so the screen can complain.
func TestLoad_invalid_yaml_returns_error(t *testing.T) {
	f := sysops.NewFake()
	f.Files[settingsPath] = []byte("not: [valid: yaml: at: all\n")
	_, err := config.Load(context.Background(), f, settingsPath)
	require.Error(t, err)
}

// TestSave_writes_via_AtomicWriteFile: after Save, Fake.Calls must record
// exactly one AtomicWriteFile call to settingsPath; round-trip Load returns
// identical settings.
func TestSave_writes_via_AtomicWriteFile(t *testing.T) {
	f := sysops.NewFake()
	want := config.Settings{
		DetailRetentionDays: 60,
		DBMaxSizeMB:         750,
		CompactAfterDays:    60,
	}
	require.NoError(t, config.Save(context.Background(), f, settingsPath, want))

	var awf []sysops.FakeCall
	for _, c := range f.Calls {
		if c.Method == "AtomicWriteFile" {
			awf = append(awf, c)
		}
	}
	require.Len(t, awf, 1, "exactly one AtomicWriteFile call expected")
	require.Equal(t, settingsPath, awf[0].Args[0])

	got, err := config.Load(context.Background(), f, settingsPath)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// TestSave_validates_first: invalid Settings must fail before any file write.
// Fake.Calls must NOT contain AtomicWriteFile.
func TestSave_validates_first(t *testing.T) {
	f := sysops.NewFake()
	bad := config.Settings{
		DetailRetentionDays: 90,
		DBMaxSizeMB:         50, // below 100 floor
		CompactAfterDays:    90,
	}
	err := config.Save(context.Background(), f, settingsPath, bad)
	require.Error(t, err)
	for _, c := range f.Calls {
		require.NotEqual(t, "AtomicWriteFile", c.Method,
			"validation must skip the write")
	}
}

// TestValidate_detail_retention_days_range: 0 / -1 / 3651 fail; 1 / 90 / 3650 pass.
func TestValidate_detail_retention_days_range(t *testing.T) {
	base := config.Defaults()

	for _, bad := range []int{0, -1, 3651} {
		s := base
		s.DetailRetentionDays = bad
		// CompactAfterDays must remain valid relative to the bad value, so
		// shrink it; the test target is the detail-retention rule alone.
		if bad > 0 && bad < s.CompactAfterDays {
			s.CompactAfterDays = bad
		}
		errs := config.Validate(s)
		require.NotEmpty(t, errs, "expected validation error for detail_retention_days=%d", bad)
	}
	for _, good := range []int{1, 90, 3650} {
		s := base
		s.DetailRetentionDays = good
		if s.CompactAfterDays > good {
			s.CompactAfterDays = good
		}
		errs := config.Validate(s)
		require.Empty(t, errs, "unexpected error for detail_retention_days=%d: %v", good, errs)
	}
}

// TestValidate_db_max_size_mb_floor: 99 fails; 100 / 500 / 100000 pass; 100001 fails.
func TestValidate_db_max_size_mb_floor(t *testing.T) {
	base := config.Defaults()

	s := base
	s.DBMaxSizeMB = 99
	require.NotEmpty(t, config.Validate(s), "99 must fail")

	for _, good := range []int{100, 500, 100000} {
		s := base
		s.DBMaxSizeMB = good
		require.Empty(t, config.Validate(s), "%d must pass", good)
	}

	s = base
	s.DBMaxSizeMB = 100001
	require.NotEmpty(t, config.Validate(s), "100001 must fail")
}

// TestValidate_compact_after_days_le_detail: compact_after_days must be ≤
// detail_retention_days.
func TestValidate_compact_after_days_le_detail(t *testing.T) {
	bad := config.Settings{DetailRetentionDays: 30, DBMaxSizeMB: 500, CompactAfterDays: 60}
	require.NotEmpty(t, config.Validate(bad))

	good := config.Settings{DetailRetentionDays: 30, DBMaxSizeMB: 500, CompactAfterDays: 30}
	require.Empty(t, config.Validate(good))

	good2 := config.Settings{DetailRetentionDays: 30, DBMaxSizeMB: 500, CompactAfterDays: 14}
	require.Empty(t, config.Validate(good2))
}

// TestValidate_returns_all_errors_not_just_first: every failing rule
// contributes its own error so the TUI can render them as a list.
//
// Note on input shape: DetailRetentionDays is set to a VALID value (30) so
// the "compact ≤ detail" comparison is meaningful — Validate intentionally
// suppresses that comparison when detail is itself invalid (line 130: the
// `else if s.DetailRetentionDays >= 1 && …` guard). The test exercises the
// "all rules fail simultaneously" path via independently-failing values.
func TestValidate_returns_all_errors_not_just_first(t *testing.T) {
	bad := config.Settings{
		DetailRetentionDays: 30,    // valid (in-range)
		DBMaxSizeMB:         50,    // fails floor
		CompactAfterDays:    99999, // fails ≤ detail
	}
	errs := config.Validate(bad)
	require.GreaterOrEqual(t, len(errs), 2, "expected ≥2 errors, got %d: %v", len(errs), errs)
	// Sanity-check: every error message is non-empty.
	for _, e := range errs {
		require.NotEmpty(t, strings.TrimSpace(e.Error()))
	}

	// Independent verification: each rule fails on its own with a single
	// dedicated bad value, so the "list of all violations" guarantee is
	// preserved (the TUI sees one message per knob the admin needs to fix).
	require.NotEmpty(t, config.Validate(config.Settings{
		DetailRetentionDays: 0, DBMaxSizeMB: 500, CompactAfterDays: 30,
	}))
	require.NotEmpty(t, config.Validate(config.Settings{
		DetailRetentionDays: 30, DBMaxSizeMB: 50, CompactAfterDays: 30,
	}))
	require.NotEmpty(t, config.Validate(config.Settings{
		DetailRetentionDays: 30, DBMaxSizeMB: 500, CompactAfterDays: 0,
	}))
}
