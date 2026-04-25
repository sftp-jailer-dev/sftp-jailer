//go:build koanf_landed

// Package config loads and atomically saves /etc/sftp-jailer/config.yaml.
//
// This file is sftp-jailer's own config — the D-07 carve-out from the
// otherwise read-only Phase 2 boundary. Three knobs only:
//
//   - detail_retention_days [1..3650]    days to keep detail rows
//   - db_max_size_mb        [100..100000] hard cap on DB file size
//   - compact_after_days    [1..detail_retention_days] days before fold-down
//
// Atomic-write contract: Save validates → marshals via koanf → writes via
// sysops.AtomicWriteFile (tmp+fsync+rename in same dir, POSIX-atomic on
// rename). Validation runs BEFORE the write so a failing rule never touches
// the file.
//
// Pitfall acknowledged (RESEARCH Pitfall 7): koanf marshal does NOT preserve
// comments or original key order. The README documents this; a future
// v1.1 plan can switch to yaml.v3's Node API for comment preservation.
//
// Architectural invariants:
//   - Reads via sysops.ReadFile (NOT koanf's providers/file which calls
//     os.ReadFile directly — would bypass the seam).
//   - Writes via sysops.AtomicWriteFile (lands in plan 02-02 wave 2; this
//     plan ships the call site, 02-02 ships the method on SystemOps).
//   - This package never imports os or os/exec.
//
// Build/wave note: the koanf v2 dep tree (`koanf/v2 v2.3.4` + parsers/yaml +
// providers/rawbytes + providers/structs) is added to go.mod by plan 02-02
// (wave 2) per the wave-1 file-overlap discipline. The `koanf_landed`
// build tag at the top of this file keeps it out of the compile graph
// until 02-02 lands; 02-02's task list removes (or flips on) the build
// tag once `go.mod` carries the koanf deps AND `internal/sysops` exposes
// `AtomicWriteFile`. Wave ordering (02-03 wave 1 → 02-02 wave 2 with
// depends_on [02-01, 02-03]) guarantees the deps land before any consumer
// uses this package.
package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// Settings is the typed shape of /etc/sftp-jailer/config.yaml. All three
// fields are days/MB integers; the koanf struct tags map them to the
// snake_case YAML keys per RESEARCH lines 1131-1148.
type Settings struct {
	DetailRetentionDays int `koanf:"detail_retention_days"`
	DBMaxSizeMB         int `koanf:"db_max_size_mb"`
	CompactAfterDays    int `koanf:"compact_after_days"`
}

// Defaults returns the canonical default Settings. Used when the config
// file does not exist (first install) or to overlay missing keys when the
// admin has only set a subset.
func Defaults() Settings {
	return Settings{
		DetailRetentionDays: 90,
		DBMaxSizeMB:         500,
		CompactAfterDays:    90,
	}
}

// Load reads path via sysops.ReadFile, parses YAML via koanf, unmarshals
// into Settings, and overlays Defaults() for any zero-value fields. A
// missing file is NOT an error — Load returns Defaults() with nil err so
// the first-launch UX shows sensible values.
func Load(ctx context.Context, ops sysops.SystemOps, path string) (Settings, error) {
	defaults := Defaults()
	raw, err := ops.ReadFile(ctx, path)
	if errors.Is(err, fs.ErrNotExist) {
		return defaults, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("config.Load read: %w", err)
	}
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider(raw), yaml.Parser()); err != nil {
		return Settings{}, fmt.Errorf("config.Load parse: %w", err)
	}
	var s Settings
	if err := k.Unmarshal("", &s); err != nil {
		return Settings{}, fmt.Errorf("config.Load unmarshal: %w", err)
	}
	return overlayDefaults(s, defaults), nil
}

// Save validates → marshals via koanf → atomic-writes the result. Returns
// a wrapped error on any failure; the file is not touched unless validation
// passes.
//
// Mode 0o644 is the conventional permission for /etc files; root owns + writes,
// everyone reads. The S-SETTINGS screen runs as root (SAFE-01) so the chown
// is implicit.
func Save(ctx context.Context, ops sysops.SystemOps, path string, s Settings) error {
	if errs := Validate(s); len(errs) > 0 {
		return fmt.Errorf("config.Save invalid: %v", errs)
	}
	k := koanf.New(".")
	if err := k.Load(structs.Provider(s, "koanf"), nil); err != nil {
		return fmt.Errorf("config.Save struct load: %w", err)
	}
	out, err := k.Marshal(yaml.Parser())
	if err != nil {
		return fmt.Errorf("config.Save marshal: %w", err)
	}
	return ops.AtomicWriteFile(ctx, path, out, 0o644)
}

// Validate returns all rule violations as a slice. An empty slice means
// the Settings are valid. Returning all errors at once (rather than
// short-circuiting on the first) lets the TUI render them as a list so
// the admin can fix everything in one round-trip.
//
// Rules per RESEARCH lines 1171-1177:
//   - detail_retention_days ∈ [1, 3650]
//   - db_max_size_mb ∈ [100, 100000]
//   - compact_after_days ∈ [1, detail_retention_days]
func Validate(s Settings) []error {
	var errs []error
	if s.DetailRetentionDays < 1 || s.DetailRetentionDays > 3650 {
		errs = append(errs, fmt.Errorf("detail_retention_days must be a positive integer between 1 and 3650 (got %d)", s.DetailRetentionDays))
	}
	if s.DBMaxSizeMB < 100 || s.DBMaxSizeMB > 100000 {
		errs = append(errs, fmt.Errorf("db_max_size_mb must be between 100 and 100000 (got %d)", s.DBMaxSizeMB))
	}
	// compact_after_days must be at least 1, AND ≤ detail_retention_days
	// (when the latter is itself valid; when detail_retention_days is
	// already invalid, comparing against it is meaningless — but we still
	// flag a non-positive compact value).
	if s.CompactAfterDays < 1 {
		errs = append(errs, fmt.Errorf("compact_after_days must be a positive integer (got %d)", s.CompactAfterDays))
	} else if s.DetailRetentionDays >= 1 && s.CompactAfterDays > s.DetailRetentionDays {
		errs = append(errs, fmt.Errorf("compact_after_days must be ≤ detail_retention_days (got compact=%d, detail=%d)", s.CompactAfterDays, s.DetailRetentionDays))
	}
	return errs
}

// overlayDefaults populates zero-value fields in s from d. Used by Load to
// give the admin a sensible starting point when the config file is missing
// or incomplete — the alternative (failing on missing keys) breaks
// first-launch UX.
func overlayDefaults(s, d Settings) Settings {
	if s.DetailRetentionDays == 0 {
		s.DetailRetentionDays = d.DetailRetentionDays
	}
	if s.DBMaxSizeMB == 0 {
		s.DBMaxSizeMB = d.DBMaxSizeMB
	}
	if s.CompactAfterDays == 0 {
		s.CompactAfterDays = d.CompactAfterDays
	}
	return s
}
