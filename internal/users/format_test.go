// Package users_test exercises the FormatPasswordAge helper truth table.
// The helper is the single rendering site for the "pwd age" column in
// S-USERS — both live render path and TSV path call into it. The truth
// table covers all five user-visible buckets at the boundaries:
//
//	"—"            ageDays < 0
//	"∞"            maxDays >= 99999 OR maxDays == 0 (no expiry policy)
//	"Nd (fresh)"   ageDays < agingDays
//	"Nd (aging)"   agingDays <= ageDays < staleDays
//	"Nd (stale)"   ageDays >= staleDays
package users_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// TestFormatPasswordAge_truth_table covers the five buckets at their
// boundary values with thresholds aging=180, stale=365 (the canonical
// Defaults() values). The "indefinite" bucket is exercised by both the
// >=99999 sentinel and the empty/0 case.
func TestFormatPasswordAge_truth_table(t *testing.T) {
	const (
		aging = 180
		stale = 365
	)
	cases := []struct {
		name    string
		age     int
		max     int
		want    string
		comment string
	}{
		// Unknown bucket — preserves Phase-1/-2 behavior on any error path.
		{"unknown_negative_age", -1, 90, "—", "ageDays<0 wins regardless of max"},
		{"unknown_negative_age_indefinite_max", -1, 99999, "—", "ageDays<0 short-circuits before indefinite check"},

		// Indefinite bucket — max>=99999 OR max==0.
		{"indefinite_max_99999", 50, 99999, "∞", "max==99999 → no expiry policy"},
		{"indefinite_max_above_99999", 50, 100000, "∞", "any max>=99999 → no expiry policy"},
		{"indefinite_max_zero", 50, 0, "∞", "empty/0 max → no expiry policy"},

		// Fresh bucket — ageDays < agingDays. Boundary: 0, 1, 179.
		{"fresh_zero", 0, 90, "0d (fresh)", "just changed today"},
		{"fresh_one_day", 1, 90, "1d (fresh)", "one day old"},
		{"fresh_just_below_aging", aging - 1, 90, "179d (fresh)", "boundary: aging-1 still fresh"},

		// Aging bucket — agingDays <= ageDays < staleDays. Boundaries: 180, 364.
		{"aging_at_aging_threshold", aging, 90, "180d (aging)", "boundary: at aging exactly"},
		{"aging_just_below_stale", stale - 1, 90, "364d (aging)", "boundary: stale-1 still aging"},

		// Stale bucket — ageDays >= staleDays. Boundaries: 365, 1000.
		{"stale_at_stale_threshold", stale, 90, "365d (stale)", "boundary: at stale exactly"},
		{"stale_well_past", 1000, 90, "1000d (stale)", "very stale"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := users.FormatPasswordAge(tc.age, tc.max, aging, stale)
			require.Equal(t, tc.want, got, "case=%s (%s); age=%d max=%d aging=%d stale=%d",
				tc.name, tc.comment, tc.age, tc.max, aging, stale)
		})
	}
}
