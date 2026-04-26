package users

import "fmt"

// FormatPasswordAge is the single rendering helper for the S-USERS "pwd
// age" column. Shared between the live-render path and the TSV/clipboard
// path — the truth table is the source of truth for what an admin sees.
//
// Inputs:
//   - ageDays: -1 = unknown (sysops error / shadow missing). >= 0 = real age
//   - maxDays: -1 = unknown; 0 = empty/no max set; >= 99999 = indefinite
//   - agingDays: aging-bucket lower threshold (cfg.PasswordAgingDays, e.g. 180)
//   - staleDays: stale-bucket lower threshold (cfg.PasswordStaleDays, e.g. 365)
//
// Output (one of five strings):
//
//	"—"             ageDays < 0
//	"∞"             maxDays >= 99999 OR maxDays == 0 (no expiry policy)
//	"Nd (fresh)"    ageDays < agingDays
//	"Nd (aging)"    agingDays <= ageDays < staleDays
//	"Nd (stale)"    ageDays >= staleDays
//
// Precedence is intentional: the unknown bucket short-circuits before the
// indefinite check (a row whose age we cannot read should render as the
// neutral "—" rather than masquerading as "∞"). Admins read this column
// to spot accounts that need a password rotation; the legend in S-USERS
// explains the bucket meanings.
func FormatPasswordAge(ageDays, maxDays, agingDays, staleDays int) string {
	if ageDays < 0 {
		return "—"
	}
	// "No expiry policy" wins over numeric bucket — an account flagged as
	// "indefinite" should not also be screaming "stale" because the admin
	// has explicitly opted out of the aging discipline for that account.
	if maxDays >= 99999 || maxDays == 0 {
		return "∞"
	}
	if ageDays < agingDays {
		return fmt.Sprintf("%dd (fresh)", ageDays)
	}
	if ageDays < staleDays {
		return fmt.Sprintf("%dd (aging)", ageDays)
	}
	return fmt.Sprintf("%dd (stale)", ageDays)
}
