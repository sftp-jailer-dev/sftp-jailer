// Package users composes /etc/group, /etc/passwd, sshd_config drop-ins,
// store.Queries, and firewall.Enumerate into a single typed shape consumed
// by the S-USERS screen (USER-01/USER-02). The membership filter is the
// D-10 union (sftp* group ∪ ChrootDirectory home users). D-12 INFO
// pseudo-rows surface orphan chroot dirs, missing Match Group sftp* blocks,
// and missing ChrootDirectory directives — each carries the literal
// "[fix in Phase 3]" hint per UI-SPEC.
//
// Architectural invariants:
//   - All filesystem reads + Glob calls + subprocess execution flow through
//     sysops.SystemOps. This package never imports os, os/exec, or os/user
//     (CI guard scripts/check-no-exec-outside-sysops.sh enforces).
//   - sshd_config parsing reuses internal/sshdcfg.ParseDropIn (Phase 1) —
//     this package never re-implements the parser.
//   - The literal hint string "[fix in Phase 3]" appears in source so a
//     future grep-audit can confirm the contract holds.
package users

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// InfoKind discriminates the three D-12 INFO pseudo-row variants.
type InfoKind string

const (
	// InfoOrphan flags a chroot dir whose name has no matching system user
	// in /etc/passwd. Phase 3 (USER-04) ships the reconciliation flow.
	InfoOrphan InfoKind = "orphan"
	// InfoMissingMatch flags an sshd_config that has no `Match Group sftp*`
	// block. Phase 3 (SETUP-02) proposes + applies a canonical block.
	InfoMissingMatch InfoKind = "missing-match"
	// InfoMissingChroot flags an sshd_config with no `ChrootDirectory`
	// directive in any Match block. Phase 3 (SETUP-02) handles.
	InfoMissingChroot InfoKind = "missing-chroot"
)

// hintFixInPhase3 is the literal hint string carried on every InfoRow per
// UI-SPEC. Kept as a const so future plans can grep for the contract.
const hintFixInPhase3 = "[fix in Phase 3]"

// InfoRow is the D-12 pseudo-row shape rendered ABOVE the real user rows in
// S-USERS. It is non-selectable in the UI; this package only exposes the
// data — rendering is the screen's concern.
type InfoRow struct {
	Kind   InfoKind
	Detail string
	Hint   string
}

// Row is one D-10 user row consumed by S-USERS. Fields without data carry
// zero values: KeysCount/IPAllowlistCount=0, LastLoginNs=0, FirstSeenIP="".
//
// Password-age semantics (02-11 / SC #3):
//   - PasswordAgeDays: -1 = unknown (shadow unreadable / user missing /
//     field empty). >= 0 = real age in days, computed as
//     daysSinceEpoch(now) - lstchg.
//   - PasswordMaxDays: -1 = unknown; 0 = empty/no max set;
//     >= 99999 conventionally means "no expiry policy" (the indefinite
//     marker, treated as ∞ by FormatPasswordAge).
type Row struct {
	Username         string
	UID              int
	ChrootPath       string // resolved via sshdcfg ChrootDirectory or /etc/passwd home
	HomePath         string // /etc/passwd home dir
	PasswordAgeDays  int    // -1 = unknown; >=0 = days since lstchg
	PasswordMaxDays  int    // -1 = unknown; 0 = empty; >=99999 = indefinite policy
	KeysCount        int
	LastLoginNs      int64
	FirstSeenIP      string
	IPAllowlistCount int
}

// Enumerator holds the read-side composition seam. Construct via New;
// the type is stateless beyond the SystemOps + Queries handles + the
// chroot-root path used for orphan detection.
type Enumerator struct {
	ops        sysops.SystemOps
	queries    *store.Queries
	chrootRoot string
}

// New returns an Enumerator wired to ops + queries. Production code passes
// sysops.NewReal() and a *store.Queries built from the live Store; tests
// pass sysops.NewFake() and a Queries over a tmp DB.
func New(ops sysops.SystemOps, queries *store.Queries) *Enumerator {
	return &Enumerator{
		ops:        ops,
		queries:    queries,
		chrootRoot: "/srv/sftp",
	}
}

// Enumerate returns the D-10 union of user rows + the D-12 INFO pseudo-rows.
// Read-only: the caller decides how to render (S-USERS in plan 02-04).
//
// The pipeline (every step uses sysops methods — no direct os calls):
//  1. Read /etc/group → collect members of every group whose name starts
//     with "sftp" into a unique set.
//  2. Glob /etc/ssh/sshd_config.d/*.conf → parse each via sshdcfg.ParseDropIn
//     → collect ChrootDirectory values from any Match block whose Condition
//     starts with "Group sftp"; track whether any sftp* match block exists
//     and whether any ChrootDirectory directive exists at all.
//  3. Read /etc/passwd → for each line, build a Row if the user is in the
//     sftp* set OR has a home dir under any collected ChrootDirectory.
//  4. Per-row enrichment (independent calls so a single failure doesn't
//     poison the whole result):
//     - keys count via ~user/.ssh/authorized_keys
//     - last login via store.Queries.LastLoginPerUser
//     - allowlist count via firewall.Enumerate (filtered by user)
//  5. INFO pseudo-rows: missing-match, missing-chroot, orphan dirs.
func (e *Enumerator) Enumerate(ctx context.Context) ([]Row, []InfoRow, error) {
	sftpUsers, err := e.readSftpGroupMembers(ctx)
	if err != nil {
		return nil, nil, err
	}

	chrootDirs, hasMatchSftp, hasChrootDir := e.collectChrootDirectories(ctx)

	rows, err := e.readPasswdAndEnrich(ctx, sftpUsers, chrootDirs)
	if err != nil {
		return nil, nil, err
	}

	e.enrichKeys(ctx, rows)
	e.enrichLogins(ctx, rows)
	e.enrichAllowlistCount(ctx, rows)

	var infos []InfoRow
	if !hasMatchSftp {
		infos = append(infos, InfoRow{
			Kind:   InfoMissingMatch,
			Detail: "no `Match Group sftp*` block in sshd_config",
			Hint:   hintFixInPhase3,
		})
	}
	if !hasChrootDir {
		infos = append(infos, InfoRow{
			Kind:   InfoMissingChroot,
			Detail: "ChrootDirectory not configured in sshd_config",
			Hint:   hintFixInPhase3,
		})
	}
	infos = append(infos, e.detectOrphans(ctx, rows)...)
	return rows, infos, nil
}

// readSftpGroupMembers reads /etc/group via sysops.ReadFile and returns the
// set of unique members across every group whose name starts with "sftp".
// A missing /etc/group is reported as an error (it is system-mandatory);
// individual malformed lines are silently dropped.
func (e *Enumerator) readSftpGroupMembers(ctx context.Context) (map[string]struct{}, error) {
	raw, err := e.ops.ReadFile(ctx, "/etc/group")
	if err != nil {
		return nil, fmt.Errorf("users.Enumerate read /etc/group: %w", err)
	}
	out := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		if !strings.HasPrefix(fields[0], "sftp") {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				out[m] = struct{}{}
			}
		}
	}
	return out, nil
}

// collectChrootDirectories enumerates /etc/ssh/sshd_config.d/*.conf via
// sysops.Glob, parses each via sshdcfg.ParseDropIn, and returns:
//   - chrootDirs: every ChrootDirectory value found inside any Match block
//     whose Condition starts with "Group sftp" (so admin-defined Match
//     blocks targeting non-sftp groups don't pollute the home-under-chroot
//     filter).
//   - hasMatchSftp: any drop-in contains a `Match Group sftp*` block.
//   - hasChrootDir: any drop-in contains a `ChrootDirectory` directive
//     anywhere (top-level or inside a Match block).
//
// Glob errors are tolerated (treated as "no drop-ins"); per-file ReadFile
// errors are tolerated (skip the file). The S-USERS screen surfaces the
// missing-match / missing-chroot states via InfoRow rather than erroring.
func (e *Enumerator) collectChrootDirectories(ctx context.Context) (chrootDirs []string, hasMatchSftp, hasChrootDir bool) {
	paths, err := e.ops.Glob(ctx, "/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		return nil, false, false
	}
	for _, p := range paths {
		b, err := e.ops.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		parsed, _ := sshdcfg.ParseDropIn(b)
		for _, m := range parsed.Matches {
			fields := strings.Fields(m.Condition)
			isSftpGroup := false
			if len(fields) >= 2 && strings.EqualFold(fields[0], "Group") && strings.HasPrefix(fields[1], "sftp") {
				hasMatchSftp = true
				isSftpGroup = true
			}
			for _, dir := range m.Body {
				if dir.Keyword == "chrootdirectory" {
					hasChrootDir = true
					if isSftpGroup {
						chrootDirs = append(chrootDirs, dir.Value)
					}
				}
			}
		}
		// Top-level ChrootDirectory directives count toward hasChrootDir
		// but not toward chrootDirs (they would apply to every user, which
		// is not the sftp-jailer-managed contract).
		for _, dir := range parsed.Directives {
			if dir.Keyword == "chrootdirectory" {
				hasChrootDir = true
			}
		}
	}
	return chrootDirs, hasMatchSftp, hasChrootDir
}

// readPasswdAndEnrich reads /etc/passwd and emits one Row per user that
// either belongs to the sftp* group set OR has a home dir under any of
// the collected ChrootDirectory values. Returns the rows sorted by
// /etc/passwd order (preserves admin's mental model of UID assignment).
func (e *Enumerator) readPasswdAndEnrich(ctx context.Context, sftpUsers map[string]struct{}, chrootDirs []string) ([]Row, error) {
	raw, err := e.ops.ReadFile(ctx, "/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("users.Enumerate read /etc/passwd: %w", err)
	}

	// Pre-clean chrootDirs once so the per-line homeUnderChroot check is fast.
	cleanedChroots := make([]string, 0, len(chrootDirs))
	for _, c := range chrootDirs {
		// %u tokens expand per-user — for matching purposes the parent dir
		// is what counts. /srv/sftp/%u → /srv/sftp.
		c = strings.ReplaceAll(c, "/%u", "")
		cleanedChroots = append(cleanedChroots, filepath.Clean(c))
	}

	var rows []Row
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		username := fields[0]
		var uid int
		if _, err := fmt.Sscanf(fields[2], "%d", &uid); err != nil {
			continue
		}
		home := fields[5]

		_, inSftpGroup := sftpUsers[username]
		homeUnderChroot := false
		for _, c := range cleanedChroots {
			if c != "" && c != "/" && strings.HasPrefix(filepath.Clean(home), c+"/") {
				homeUnderChroot = true
				break
			}
		}
		if !inSftpGroup && !homeUnderChroot {
			continue
		}
		rows = append(rows, Row{
			Username:        username,
			UID:             uid,
			HomePath:        home,
			ChrootPath:      home, // best-effort: most setups colocate chroot=home
			PasswordAgeDays: -1,   // overwritten by enrichPasswordAge on success
			PasswordMaxDays: -1,   // overwritten by enrichPasswordAge on success
		})
	}
	return rows, nil
}

// enrichKeys reads ~user/.ssh/authorized_keys via sysops.ReadFile and counts
// non-empty non-comment lines. A missing or unreadable file silently leaves
// KeysCount at 0 — the screen renders 0 the same way whether the file is
// missing or empty (the distinction is not actionable for the admin).
func (e *Enumerator) enrichKeys(ctx context.Context, rows []Row) {
	for i := range rows {
		path := filepath.Join(rows[i].HomePath, ".ssh", "authorized_keys")
		raw, err := e.ops.ReadFile(ctx, path)
		if err != nil {
			continue
		}
		count := 0
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			count++
		}
		rows[i].KeysCount = count
	}
}

// enrichLogins joins LastLoginPerUser onto the row slice. A missing Queries
// handle (e.g. tests that don't care about login enrichment) is tolerated;
// query errors are silently dropped — the column renders "—" in the UI when
// LastLoginNs == 0 and that's a survivable degradation.
//
// First-seen-IP is best-effort and currently left empty: deriving it
// requires a separate query that doesn't exist on Phase 1's Queries surface;
// the column is documented to render "—" when empty per UI-SPEC line 380.
// A future plan can add Queries.FirstSeenPerUser without breaking this API.
func (e *Enumerator) enrichLogins(ctx context.Context, rows []Row) {
	if e.queries == nil {
		return
	}
	logins, err := e.queries.LastLoginPerUser(ctx)
	if err != nil {
		return
	}
	byUser := make(map[string]int64, len(logins))
	for _, l := range logins {
		byUser[l.User] = l.LastLoginNs
	}
	for i := range rows {
		if ts, ok := byUser[rows[i].Username]; ok {
			rows[i].LastLoginNs = ts
		}
	}
}

// enrichAllowlistCount runs firewall.Enumerate once and counts rules per
// user, then writes the count back into each Row. Errors (ufw inactive,
// not installed) silently leave the count at 0 — the column renders
// 0 the same way as "ufw inactive" and the S-FIREWALL screen surfaces
// the underlying state separately.
func (e *Enumerator) enrichAllowlistCount(ctx context.Context, rows []Row) {
	rules, err := firewall.Enumerate(ctx, e.ops)
	if err != nil {
		return
	}
	counts := map[string]int{}
	for _, r := range rules {
		if r.User != "" {
			counts[r.User]++
		}
	}
	for i := range rows {
		rows[i].IPAllowlistCount = counts[rows[i].Username]
	}
}

// detectOrphans enumerates the chroot root via sysops.ReadDir and emits an
// InfoOrphan row for every top-level dir whose name has no corresponding
// Row in the user list. The hint string "[fix in Phase 3]" tells the admin
// that USER-04 (Phase 3) will handle reconciliation.
//
// A missing chroot root (ReadDir returns ErrNotExist) is silently treated
// as "no orphans" — that's a different problem surfaced by the doctor.
func (e *Enumerator) detectOrphans(ctx context.Context, rows []Row) []InfoRow {
	entries, err := e.ops.ReadDir(ctx, e.chrootRoot)
	if err != nil {
		return nil
	}
	known := map[string]bool{}
	for _, r := range rows {
		known[r.Username] = true
	}
	var infos []InfoRow
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if known[name] {
			continue
		}
		infos = append(infos, InfoRow{
			Kind:   InfoOrphan,
			Detail: fmt.Sprintf("%s/%s (no backing system user)", e.chrootRoot, name),
			Hint:   hintFixInPhase3,
		})
	}
	return infos
}
