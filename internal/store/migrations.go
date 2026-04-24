package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// migrationsFS embeds the migrations/ directory into the binary.
//
// Directive shape matters: we use `//go:embed all:migrations` rather than
// `//go:embed migrations/*.sql`. The glob form fails at compile time when
// the directory contains no .sql files — which is the Phase 1 state
// because only `.gitkeep` lives there. The plain `//go:embed migrations`
// form ALSO fails because `//go:embed` excludes dotfiles by default, and
// `.gitkeep` is the only tracked file. The `all:` prefix opts dotfiles in,
// letting the directive succeed against a `.gitkeep`-only directory.
// fs.ReadDir at runtime filters to `.sql` extensions so `.gitkeep` never
// gets treated as a migration. Phase 2 populates 001_init.sql etc.
// without touching this directive.
//
//go:embed all:migrations
var migrationsFS embed.FS

// Migrate applies any migrations/NNN_name.sql files that haven't been
// applied yet, tracking progress via SQLite's PRAGMA user_version.
//
// File naming convention: the numeric prefix before the first underscore
// IS the target user_version. Example:
//
//	migrations/001_init.sql                 → user_version = 1
//	migrations/002_add_observations.sql     → user_version = 2
//	migrations/003_user_ips.sql             → user_version = 3
//
// Each migration runs inside its own transaction; the PRAGMA user_version
// update is in the same tx. If the DDL fails, the transaction rolls back
// and the user_version stays where it was. Migrations are applied in
// numeric order regardless of lexical order of file names.
//
// Phase 1 ships an empty migrations/ directory (only .gitkeep), so this
// function is a no-op until Phase 2 populates it. Callers must treat
// "no migrations to run" as success.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		// Defensive: if the embedded directory is somehow absent (shouldn't
		// happen given the //go:embed directive), treat as no-op rather
		// than forcing a release blocker on empty-migrations day 1.
		if strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "file does not exist") {
			return nil
		}
		return fmt.Errorf("store.Migrate: read embedded dir: %w", err)
	}

	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".sql") {
			continue
		}
		dash := strings.Index(n, "_")
		if dash < 1 {
			continue
		}
		v, err := strconv.Atoi(n[:dash])
		if err != nil {
			continue
		}
		migs = append(migs, mig{version: v, name: n})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	var currentVersion int
	if err := s.W.QueryRowContext(ctx, "PRAGMA user_version").Scan(&currentVersion); err != nil {
		return fmt.Errorf("store.Migrate: read user_version: %w", err)
	}

	for _, m := range migs {
		if m.version <= currentVersion {
			continue
		}
		sqlBytes, err := fs.ReadFile(migrationsFS, "migrations/"+m.name)
		if err != nil {
			return fmt.Errorf("store.Migrate: read %s: %w", m.name, err)
		}
		tx, err := s.W.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store.Migrate: begin %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store.Migrate: exec %s: %w", m.name, err)
		}
		// PRAGMA user_version can't be parameterized — format the int into
		// the statement. Safe: the value comes from a %d scan of a file
		// name prefix under our control, not user input.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store.Migrate: set user_version for %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store.Migrate: commit %s: %w", m.name, err)
		}
	}
	return nil
}
