package store

import (
	"context"
	"embed"
	"errors"
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
// the directory contains no .sql files - which is the Phase 1 state
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

// MigrateOption configures Migrate behavior. Use WithProgress to install
// a progress callback. Multiple options may be passed; they are applied
// in order.
type MigrateOption func(*migrateOpts)

// migrateOpts is the internal options struct populated by MigrateOption
// functions. Fields are package-private; callers configure via the
// exported With* helpers.
type migrateOpts struct {
	progress func(label string)
}

// WithProgress installs a progress callback that fires once per migration
// applied (i.e., migrations whose numeric prefix > current user_version).
// The callback receives a human-friendly label tied to the migration's
// purpose. On an already-migrated DB, the callback is NOT called.
//
// Phase 9 plan 09-02 ships this hook. Phase 12's launch state machine
// will plumb the callback into the splash/doctor handoff to render
// "Upgrading observation index..." during multi-second migrations on
// noisy lab hosts (per 09-CONTEXT.md D-15).
//
// Passing a nil callback is safe and silent (treated as no-op, identical
// to omitting the option entirely).
func WithProgress(fn func(label string)) MigrateOption {
	return func(o *migrateOpts) {
		if fn != nil {
			o.progress = fn
		}
	}
}

// migrationLabel maps a migration filename to a human-friendly progress
// label. Unknown migrations fall back to a generic "Applying NNN..."
// string so future migrations don't crash callers that haven't yet been
// updated. Labels for known migrations are LOCKED at plan time per
// 09-CONTEXT.md D-15 (the "Upgrading observation index..." string is
// the load-bearing user-facing copy for the Phase 12 splash).
func migrationLabel(name string) string {
	switch name {
	case "001_init.sql":
		return "Creating observation tables..."
	case "002_add_indexes.sql":
		return "Creating observation indexes..."
	case "003_user_ips.sql":
		return "Creating user-IP cache table..."
	case "004_add_dedup_index.sql":
		return "Upgrading observation index..."
	default:
		return "Applying " + name + "..."
	}
}

// Migrate applies any migrations/NNN_name.sql files that haven't been
// applied yet, tracking progress via SQLite's PRAGMA user_version.
//
// File naming convention: the numeric prefix before the first underscore
// IS the target user_version. Example:
//
//	migrations/001_init.sql                 → user_version = 1
//	migrations/002_add_observations.sql     → user_version = 2
//	migrations/003_user_ips.sql             → user_version = 3
//	migrations/004_add_dedup_index.sql      → user_version = 4
//
// Each migration runs inside its own transaction; the PRAGMA user_version
// update is in the same tx. If the DDL fails, the transaction rolls back
// and the user_version stays where it was. Migrations are applied in
// numeric order regardless of lexical order of file names.
//
// Phase 1 ships an empty migrations/ directory (only .gitkeep), so this
// function is a no-op until Phase 2 populates it. Callers must treat
// "no migrations to run" as success.
//
// Variadic MigrateOption arguments configure optional behavior. Use
// WithProgress to receive a per-applied-migration callback (Phase 9 plan
// 09-02 hook for Phase 12's splash UI). The 1-arg form `s.Migrate(ctx)`
// remains supported for all existing call sites (variadic = backwards-compatible).
func (s *Store) Migrate(ctx context.Context, opts ...MigrateOption) error {
	var o migrateOpts
	for _, opt := range opts {
		opt(&o)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		// Defensive: if the embedded directory is somehow absent (shouldn't
		// happen given the //go:embed directive), treat as no-op rather
		// than forcing a release blocker on empty-migrations day 1.
		// Use errors.Is(err, fs.ErrNotExist) instead of string-matching the
		// error message: the wording is not part of the stdlib API contract
		// and may shift between Go versions, but fs.ErrNotExist is.
		if errors.Is(err, fs.ErrNotExist) {
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
		// Fire progress callback BEFORE executing the migration so the UI
		// can paint the label before the synchronous DDL stalls the
		// goroutine. On an already-migrated DB, none of the loop body
		// runs so the callback is never called (per WithProgress contract).
		if o.progress != nil {
			o.progress(migrationLabel(m.name))
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
		// PRAGMA user_version can't be parameterized - format the int into
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
