// Package store opens the sftp-jailer observation SQLite database with
// the reader-pool / single-writer split documented in ARCHITECTURE.md
// pattern 5.
//
// The split exists because WAL mode in SQLite (and in modernc.org/sqlite
// specifically) gives best throughput when a single connection is
// dedicated to writes while readers draw from a pool — this avoids
// SQLITE_BUSY under the TUI + cron concurrency pattern this project
// exhibits (the user browses the observation view while the weekly
// systemd timer ingests new journal lines).
//
// Phase 1 ships plumbing only. Phase 2 populates migrations/*.sql with
// the observations / observation_runs / noise_counters schema (OBS-*).
// Phase 4 adds 003_user_ips.sql for the FW-08 belt-and-suspenders
// recovery mirror.
package store

import (
	"context"
	"database/sql"
	"fmt"

	// modernc.org/sqlite is the pure-Go driver (no cgo), mandated by the
	// CGO_ENABLED=0 single-static-binary constraint. See STACK.md §3.
	_ "modernc.org/sqlite"
)

// ExpectedSchemaVersion is the highest user_version this binary's embedded
// migrations will advance the DB to. The OBS-04 schema-drift gate compares
// this against the on-disk PRAGMA user_version BEFORE Migrate runs, so the
// `observe-run` subcommand can refuse to operate on a DB written by a
// newer binary (which might have introduced columns this code does not
// know how to populate).
//
// MUST equal the highest numeric prefix in `internal/store/migrations/`.
// The TestExpectedSchemaVersion_constant test pins this invariant.
const ExpectedSchemaVersion = 2

// Store splits read and write traffic into two separate *sql.DB handles
// pointing at the same on-disk database. R is a pooled reader
// (MaxOpenConns=8); W is a single-connection writer (MaxOpenConns=1).
// The split is enforced by the separate handles — callers must write
// through W and read through R. A lint rule in a future phase will
// enforce call-site discipline.
type Store struct {
	R *sql.DB // reader pool (MaxOpenConns = 8)
	W *sql.DB // single-conn writer (MaxOpenConns = 1)
}

// Open opens (or creates) a SQLite database at path, enabling WAL mode,
// a 5-second busy_timeout, NORMAL sync, and foreign_keys=ON. Pragmas are
// passed via the DSN so they apply to every connection the pool creates,
// not just the first.
//
// The caller should invoke Store.Migrate after Open to bring the schema
// to the binary's expected user_version. Phase 1 ships an empty
// migrations/ directory so Migrate is a no-op until Phase 2.
//
// Both handles are Ping()'d before return; any driver error closes the
// handles that did open and returns a wrapped error.
func Open(path string) (*Store, error) {
	// modernc.org/sqlite supports ?_pragma=key(value) in the DSN, and the
	// query param is repeatable. journal_mode=WAL sticks across connections
	// once any connection turns it on for the database file — but we
	// specify it on every connection for belt-and-suspenders.
	dsn := fmt.Sprintf(
		"%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path,
	)

	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open reader: %w", err)
	}
	r.SetMaxOpenConns(8)
	if err := r.Ping(); err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("store.Open reader ping: %w", err)
	}

	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("store.Open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, fmt.Errorf("store.Open writer ping: %w", err)
	}

	return &Store{R: r, W: w}, nil
}

// PeekUserVersion opens path with a one-shot connection, reads PRAGMA
// user_version, and returns it WITHOUT applying any migrations. Used by
// `sftp-jailer observe-run` to implement the OBS-04 schema-drift gate:
// if the on-disk DB reports a version higher than ExpectedSchemaVersion,
// the binary refuses to run rather than silently downgrading or
// corrupting newer columns.
//
// Behavior corner cases:
//   - If the file does not exist, the sqlite driver auto-creates it. The
//     newly-created file has user_version=0, so this function returns 0
//     with no error — the caller's subsequent Migrate() will bring it
//     forward.
//   - PeekUserVersion does NOT acquire the writer lock, so it is safe to
//     call concurrently with an in-flight Open()/Migrate() on the same
//     file (although the race is academic in practice — the OBS-04 gate
//     runs once, before Open).
func PeekUserVersion(ctx context.Context, path string) (int, error) {
	// Mirror Open()'s busy_timeout pragma so PeekUserVersion plays nicely
	// with a live writer; we deliberately omit journal_mode/foreign_keys
	// because we are read-only and want zero schema-mutating side effects.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, fmt.Errorf("store.PeekUserVersion open: %w", err)
	}
	defer func() { _ = db.Close() }()

	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store.PeekUserVersion query: %w", err)
	}
	return v, nil
}

// Close closes both the reader and writer handles. If both return an
// error, the reader error is returned (the writer error is logged via
// the returned error chain only when reader close succeeds) — consistent
// with standard Go "first error wins" convention.
func (s *Store) Close() error {
	errR := s.R.Close()
	errW := s.W.Close()
	if errR != nil {
		return errR
	}
	return errW
}
