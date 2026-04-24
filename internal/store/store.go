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
	"database/sql"
	"fmt"

	// modernc.org/sqlite is the pure-Go driver (no cgo), mandated by the
	// CGO_ENABLED=0 single-static-binary constraint. See STACK.md §3.
	_ "modernc.org/sqlite"
)

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
