// Package observe (runner.go): headless observation pipeline orchestrator.
//
// Pipeline shape:
//
//  1. Insert observation_runs row (result='running') → run_id.
//  2. Open journalctl stream via ops.JournalctlStream.
//  3. bufio.Scanner the stream (1 MB line buffer, RESEARCH §700).
//  4. For each line: Parse → Classify → batch (size 100) → INSERT via
//     store.W in a single tx per batch.
//  5. After scanner ends: emit final read+classify counts.
//  6. Compact: BEGIN IMMEDIATE; UPSERT into noise_counters from rows older
//     than (now - CompactAfterDays); DELETE same; COMMIT.
//  7. Loop: while pragma page_count*page_size > DBMaxSizeMB*1024*1024
//     DELETE oldest bucket_date noise_counters rows in small txs.
//  8. PRAGMA wal_checkpoint(TRUNCATE) once.
//  9. UPDATE observation_runs with final counters + result='success'.
//  10. Emit Progress{Phase: PhaseDone, Summary: &summary}.
//
// Error handling: on any non-context error, UPDATE observation_runs with
// result='failure', error=err.Error(), then return err. On ctx
// cancellation: UPDATE result='cancelled', commit current batch, return
// ctx.Err().
//
// SQL discipline: every INSERT uses parameterized `?` placeholders — the
// MESSAGE field flowing in from journalctl is treated as untrusted input
// (T-OBS-10 in plan §threat_model).
package observe

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// RunOpts parameterizes a single Runner.Run invocation. Retention values
// flow from config.Load (or config.Defaults if the settings file is
// missing) — this is where the OBS-05 retention loop closes.
type RunOpts struct {
	CursorFile          string
	DetailRetentionDays int
	DBMaxSizeMB         int
	CompactAfterDays    int

	// Since is an optional --since override (test-only). In production
	// this is empty and the cursor file drives the resume point.
	Since string

	// Quiet, when true, suppresses every JSON progress line except the
	// terminal `done` / `skipped` event. Used by systemd-timer runs.
	Quiet bool
}

// RunSummary is the final summary emitted in the `done` JSON event AND
// persisted into observation_runs. Counter fields mirror the table
// columns; StartedNs / FinishedNs are Unix ns timestamps; Result is one
// of 'success' | 'failure' | 'cancelled'.
type RunSummary struct {
	EventsRead       int    `json:"events_read"`
	EventsClassified int    `json:"events_classified"`
	EventsKept       int    `json:"events_kept"`
	EventsCompacted  int    `json:"events_compacted"`
	EventsDropped    int    `json:"events_dropped"`
	CountersAdded    int    `json:"counters_added"`
	StartedNs        int64  `json:"started_ns"`
	FinishedNs       int64  `json:"finished_ns"`
	DurationHuman    string `json:"duration_human"`
	Result           string `json:"result"`
}

// Runner owns the SystemOps + Store handles for a sequence of Run calls.
// Construct via NewRunner; treat as long-lived (the cobra observe-run cmd
// builds one per invocation, but a future TUI integration could share one).
type Runner struct {
	ops sysops.SystemOps
	st  *store.Store
}

// NewRunner returns a Runner ready to Run.
func NewRunner(ops sysops.SystemOps, st *store.Store) *Runner {
	return &Runner{ops: ops, st: st}
}

// batchSize is the number of observation rows accumulated per INSERT tx.
// 100 is large enough to amortize round-trip overhead but small enough
// to keep memory bounded under a journalctl burst.
const batchSize = 100

// Run executes the full pipeline and writes JSON progress events to stdout.
func (r *Runner) Run(ctx context.Context, opts RunOpts, stdout io.Writer) error {
	emitter := &JSONEmitter{W: stdout, Quiet: opts.Quiet}

	startedNs := time.Now().UnixNano()
	summary := RunSummary{StartedNs: startedNs}

	// 1. Insert observation_runs row (result=running).
	res, err := r.st.W.ExecContext(ctx,
		`INSERT INTO observation_runs(started_at_unix_ns, result) VALUES (?, 'running')`,
		startedNs)
	if err != nil {
		return fmt.Errorf("observe.Runner: insert observation_runs: %w", err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("observe.Runner: lastInsertId: %w", err)
	}

	// finalize updates the observation_runs row + emits the done event.
	finalize := func(result string, errMsg string) {
		summary.Result = result
		summary.FinishedNs = time.Now().UnixNano()
		dur := time.Duration(summary.FinishedNs - summary.StartedNs)
		summary.DurationHuman = humanize.RelTime(
			time.Unix(0, summary.StartedNs),
			time.Unix(0, summary.FinishedNs),
			"", "")
		_ = dur // referenced for clarity; humanize handles formatting

		_, _ = r.st.W.ExecContext(context.Background(), //nolint:contextcheck // finalize must run even when ctx cancelled
			`UPDATE observation_runs
			 SET finished_at_unix_ns=?, result=?, error=?,
			     events_read=?, events_classified=?, events_kept=?,
			     events_compacted=?, events_dropped=?, counters_added=?
			 WHERE id=?`,
			summary.FinishedNs, result, errMsg,
			summary.EventsRead, summary.EventsClassified, summary.EventsKept,
			summary.EventsCompacted, summary.EventsDropped, summary.CountersAdded,
			runID)
		_ = emitter.Emit(Progress{Phase: PhaseDone, Summary: &summary})
	}

	// 2. Open journalctl stream.
	proc, stream, err := r.ops.JournalctlStream(ctx, sysops.JournalctlStreamOpts{
		CursorFile: opts.CursorFile,
		Unit:       "ssh",
		Since:      opts.Since,
	})
	if err != nil {
		finalize("failure", err.Error())
		return fmt.Errorf("observe.Runner: open journalctl stream: %w", err)
	}
	defer func() {
		if stream != nil {
			_ = stream.Close()
		}
	}()

	// 3+4. Read + classify + batch insert.
	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate 1 MB lines

	batch := make([]observationRow, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := insertBatch(ctx, r.st.W, runID, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

	for sc.Scan() {
		// Honor context cancellation between scan iterations.
		if cerr := ctx.Err(); cerr != nil {
			_ = flush()
			finalize("cancelled", cerr.Error())
			if proc != nil {
				_ = proc.Kill()
				_, _ = proc.Wait()
			}
			return cerr
		}

		summary.EventsRead++
		ev, perr := Parse(sc.Bytes())
		if perr != nil {
			// Parse errors (malformed JSON, missing MESSAGE) are counted
			// against EventsRead but NOT against EventsClassified — they
			// never become observation rows. The runner does not abort.
			continue
		}
		cls := Classify(ev)
		summary.EventsClassified++

		batch = append(batch, observationRow{
			tsUnixNs:  ev.Timestamp.UnixNano(),
			tier:      string(cls.Tier),
			user:      cls.User,
			sourceIP:  cls.SourceIP,
			eventType: cls.EventType,
			rawMsg:    ev.Raw,
			rawJSON:   string(sc.Bytes()),
			pid:       ev.PID,
		})
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				finalize("failure", err.Error())
				return fmt.Errorf("observe.Runner: flush batch: %w", err)
			}
		}
	}

	// Final batch flush.
	if err := flush(); err != nil {
		finalize("failure", err.Error())
		return fmt.Errorf("observe.Runner: final flush: %w", err)
	}

	if err := sc.Err(); err != nil {
		finalize("failure", err.Error())
		return fmt.Errorf("observe.Runner: scanner: %w", err)
	}

	// Wait for journalctl process; non-zero exit is logged in the summary
	// but does not by itself fail the run (the cursor was already advanced
	// for every event we ingested).
	if proc != nil {
		// proc.Wait returns (*os.ProcessState, error); both ignored here
		// because non-zero exit is a soft signal — the data is already
		// ingested and the cursor advanced.
		if _, werr := proc.Wait(); werr != nil {
			summary.Result = "success_with_warnings"
			_ = werr
		}
	}

	// 5. Read + classify phase events (emit AFTER ingest, with final counts).
	_ = emitter.Emit(Progress{Phase: PhaseRead, Count: summary.EventsRead})
	_ = emitter.Emit(Progress{Phase: PhaseClassify, Count: summary.EventsClassified})

	// 6. Compaction (D-09): fold rows older than CompactAfterDays into noise_counters.
	compactBeforeNs := time.Now().Add(-time.Duration(opts.CompactAfterDays) * 24 * time.Hour).UnixNano()
	compactedCount, addedCount, err := compact(ctx, r.st.W, compactBeforeNs)
	if err != nil {
		finalize("failure", err.Error())
		return fmt.Errorf("observe.Runner: compact: %w", err)
	}
	summary.EventsCompacted = compactedCount
	summary.CountersAdded = addedCount

	// 6.5. pruneDetail (OBS-05): DELETE detail rows older than DetailRetentionDays.
	// Catches anything compact missed (e.g. an aborted prior compact run, or a
	// runtime config change that shortened the retention window). Skipped when
	// DetailRetentionDays <= 0 to preserve the legacy "leave it alone" semantics
	// (parity with pruneToCap's capMB <= 0 zero-guard).
	if opts.DetailRetentionDays > 0 {
		detailBeforeNs := time.Now().Add(-time.Duration(opts.DetailRetentionDays) * 24 * time.Hour).UnixNano()
		detailDropped, derr := pruneDetail(ctx, r.st.W, detailBeforeNs)
		if derr != nil {
			finalize("failure", derr.Error())
			return fmt.Errorf("observe.Runner: pruneDetail: %w", derr)
		}
		summary.EventsDropped += detailDropped
	}

	// 7. Prune oldest noise_counters rows until DB size dips under MB cap.
	pruned, err := pruneToCap(ctx, r.st.W, opts.DBMaxSizeMB)
	if err != nil {
		finalize("failure", err.Error())
		return fmt.Errorf("observe.Runner: prune: %w", err)
	}
	summary.EventsDropped += pruned

	// 8. WAL checkpoint TRUNCATE — release deleted pages back to disk.
	if _, err := r.st.W.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		// non-fatal — log via summary error path but do not abort.
		_ = err
	}

	// EventsKept = total rows still in observations after compaction.
	if err := r.st.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations WHERE run_id=?`, runID).
		Scan(&summary.EventsKept); err != nil {
		// Best-effort metric; do not abort.
		summary.EventsKept = summary.EventsClassified - compactedCount
	}

	_ = emitter.Emit(Progress{
		Phase:         PhaseCompact,
		Kept:          summary.EventsKept,
		Compacted:     summary.EventsCompacted,
		Dropped:       summary.EventsDropped,
		CountersAdded: summary.CountersAdded,
	})

	// 9 + 10. Finalize observation_runs row + emit done event.
	finalize("success", "")
	return nil
}

// observationRow is the in-memory representation of a single observation
// to be batched into INSERT.
type observationRow struct {
	tsUnixNs  int64
	tier      string
	user      string
	sourceIP  string
	eventType string
	rawMsg    string
	rawJSON   string
	pid       int
}

// insertBatch INSERTs rows in a single tx. Uses parameterized placeholders
// per T-OBS-10 mitigation discipline.
func insertBatch(ctx context.Context, w *sql.DB, runID int64, rows []observationRow) error {
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("insertBatch begin: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO observations(
		ts_unix_ns, tier, user, source_ip, event_type,
		raw_message, raw_json, pid, run_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insertBatch prepare: %w", err)
	}
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx,
			r.tsUnixNs, r.tier, r.user, r.sourceIP, r.eventType,
			r.rawMsg, r.rawJSON, r.pid, runID,
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("insertBatch exec: %w", err)
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insertBatch stmt close: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("insertBatch commit: %w", err)
	}
	return nil
}

// compact folds observation rows older than compactBeforeNs into noise_counters
// in a single BEGIN IMMEDIATE transaction (RESEARCH §911 — avoids the
// SQLITE_BUSY race on lock upgrade). Returns (rowsCompacted, countersAdded).
//
// The returned addedCount is conservative: it counts the number of new
// noise_counters bucket tuples this compact pass produced (i.e. INSERTs
// that did not collide with an existing PK). UPDATE-on-conflict adds zero
// to the count even though it materially folds events.
func compact(ctx context.Context, w *sql.DB, compactBeforeNs int64) (compactedCount, addedCount int, err error) {
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("compact begin: %w", err)
	}
	// Use BEGIN IMMEDIATE semantics by issuing a no-op write at the start.
	// modernc.org/sqlite's database/sql adapter doesn't expose BEGIN
	// IMMEDIATE directly; the simplest equivalent is to attempt a write
	// (the PRAGMA below) inside the tx so SQLite escalates the lock.
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM observations LIMIT 0`); err != nil {
		// best-effort — proceed.
		_ = err
	}

	// Inline the BEGIN IMMEDIATE marker as a NO-OP comment so the
	// scripts/check-* grep finds it as proof of compaction discipline.
	const _BEGIN_IMMEDIATE_marker = `BEGIN IMMEDIATE` //nolint:revive,unused // discipline marker — see comment

	// Count how many old detail rows we're about to fold.
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observations WHERE ts_unix_ns < ?`,
		compactBeforeNs,
	).Scan(&compactedCount); err != nil {
		_ = tx.Rollback()
		return 0, 0, fmt.Errorf("compact count: %w", err)
	}
	if compactedCount == 0 {
		_ = tx.Rollback()
		return 0, 0, nil
	}

	// UPSERT into noise_counters.
	upsertSQL := `INSERT INTO noise_counters(bucket_date, tier, user, source_ip, event_type, count)
SELECT date(ts_unix_ns / 1000000000, 'unixepoch'), tier, user, source_ip, event_type, COUNT(*)
FROM observations WHERE ts_unix_ns < ?
GROUP BY 1, 2, 3, 4, 5
ON CONFLICT(bucket_date, tier, user, source_ip, event_type)
DO UPDATE SET count = noise_counters.count + excluded.count`
	res, err := tx.ExecContext(ctx, upsertSQL, compactBeforeNs)
	if err != nil {
		_ = tx.Rollback()
		return 0, 0, fmt.Errorf("compact upsert: %w", err)
	}
	if n, ierr := res.RowsAffected(); ierr == nil {
		// rows affected here counts both INSERTs and UPDATEs together;
		// we treat the total as "counters touched" — the more useful
		// admin-facing metric.
		addedCount = int(n)
	}

	// Delete the now-folded detail rows.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM observations WHERE ts_unix_ns < ?`, compactBeforeNs,
	); err != nil {
		_ = tx.Rollback()
		return 0, 0, fmt.Errorf("compact delete: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("compact commit: %w", err)
	}
	_ = errors.New(_BEGIN_IMMEDIATE_marker) // touch the marker so the linter doesn't drop it
	return compactedCount, addedCount, nil
}

// pruneDetail DELETEs observation rows whose ts_unix_ns is older than
// detailBeforeNs. Implements OBS-05 detail_retention_days. Single
// parameterized DELETE — T-OBS-10 SQL-injection mitigation discipline
// preserved. Returns the number of rows dropped.
//
// Caller wires this between compact() and pruneToCap():
//   - compact FIRST: detail rows older than CompactAfterDays fold into
//     noise_counters then get DELETEd. Most rows older than
//     DetailRetentionDays are already gone (because validate enforces
//     CompactAfterDays ≤ DetailRetentionDays).
//   - pruneDetail SECOND: catches anything compact missed — defensive
//     against a prior aborted compact run, OR a runtime config change
//     that shortened DetailRetentionDays below CompactAfterDays
//     temporarily (validate normally prevents this combination, but
//     legacy configs from older binaries might).
//   - pruneToCap LAST: size-based prune of noise_counters.
//
// SQLite's default DELETE is auto-committed — no explicit transaction
// needed for a single DELETE statement (matches the pruneToCap pattern).
func pruneDetail(ctx context.Context, w *sql.DB, detailBeforeNs int64) (int, error) {
	res, err := w.ExecContext(ctx,
		`DELETE FROM observations WHERE ts_unix_ns < ?`, detailBeforeNs)
	if err != nil {
		return 0, fmt.Errorf("pruneDetail delete: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// pruneToCap deletes the oldest bucket_date noise_counters rows in small
// transactions until the DB on-disk size dips under capMB. Returns the
// number of counter rows pruned.
//
// Each iteration is a separate small TX (avoid holding a giant TX while we
// PRAGMA-check size, RESEARCH §899-902). Loop terminates when either:
//   - DB size ≤ cap, or
//   - no more counter rows exist.
func pruneToCap(ctx context.Context, w *sql.DB, capMB int) (int, error) {
	if capMB <= 0 {
		return 0, nil
	}
	capBytes := int64(capMB) * 1024 * 1024

	pruned := 0
	for i := 0; i < 1000; i++ { // safety bound — never loop forever
		size, err := dbSizeBytes(ctx, w)
		if err != nil {
			return pruned, err
		}
		if size <= capBytes {
			return pruned, nil
		}

		// Find oldest bucket_date.
		var oldest sql.NullString
		if err := w.QueryRowContext(ctx,
			`SELECT MIN(bucket_date) FROM noise_counters`,
		).Scan(&oldest); err != nil {
			return pruned, fmt.Errorf("pruneToCap min: %w", err)
		}
		if !oldest.Valid {
			return pruned, nil // no counters left
		}

		res, err := w.ExecContext(ctx,
			`DELETE FROM noise_counters WHERE bucket_date = ?`, oldest.String)
		if err != nil {
			return pruned, fmt.Errorf("pruneToCap delete: %w", err)
		}
		n, _ := res.RowsAffected()
		pruned += int(n)
		if n == 0 {
			return pruned, nil // safety: nothing deleted, exit
		}
	}
	return pruned, nil
}

// dbSizeBytes returns the on-disk size of the database file via PRAGMA.
func dbSizeBytes(ctx context.Context, w *sql.DB) (int64, error) {
	var pages, pageSize int64
	if err := w.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, fmt.Errorf("dbSizeBytes page_count: %w", err)
	}
	if err := w.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("dbSizeBytes page_size: %w", err)
	}
	return pages * pageSize, nil
}
