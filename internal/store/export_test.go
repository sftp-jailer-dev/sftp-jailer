package store

// Test-only exports for queries_test.go (package store_test). The _test.go
// suffix scopes these names to test compilation only - they are NOT part
// of the public API.
//
// First-occurrence idiom in this repo (Phase 9 plan 09-03 ADR-3): the EQP
// regression tests need to feed the unexported SQL strings directly to
// `db.Query("EXPLAIN QUERY PLAN " + sql)` so the planner sees the same
// statement the production code path runs. Re-issuing through the
// Queries.* methods would not give us a hook to wrap the SQL with the
// EQP prefix.

// DedupRowsSQL exports dedupRowsSQL for the EQP regression test in
// TestQueries_DedupRows_uses_covering_index.
var DedupRowsSQL = dedupRowsSQL
