package revert

// testseam.go — production-code seams for tests. Per the Phase 3
// testseam pattern (internal/keys/testseam.go), all SetXForTest /
// ResetXForTest pairs live in this file so the production API stays
// free of test-only exports.
//
// Production callers must NEVER use these helpers — they exist so
// tests can redirect the on-disk pointer file into t.TempDir() without
// the production var being exported. There is no CI guard today; the
// discipline lives in code review.

// SetPointerPathForTest redirects PointerPath() to the given test-owned
// path (typically t.TempDir()+"/revert.active"). Pair with
// t.Cleanup(ResetPointerPathForTest) so the override is rolled back even
// on test failure.
func SetPointerPathForTest(path string) {
	pointerPathMu.Lock()
	defer pointerPathMu.Unlock()
	pointerPath = path
}

// ResetPointerPathForTest restores the production pointer-file path.
// Mirrors the Reset half of the seam pair (internal/keys/testseam.go
// convention).
func ResetPointerPathForTest() {
	pointerPathMu.Lock()
	defer pointerPathMu.Unlock()
	pointerPath = "/var/lib/sftp-jailer/revert.active"
}
