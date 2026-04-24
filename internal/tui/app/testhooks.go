package app

// ResetPlaceholderResolversForTest clears the package-level resolver slice.
// Exported (with the long name) rather than exposed via a `_test.go` helper
// because the app tests live in package app_test and cannot poke unexported
// state. The cost of a real export is acceptable: the name makes the
// test-only contract obvious, and the function is a no-op in production.
func ResetPlaceholderResolversForTest() {
	placeholderResolvers = nil
}
