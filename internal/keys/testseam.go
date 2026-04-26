package keys

// This file exposes a controlled mutation surface to external _test
// packages so they can stub the GitHub HTTP endpoints with httptest.
// Naming convention `testseam.go` mirrors internal/chrootcheck/testseam.go
// from plan 03-02 — single file per package, public Set/Reset symbols
// only, never the underlying var.
//
// Production callers must NEVER use these helpers — they exist to keep
// the unexported `githubBaseURL` / `githubAPIBaseURL` package vars
// unexported while still allowing tests to override them. There is no
// CI guard today; the discipline lives in code review.

// SetGithubBaseURLForTest overrides the prefix used by FetchGitHub.
// Tests should pair every call with a t.Cleanup(ResetGithubBaseURLForTest)
// so the override is rolled back even on test failure.
func SetGithubBaseURLForTest(url string) { githubBaseURL = url }

// ResetGithubBaseURLForTest restores the production GitHub host.
func ResetGithubBaseURLForTest() { githubBaseURL = "https://github.com" }

// SetGithubAPIBaseURLForTest overrides the prefix used by FetchGitHubByID.
// Tests should pair every call with a t.Cleanup(ResetGithubAPIBaseURLForTest).
func SetGithubAPIBaseURLForTest(url string) { githubAPIBaseURL = url }

// ResetGithubAPIBaseURLForTest restores the production GitHub API host.
func ResetGithubAPIBaseURLForTest() { githubAPIBaseURL = "https://api.github.com" }
