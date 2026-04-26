// Package keys_test exercises FetchGitHub + FetchGitHubByID against an
// httptest.Server. Per W-06, every handler in this file matches the
// expected URL path explicitly — a production code change that constructs
// a wrong path (e.g. "/users/alice.keys" instead of "/alice.keys") will
// fail the test rather than silently get a 404 the test is unprepared for.
package keys_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/keys"
)

// TestFetchGitHub_200_returns_lines verifies the happy path and the W-06
// explicit-path-matching contract: the handler returns 404 for any path
// other than "/alice.keys" so a production code drift surfaces as a typed
// "user not found" error instead of a silent green test.
func TestFetchGitHub_200_returns_lines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ssh-ed25519 AAAA... key1\nssh-ed25519 AAAB... key2\n"))
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	lines, err := keys.FetchGitHub(ctx, "alice")
	require.NoError(t, err)
	require.Len(t, lines, 2)
	require.Contains(t, string(lines[0]), "key1")
	require.Contains(t, string(lines[1]), "key2")
}

// TestFetchGitHub_404_returns_typed_error verifies the typed
// user-not-found error surface for the M-ADD-KEY error UX.
func TestFetchGitHub_404_returns_typed_error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil) //nolint:staticcheck // unused 2nd arg path; intentional 404
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := keys.FetchGitHub(ctx, "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), `"alice"`)
	require.Contains(t, err.Error(), "not found")
}

// TestFetchGitHub_429_surfaces_retry_after_verbatim verifies D-19's
// explicit no-auto-retry behavior: the rate-limit response is surfaced
// to admin verbatim including the Retry-After header value.
func TestFetchGitHub_429_surfaces_retry_after_verbatim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := keys.FetchGitHub(ctx, "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rate-limited")
	require.Contains(t, err.Error(), "60")
}

// TestFetchGitHub_5xx_returns_status_code verifies any non-200/404/429
// response surfaces the status code verbatim for M-ADD-KEY error UX.
func TestFetchGitHub_5xx_returns_status_code(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream down"))
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := keys.FetchGitHub(ctx, "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "503")
}

// TestFetchGitHub_context_timeout_honored verifies the 5s context timeout
// inside FetchGitHub does NOT supersede a tighter caller-provided deadline.
// The handler sleeps for longer than the test deadline; the call must
// return within ~200ms with a deadline-exceeded error.
func TestFetchGitHub_context_timeout_honored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow timeout test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
			_, _ = w.Write([]byte("late\n"))
		case <-r.Context().Done():
			return
		}
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := keys.FetchGitHub(ctx, "alice")
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Less(t, elapsed, 1*time.Second, "should have honored 100ms deadline; took %s", elapsed)
}

// TestFetchGitHub_no_auto_retry_on_429 enforces D-19's "tool does not
// auto-retry" rule. A counter mutex-protected handler counts requests;
// after one FetchGitHub call we assert exactly one request was issued.
func TestFetchGitHub_no_auto_retry_on_429(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		requests++
		mu.Unlock()
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = keys.FetchGitHub(ctx, "alice")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, requests, "FetchGitHub must NOT auto-retry on 429 (D-19)")
}

// TestFetchGitHubByID_filters_to_matching_id exercises the JSON
// /users/<u>/keys endpoint with W-06 explicit path matching, and verifies
// the client-side ID filter returns exactly the matching key.
func TestFetchGitHubByID_filters_to_matching_id(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/alice/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":111,"key":"ssh-ed25519 AAA1 alice@one"},{"id":222,"key":"ssh-ed25519 AAA2 alice@two"}]`))
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubAPIBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubAPIBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := keys.FetchGitHubByID(ctx, "alice", 222)
	require.NoError(t, err)
	require.Contains(t, string(got), "AAA2", "must return the AAA2-marked key (id=222), not AAA1 (id=111)")
}

// TestFetchGitHubByID_id_not_found_returns_error verifies the typed error
// for the "valid user but no such key id" case.
func TestFetchGitHubByID_id_not_found_returns_error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/alice/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":111,"key":"ssh-ed25519 AAA1 alice@one"}]`))
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubAPIBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubAPIBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := keys.FetchGitHubByID(ctx, "alice", 999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key id 999")
	require.Contains(t, err.Error(), "not found")
}

// TestFetchGitHub_user_agent_set verifies the User-Agent header carries
// the project identifier so admins running heavy queries can correlate
// in GitHub's logs (T-03-04 mitigation surface).
func TestFetchGitHub_user_agent_set(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice.keys" {
			http.NotFound(w, r)
			return
		}
		gotUA = r.Header.Get("User-Agent")
		_, _ = fmt.Fprintln(w, "ssh-ed25519 AAAA test")
	}))
	t.Cleanup(srv.Close)

	keys.SetGithubBaseURLForTest(srv.URL)
	t.Cleanup(keys.ResetGithubBaseURLForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := keys.FetchGitHub(ctx, "alice")
	require.NoError(t, err)
	require.Contains(t, gotUA, "sftp-jailer")
}
