package keys

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// githubBaseURL is the prefix for the plain-text /<user>.keys endpoint.
// Package-level var so tests can override via SetGithubBaseURLForTest
// (testseam.go). Defaults to GitHub's public host; production callers
// never touch this var.
var githubBaseURL = "https://github.com"

// githubAPIBaseURL is the prefix for the JSON /users/<user>/keys
// endpoint used by FetchGitHubByID. Same test-override pattern as
// githubBaseURL.
var githubAPIBaseURL = "https://api.github.com"

// githubUserAgent is the User-Agent string sent on all GitHub requests.
// Surfaces sftp-jailer in GitHub's logs so admins running heavy queries
// can correlate the source. Honors the project's canonical URL.
const githubUserAgent = "sftp-jailer/v1 (+https://sftp-jailer.com)"

// fetchTimeout is the per-call context deadline applied to GitHub HTTP
// requests. 5 seconds covers slow networks while keeping the M-ADD-KEY
// modal responsive (RESEARCH A4).
const fetchTimeout = 5 * time.Second

// FetchGitHub retrieves all public SSH keys for a GitHub username via
// https://github.com/<user>.keys (plain text, newline-separated). Per
// D-19, the tool does NOT auto-retry on 429 — the Retry-After header
// surfaces verbatim to the admin so they can decide. 5s context timeout
// covers slow networks (RESEARCH A4).
//
// Each returned []byte is a fresh defensive copy from the bufio.Scanner
// buffer — safe for the caller to retain across subsequent calls.
//
// Call-site invariant (T-03-04-02): the caller MUST validate `user`
// against GitHub's allowed username charset ([A-Za-z0-9-]+) before
// invoking. The keys package does NOT validate; the M-ADD-KEY modal
// (plan 03-08) is the responsible call site.
func FetchGitHub(ctx context.Context, user string) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/%s.keys", githubBaseURL, user)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("keys.FetchGitHub %s: %w", user, err)
	}
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keys.FetchGitHub %s: %w", user, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusNotFound:
		return nil, fmt.Errorf("keys.FetchGitHub: user %q not found", user)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("keys.FetchGitHub: rate-limited (429); retry after %s",
			resp.Header.Get("Retry-After"))
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("keys.FetchGitHub: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var lines [][]byte
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		// Defensive copy — Scanner reuses the underlying buffer.
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("keys.FetchGitHub: scan response: %w", err)
	}
	return lines, nil
}

// ghAPIKey is the JSON-decoded shape from /users/<user>/keys.
// Only id + key are consumed; GitHub returns more fields but we ignore.
type ghAPIKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

// FetchGitHubByID retrieves a specific SSH key by its GitHub numeric ID
// via https://api.github.com/users/<user>/keys (JSON). Filters
// client-side and returns the matching key's bytes or an error. Same
// 5s timeout, same no-auto-retry posture as FetchGitHub. Used by D-19
// gh:<user>/<id> source.
//
// Call-site invariant (T-03-04-07): same as FetchGitHub — the caller
// MUST validate `user` against [A-Za-z0-9-]+ before invoking.
func FetchGitHubByID(ctx context.Context, user string, id int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/users/%s/keys", githubAPIBaseURL, user)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("keys.FetchGitHubByID %s: %w", user, err)
	}
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keys.FetchGitHubByID %s: %w", user, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusNotFound:
		return nil, fmt.Errorf("keys.FetchGitHubByID: user %q not found", user)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("keys.FetchGitHubByID: rate-limited (429); retry after %s",
			resp.Header.Get("Retry-After"))
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("keys.FetchGitHubByID: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var ks []ghAPIKey
	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return nil, fmt.Errorf("keys.FetchGitHubByID: decode JSON: %w", err)
	}
	for _, k := range ks {
		if k.ID == id {
			return []byte(k.Key), nil
		}
	}
	return nil, fmt.Errorf("keys.FetchGitHubByID: key id %d not found in %s's keys", id, user)
}
