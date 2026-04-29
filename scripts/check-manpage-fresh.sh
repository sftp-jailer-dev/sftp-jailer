#!/usr/bin/env bash
# Enforces that docs/man/ is in sync with the cobra command tree exposed by
# cmd/gen-manpage. If the generator produces output that differs from what's
# committed under docs/man/, CI fails with a clear remediation hint.
#
# Pattern matches scripts/check-go-mod-pins.sh (set -euo pipefail, FAIL: prefix
# on stderr, exit 1 on drift, OK: line on success). The CI workflow at
# .github/workflows/ci.yml + the release workflow at .github/workflows/release.yml
# (plan 05-06) both invoke this script.
#
# Run from repo root.
set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Re-run the generator into a clean tmpdir.
go run ./cmd/gen-manpage --output "$tmpdir" >/dev/null

# Compare. `diff -ru` returns 0 on identical, 1 on different, 2 on error.
if ! diff -ru docs/man/ "$tmpdir/" >/dev/null 2>&1; then
    echo "FAIL: docs/man/ is stale relative to cmd/gen-manpage output." >&2
    echo "      Run 'go run ./cmd/gen-manpage --output docs/man' and commit the diff." >&2
    echo "" >&2
    diff -ru docs/man/ "$tmpdir/" >&2 || true
    exit 1
fi

echo "OK: docs/man/ matches cmd/gen-manpage output (4 .1 pages — root + version + doctor + observe-run)"
