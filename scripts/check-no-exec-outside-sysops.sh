#!/usr/bin/env bash
# Enforces the architectural invariant that only internal/sysops may call
# exec.Command or exec.CommandContext. Run from repo root.
# Exits 0 on clean, 1 on any violation.
set -euo pipefail

violations=$(grep -rn -E 'exec\.Command|exec\.CommandContext|"os/exec"' internal/ \
               --include='*.go' \
               --exclude-dir=sysops 2>/dev/null || true)

if [[ -n "$violations" ]]; then
    echo "FAIL: exec.Command outside internal/sysops:" >&2
    echo "$violations" >&2
    exit 1
fi

echo "OK: no exec.Command outside internal/sysops"
