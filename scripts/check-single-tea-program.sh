#!/usr/bin/env bash
# Enforces pitfall E1: exactly one tea.NewProgram in the tree.
set -euo pipefail

count=$(grep -rn 'tea\.NewProgram' --include='*.go' . --exclude-dir=.git --exclude-dir=.planning | wc -l | tr -d ' ')

if [[ "$count" != "1" ]]; then
    echo "FAIL: expected exactly 1 tea.NewProgram invocation, found $count" >&2
    grep -rn 'tea\.NewProgram' --include='*.go' . --exclude-dir=.git --exclude-dir=.planning >&2 || true
    exit 1
fi

echo "OK: single tea.NewProgram (pitfall E1 retired)"
