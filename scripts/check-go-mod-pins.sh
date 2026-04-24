#!/usr/bin/env bash
# Enforces the exact pinned versions for every direct dep declared in go.mod.
# If any pin drifts, CI fails and the developer must update this script
# deliberately alongside go.mod.
set -euo pipefail

declare -a REQUIRED=(
    'charm.land/bubbletea/v2 v2.0.6'
    'charm.land/bubbles/v2 v2.1.0'
    'charm.land/lipgloss/v2 v2.0.3'
    'github.com/spf13/cobra v1.10.2'
    'github.com/sahilm/fuzzy v0.1.1'
    'golang.org/x/sys v0.43.0'
    'modernc.org/sqlite v1.49.1'
)

fail=0
for pin in "${REQUIRED[@]}"; do
    if ! grep -q "$pin" go.mod; then
        echo "FAIL: go.mod missing expected pin: $pin" >&2
        fail=1
    fi
done

if [[ "$fail" == "1" ]]; then
    exit 1
fi
echo "OK: all 7 direct-dep pins match (bubbletea/bubbles/lipgloss/cobra/fuzzy/x-sys/sqlite)"
