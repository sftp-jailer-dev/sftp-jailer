#!/usr/bin/env bash
# Enforces the exact pinned versions for every direct dep declared in go.mod.
# If any pin drifts, CI fails and the developer must update this script
# deliberately alongside go.mod.
#
# Phase 2 (plan 02-02) bumped the count from 7 → 11 with the koanf v2 family
# (consumed by internal/config) plus go-humanize (consumed by
# internal/observe.Runner for RunSummary.DurationHuman). The koanf
# providers/structs sub-provider is unversioned-latest in its README and
# pins via go.sum; we anchor only the four primary entries here.
#
# Phase 3 (plan 03-04) bumped the count from 11 → 12 with golang.org/x/crypto
# (consumed by internal/keys for ssh.ParseAuthorizedKey + FingerprintSHA256).
set -euo pipefail

declare -a REQUIRED=(
    'charm.land/bubbletea/v2 v2.0.6'
    'charm.land/bubbles/v2 v2.1.0'
    'charm.land/lipgloss/v2 v2.0.3'
    'github.com/spf13/cobra v1.10.2'
    'github.com/sahilm/fuzzy v0.1.1'
    'golang.org/x/sys v0.43.0'
    'modernc.org/sqlite v1.49.1'
    'github.com/dustin/go-humanize v1.0.1'
    'github.com/knadh/koanf/v2 v2.3.4'
    'github.com/knadh/koanf/parsers/yaml'
    'github.com/knadh/koanf/providers/rawbytes'
    'golang.org/x/crypto v0.50.0'
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
echo "OK: all 12 direct-dep pins match (bubbletea/bubbles/lipgloss/cobra/fuzzy/x-sys/sqlite + humanize + koanf/v2 + koanf/parsers/yaml + koanf/providers/rawbytes + x/crypto)"
