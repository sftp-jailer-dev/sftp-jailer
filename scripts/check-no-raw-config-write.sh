#!/usr/bin/env bash
# Architectural invariant: writes to /etc/sftp-jailer/config.yaml (and any
# other system-state mutation in Phase 2) MUST go through internal/config
# → internal/sysops.AtomicWriteFile. No raw os.WriteFile / os.Create /
# ioutil.WriteFile / os.OpenFile(O_CREATE|O_WRONLY) outside the sanctioned
# paths.
#
# Plan 02-07 / OBS-05 / D-07: the S-SETTINGS screen is the only writable
# surface in Phase 2, and its writes route through config.Save which calls
# sysops.AtomicWriteFile. This script enforces that nothing else in
# internal/ takes a shortcut around the seam.
#
# Exit codes:
#   0 — clean
#   1 — at least one violation found
#
# Excludes:
#   - internal/sysops/  (the canonical seam; AtomicWriteFile lives here)
#   - internal/config/  (Marshals YAML and calls sysops.AtomicWriteFile)
#   - *_test.go          (test fixtures legitimately write to t.TempDir())
set -euo pipefail

violations=$(grep -rn -E 'os\.WriteFile|ioutil\.WriteFile|os\.Create\(|os\.OpenFile' internal/ \
               --include='*.go' \
               --exclude-dir=sysops \
               --exclude-dir=config 2>/dev/null || true)

# Filter out test files (they may legitimately scaffold fixtures via os.WriteFile
# into t.TempDir()).
violations=$(echo "$violations" | grep -v '_test\.go:' || true)

# Filter out lines explicitly marked as exempt via the architectural carve-out
# tag. This is the escape hatch for non-config writes (e.g. internal/tui's
# /tmp/ recovery script per pitfall E2) that have nothing to do with
# /etc/sftp-jailer/config.yaml. New uses must include the tag inline AND a
# rationale comment explaining the carve-out — reviewer scrutiny is
# expected at the PR layer.
violations=$(echo "$violations" | grep -v 'sftpj-allow-raw-write' || true)

if [[ -n "$violations" ]]; then
    echo "FAIL: raw file-create outside internal/sysops + internal/config:" >&2
    echo "$violations" >&2
    exit 1
fi
echo "OK: no raw config-write outside internal/sysops + internal/config"
