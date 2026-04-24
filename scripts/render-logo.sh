#!/usr/bin/env bash
# Pre-renders sftp-jailer-logo.png into four ANSI variants for go:embed.
# HARD REQUIREMENT: chafa must be on PATH. No fallback — if chafa is missing
# we refuse to produce bogus placeholder artifacts.
set -euo pipefail

if ! command -v chafa >/dev/null; then
    echo "FAIL: chafa not found on PATH. Install via 'sudo apt install chafa' or 'brew install chafa'." >&2
    exit 1
fi

SRC="sftp-jailer-logo.png"
OUT="internal/tui/screens/splash/embedded"
SIZE="40x20"
mkdir -p "$OUT"

if ! [[ -f "$SRC" ]]; then
    echo "FAIL: source image $SRC not found (run from repo root)" >&2
    exit 1
fi

# Truecolor (24-bit) — modern terminals
chafa --colors full  --size "$SIZE" --format symbols --symbols block+border --fg-only "$SRC" > "$OUT/logo-truecolor.ans"

# 256-color (240 in chafa terminology — lower 16 are unreliable)
chafa --colors 240   --size "$SIZE" --format symbols --symbols block+border --fg-only "$SRC" > "$OUT/logo-256.ans"

# 16-color (safe floor for TERM=linux, old xterm)
chafa --colors 16    --size "$SIZE" --format symbols --symbols block+border --fg-only "$SRC" > "$OUT/logo-16.ans"

# Plain ASCII — no escape sequences at all
chafa --colors none  --size "$SIZE" --format symbols --symbols ascii                     "$SRC" > "$OUT/logo-ascii.txt"

for f in logo-truecolor.ans logo-256.ans logo-16.ans logo-ascii.txt; do
    if ! [[ -s "$OUT/$f" ]]; then
        echo "FAIL: chafa produced empty $f" >&2
        exit 1
    fi
done
echo "OK: four variants rendered under $OUT/"
wc -c "$OUT"/logo-*
