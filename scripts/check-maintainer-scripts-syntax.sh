#!/usr/bin/env bash
# Enforces POSIX sh syntax validity for the Debian maintainer scripts.
# A syntax error in postinst/prerm/postrm fails dpkg with a non-recoverable
# state mid-install or mid-purge — `sh -n` catches the regression at PR time
# instead of on a tagged-release UAT host. Run from repo root.
# Exits 0 on clean, 1 on any violation.
set -euo pipefail

scripts=(
    packaging/debian/postinst
    packaging/debian/prerm
    packaging/debian/postrm
)

fail=0
for s in "${scripts[@]}"; do
    if [[ ! -f "$s" ]]; then
        echo "FAIL: maintainer script missing: $s" >&2
        fail=1
        continue
    fi
    if ! sh -n "$s" 2>/dev/null; then
        echo "FAIL: POSIX sh syntax error in $s" >&2
        sh -n "$s" >&2 || true
        fail=1
    fi
done

if [[ "$fail" == "1" ]]; then
    exit 1
fi

echo "OK: postinst/prerm/postrm pass sh -n"
