#!/usr/bin/env bash
# Enforces DIST-09 brownfield safety: the Debian maintainer scripts must
# never reference /etc/ssh. The runtime canonical writer (Phase 3 D-08) owns
# the sshd drop-in end-to-end; dpkg never touches files it didn't ship.
# postinst/postrm operate solely on /var/lib/sftp-jailer; prerm invokes the
# binary which knows the drop-in path internally. A regression that shells
# out to /etc/ssh from a maintainer script breaks the brownfield contract
# (admin's main sshd_config must remain byte-identical pre-install vs
# post-purge - verified empirically in Phase 5 UAT Variant B). Run from
# repo root. Exits 0 on clean, 1 on any violation.
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
    if grep -nE '/etc/ssh' "$s"; then
        echo "FAIL: $s references /etc/ssh - DIST-09 brownfield safety regression" >&2
        fail=1
    fi
done

if [[ "$fail" == "1" ]]; then
    exit 1
fi

echo "OK: postinst/prerm/postrm contain no /etc/ssh references (DIST-09 brownfield safe)"
