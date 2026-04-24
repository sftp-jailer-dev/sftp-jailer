#!/usr/bin/env bash
# Phase 1 architecture-invalidating smoke test.
# Validates the Phase 4 firewall-as-source-of-truth premise: Ubuntu 24.04's
# ufw 0.36.2 must preserve the sftp-jailer structured comment across
# `ufw reload`. If this fails, Phase 4 (FW-08 especially) cannot proceed —
# user↔IP mapping lives in rule comments and nowhere else.
#
# Run on an Ubuntu 24.04 VM as root. CAUTION: calls `ufw --force reset`
# which wipes the current ufw ruleset — DO NOT RUN ON A PRODUCTION BOX.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 2
fi

if ! command -v ufw >/dev/null; then
    echo "error: ufw not installed (apt install ufw)" >&2
    exit 2
fi

if ! command -v nft >/dev/null; then
    echo "error: nft not installed (apt install nftables)" >&2
    exit 2
fi

TEST_COMMENT='sftpj:v=1:user=alice'
TEST_IP='203.0.113.1'

echo "smoke-ufw: resetting ufw (wipes current rules — expected on a VM)"
ufw --force reset >/dev/null

echo "smoke-ufw: adding test rule with comment"
ufw allow from "$TEST_IP" to any port 22 proto tcp comment "$TEST_COMMENT"

echo "smoke-ufw: reading BEFORE ufw reload"
BEFORE=$(ufw status verbose | grep "$TEST_IP" || true)
echo "  BEFORE: $BEFORE"

echo "smoke-ufw: running ufw reload"
ufw reload >/dev/null

echo "smoke-ufw: reading AFTER ufw reload"
AFTER=$(ufw status verbose | grep "$TEST_IP" || true)
echo "  AFTER:  $AFTER"

if [[ "$BEFORE" != "$AFTER" ]]; then
    echo "FAIL: comment mangled across ufw reload" >&2
    echo "  BEFORE line: $BEFORE" >&2
    echo "  AFTER  line: $AFTER" >&2
    exit 1
fi

echo "smoke-ufw: cross-checking via nft list ruleset"
if ! nft list ruleset | grep -q "$TEST_COMMENT"; then
    echo "FAIL: comment not visible in nft list ruleset" >&2
    nft list ruleset | head -80 >&2
    exit 1
fi

echo "PASS: ufw preserves '$TEST_COMMENT' across reload (comment reached kernel table)"
