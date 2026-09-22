#!/usr/bin/env bash
# Two-daemon RFC 8277 labelled-unicast interop test: run two lr-daemon
# processes connected by a real TCP socket on localhost, exchange a
# labelled BGP UPDATE (AFI=1, SAFI=4), and verify the label stack
# propagates from A to B.
#
#   A (AS64512, listens :11794, originates 198.51.100.0/24 label 100)
#        ↑↓ TCP
#   B (AS64513, connects, receives the labelled route)
#
# Both sides negotiate IPv4 labelled-unicast via `--mp-family
# ipv4-labeled-unicast` and disable RFC 8212 policy with
# `--ebgp-policy accept-all` so the route is accepted without an
# explicit import filter.
#
# Library-based (tests/interop/_lib.sh): portable across Linux, macOS
# and Windows/Git-Bash.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11794}
OUT=/tmp/lr_interop_labeled
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== starting daemon A (listener, AS64512, label 100) =="
DAEMON_A=$(lr_daemon_spawn "$OUT/a.log" \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast \
    --labeled-network "198.51.100.0/24 100")

echo "== starting daemon B (connector, AS64513) =="
DAEMON_B=$(lr_daemon_spawn "$OUT/b.log" \
    --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --ebgp-policy accept-all \
    --peer 127.0.0.1:$PORT --local-address 192.0.2.2 \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast)

# --- 1. ESTABLISHED + LEARNED (up to 30 s: slow CI runners) ---
echo "== waiting for the session to establish and the labelled route to propagate =="
lr_wait_log "$OUT/a.log" "session #1 → Established" 30
lr_wait_log "$OUT/b.log" "session #1 → Established" 30
lr_wait_log "$OUT/a.log" "originating labelled 198.51.100.0/24" 30
lr_wait_log "$OUT/b.log" "route installed 198.51.100.0/24" 30
kill -0 "$DAEMON_A" 2>/dev/null || { echo "FAIL: daemon A died"; cat "$OUT/a.log"; exit 1; }
kill -0 "$DAEMON_B" 2>/dev/null || { echo "FAIL: daemon B died"; cat "$OUT/b.log"; exit 1; }

# --- 2. TEARDOWN: A's death withdraws the labelled route from B ---
echo "== teardown: A's death withdraws the labelled route from B =="
kill -9 "$DAEMON_A" 2>/dev/null || true
LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$DAEMON_A/}"
lr_wait_log "$OUT/b.log" "route withdrawn 198.51.100.0/24" 30
echo "   PASS: labelled route withdrawn after session loss"

echo
echo "PASS: two-daemon RFC 8277 labelled-unicast interop — labelled route propagated + withdrawn"
