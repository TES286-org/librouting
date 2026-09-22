#!/usr/bin/env bash
# Two-daemon interop test: run two lr-daemon processes connected by a
# real TCP socket on localhost, exchange BGP OPEN/KEEPALIVE/UPDATE, and
# verify the route propagates from A to B.
#
#   A (AS64512, listens :11791, originates 203.0.113.0/24)
#        ↑↓ TCP
#   B (AS64513, connects, receives the route)
#
# Library-based (tests/interop/_lib.sh): portable across Linux, macOS
# and Windows/Git-Bash — the shared resolver finds the .exe build and
# the cleanup trap manages the spawned daemons.
#
# NOTE: log matching uses POSIX `grep -qF`, not ripgrep — CI images do
# not guarantee `rg` on PATH and a missing binary fails every iteration
# of the poll loop while its stderr is swallowed by `2>/dev/null`.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11791}
OUT=/tmp/lr_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== starting daemon A (listener, AS64512) =="
DAEMON_A=$(lr_daemon_spawn "$OUT/a.log" \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --network 203.0.113.0/24)

echo "== starting daemon B (connector, AS64513) =="
DAEMON_B=$(lr_daemon_spawn "$OUT/b.log" \
    --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --ebgp-policy accept-all \
    --peer 127.0.0.1:$PORT --local-address 192.0.2.2)

# --- 1. ESTABLISHED + LEARNED (up to 30 s: slow CI runners) ---
echo "== waiting for the session to establish and the route to propagate =="
lr_wait_log "$OUT/a.log" "session #1 → Established" 30
lr_wait_log "$OUT/b.log" "session #1 → Established" 30
lr_wait_log "$OUT/b.log" "route installed 203.0.113.0/24" 30
kill -0 "$DAEMON_A" 2>/dev/null || { echo "FAIL: daemon A died"; cat "$OUT/a.log"; exit 1; }
kill -0 "$DAEMON_B" 2>/dev/null || { echo "FAIL: daemon B died"; cat "$OUT/b.log"; exit 1; }

# --- 2. TEARDOWN: A's death withdraws the route from B ---
echo "== teardown: A's death withdraws the route from B =="
kill -9 "$DAEMON_A" 2>/dev/null || true
LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$DAEMON_A/}"
lr_wait_log "$OUT/b.log" "route withdrawn 203.0.113.0/24" 30
echo "   PASS: route withdrawn after session loss"

echo
echo "PASS: two-daemon TCP interop — session established + route propagated + withdrawn"
