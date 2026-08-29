#!/usr/bin/env bash
# Two-daemon interop test: run two lr-daemon processes connected by a real
# TCP socket on localhost, exchange BGP OPEN/KEEPALIVE/UPDATE, and verify
# the route propagates from A to B.
#
#   A (AS64512, listens :1179, originates 203.0.113.0/24)
#        ↑↓ TCP
#   B (AS64513, connects, receives the route)
#
# NOTE: log matching uses POSIX `grep -qF`, not ripgrep — CI images do not
# guarantee `rg` on PATH and a missing binary fails every iteration of the
# poll loop while its stderr is swallowed by `2>/dev/null`.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
PORT=${PORT:-11791}
OUT=/tmp/lr_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== starting daemon A (listener, AS64512) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    >"$OUT/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT

sleep 1

echo "== starting daemon B (connector, AS64513) =="
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 --ebgp-policy accept-all \
    --peer 127.0.0.1:$PORT --local-address 192.0.2.2 \
    >"$OUT/b.log" 2>&1 &
B_PID=$!

# Wait for the session to establish and the route to propagate (up to 30s:
# slow CI runners can take several seconds through connect + OPEN/KEEPALIVE).
ok=1
reason="timeout waiting for route propagation"
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 203.0.113.0/24" "$OUT/b.log" 2>/dev/null; then
        ok=0
        break
    fi
    if ! kill -0 $A_PID 2>/dev/null || ! kill -0 $B_PID 2>/dev/null; then
        reason="a daemon died"
        break
    fi
done

kill $B_PID 2>/dev/null || true
kill $A_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "== daemon A log =="
cat "$OUT/a.log"
echo "== daemon B log =="
cat "$OUT/b.log"

if [ $ok -ne 0 ]; then
    echo "FAIL: route did not propagate to B ($reason)"
    exit 1
fi
if ! grep -qF "session #1 → Established" "$OUT/b.log"; then
    echo "FAIL: B never reached Established"
    exit 1
fi
echo "PASS: two-daemon TCP interop — session established + route propagated"
