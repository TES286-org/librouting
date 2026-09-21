#!/usr/bin/env bash
# Two-daemon RFC 8277 labelled-unicast interop test: run two lr-daemon
# processes connected by a real TCP socket on localhost, exchange a
# labelled BGP UPDATE (AFI=1, SAFI=4), and verify the label stack
# propagates from A to B.
#
#   A (AS64512, listens :1179, originates 198.51.100.0/24 label 100)
#        ↑↓ TCP
#   B (AS64513, connects, receives the labelled route)
#
# Both sides negotiate IPv4 labelled-unicast via `--mp-family
# ipv4-labeled-unicast` and disable RFC 8212 policy with
# `--ebgp-policy accept-all` so the route is accepted without an
# explicit import filter.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh)
PORT=${PORT:-11794}
OUT=/tmp/lr_interop_labeled
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== starting daemon A (listener, AS64512, label 100) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast \
    --labeled-network "198.51.100.0/24 100" \
    >"$OUT/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT

sleep 1

echo "== starting daemon B (connector, AS64513) =="
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --ebgp-policy accept-all \
    --peer 127.0.0.1:$PORT --local-address 192.0.2.2 \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast \
    >"$OUT/b.log" 2>&1 &
B_PID=$!

# Wait for the session to establish and the labelled route to propagate.
ok=1
reason="timeout waiting for labelled route propagation"
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 198.51.100.0/24" "$OUT/b.log" 2>/dev/null; then
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
    echo "FAIL: labelled route did not propagate to B ($reason)"
    exit 1
fi
if ! grep -qF "session #1 → Established" "$OUT/b.log"; then
    echo "FAIL: B never reached Established"
    exit 1
fi
if ! grep -qF "originating labelled 198.51.100.0/24" "$OUT/a.log"; then
    echo "FAIL: A did not originate the labelled network"
    exit 1
fi
echo "PASS: two-daemon RFC 8277 labelled-unicast interop — labelled route propagated"
