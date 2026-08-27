#!/usr/bin/env bash
# RFC 5925 (TCP-AO) session-authentication interop between two lr-daemons.
#
#   phase 1: both daemons use key (1:alpha)   — session MUST establish
#   phase 2: same KeyID, different secret     — session MUST NOT establish
#
# TCP-AO needs Linux >= 6.7 (CONFIG_TCP_AO). On older kernels both
# daemons exit with "Protocol not available" during key installation;
# the script detects that and SKIPs (exit 0) so CI on older images
# stays green.
#
# Env overrides:
#   PORT1 / PORT2   TCP ports for the phases (default 11821/11822)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
PORT1=${PORT1:-11821}
PORT2=${PORT2:-11822}
OUT=/tmp/lr_ao_interop
rm -rf "$OUT"; mkdir -p "$OUT"

# ---------------------------------------------------------------------------
# Kernel-support probe: arm a listener with one TCP-AO key and watch for
# ENOPROTOOPT ("Protocol not available").
# ---------------------------------------------------------------------------
echo "== probing kernel TCP-AO support =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT1 --tcp-ao-key 1:probe \
    >"$OUT/probe.log" 2>&1 &
PROBE_PID=$!
sleep 1
kill $PROBE_PID 2>/dev/null || true
wait 2>/dev/null || true

if grep -q "Protocol not available" "$OUT/probe.log" 2>/dev/null; then
    echo "SKIP: kernel lacks TCP-AO (needs Linux >= 6.7):"
    tail -2 "$OUT/probe.log"
    exit 0
fi
if grep -qF "session auth arming failed" "$OUT/probe.log" 2>/dev/null; then
    echo "FAIL: TCP-AO key installation failed for a non-kernel reason:"
    cat "$OUT/probe.log"
    exit 1
fi

fail=0

# ---------------------------------------------------------------------------
# Phase 1: matching keys — must establish and propagate a route.
# ---------------------------------------------------------------------------
echo "== phase 1: two lr-daemons, same TCP-AO key (1:alpha) =="
mkdir -p "$OUT/p1"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT1 --local-address 192.0.2.1 \
    --tcp-ao-key 1:alpha --network 203.0.113.0/24 \
    >"$OUT/p1/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT1 --local-address 192.0.2.2 \
    --tcp-ao-key 1:alpha \
    >"$OUT/p1/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

ok=1
reason="timeout waiting for route propagation"
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 203.0.113.0/24" "$OUT/p1/b.log" 2>/dev/null; then
        ok=0
        break
    fi
    if ! kill -0 $A_PID 2>/dev/null || ! kill -0 $B_PID 2>/dev/null; then
        reason="a daemon died"
        break
    fi
done
kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "== daemon A log (phase 1) =="
cat "$OUT/p1/a.log"
echo "== daemon B log (phase 1) =="
cat "$OUT/p1/b.log"

if [ $ok -ne 0 ] || ! grep -qF "session #1 → Established" "$OUT/p1/b.log"; then
    echo "FAIL: TCP-AO-authenticated session did not establish ($reason)"
    fail=1
else
    echo "PASS: phase 1 — TCP-AO-authenticated session established + route propagated"
fi

# ---------------------------------------------------------------------------
# Phase 2: same KeyID, different secret — MAC verification must fail and
# the session must never establish.
# ---------------------------------------------------------------------------
echo "== phase 2: same KeyID, different secret (1:alpha vs 1:beta) =="
mkdir -p "$OUT/p2"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT2 --local-address 192.0.2.1 \
    --tcp-ao-key 1:alpha --network 203.0.113.0/24 \
    >"$OUT/p2/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT2 --local-address 192.0.2.2 \
    --tcp-ao-key 1:beta \
    >"$OUT/p2/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

# Give the wrong-key handshake ~8 s to (wrongly) establish.
sleep 8
leaked=0
if grep -qF "session #1 → Established" "$OUT/p2/b.log" 2>/dev/null; then
    leaked=1
fi
if grep -qF "route installed 203.0.113.0/24" "$OUT/p2/b.log" 2>/dev/null; then
    leaked=1
fi
kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "== daemon B log (phase 2) =="
cat "$OUT/p2/b.log"

if [ $leaked -ne 0 ]; then
    echo "FAIL: session established despite TCP-AO MAC mismatch"
    fail=1
else
    echo "PASS: phase 2 — wrong TCP-AO key rejected (no session, no route)"
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: TCP-AO (RFC 5925) interop suite complete"
fi
exit $fail
