#!/usr/bin/env bash
# RFC 7911 Add-Path daemon interop: two lr-daemon processes over a real
# TCP socket negotiate the Add-Path capability and exchange a route whose
# NLRI carries a 4-octet path identifier.
#
#   phase 1: A (--add-path) ↔ B (--add-path) — the route arrives at B
#            carrying the transmitter-assigned path identifier 1,
#            observable through B's runtime API `routes` dump.
#   phase 2: A (--add-path) ↔ B' (plain)      — the peer did not offer
#            Add-Path, so the session stays single-path and the route
#            carries no identifier (path-id=0).
#
# The path-id in B's Loc-RIB proves the whole chain: capability
# negotiation in OPEN, Add-Path NLRI framing on the wire, per-path
# Adj-RIB-In keying and selection.
#
# NOTE: log matching uses POSIX `grep -qF`, not ripgrep — CI images do not
# guarantee `rg` on PATH.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
PORT1=${PORT1:-11821}
PORT2=${PORT2:-11822}
OUT=/tmp/lr_addpath_interop
rm -rf "$OUT"; mkdir -p "$OUT"

fail=0

# Query one command over the daemon's runtime API socket (POSIX-ish
# systems have python3 in CI; socat is not guaranteed).
api_cmd() {
    python3 - "$1" "$2" <<'PYEOF'
import socket, sys
path, cmd = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(path)
except OSError:
    sys.exit(1)
try:
    s.sendall((cmd + "\n").encode())
    out = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        out += d
except OSError:
    pass
sys.stdout.write(out.decode("utf-8", "replace"))
s.close()
PYEOF
}

# ---------------------------------------------------------------------------
# Phase 1: both daemons negotiate Add-Path.
# ---------------------------------------------------------------------------
echo "== phase 1: add-path on both sides =="
mkdir -p "$OUT/p1"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT1 --local-address 192.0.2.1 \
    --network 203.0.113.0/24 --add-path \
    >"$OUT/p1/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT1 --local-address 192.0.2.2 \
    --add-path --api-socket "$OUT/p1/b.api" \
    >"$OUT/p1/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

ok=1
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 203.0.113.0/24" "$OUT/p1/b.log" 2>/dev/null; then
        ok=0
        break
    fi
    if ! kill -0 $A_PID 2>/dev/null || ! kill -0 $B_PID 2>/dev/null; then
        break
    fi
done

path_id=""
if [ $ok -eq 0 ]; then
    for i in $(seq 1 20); do
        routes=$(api_cmd "$OUT/p1/b.api" "routes" 2>/dev/null || true)
        path_id=$(printf '%s\n' "$routes" | grep -F "203.0.113.0/24" \
            | grep -oE 'path-id=[0-9]+' | head -1 | cut -d= -f2 || true)
        if [ -n "$path_id" ]; then
            break
        fi
        sleep 0.25
    done
fi

kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

echo "== daemon B log (phase 1) =="
cat "$OUT/p1/b.log"
if [ $ok -ne 0 ]; then
    echo "FAIL: route did not propagate with add-path enabled"
    fail=1
elif [ "$path_id" != "1" ]; then
    echo "FAIL: expected path-id=1 at B, got '${path_id:-none}'"
    fail=1
else
    echo "PASS: phase 1 — add-path negotiated, route carried path-id=1"
fi

# ---------------------------------------------------------------------------
# Phase 2: only A offers Add-Path; B' stays single-path (RFC 7911 §4.4:
# both speakers must advertise the capability).
# ---------------------------------------------------------------------------
echo "== phase 2: add-path offered, peer declines =="
mkdir -p "$OUT/p2"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT2 --local-address 192.0.2.1 \
    --network 203.0.113.0/24 --add-path \
    >"$OUT/p2/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT2 --local-address 192.0.2.2 \
    --api-socket "$OUT/p2/b.api" \
    >"$OUT/p2/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

ok=1
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 203.0.113.0/24" "$OUT/p2/b.log" 2>/dev/null; then
        ok=0
        break
    fi
    if ! kill -0 $A_PID 2>/dev/null || ! kill -0 $B_PID 2>/dev/null; then
        break
    fi
done

path_id=""
if [ $ok -eq 0 ]; then
    for i in $(seq 1 20); do
        routes=$(api_cmd "$OUT/p2/b.api" "routes" 2>/dev/null || true)
        path_id=$(printf '%s\n' "$routes" | grep -F "203.0.113.0/24" \
            | grep -oE 'path-id=[0-9]+' | head -1 | cut -d= -f2 || true)
        if [ -n "$path_id" ]; then
            break
        fi
        sleep 0.25
    done
fi

kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ $ok -ne 0 ]; then
    echo "FAIL: route did not propagate without add-path on the peer"
    cat "$OUT/p2/a.log" "$OUT/p2/b.log"
    fail=1
elif [ "$path_id" != "0" ]; then
    echo "FAIL: expected plain path-id=0 at B', got '${path_id:-none}'"
    fail=1
else
    echo "PASS: phase 2 — peer without add-path stays single-path (path-id=0)"
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: RFC 7911 Add-Path daemon interop complete"
fi
exit $fail
