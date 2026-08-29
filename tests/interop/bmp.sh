#!/usr/bin/env bash
# BMP (RFC 7854) end-to-end: a BGP-speaking lr-daemon mirrors Peer
# Up/Down + Route Monitoring to a monitoring station; a second
# lr-daemon in collector mode receives, decodes and serves the
# monitored routes.
#
#   lr-daemon B (AS64513, originates 203.0.113.0/24)
#        ↑ TCP :$BGPPORT
#   lr-daemon A (AS64512, learns the route, --bmp-target 127.0.0.1:$PORT)
#        └── BMP stream (Peer Up + Route Monitoring) ──┐
#                                                       ↓
#   lr-daemon C --protocol bmp --listen 127.0.0.1:$PORT (collector)
#
# Success criteria:
#   1. The collector logs the station connection + Peer Up.
#   2. The monitored route (203.0.113.0/24, learned by A from B) appears
#      in the collector (log + runtime API `routes`).
#   3. The collector's RIB is dumpable via the `mrt` API command.
#
# A BIRD-based variant (BIRD's `protocol bmp` as the station) is the
# natural reference test, but Debian's bird2 package is built without
# the BMP protocol (verified on 2.17.5); revisit when a BMP-enabled
# BIRD is packaged or built from source (see docs/INTEROP.md).
#
# NOTE: log matching uses POSIX `grep -qF`, not ripgrep — CI images do
# not guarantee `rg` on PATH.
set -euo pipefail
cd "$(dirname "$0")/../.."

DAEMON=target/debug/lr-daemon
if [ ! -x "$DAEMON" ]; then
    DAEMON=target/release/lr-daemon
fi
if [ ! -x "$DAEMON" ]; then
    echo "SKIP: lr-daemon not built (cargo build -p lr-cli)"
    exit 0
fi
command -v python3 >/dev/null 2>&1 || {
    echo "SKIP: python3 not installed (API socket queries)"
    exit 0
}

PORT=${PORT:-11851}
BGPPORT=${BGPPORT:-11852}
OUT=/tmp/lr_bmp_interop
rm -rf "$OUT"; mkdir -p "$OUT"

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

api_cmd() {
    python3 - "$1" "$2" <<'PYEOF'
import socket, sys
path, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(path)
s.sendall((cmd + "\n").encode())
out = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
except socket.timeout:
    pass
sys.stdout.write(out.decode(errors="replace"))
PYEOF
}

echo "== starting the lr-daemon BMP collector on 127.0.0.1:$PORT =="
"$DAEMON" --protocol bmp --listen 127.0.0.1:$PORT \
    --router-id 10.0.0.9 --api-socket "$OUT/collector.api" \
    >"$OUT/collector.log" 2>&1 &
COLLECTOR_PID=$!
trap 'kill $COLLECTOR_PID $A_PID $B_PID 2>/dev/null || true' EXIT
A_PID=""
B_PID=""

echo "== starting the monitored speaker A (AS64512, --bmp-target) =="
"$DAEMON" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 --ebgp-policy accept-all \
    --listen 127.0.0.1:$BGPPORT --local-address 192.0.2.1 \
    --bmp-target 127.0.0.1:$PORT \
    >"$OUT/a.log" 2>&1 &
A_PID=$!

echo "== starting the route originator B (AS64513, connects to A) =="
"$DAEMON" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 --ebgp-policy accept-all \
    --peer 127.0.0.1:$BGPPORT --local-address 192.0.2.2 \
    --network 203.0.113.0/24 \
    >"$OUT/b.log" 2>&1 &
B_PID=$!

echo "== waiting for the BMP stream =="
wait_log "$OUT/a.log" "bmp mirroring to 127.0.0.1:$PORT"
wait_log "$OUT/a.log" "bmp station 127.0.0.1:$PORT connected"
wait_log "$OUT/collector.log" "bmp station connected"
wait_log "$OUT/collector.log" "bmp peer up"

echo "== waiting for the monitored route in the collector =="
wait_log "$OUT/collector.log" "bmp route 203.0.113.0/24"

echo "== verifying the collector's Loc-RIB via the runtime API =="
api_cmd "$OUT/collector.api" "routes" >"$OUT/routes.api"
grep -qF "203.0.113.0/24" "$OUT/routes.api" || {
    echo "FAIL: route missing from collector routes"
    cat "$OUT/routes.api"
    exit 1
}
echo "   routes: $(grep -cF '203.0.113.0/24' "$OUT/routes.api") monitored route(s)"

echo "== dumping the collector's RIB to MRT =="
api_cmd "$OUT/collector.api" "mrt $OUT/collector.mrt" >"$OUT/mrt.api"
grep -qF "mrt-dump $OUT/collector.mrt" "$OUT/mrt.api"
grep -qEv "records=0" "$OUT/mrt.api"

api_cmd "$OUT/collector.api" "shutdown" >/dev/null || true
kill "$A_PID" "$B_PID" 2>/dev/null || true
trap - EXIT

echo
echo "BMP collector e2e: PASS"
echo "  - station connected; Peer Up observed by the collector"
echo "  - Route Monitoring installed the monitored prefix (API routes)"
echo "  - collector RIB dumpable via MRT"
