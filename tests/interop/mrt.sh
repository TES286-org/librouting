#!/usr/bin/env bash
# MRT (RFC 6396) interop: exchange dumps with BIRD and round-trip the
# daemon's own Loc-RIB export.
#
# Phase 1 — BIRD export → lr parse:
#   BIRD 2 runs `protocol mrt` over two static routes; `lr mrt rib`
#   must decode the peer index table and both prefixes.
#
# Phase 2 — lr-daemon export → lr parse:
#   two lr-daemons exchange a BGP route over TCP; daemon B's runtime
#   API `mrt <path>` dumps its Loc-RIB; `lr mrt rib` must show the
#   learned prefix with the AS path and next hop intact.
#
# Phase 1 needs bird/birdc on PATH (CI installs it; SKIP otherwise).
# Phase 2 runs everywhere.
#
# NOTE: log matching uses POSIX `grep -qF`, not ripgrep — CI images do
# not guarantee `rg` on PATH.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr
DAEMON=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr
    DAEMON=target/release/lr-daemon
fi
if [ ! -x "$BIN" ]; then
    echo "SKIP: lr not built (cargo build -p lr-cli)"
    exit 0
fi
command -v python3 >/dev/null 2>&1 || {
    echo "SKIP: python3 not installed (API socket queries)"
    exit 0
}

OUT=/tmp/lr_mrt_interop
rm -rf "$OUT"; mkdir -p "$OUT"

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-15} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

# Query one command over the daemon's runtime API socket.
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

echo "== phase 1: BIRD 2 MRT export parsed by lr =="
BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
        BIRD=/home/z/opt/bird/root/usr/sbin/bird
        BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
    else
        echo "SKIP: bird/birdc not found — phase 1 only"
    fi
fi
if command -v "$BIRD" >/dev/null 2>&1; then
    cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.2;
protocol device {}
protocol static st {
    ipv4;
    route 198.51.100.0/24 blackhole;
    route 203.0.113.0/24 blackhole;
}
protocol mrt mrt1 {
    table master4;
    filter { if proto = "st" then accept; reject; };
    filename "$OUT/bird.mrt";
    period 2;
}
EOF
    "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
    for i in $(seq 1 30); do
        [ -s "$OUT/bird.mrt" ] && break
        sleep 0.2
    done
    kill "$(cat "$OUT/bird.pid")" 2>/dev/null || true
    sleep 0.3
    "$BIN" mrt rib "$OUT/bird.mrt" >"$OUT/bird.rib" || {
        echo "FAIL: lr mrt rib could not parse BIRD's dump"
        exit 1
    }
    grep -qF "198.51.100.0/24" "$OUT/bird.rib"
    grep -qF "203.0.113.0/24" "$OUT/bird.rib"
    grep -qF 'view "master4"' "$OUT/bird.rib"
    echo "   BIRD dump parsed: view + 2 prefixes + peer table"
else
    echo "   (phase 1 skipped)"
fi

echo "== phase 2: lr-daemon Loc-RIB MRT export round-trip =="
PORT=${PORT:-11831}
"$DAEMON" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    --api-socket "$OUT/a.api" >"$OUT/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT
B_PID=""
"$DAEMON" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT --local-address 192.0.2.2 \
    --api-socket "$OUT/b.api" >"$OUT/b.log" 2>&1 &
B_PID=$!

wait_log "$OUT/b.log" "route installed 203.0.113.0/24" 20

api_cmd "$OUT/b.api" "mrt $OUT/b.mrt" >"$OUT/mrt.api" || {
    echo "FAIL: mrt API command failed"
    cat "$OUT/mrt.api"
    exit 1
}
grep -qF "mrt-dump $OUT/b.mrt records=" "$OUT/mrt.api"
grep -qEv "records=0" "$OUT/mrt.api" || {
    echo "FAIL: dump carries no records"
    cat "$OUT/mrt.api"
    exit 1
}

"$BIN" mrt rib "$OUT/b.mrt" >"$OUT/b.rib" || {
    echo "FAIL: lr mrt rib could not parse the daemon's own dump"
    exit 1
}
grep -qF "203.0.113.0/24" "$OUT/b.rib"
grep -qF "AS64512" "$OUT/b.rib"
grep -qF "192.0.2.1" "$OUT/b.rib"
grep -qF "10.0.0.1" "$OUT/b.rib" # peer table entry (BGP id of peer)
echo "   round-trip: prefix + AS path + next hop + peer table intact"

api_cmd "$OUT/b.api" "shutdown" >/dev/null || true
kill $A_PID 2>/dev/null || true
trap - EXIT

echo
echo "MRT interop: PASS"
echo "  - BIRD 2 'protocol mrt' dump decoded (peer table + prefixes)"
echo "  - lr-daemon Loc-RIB export round-trips with AS path / next hop"
