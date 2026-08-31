#!/usr/bin/env bash
# Wire-level parity harness (STATUS.md W5.3): replay a captured UPDATE
# stream and diff the Loc-RIBs.
#
#   1. lr-daemon listens on LPORT and originates two IPv4 prefixes.
#   2. BIRD 2 connects THROUGH the recording proxy (PROXY -> LPORT), so
#      every byte lr sends is captured; BIRD learns the routes.
#   3. BIRD's own view of the lr-learned routes is exported as MRT
#      (protocol mrt filtered to proto = "lr") — the ground truth.
#   4. `lr parity-replay` replays the captured lr->BIRD stream into an
#      offline router taking BIRD's role and dumps its Loc-RIB as MRT.
#   5. `lr mrt diff` must report the two dumps IDENTICAL: the replayed
#      pipeline holds exactly what the reference implementation held.
#
# BIRD is optional: without it the script SKIPs (the in-process replay
# parity is covered by `cargo test -p lr-cli --bin lr parity`).
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
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
        BIRD=/home/z/opt/bird/root/usr/sbin/bird
        BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
    fi
fi
command -v "$BIRD" >/dev/null 2>&1 || { echo "SKIP: bird not found"; exit 0; }

LPORT=${LPORT:-17997}
PROXY=${PROXY:-17996}
OUT=/tmp/lr_parity_interop
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

cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;   # must NOT leak into the diff
}

protocol bgp lr {
    local port 17995 as 64513;
    neighbor 127.0.0.1 port $PROXY as 64512;
    multihop 2;       # eBGP over loopback
    ipv4 {
        import all;
        export none;
    };
}

protocol mrt mrt1 {
    table master4;
    filter { if proto = "lr" then accept; reject; };
    filename "$OUT/bird.mrt";
    period 1;
}
EOF

echo "== starting BIRD (AS64513, connects through the proxy :$PROXY) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
cleanup() { kill $LR_PID $BIRD_PID $PROXY_PID 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

echo "== starting the recording proxy (:${PROXY} -> :${LPORT}) =="
python3 tests/parity/capture_proxy.py --listen "127.0.0.1:$PROXY" \
    --upstream "127.0.0.1:$LPORT" --capture "$OUT/capture.jsonl" \
    >"$OUT/proxy.log" 2>&1 &
PROXY_PID=$!

echo "== starting lr-daemon (AS64512, listener, originates two prefixes) =="
"$DAEMON" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 --ebgp-policy accept-all \
    --listen 127.0.0.1:$LPORT --local-address 192.0.2.1 \
    --network 203.0.113.0/24 --network 203.0.114.0/24 \
    --api-socket "$OUT/lr.api" >"$OUT/lr.log" 2>&1 &
LR_PID=$!

# Convergence: BIRD's table must carry both learned prefixes.
converged=1
for i in $(seq 1 120); do
    sleep 0.25
    if "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "203.0.114.0/24"; then
        converged=0
        break
    fi
done
[ "$converged" -eq 0 ] || {
    echo "FAIL: BIRD never learned the lr prefixes"
    "$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
    cat "$OUT/lr.log" "$OUT/bird.log" 2>/dev/null | tail -30
    exit 1
}
echo "   BIRD learned both prefixes (203.0.113.0/24 + 203.0.114.0/24)"

# Ground truth: BIRD's own MRT dump of the lr-learned routes. Poll for
# it while the session is still up — once the session drops, BIRD
# withdraws the routes and later dumps are empty.
ok_mrt=1
for i in $(seq 1 50); do
    if [ -s "$OUT/bird.mrt" ] && "$BIN" mrt rib "$OUT/bird.mrt" >/dev/null 2>&1; then
        ok_mrt=0
        break
    fi
    sleep 0.2
done
[ "$ok_mrt" -eq 0 ] || {
    echo "FAIL: BIRD's MRT dump never contained RIB records"
    exit 1
}

# Stop the proxy first: the capture must end at convergence, before any
# teardown NOTIFICATION noise.
kill "$PROXY_PID" 2>/dev/null || true
sleep 0.3

grep -q '"dir":"down"' "$OUT/capture.jsonl" || {
    echo "FAIL: capture recorded no lr-to-BIRD messages"
    head -5 "$OUT/capture.jsonl"
    exit 1
}
n_msgs=$(wc -l <"$OUT/capture.jsonl")
echo "   capture: $n_msgs BGP message(s)"

cleanup
sleep 0.5

"$BIN" mrt rib "$OUT/bird.mrt" >"$OUT/bird.rib" || {
    echo "FAIL: cannot parse BIRD's MRT dump"
    exit 1
}
grep -q "203.0.113.0/24" "$OUT/bird.rib" || {
    echo "FAIL: BIRD's dump does not carry the first prefix"
    cat "$OUT/bird.rib"
    exit 1
}
grep -q "203.0.114.0/24" "$OUT/bird.rib" || {
    echo "FAIL: BIRD's dump does not carry the second prefix"
    cat "$OUT/bird.rib"
    exit 1
}
if grep -q "198.51.100.0/24" "$OUT/bird.rib"; then
    echo "FAIL: the static route leaked through the proto filter"
    cat "$OUT/bird.rib"
    exit 1
fi
echo "   ground truth: BIRD's MRT dump carries exactly the lr prefixes"

echo "== replaying the captured lr->BIRD stream into an offline router =="
# The proxy labels client->upstream "up" and upstream->client "down";
# here the TCP client is BIRD, so lr's messages (the routes) are the
# "down" stream. The replay router takes BIRD's role (AS64513).
"$BIN" parity-replay --capture "$OUT/capture.jsonl" --direction down \
    --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --output "$OUT/replay.mrt" || {
    echo "FAIL: parity-replay failed"
    exit 1
}

echo "== diffing the Loc-RIBs =="
if "$BIN" mrt diff "$OUT/bird.mrt" "$OUT/replay.mrt"; then
    echo "PASS: wire-level parity — the replayed Loc-RIB matches BIRD's view"
else
    echo "FAIL: Loc-RIB parity violated (differences above)"
    exit 1
fi
