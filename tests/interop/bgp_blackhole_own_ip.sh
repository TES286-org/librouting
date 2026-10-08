#!/usr/bin/env bash
# Reproduces the production scenario: lr-daemon with a static blackhole
# for its own listener IP, BIRD as the peer. Before the fix, on Windows
# the blackhole install would shadow local delivery and BIRD's inbound
# SYN would never reach lr's listener — the BGP session would never
# establish. On Linux the local route wins, but the daemon's "skipping
# blackhole install" log line proves the fix is active.
#
# Success criteria:
#   1. lr-daemon logs "mirror: skipping blackhole install for 127.0.0.1/32".
#   2. BGP session reaches Established on both sides.
#   3. BIRD learns lr-daemon's 203.0.113.0/24 route.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x $HOME/opt/bird/root/usr/sbin/bird ]; then
        BIRD=$HOME/opt/bird/root/usr/sbin/bird
        BIRDC=$HOME/opt/bird/root/usr/sbin/birdcl
    else
        echo "SKIP: bird/birdc not found"
        exit 0
    fi
fi
command -v "$BIRD" >/dev/null 2>&1 || { echo "SKIP: bird not found"; exit 0; }

PORT=${PORT:-17995}
OUT=/tmp/lr_bird_blackhole_own_ip
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local port 17994 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD (AS64513, connects to lr-daemon :$PORT) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID $LR_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, listener, static blackhole for own IP) =="
cat >"$OUT/lr.toml" <<EOF
[bgp]
local_as = 64512
router_id = "10.0.0.1"
ebgp_policy = "accept-all"
listen_addr = "127.0.0.1:$PORT"
local_address = "127.0.0.1"
install_kernel = true
networks = ["203.0.113.0/24"]

[[static.route]]
prefix = "127.0.0.1/32"
next_hop = "blackhole"

[[peer]]
name = "bird"
remote = "127.0.0.1:17994"
peer_as = 64513
EOF
"$BIN" --config "$OUT/lr.toml" >"$OUT/lr.log" 2>&1 &
LR_PID=$!
sleep 1

ok_skip=1
ok_bird=1
ok_lr=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_skip -ne 0 ] && grep -qF "skipping blackhole install for 127.0.0.1/32" "$OUT/lr.log" 2>/dev/null; then
        ok_skip=0
    fi
    if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "203.0.113.0/24"; then
        ok_bird=0
    fi
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_skip -eq 0 ] && [ $ok_bird -eq 0 ] && [ $ok_lr -eq 0 ]; then
        break
    fi
done

echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD routing table =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== BIRD log (tail) =="
tail -25 "$OUT/bird.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_skip -ne 0 ]; then
    echo "FAIL: lr-daemon did not log 'skipping blackhole install for 127.0.0.1/32'"
    fail=1
fi
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from lr-daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD interop — static blackhole for own IP skipped, session established"
fi
exit $fail
