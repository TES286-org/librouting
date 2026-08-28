#!/usr/bin/env bash
# BIRD interop test: RFC 5082 GTSM (TTL security).
#
#   lr-daemon (AS64512, listener, TTL=255 both directions)
#        ↑↓ TCP on 127.0.0.1
#   BIRD 2     (AS64513, connector, `ttl security` on the BGP channel)
#
# Success criteria:
#   1. The BGP session reaches Established on both sides (both speakers
#      set TTL=255, so the min-TTL filter passes).
#   2. Route propagation works in both directions.
#
# This test runs on Linux only (IP_MINTTL is Linux-specific). BIRD 2.x
# uses `ttl security` inside the BGP channel block.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           lr-daemon listen port (default 17998)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
        BIRD=/home/z/opt/bird/root/usr/sbin/bird
        BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
    else
        echo "SKIP: bird/birdc not found"
        exit 0
    fi
fi
command -v "$BIRD" >/dev/null 2>&1 || { echo "SKIP: bird not found"; exit 0; }

PORT=${PORT:-17998}
OUT=/tmp/lr_bird_gtsm_interop
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting GTSM interop test.
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
    local 127.0.0.1 port 17999 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;
    ttl security;     # RFC 5082 — require TTL=255 on inbound
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD (AS64513, ttl security) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, --gtsm, listener) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT --local-address 127.0.0.1 \
    --gtsm \
    --network 203.0.113.0/24 \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT

# Wait for both directions to converge (up to 30 s on slow runners).
ok_bird=1
ok_lr=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "203.0.113.0/24"; then
        ok_bird=0
    fi
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_bird -eq 0 ] && [ $ok_lr -eq 0 ]; then
        break
    fi
done

echo "== BIRD routing table =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== BIRD protocol state =="
"$BIRDC" -s "$OUT/bird.ctl" show protocols all lr 2>/dev/null | head -25 || true
echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD log (tail) =="
tail -25 "$OUT/bird.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from lr-daemon (GTSM)"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD (GTSM)"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD GTSM interop — TTL=255 session established, routes exchanged"
fi
exit $fail
