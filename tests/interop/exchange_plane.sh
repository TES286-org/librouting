#!/usr/bin/env bash
# W6.3 exchange-plane fallback gate: lr-daemon with the plane ENABLED
# peers with BIRD 2, which does not advertise the capability.
#
#   lr-daemon (AS64512, --exchange-plane, originates 203.0.113.0/24)
#        ↑↓ TCP on 127.0.0.1
#   BIRD 2     (AS64513, exports static 198.51.100.0/24, passive listener)
#
# The RFC 5492 §3 transparent fallback: BIRD treats the unknown
# capability as inert, the plane never activates, and the session plus
# routing behave exactly like the plain interop test. Success criteria:
#   1. The BGP session reaches Established on both sides.
#   2. Routes flow in both directions (203.0.113.0/24 ↔ 198.51.100.0/24).
#   3. No exchange-plane records surface anywhere (the negotiation
#      never activated).
#
# Requires a daemon built with `--features exchange-plane` (the script
# SKIPs on a feature-less binary so plain checkouts are unaffected).
# Env overrides: BIRD / BIRDC / PORT (default 17995).
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
if [ ! -x "$BIN" ]; then
    echo "SKIP: lr-daemon not built (cargo build -p lr-cli --features exchange-plane)"
    exit 0
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

PORT=${PORT:-17995}
OUT=/tmp/lr_xp_interop
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the exchange-plane fallback gate.
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
    multihop 2;       # eBGP over loopback
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD (AS64513) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, exchange-plane ON) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 127.0.0.1 \
    --network 203.0.113.0/24 \
    --exchange-plane --exchange-plane-key 1:alpha \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT
sleep 1
if grep -q "built without the exchange-plane feature" "$OUT/lr.log"; then
    echo "SKIP: daemon binary lacks the exchange-plane feature"
    exit 0
fi

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
echo "== lr-daemon log =="
cat "$OUT/lr.log"

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from the exchange-plane daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: the exchange-plane daemon did not learn 198.51.100.0/24 from BIRD"
    fail=1
fi
if grep -q "exchange-plane: session" "$OUT/lr.log"; then
    echo "FAIL: records surfaced on a session with a non-lr peer — the fallback broke"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: exchange-plane fallback gate — plane on, BIRD plain, routing unaffected"
fi
exit $fail
