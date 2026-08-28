#!/usr/bin/env bash
# BIRD interop test: pure IPv6 BGP session (IPv6 transport + IPv6 NLRI).
#
#   lr-daemon (AS64512, originates 2001:db8:1::/64 over IPv6 transport)
#        ↑↓ TCP on [::1]
#   BIRD 2     (AS64513, exports 2001:db8:2::/64, passive listener)
#
# Success criteria:
#   1. BIRD's table contains 2001:db8:1::/64 learned from lr-daemon.
#   2. lr-daemon's log shows 2001:db8:2::/64 installed from BIRD.
#   3. The BGP session reaches Established on both sides.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           lr-daemon listen port (default 17996)
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

PORT=${PORT:-17996}
OUT=/tmp/lr_bird_ipv6_interop
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting pure-IPv6 interop test.
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv6;
    route 2001:db8:2::/64 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local ::1 port 17997 as 64513;
    neighbor ::1 port $PORT as 64512;
    multihop 2;
    ipv6 {
        import all;
        export filter export_to_lr;
        next hop address 2001:db8::2;
    };
}
EOF

echo "== starting BIRD (AS64513, ::1, IPv6 NLRI) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, [::1]:$PORT, IPv6 NLRI only) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen "[::1]:$PORT" --local-address-v6 "2001:db8::1" \
    --mp-family ipv6-unicast \
    --network "2001:db8:1::/64" \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT

# Wait for both directions to converge.
ok_bird=1
ok_lr=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "2001:db8:1::/64"; then
        ok_bird=0
    fi
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 2001:db8:2::/64" "$OUT/lr.log" 2>/dev/null; then
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
    echo "FAIL: BIRD did not learn 2001:db8:1::/64 from lr-daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 2001:db8:2::/64 from BIRD"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD IPv6 interop — pure IPv6 BGP session"
fi
exit $fail
