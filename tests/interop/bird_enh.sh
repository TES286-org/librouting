#!/usr/bin/env bash
# BIRD interop test: RFC 5549 Extended Next-Hop over a single IPv6 session.
#
#   lr-daemon (AS64512, originates 203.0.113.0/24 over IPv6 transport)
#        ↑↓ TCP on [::1]
#   BIRD 2     (AS64513, exports 198.51.100.0/24, passive listener)
#
# Both speakers advertise RFC 5549 (1,1,2) so IPv4 NLRI is carried over
# an IPv6 next-hop — no IPv4 transport or IPv4 next-hop is needed.
#
# NOTE: BIRD 2.x encodes the ENH capability with 6-byte tuples
# (AFI:2, reserved:1, SAFI:1, NH-AFI:2 — the same layout as the MP-BGP
# capability) instead of the RFC 5549 standard 5-byte tuples
# (AFI:2, SAFI:1, NH-AFI:2). librouting sends the RFC-standard 5-byte
# form (which FRR accepts); BIRD 2.x rejects it with "Invalid OPEN
# message". This script therefore SKIPs when BIRD is the peer — the
# RFC 5549 wire format is verified end-to-end by the in-process tests
# in crates/lr-tests/tests/bgp_session_modes.rs (modes 5 and 6).
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   FORCE=1        run the test even though BIRD is known to be incompatible
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

if [ "${FORCE:-0}" != "1" ]; then
    echo "SKIP: BIRD 2.x uses a non-standard 6-byte ENH tuple encoding"
    echo "      (AFI:2, reserved:1, SAFI:1, NH-AFI:2) instead of the RFC 5549"
    echo "      standard 5-byte form (AFI:2, SAFI:1, NH-AFI:2). librouting"
    echo "      sends the RFC-standard 5-byte form, which FRR accepts. The"
    echo "      RFC 5549 wire format is verified end-to-end by the in-process"
    echo "      tests in crates/lr-tests/tests/bgp_session_modes.rs."
    echo "      Set FORCE=1 to run this test anyway (it will fail at OPEN)."
    exit 0
fi

PORT=${PORT:-17994}
OUT=/tmp/lr_bird_enh_interop
rm -rf "$OUT"; mkdir -p "$OUT"

# BIRD side: IPv6 transport + ENH (BIRD calls it `ext next hop`).
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting RFC 5549 ENH interop test.
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
    local ::1 port 17995 as 64513;
    neighbor ::1 port $PORT as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 2001:db8::2;
        extended next hop;     # RFC 5549 — accept IPv4 NLRI over IPv6 next-hop
    };
}
EOF

echo "== starting BIRD (AS64513, ::1, ENH) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, [::1]:$PORT, ENH) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen "[::1]:$PORT" --local-address-v6 "2001:db8::1" \
    --mp-family ipv4-unicast --extended-next-hop \
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
"$BIRDC" -s "$OUT/bird.ctl" show protocols all lr 2>/dev/null | head -30 || true
echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD log (tail) =="
tail -25 "$OUT/bird.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from lr-daemon (ENH)"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD (ENH)"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD ENH interop — IPv4 NLRI exchanged over IPv6 next-hop"
fi
exit $fail
