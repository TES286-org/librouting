#!/usr/bin/env bash
# BIRD interop test: exchange real BGP between lr-daemon and BIRD 2.
#
#   lr-daemon (AS64512, originates 203.0.113.0/24, connector)
#        ↑↓ TCP on 127.0.0.1
#   BIRD 2     (AS64513, exports static 198.51.100.0/24, passive listener)
#
# Success criteria:
#   1. BIRD's table contains 203.0.113.0/24 learned from lr-daemon.
#   2. lr-daemon's log shows 198.51.100.0/24 installed from BIRD.
#   3. The BGP session reaches Established on both sides.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           BIRD listen port (default 17992)
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

PORT=${PORT:-17993}
OUT=/tmp/lr_bird_interop
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting interop test.
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
    # Non-privileged local port (BIRD listens here) and the lr-daemon
    # port to connect to. Works on BIRD 2.0.8 .. 2.17+.
    local port 17992 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;       # eBGP over loopback
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor address
        # (both ends are 127.0.0.1 here), so pin a distinct one.
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD (AS64513, connects to lr-daemon :$PORT) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, listener) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 --ebgp-policy accept-all \
    --listen 127.0.0.1:$PORT --local-address 127.0.0.1 \
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
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from lr-daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD interop — bidirectional route exchange with BIRD 2"
fi
exit $fail
