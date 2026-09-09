#!/usr/bin/env bash
# BIRD interop test for the compat surface (W5.4): lr-daemon runs a
# BIRD 2 configuration file NATIVELY (`lr-daemon --config bird.conf`)
# and exchanges real BGP with an actual BIRD 2 instance.
#
#   lr-daemon from bird.conf (AS64512, connector, originates
#   203.0.113.0/24 via a BIRD static protocol)
#        ↑↓ TCP on 127.0.0.1
#   BIRD 2     (AS64513, exports static 198.51.100.0/24, listener)
#
# Success criteria:
#   1. The session reaches Established (lr log).
#   2. BIRD's table contains 203.0.113.0/24 learned from lr-daemon.
#   3. lr-daemon's log shows 198.51.100.0/24 installed from BIRD.
#   4. The dialect-defaults warning proves the compat path ran, and
#      the `lr: api-socket` directive created the runtime API socket.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           BIRD listen port (default 17994)
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

PORT=${PORT:-17994}
OUT=/tmp/lr_compat_bird_interop
rm -rf "$OUT"; mkdir -p "$OUT"

# The reference side (real BIRD 2): passive listener exporting its
# static route, same shape as bird.sh.
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting compat interop test.
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
    local port 17992 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;       # eBGP over loopback
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor
        # address (both ends are 127.0.0.1 here), so pin a distinct one.
        next hop address 192.0.2.10;
    };
}
EOF

# The subject: lr-daemon runs the BIRD-shaped config DIRECTLY — no
# conversion step. `lr: api-socket` is an lr-specific extension the
# reference implementation ignores.
cat >"$OUT/lr.bird.conf" <<EOF
# lr compat-mode BIRD dialect config (runs via: lr-daemon --config).
router id 10.0.0.1;

protocol static seed {
    ipv4;
    route 203.0.113.0/24 blackhole;
}

protocol bgp bird {
    local as 64512;
    local address 192.0.2.1;
    neighbor 127.0.0.1 port 17992 as 64513;
    hold time 30;
    ipv4 {
        import all;
        export all;
    };
}

# lr: api-socket $OUT/api.sock
EOF

echo "== starting BIRD (AS64513, listener :17992) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon from the BIRD dialect config (AS64512, connector) =="
"$BIN" --config "$OUT/lr.bird.conf" >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT

ok_bird=1
ok_lr=1
ok_compat=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "203.0.113.0/24"; then
        ok_bird=0
    fi
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_compat -ne 0 ] && [ -S "$OUT/api.sock" ] \
        && grep -qF "bird dialect defaults applied" "$OUT/lr.log" 2>/dev/null; then
        ok_compat=0
    fi
    if [ $ok_bird -eq 0 ] && [ $ok_lr -eq 0 ] && [ $ok_compat -eq 0 ]; then
        break
    fi
done

echo "== BIRD routing table =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD log (tail) =="
tail -25 "$OUT/bird.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from the compat-mode lr-daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD"
    fail=1
fi
if [ $ok_compat -ne 0 ]; then
    echo "FAIL: compat-mode markers missing (dialect-defaults warning / api socket)"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD compat interop — lr-daemon ran the BIRD config natively and exchanged routes with BIRD 2"
fi
exit $fail
