#!/usr/bin/env bash
# OSPF Graceful Restart interop against BIRD 2 as the helper
# (RFC 3623): lr-daemon restarts gracefully; BIRD — whose OSPF runs
# helper mode by default (BIRD "AWARE") — must retain the adjacency
# and the route through the restart, and release them on lr's
# Grace-LSA flush.
#
# Topology (one netns per router, raw sockets, rootless):
#
#   netns r1: lr-daemon 1.1.1.1, --ospf-graceful-restart (grace 20 s)
#             veth0: 10.99.1.1/24 + 10.99.2.1/24 (stub net A)
#        ↑↓ OSPFv2 ptp
#   netns r2: BIRD 2.2.2.2 (helper default on)
#             veth1: 10.99.1.2/24 + 10.99.3.1/24 (stub net B)
#
# Success criteria:
#   1. Full adjacency + stub nets propagated both ways.
#   2. SIGTERM r1 → BIRD's log shows the neighbour "started graceful
#      restart" (its helper mode engaged on lr's Grace-LSA).
#   3. r1 silent past BIRD's dead interval → BIRD still routes
#      10.99.2.0/24 (LSA retention).
#   4. r1 restarts → adjacency Full again, BIRD logs "finished
#      graceful restart" (lr's flush worked), routes intact.
#
# SKIPs when bird/birdc, iproute2, user namespaces or python3 are
# unavailable (CI installs bird2 in the interop job; forks skip).
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
if [ ! -x "$BIN" ]; then
    echo "SKIP: lr-daemon not built (cargo build -p lr-cli)"
    exit 0
fi
command -v ip >/dev/null 2>&1 || {
    echo "SKIP: iproute2 (ip) not installed"
    exit 0
}
command -v nsenter >/dev/null 2>&1 || {
    echo "SKIP: nsenter (util-linux) not installed"
    exit 0
}
command -v python3 >/dev/null 2>&1 || {
    echo "SKIP: python3 not installed (API socket queries)"
    exit 0
}
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}
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

REPO=$(pwd)
export REPO BIN BIRD BIRDC

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_gr_bird_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the lab (veth pair, lr + BIRD) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 180 &
R1=$!
unshare -n sleep 180 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${LR_PID2:-}" 2>/dev/null || true
    kill "$(cat "$OUT/bird.pid" 2>/dev/null || echo 0)" 2>/dev/null || true
    kill "$R1" "$R2" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0 netns "$R1"
ip link set veth1 netns "$R2"
nsenter -t "$R1" -n ip link set lo up
nsenter -t "$R2" -n ip link set lo up
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip addr add 10.99.2.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip addr add 10.99.3.1/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        [ -f "$file" ] && grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file (tail) --"
    tail -40 "$file" 2>/dev/null
    return 1
}

birdc_r2() { # <command...>
    nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird.ctl" "$@"
}

bird_has_route() {
    birdc_r2 "show route table master4" 2>/dev/null | grep -q "10.99.2.0/24"
}

echo "== starting BIRD 2 (2.2.2.2, ospf v2 ptp on veth1) =="
cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;
protocol device {}
protocol ospf v2 ospf1 {
    debug all;
    area 0 {
        interface "veth1" {
            type ptp;
            hello 1;
            dead 4;
        };
    };
}
EOF
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"

echo "== starting lr-daemon r1 (1.1.1.1, graceful restart, grace 20 s) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 20 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency + route propagation =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 30
for i in $(seq 1 60); do
    birdc_r2 "show ospf neighbors" 2>/dev/null | grep -q "1.1.1.1.*Full" && break
    sleep 0.5
done
birdc_r2 "show ospf neighbors" | grep -q "1.1.1.1.*Full" || {
    echo "FAIL: BIRD never reached Full with lr"
    birdc_r2 "show ospf neighbors"
    exit 1
}
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 30
for i in $(seq 1 60); do
    bird_has_route && break
    sleep 0.5
done
bird_has_route || {
    echo "FAIL: BIRD does not carry our stub net"
    exit 1
}
echo "   adjacency + propagation: OK (lr Full, BIRD Full, 10.99.2.0/24 routed)"

echo "== SIGTERM r1: BIRD must engage helper mode on the Grace-LSA =="
kill -TERM "$LR_PID"
wait_log "$OUT/r1.log" "graceful shutdown complete" 10
wait_log "$OUT/bird.log" "started graceful restart" 15
echo "   helper: OK (BIRD: 'Neighbor 1.1.1.1 ... started graceful restart')"

echo "== r1 silent past BIRD's dead interval (4 s): route must survive =="
sleep 7
bird_has_route || {
    echo "FAIL: BIRD dropped 10.99.2.0/24 during the grace window"
    birdc_r2 "show route table master4"
    tail -20 "$OUT/bird.log"
    exit 1
}
echo "   retention: OK (BIRD still routes 10.99.2.0/24 while 1.1.1.1 is down)"

echo "== restarting r1: recovery + flush, BIRD releases the helper =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 20 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1b.log" 2>&1 &
LR_PID2=$!
disown "$LR_PID2"
wait_log "$OUT/r1b.log" "ospf neighbor 2.2.2.2 Full (area" 30
wait_log "$OUT/r1b.log" "recovery ended" 30
if ! grep -qF "recovery ended — all adjacencies re-established" "$OUT/r1b.log"; then
    echo "FAIL: lr recovery exited without success:"
    grep -F "recovery ended" "$OUT/r1b.log" || true
    exit 1
fi
wait_log "$OUT/bird.log" "finished graceful restart" 20
echo "   recovery: OK (lr re-synced and exited recovery; BIRD released the helper)"
for i in $(seq 1 60); do
    birdc_r2 "show ospf neighbors" 2>/dev/null | grep -q "1.1.1.1.*Full" && break
    sleep 0.5
done
birdc_r2 "show ospf neighbors" | grep -q "1.1.1.1.*Full" || {
    echo "FAIL: BIRD lost the adjacency across lr's restart"
    birdc_r2 "show ospf neighbors"
    exit 1
}
bird_has_route || {
    echo "FAIL: BIRD lost 10.99.2.0/24 across the restart"
    exit 1
}
wait_log "$OUT/r1b.log" "route installed 10.99.3.0/24" 30
echo "   routes: OK (10.99.2.0/24 survived the whole restart in BIRD)"

echo
echo "OSPF graceful restart x BIRD helper: PASS"
echo "  - lr's Grace-LSA engages BIRD's helper mode (RFC 3623 3.1)"
echo "  - BIRD retains the adjacency + route through the restart window"
echo "  - lr's post-recovery flush releases the helper (3.2 (1))"
INNER
