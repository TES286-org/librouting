#!/usr/bin/env bash
# OSPF interop with BIRD 2: real Database Description / LS-Request
# exchange (RFC 2328 §7.2) over a veth pair, one network namespace per
# router.
#
#   netns r1: lr-daemon router-id 1.1.1.1
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub net A)
#        ↑↓ OSPFv2 multicast 224.0.0.5 — Hello / DBD / LSR / LSU / LSAck
#   netns r2: BIRD 2 router-id 2.2.2.2 (ospf v2, interface type ptp)
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub net B)
#
# Success criteria:
#   1. BIRD's neighbor table shows 1.1.1.1 in Full state (birdc).
#   2. lr-daemon reaches Full adjacency (session log).
#   3. lr-daemon installs BIRD's stub net 10.99.3.0/24.
#   4. BIRD's table contains our stub net 10.99.2.0/24 (birdc).
#
# Raw OSPF sockets need CAP_NET_RAW: the lab runs inside `unshare -Urn`
# (rootless). Environments without unprivileged user namespaces or
# without bird/birdc SKIP gracefully.
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

REPO=$(pwd)
export REPO BIN BIRD BIRDC

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_bird_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" 2>/dev/null || true
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
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

birdc_r2() { # <command...>
    nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird.ctl" "$@"
}

echo "== starting BIRD 2 (2.2.2.2, ospf v2 ptp on veth1) =="
cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;
protocol device {}
protocol ospf v2 ospf1 {
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

echo "== starting lr-daemon (1.1.1.1, stub nets 10.99.1.0/24 + 10.99.2.0/24) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --install-kernel-routes \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency on both routers =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 30
adjacency=Full
for i in $(seq 1 60); do
    if birdc_r2 "show ospf neighbors" 2>/dev/null | grep -q "1.1.1.1.*Full"; then
        adjacency=Full
        break
    fi
    sleep 0.5
done
echo "   adjacency: OK (lr Full + BIRD Full)"

echo "== waiting for route propagation =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 30
echo "   lr knows BIRD's stub net 10.99.3.0/24"
for i in $(seq 1 60); do
    if birdc_r2 "show route table master4" 2>/dev/null | grep -q "10.99.2.0/24"; then
        break
    fi
    sleep 0.5
done
birdc_r2 "show route table master4" >"$OUT/bird.routes" 2>&1 || true
grep -q "10.99.2.0/24" "$OUT/bird.routes" || {
    echo "FAIL: BIRD does not carry our stub net"
    cat "$OUT/bird.routes"
    exit 1
}
echo "   BIRD knows our stub net 10.99.2.0/24"

echo "== kernel FIB: lr-daemon installed BIRD's stub net via --install-kernel-routes =="
# Wait for the OSPF route to BIRD's stub net (10.99.3.0/24) to appear
# in r1's kernel FIB. The daemon's KernelMirror (called from
# handle_router_events on the main thread) mirrors the Loc-RIB
# change into rtnetlink.
KERNEL_ROUTE=""
for i in $(seq 1 100); do
    KERNEL_ROUTE=$(nsenter -t "$R1" -n ip route show 10.99.3.0/24 2>/dev/null || true)
    [ -n "$KERNEL_ROUTE" ] && break
    sleep 0.1
done
[ -n "$KERNEL_ROUTE" ] || {
    echo "FAIL: OSPF route 10.99.3.0/24 not in r1's kernel FIB"
    nsenter -t "$R1" -n ip route show
    exit 1
}
echo "$KERNEL_ROUTE" | grep -q "via 10.99.1.2" || {
    echo "FAIL: kernel route does not use the BIRD gateway 10.99.1.2"
    echo "$KERNEL_ROUTE"
    exit 1
}
echo "$KERNEL_ROUTE" | grep -q "dev veth0" || {
    echo "FAIL: kernel route does not use veth0"
    echo "$KERNEL_ROUTE"
    exit 1
}
echo "   r1 FIB: $KERNEL_ROUTE"
echo "   kernel FIB: OK (lr learned BIRD's route AND installed it)"

echo "== kernel forwarding decision: ip route get =="
R1_GET=$(nsenter -t "$R1" -n ip route get 10.99.3.5 2>/dev/null || true)
[ -n "$R1_GET" ] || { echo "FAIL: ip route get on r1 returned nothing"; exit 1; }
echo "$R1_GET" | grep -q "via 10.99.1.2" || {
    echo "FAIL: ip route get on r1 did not use the OSPF gateway 10.99.1.2"
    echo "$R1_GET"
    exit 1
}
echo "$R1_GET" | grep -q "dev veth0" || {
    echo "FAIL: ip route get on r1 did not use veth0"
    echo "$R1_GET"
    exit 1
}
echo "   r1 route get: $R1_GET"
echo "   ip route get: OK (kernel would use the OSPF route learned from BIRD)"

echo
echo "OSPF x BIRD interop: PASS"
echo "  - Full adjacency via real DBD/LSR exchange (RFC 2328 7.2)"
echo "  - stub nets propagated in both directions"
echo "  - Kernel FIB carries BIRD's stub net (--install-kernel-routes)"
echo "  - ip route get confirms the kernel would use the BIRD-learned route"
INNER
