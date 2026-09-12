#!/usr/bin/env bash
# Multi-protocol interop (rc.3): one lr-daemon process running
# `--protocol bgp,ospf` exchanges OSPF and BGP with ONE BIRD 2 process
# running both protocols — the reference-implementation mirror of the
# combination under test.
#
#   netns r1: lr-daemon --protocol bgp,ospf, router-id 1.1.1.1, AS64512
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub net A)
#             BGP listener 10.99.1.1:179 (BIRD connects)
#        ↑↓ OSPFv2 multicast 224.0.0.5 (ptp, hello 1 / dead 4)
#        ↑↓ eBGP 64512 ↔ 64513 over the veth pair
#   netns r2: BIRD 2.17 router-id 2.2.2.2, AS64513 (ospf v2 + bgp)
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub net B)
#
# Success criteria:
#   1. OSPF Full adjacency on both sides (real DBD/LSR, RFC 2328 §7.2).
#   2. The BGP session establishes while OSPF runs in the same process.
#   3. lr's ONE shared Loc-RIB holds both engines' knowledge:
#      10.99.3.0/24 (BIRD's stub, learned via OSPF and via BGP —
#      `export all` on BIRD's side) with the BGP path preferred
#      (admin 20 < 110, the cross-protocol merge), and 10.99.2.0/24.
#   4. No implicit redistribution in lr: BIRD's BGP receives exactly
#      the explicitly originated 198.51.100.0/24 — never the
#      OSPF-learned 10.99.3.0/24 or lr's own OSPF stub 10.99.2.0/24
#      (FRR `redistribute` / BIRD `pipe` semantics: cross-protocol
#      export is opt-in).
#   5. SIGTERM: both engines stop, supervisor exits cleanly.
#
# Raw OSPF sockets + BGP :179 need the user namespace's capabilities:
# the lab runs inside `unshare -Urn` (rootless), exactly what CI does.
# Environments without unprivileged user namespaces, iproute2 or
# bird/birdc SKIP gracefully.
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
OUT=/tmp/lr_multi_protocol_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 240 &
R1=$!
unshare -n sleep 240 &
R2=$!
LR_PID=""
cleanup() {
    [ -n "$LR_PID" ] && kill "$LR_PID" 2>/dev/null || true
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
    local file=$1 pat=$2 tmo=${3:-30} i
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

api() { # <command> — lr-daemon runtime API (shared filesystem socket)
    timeout 5 python3 - "$OUT/r1.ctl" "$1" <<'PYEOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(4)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
time.sleep(0.3)
s.settimeout(0.5)
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except socket.timeout:
    pass
sys.stdout.write(data.decode(errors="replace"))
PYEOF
}

echo "== starting BIRD 2 (2.2.2.2 / AS64513, ospf v2 ptp + eBGP on veth1) =="
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
protocol bgp bgp1 {
    local 10.99.1.2 as 64513;
    neighbor 10.99.1.1 as 64512;
    ipv4 {
        import all;
        export all;
    };
}
EOF
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
sleep 1

echo "== starting lr-daemon (1.1.1.1 / AS64512, --protocol bgp,ospf) =="
nsenter -t "$R1" -n "$BIN" \
    --protocol bgp,ospf \
    --router-id 1.1.1.1 \
    --local-as 64512 --peer-as 64513 \
    --listen 10.99.1.1:179 --local-address 10.99.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --network 198.51.100.0/24 \
    --ebgp-policy accept-all \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for the combination to come up =="
wait_log "$OUT/r1.log" "daemon: 2 engine(s) running"
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area"
echo "   OSPF adjacency: Full (lr side)"

adjacency=""
for i in $(seq 1 60); do
    if birdc_r2 "show ospf neighbors" 2>/dev/null | grep -q "1.1.1.1.*Full"; then
        adjacency=Full
        break
    fi
    sleep 0.5
done
[ "$adjacency" = "Full" ] || {
    echo "FAIL: BIRD never reached Full adjacency"
    birdc_r2 "show ospf neighbors" || true
    exit 1
}
echo "   OSPF adjacency: Full (BIRD side)"

# The BGP session runs in the same process (session number is racy
# between the two engines — match any Established session).
wait_log "$OUT/r1.log" "→ Established"
bgp_up=""
for i in $(seq 1 40); do
    if birdc_r2 "show protocols" 2>/dev/null | grep -q "bgp1.*up"; then
        bgp_up=yes
        break
    fi
    sleep 0.5
done
[ "$bgp_up" = "yes" ] || {
    echo "FAIL: BIRD's bgp1 never came up"
    birdc_r2 "show protocols all bgp1" || true
    exit 1
}
echo "   BGP session: Established (both protocols in both processes)"

echo "== one shared Loc-RIB: both engines' knowledge, one best path =="
# 10.99.3.0/24 (BIRD's stub net) arrives through BOTH engines (OSPF
# learning + BIRD's `export all` over BGP); the merged RIB must show
# one entry with the BGP path preferred (admin 20 < 110).
routes=""
for i in $(seq 1 40); do
    routes="$(api routes || true)"
    echo "$routes" | grep -q "10.99.3.0/24" && break
    sleep 0.5
done
echo "$routes" | grep -q "10.99.3.0/24" || {
    echo "FAIL: lr's shared RIB never learned 10.99.3.0/24"
    echo "$routes"
    exit 1
}
echo "$routes" | grep "10.99.3.0/24" | grep -q "proto=Bgp" || {
    echo "FAIL: 10.99.3.0/24 must prefer the BGP path (admin 20 < OSPF 110)"
    echo "$routes" | grep "10.99.3.0/24"
    exit 1
}
echo "   10.99.3.0/24 merged: BGP best (learned by both engines)"
echo "$routes" | grep -q "10.99.2.0/24" || {
    echo "FAIL: lr's own stub net missing from the RIB"
    echo "$routes"
    exit 1
}
echo "   10.99.2.0/24 (own stub) present in the shared RIB"

echo "== no implicit redistribution: BGP carries only the originated prefix =="
bird_bgp_routes=""
for i in $(seq 1 40); do
    bird_bgp_routes="$(birdc_r2 'show route protocol bgp1' 2>/dev/null || true)"
    echo "$bird_bgp_routes" | grep -q "198.51.100.0/24" && break
    sleep 0.5
done
echo "$bird_bgp_routes" | grep -q "198.51.100.0/24" || {
    echo "FAIL: BIRD's BGP never received the originated 198.51.100.0/24"
    echo "$bird_bgp_routes"
    exit 1
}
echo "   BIRD's BGP received the originated 198.51.100.0/24"
if echo "$bird_bgp_routes" | grep -q "10.99.2.0/24\|10.99.3.0/24"; then
    echo "FAIL: OSPF knowledge leaked into lr's BGP export (no implicit redistribution)"
    echo "$bird_bgp_routes"
    exit 1
fi
echo "   no OSPF-learned route leaked into lr's BGP advertisements"

echo "== graceful shutdown of the whole combination =="
kill -TERM "$LR_PID"
wait_log "$OUT/r1.log" "multi-protocol shutdown complete" 15
wait "$LR_PID"
echo "   supervisor joined both engines cleanly"

echo
echo "multi-protocol x BIRD interop: PASS"
echo "  - one lr-daemon process ran bgp + ospf (shared Loc-RIB, shared API)"
echo "  - OSPF Full adjacency + BGP session with one BIRD process"
echo "  - cross-protocol merge: BGP path preferred for the shared prefix"
echo "  - no implicit redistribution toward BGP (opt-in only)"
INNER
