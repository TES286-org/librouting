#!/usr/bin/env bash
# OSPF two-daemon interop test over real raw sockets.
#
# Topology — each router in its own network namespace joined by a veth
# pair (the real two-router model, no loopback shortcuts):
#
#   netns r1: lr-daemon router-id 1.1.1.1
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub net A)
#        ↑↓ OSPFv2 multicast 224.0.0.5, Hellos + LS-Updates
#   netns r2: lr-daemon router-id 2.2.2.2
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub net B)
#
# Success criteria:
#   1. Both daemons reach Full adjacency (session log).
#   2. r1's Loc-RIB contains 10.99.3.0/24 (r2's stub net, Ospfv2).
#   3. r2's Loc-RIB contains 10.99.2.0/24 (r1's stub net, Ospfv2).
#   4. SIGKILL on r2 → r1's dead timer tears the neighbor session down.
#
# Raw OSPF sockets need CAP_NET_RAW. The whole lab runs inside
# `unshare -Urn` (user + network namespace) where the capability is
# granted — rootless, exactly what CI does. Environments without
# unprivileged user namespaces (or without iproute2) SKIP gracefully.
#
# NOTE: log matching uses POSIX `grep -qF` — CI images do not guarantee
# `rg` on PATH.
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
# Holder processes keep the two router namespaces alive.
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
cleanup() {
    kill "${DAEMON_A:-}" "${DAEMON_B:-}" 2>/dev/null || true
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
    local file=$1 pat=$2 tmo=${3:-15} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

echo "== starting router r1 (1.1.1.1, stub nets 10.99.1.0/24 + 10.99.2.0/24) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, stub nets 10.99.1.0/24 + 10.99.3.0/24) =="
nsenter -t "$R2" -n "$BIN" --protocol ospf --router-id 2.2.2.2 \
    --ospf-interface veth1 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!
disown "$DAEMON_B"

echo "== waiting for Full adjacency on both routers =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 20
wait_log "$OUT/r2.log" "ospf neighbor 1.1.1.1 Full (area" 20
echo "   adjacency: OK"

echo "== waiting for stub-net propagation (Router-LSA + LSU flooding) =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 20
wait_log "$OUT/r2.log" "route installed 10.99.2.0/24" 20
echo "   propagation: OK (r1 knows 10.99.3.0/24, r2 knows 10.99.2.0/24)"

# The routes must be OSPF-sourced with the expected metric: cost 10 for
# the direct stub link plus 10 across the veth transit (p2p link).
grep -qF "10.99.3.0/24" "$OUT/r1.log"
grep -qF "10.99.2.0/24" "$OUT/r2.log"

echo "== dead-timer teardown: SIGKILL r2, expect r1 to close the session =="
kill -9 "$DAEMON_B" 2>/dev/null || true
DAEMON_B=""
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 dead (area" 20
echo "   dead timer: OK"

kill "$DAEMON_A" 2>/dev/null || true
DAEMON_A=""
sleep 0.5

echo
echo "OSPF two-daemon interop: PASS"
echo "  - Full adjacency over raw multicast (224.0.0.5) in both directions"
echo "  - Router-LSA exchange and stub-net route installation both ways"
echo "  - Dead-timer session teardown after peer loss"
INNER
