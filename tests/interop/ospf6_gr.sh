#!/usr/bin/env bash
# OSPFv3 Graceful Restart interop test (RFC 5187): two lr-daemons over
# a veth pair; one gracefully restarts, the other helps.
#
# Topology — same lab shape as ospf6.sh (one netns per router, raw
# IPv6 sockets, rootless via `unshare -Urn`):
#
#   netns r1: lr-daemon 1.1.1.1, --ospf-graceful-restart (grace 15 s)
#             veth0: fd00:10::1/64 + fd00:20::1/64 (stub net A)
#        ↑↓ OSPFv3 (ff02::5, link-local sources, p2p network)
#   netns r2: lr-daemon 2.2.2.2 (helper, default on)
#             veth1: fd00:10::2/64 + fd00:30::1/64 (stub net B)
#
# Phase 1 — planned restart, retention + recovery (RFC 5187 2/3):
#   1. Full adjacency + stub-net routes both ways.
#   2. SIGTERM r1 → Grace-LSA flood (LS type 0x000b, LS ID = the
#      Interface ID) → r2 enters helper mode.
#   3. r1 stays silent past r2's dead interval → r2 KEEPS the route
#      to fd00:20::/64 (the adjacency is retained).
#   4. r1 restarts → recovery (2.2): re-syncs, adjacency Full again,
#      exits recovery (2.2 (1)), flushes the Grace-LSA (2.3 (6)) →
#      r2 exits helper mode on the flush (3.2 (1)).
#   5. Routes still present on both sides; the network never lost
#      r2's path to fd00:20::/64.
#
# Phase 2 — grace-period timeout (RFC 5187 3.2 (2)):
#   6. SIGTERM r1 again → r2 helps.
#   7. r1 never comes back → the grace period expires → r2 exits
#      helper mode, tears the adjacency, withdraws the route.
#
# Environments without unprivileged user namespaces / iproute2 /
# python3 SKIP gracefully (python3 queries the runtime API socket).
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

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf6_gr_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 300 &
R1=$!
unshare -n sleep 300 &
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
nsenter -t "$R1" -n ip addr add fd00:10::1/64 dev veth0
nsenter -t "$R1" -n ip addr add fd00:20::1/64 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add fd00:10::2/64 dev veth1
nsenter -t "$R2" -n ip addr add fd00:30::1/64 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-15} i
    for ((i = 0; i < tmo * 10; i++)); do
        [ -f "$file" ] && grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file (tail) --"
    tail -40 "$file" 2>/dev/null
    return 1
}

# Query one command over the daemon's runtime API socket (same shape
# as ospf_gr.sh: read until a short quiet window after the first data
# so the route_count polls stay fast enough for grace-window checks).
api_cmd() {
    python3 - "$1" "$2" <<'PYEOF'
import socket, sys, time
path, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(0.3)
s.connect(path)
s.sendall((cmd + "\n").encode())
out = b""
got_any = False
deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    try:
        chunk = s.recv(4096)
    except socket.timeout:
        if got_any:
            break
        continue
    if not chunk:
        break
    out += chunk
    got_any = True
sys.stdout.write(out.decode(errors="replace"))
PYEOF
}

route_count() { # <api-socket> <prefix>
    api_cmd "$1" routes | grep -cF "$2" || true
}

echo "== phase 1: planned graceful restart (RFC 5187 2/3) =="
echo "-- starting r1 (1.1.1.1, v3, graceful restart, grace 15 s) --"
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 15 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!
echo "-- starting r2 (2.2.2.2, v3, helper default on) --"
nsenter -t "$R2" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 2.2.2.2 \
    --ospf-interface veth1 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!
disown "$DAEMON_B"

wait_log "$OUT/r1.log" "ospf3 neighbor 2.2.2.2 Full (area" 25
wait_log "$OUT/r2.log" "ospf3 neighbor 1.1.1.1 Full (area" 25
echo "   adjacency: OK"
wait_log "$OUT/r1.log" "route installed fd00:30::/64" 25
wait_log "$OUT/r2.log" "route installed fd00:20::/64" 25
echo "   propagation: OK"
[ "$(route_count "$OUT/r2.ctl" "fd00:20::/64")" -ge 1 ] || {
    echo "FAIL: r2 lost the route before the restart"; exit 1;
}

echo "-- SIGTERM r1: the graceful shutdown floods the Grace-LSAs (0x000b) --"
kill -TERM "$DAEMON_A"
wait_log "$OUT/r1.log" "graceful shutdown complete" 10
wait_log "$OUT/r2.log" "helper mode entered" 10
echo "   helper mode: OK (r2 retains 1.1.1.1's adjacency and LSAs)"

echo "-- r1 silent past r2's dead interval (4 s): the route must survive --"
sleep 7
[ "$(route_count "$OUT/r2.ctl" "fd00:20::/64")" -ge 1 ] || {
    echo "FAIL: r2 dropped fd00:20::/64 during the grace window (helper retention broken)"
    cat "$OUT/r2.log"
    exit 1
}
if grep -qF "ospf3 neighbor 1.1.1.1 dead" "$OUT/r2.log"; then
    echo "FAIL: r2 tore the helper adjacency down during the grace period"
    exit 1
fi
echo "   retention: OK (fd00:20::/64 still installed while 1.1.1.1 restarts)"

echo "-- restarting r1: recovery, re-sync, exit (RFC 5187 2.2 (1)) --"
# Same configuration as before the restart — including the API socket
# path, so the grace state file (<api-socket>.gr) written at shutdown
# is found and recovery is resumed (exactly how an operator restarts
# the daemon with its config).
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 15 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1b.log" 2>&1 &
DAEMON_A=$!
disown "$DAEMON_A"
wait_log "$OUT/r1b.log" "graceful restart recovery started" 10
wait_log "$OUT/r1b.log" "ospf3 neighbor 2.2.2.2 Full (area" 25
wait_log "$OUT/r1b.log" "recovery ended" 25
if ! grep -qF "recovery ended — all adjacencies re-established" "$OUT/r1b.log"; then
    echo "FAIL: r1's recovery exited without success:"
    grep -F "recovery ended" "$OUT/r1b.log"
    exit 1
fi
echo "   recovery: OK (adjacency re-established, recovery exited)"
wait_log "$OUT/r2.log" "helper mode exited" 25
if grep -qF "helper mode exited — grace period expired" "$OUT/r2.log"; then
    echo "FAIL: r2's helper exit was a timeout, not the flush — the restart missed the grace window"
    exit 1
fi
echo "   flush: OK (r2 exited helper mode on the flushed Grace-LSA, 3.2 (1))"

echo "-- post-restart state: routes intact on both sides --"
wait_log "$OUT/r1b.log" "route installed fd00:30::/64" 25
[ "$(route_count "$OUT/r2.ctl" "fd00:20::/64")" -ge 1 ] || {
    echo "FAIL: r2 lost fd00:20::/64 across the restart"; exit 1;
}
[ "$(route_count "$OUT/r1.ctl" "fd00:30::/64")" -ge 1 ] || {
    echo "FAIL: r1 missed fd00:30::/64 after recovery"; exit 1;
}
echo "   routes: OK (no route was ever withdrawn through the restart)"

echo "== phase 2: grace-period timeout (RFC 5187 3.2 (2)) =="
kill -TERM "$DAEMON_A" 2>/dev/null || true
DAEMON_A=""
# r1 (grace 15 s) asks for retention again and never returns: after
# the grace period r2 must exit helper mode on the TIMEOUT (the
# phase-1 flush exit must not satisfy this — count the entries).
entries_before=$(grep -cF "helper mode entered" "$OUT/r2.log" || true)
sleep 1
wait_log "$OUT/r2.log" "helper mode entered" 10
entries_after=$(grep -cF "helper mode entered" "$OUT/r2.log" || true)
if [ "$entries_after" -le "$entries_before" ]; then
    echo "FAIL: r2 did not re-enter helper mode for the second shutdown"
    exit 1
fi
echo "   helper re-entry: OK (r2 helping again, r1 will not return)"
wait_log "$OUT/r2.log" "helper mode exited — grace period expired" 30
wait_log "$OUT/r2.log" "ospf3 neighbor 1.1.1.1 dead" 20
echo "   timeout: OK (helper exited, adjacency torn down)"
# The route must be gone from r2's Loc-RIB.
for i in $(seq 1 50); do
    n=$(route_count "$OUT/r2.ctl" "fd00:20::/64")
    [ "$n" -eq 0 ] && break
    sleep 0.2
done
n=$(route_count "$OUT/r2.ctl" "fd00:20::/64")
if [ "$n" -ne 0 ]; then
    echo "FAIL: fd00:20::/64 still installed after the helper exit"
    api_cmd "$OUT/r2.ctl" routes
    exit 1
fi
echo "   withdrawal: OK (fd00:20::/64 retracted after the grace period)"

kill "${DAEMON_A:-}" "${DAEMON_B:-}" 2>/dev/null || true
DAEMON_A=""; DAEMON_B=""
sleep 0.5

echo
echo "OSPFv3 graceful restart interop: PASS"
echo "  - Grace-LSA flood on graceful shutdown (RFC 5187 0x000b), helper mode on the peer"
echo "  - Adjacency + route retention across the restart window"
echo "  - Restarting side: recovery, re-sync, Grace-LSA flush (2.2/2.3)"
echo "  - Grace-period timeout: helper exit + adjacency teardown + withdrawal"
INNER
