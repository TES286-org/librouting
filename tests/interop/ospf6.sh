#!/usr/bin/env bash
# OSPFv3 daemon mode (RFC 5340): two lr-daemons over a veth pair,
# running `[ospf] version = "v3"`. This is the slice-1 acceptance gate
# for the v3 daemon: real IPv6 raw sockets, link-local Hellos, the v3
# LSDB exchange (Router-LSA + Link-LSA + Intra-Area-Prefix-LSA) and the
# v3 SPF publishing IPv6 routes.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64, lo 2001:db8:1::1/64
#        ↑↓ OSPFv3 multicast (ff02::5) over the veth pair, link-local src
#   netns r2: lr-daemon 2.2.2.2 — veth1 fd00:10::2/64, lo 2001:db8:2::1/64
#
# Success criteria:
#   1. Full adjacency on both sides (daemon logs).
#   2. r1's Loc-RIB carries 2001:db8:2::/64 proto=Ospfv3 via r2's
#      link-local on veth0; r2 learns 2001:db8:1::/64 symmetrically.
#   3. With --install-kernel the kernel FIB carries the remote loopback
#      prefix via the link-local gateway on veth0 (RTA_OIF resolved from
#      the daemon's neighbor bookkeeping).
#
# Rootless: runs inside `unshare -Urn` (CAP_NET_RAW for the v6 raw
# sockets, CAP_NET_ADMIN inside the netns for the kernel install);
# skips gracefully without user namespaces or iproute2.
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
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 (ip) not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter (util-linux) not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed (API queries)"; exit 0; }
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

REPO=$(pwd)
# Kernel FIB install is now the default — the user's requirement is
# to verify routes are installed AND the OS uses them. The old
# `--kernel` flag is accepted for backward compatibility but is a no-op.
export KERNEL=1
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf6_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
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
nsenter -t "$R1" -n ip addr add fd00:10::1/64 dev veth0
nsenter -t "$R1" -n ip addr add fe80::11/64 dev lo
nsenter -t "$R1" -n ip addr add 2001:db8:1::1/64 dev lo
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add fd00:10::2/64 dev veth1
nsenter -t "$R2" -n ip addr add fe80::22/64 dev lo
nsenter -t "$R2" -n ip addr add 2001:db8:2::1/64 dev lo
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

api_cmd() { # <socket> <command>
    python3 - "$1" "$2" <<'PYEOF'
import socket, sys
path, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(path)
s.sendall((cmd + "\n").encode())
out = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
except socket.timeout:
    pass
sys.stdout.write(out.decode(errors="replace"))
PYEOF
}

KERNELFLAG=""
if [ "$KERNEL" = "1" ]; then
    KERNELFLAG="--install-kernel-routes"
fi

echo "== starting router r1 (1.1.1.1, v3) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"

[[ospf.interface]]
name = "veth0"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" --api-socket "$OUT/r1.ctl" $KERNELFLAG \
    >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, v3) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
version = "v3"

[[ospf.interface]]
name = "veth1"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$R2" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 2.2.2.2 \
    --config "$OUT/r2.toml" --api-socket "$OUT/r2.ctl" $KERNELFLAG \
    >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

echo "== waiting for the v3 adjacency =="
wait_log "$OUT/r1.log" "Full" 25
wait_log "$OUT/r2.log" "Full" 25
echo "PASS: OSPFv3 adjacency Full on both routers"

echo "== waiting for route convergence =="
wait_log "$OUT/r1.log" "route installed 2001:db8:2::/64" 25
wait_log "$OUT/r2.log" "route installed 2001:db8:1::/64" 25
echo "PASS: v3 SPF published the remote loopback prefixes"

echo "== runtime API: r1's Loc-RIB carries r2's loopback via a link-local =="
ROUTES1=$(api_cmd "$OUT/r1.ctl" routes)
echo "$ROUTES1" | grep -qF "2001:db8:2::/64" || {
    echo "-- r1 routes --"; echo "$ROUTES1"; exit 1;
}
NH1=$(echo "$ROUTES1" | grep -F "2001:db8:2::/64" | grep -o "via fe80::[0-9a-f:]*" | head -1)
[ -n "$NH1" ] || { echo "-- r1 routes --"; echo "$ROUTES1"; exit 1; }
echo "$ROUTES1" | grep -F "2001:db8:2::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r1 routes --"; echo "$ROUTES1"; exit 1;
}
echo "PASS: r1 learned 2001:db8:2::/64 proto=Ospfv3 $NH1"

ROUTES2=$(api_cmd "$OUT/r2.ctl" routes)
echo "$ROUTES2" | grep -F "2001:db8:1::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r2 routes --"; echo "$ROUTES2"; exit 1;
}
echo "PASS: r2 learned 2001:db8:1::/64 proto=Ospfv3 symmetrically"

if [ "$KERNEL" = "1" ]; then
    echo "== kernel mirror: r1's FIB carries the remote prefix via veth0 =="
    KERNEL_ROUTE=""
    for ((i = 0; i < 150; i++)); do
        KERNEL_ROUTE=$(nsenter -t "$R1" -n ip -6 route show 2>/dev/null | grep -F "2001:db8:2::/64" || true)
        [ -n "$KERNEL_ROUTE" ] && break
        sleep 0.1
    done
    echo "$KERNEL_ROUTE" | grep -qF "dev veth0" || {
        echo "-- r1 ip -6 route --"
        nsenter -t "$R1" -n ip -6 route show
        exit 1
    }
    echo "PASS: kernel FIB on r1: $KERNEL_ROUTE"

    echo "== kernel forwarding decision: ip -6 route get =="
    # ip -6 route get queries the kernel's IPv6 FIB lookup — the
    # actual routing decision the kernel would make for a packet to
    # that destination.
    R1_GET=$(nsenter -t "$R1" -n ip -6 route get 2001:db8:2::5 2>/dev/null || true)
    [ -n "$R1_GET" ] || { echo "FAIL: ip -6 route get on r1 returned nothing"; exit 1; }
    echo "$R1_GET" | grep -q "dev veth0" || {
        echo "FAIL: ip -6 route get on r1 did not use veth0"
        echo "$R1_GET"
        exit 1
    }
    echo "   r1 route get: $R1_GET"
    echo "PASS: kernel forwarding decision uses the OSPFv3-installed route"
else
    echo "== kernel mirror phase skipped (run with --kernel to enable) =="
fi

echo "== dead-timer withdrawal: killing r2 must retract its prefixes on r1 =="
kill "$DAEMON_B" 2>/dev/null || true
wait_log "$OUT/r1.log" "route withdrawn 2001:db8:2::/64" 25
echo "PASS: r1 withdrew 2001:db8:2::/64 after the neighbor died"
if [ "$KERNEL" = "1" ]; then
    for ((i = 0; i < 100; i++)); do
        nsenter -t "$R1" -n ip -6 route show 2>/dev/null | grep -qF "2001:db8:2::/64" || break
        sleep 0.1
    done
    nsenter -t "$R1" -n ip -6 route show 2>/dev/null | grep -qF "2001:db8:2::/64" && {
        echo "FAIL: kernel route survived the withdrawal"
        nsenter -t "$R1" -n ip -6 route show
        exit 1
    }
    echo "PASS: kernel route withdrawn with the neighbor"
fi

echo "ALL PASS"
INNER
