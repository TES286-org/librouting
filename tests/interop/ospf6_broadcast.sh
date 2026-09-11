#!/usr/bin/env bash
# OSPFv3 broadcast segments (RFC 5340 §4.1.2): two lr-daemons over a
# veth pair, both running `network_type = "broadcast"` — the DR/BDR
# election slice acceptance gate. The election runs the RFC 2328 §9.4
# algorithm on Router-ID identity (FRR ospf6d `dr_election` parity);
# the DR originates the Network-LSA (§4.4.3.3) and the
# network-referenced Intra-Area-Prefix-LSA (§4.4.3.5); transit links
# (§A.4.3 type 2) replace the p2p descriptions.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64, lo 2001:db8:1::1/64
#        ↑↓ OSPFv3 multicast (ff02::5) over the veth pair, broadcast type
#   netns r2: lr-daemon 2.2.2.2 — veth1 fd00:10::2/64, lo 2001:db8:2::1/64
#
# Success criteria:
#   1. The WaitTimer/BackupSeen election converges: r2 (higher Router
#      ID) is DR, r1 is BDR — both logs agree.
#   2. Full adjacency on both sides (the §10.4 gate only lets the
#      elected pair and its neighbors reach Full).
#   3. r1's Loc-RIB carries 2001:db8:2::/64 proto=Ospfv3 via r2's
#      link-local — routes resolve through the Network-LSA network
#      vertex (transit links + back-link check), not a p2p link.
#   4. r1 (the non-DR) carries fd00:10::/64 as an Ospfv3 connected
#      route — only possible via r2's network-referenced
#      Intra-Area-Prefix-LSA, because both sides skip the
#      transit-reported veth prefix from their router-referenced IAP.
#   5. Killing r2 retracts r2's loopback on r1 (the re-election makes
#      r1 the DR; its Router-LSA drops the transit link so the network
#      vertex and everything behind it disappear).
#
# Rootless: runs inside `unshare -Urn` (CAP_NET_RAW for the v6 raw
# sockets); skips gracefully without user namespaces or iproute2.
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
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf6_broadcast
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router broadcast lab (veth pair, one netns per router) =="
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

echo "== starting router r1 (1.1.1.1, v3, broadcast) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"

[[ospf.interface]]
name = "veth0"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" --api-socket "$OUT/r1.ctl" \
    >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, v3, broadcast) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
version = "v3"

[[ospf.interface]]
name = "veth1"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$R2" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 2.2.2.2 \
    --config "$OUT/r2.toml" --api-socket "$OUT/r2.ctl" \
    >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

echo "== waiting for the election to converge (§9.4 on Router-ID identity) =="
wait_log "$OUT/r1.log" "elected DR 2.2.2.2 / BDR 1.1.1.1 — we are Backup" 25
wait_log "$OUT/r2.log" "elected DR 2.2.2.2 / BDR 1.1.1.1 — we are DR" 25
echo "PASS: r2 (higher Router ID) is DR, r1 is BDR — both routers agree"

echo "== waiting for the v3 adjacency (the elected pair, §10.4) =="
wait_log "$OUT/r1.log" "Full" 25
wait_log "$OUT/r2.log" "Full" 25
echo "PASS: OSPFv3 adjacency Full on both routers"

echo "== waiting for route convergence over the transit network =="
wait_log "$OUT/r1.log" "route installed 2001:db8:2::/64" 25
wait_log "$OUT/r2.log" "route installed 2001:db8:1::/64" 25
echo "PASS: v3 SPF published the remote loopback prefixes through the Network-LSA vertex"

ROUTES1=$(api_cmd "$OUT/r1.ctl" routes)
echo "$ROUTES1" | grep -F "2001:db8:2::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r1 routes --"; echo "$ROUTES1"; exit 1;
}
NH1=$(echo "$ROUTES1" | grep -F "2001:db8:2::/64" | grep -o "via fe80::[0-9a-f:]*" | head -1)
[ -n "$NH1" ] || { echo "-- r1 routes --"; echo "$ROUTES1"; exit 1; }
echo "PASS: r1 learned 2001:db8:2::/64 proto=Ospfv3 $NH1"

ROUTES2=$(api_cmd "$OUT/r2.ctl" routes)
echo "$ROUTES2" | grep -F "2001:db8:1::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r2 routes --"; echo "$ROUTES2"; exit 1;
}
echo "PASS: r2 learned 2001:db8:1::/64 proto=Ospfv3 symmetrically"

echo "== the network-referenced Intra-Area-Prefix-LSA (§4.4.3.5) =="
echo "$ROUTES1" | grep -F "fd00:10::/64" | grep -qF "proto=Ospfv3" || {
    echo "FAIL: r1 (non-DR) lacks fd00:10::/64 — the DR's network-referenced"
    echo "      IAP never arrived (or its prefixes were skipped from it)"
    echo "-- r1 routes --"; echo "$ROUTES1"; exit 1;
}
echo "PASS: r1 carries fd00:10::/64 via r2's network-referenced IAP (the DR advertises the segment)"

echo "== dead-timer withdrawal: killing r2 must retract its prefixes on r1 =="
kill "$DAEMON_B" 2>/dev/null || true
DAEMON_B=""
wait_log "$OUT/r1.log" "route withdrawn 2001:db8:2::/64" 25
echo "PASS: r1 withdrew 2001:db8:2::/64 after the DR died"

echo "ALL PASS"
INNER
