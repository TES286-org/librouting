#!/usr/bin/env bash
# OSPF Segment Routing reception (RFC 8665 slice 2): two lr-daemons
# over a veth pair, both sides Segment Routing. This is the receiver
# half of the ospf_sr_frr.sh lab — srdb + SPF label attach — verified
# end-to-end through real raw sockets without needing kernel MPLS (the
# Loc-RIB labels are asserted via the runtime API; the kernel encap
# route is the ospf_sr_frr.sh phase-2 gate).
#
#   netns r1: lr-daemon 1.1.1.1, SRGB 16000/8000,
#             prefix-SID 10.99.2.0/24 index 100 (node, no-php)
#        ↑↓ OSPFv2 multicast over the veth pair
#   netns r2: lr-daemon 2.2.2.2, SRGB 16000/8000,
#             prefix-SID 10.99.3.0/24 index 300 (node, no-php)
#
# Success criteria:
#   1. Full adjacency (both logs).
#   2. r2's Loc-RIB carries 10.99.2.0/24 with label=16100 (base + SID)
#      via 10.99.1.1 — NP set, so the adjacent originator still pushes.
#   3. r1's Loc-RIB carries 10.99.3.0/24 with label=16300 symmetrically.
#
# Rootless: runs inside `unshare -Urn` (CAP_NET_RAW); skips gracefully
# without user namespaces or iproute2.
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
OUT=/tmp/lr_ospf_sr_interop
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
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip addr add 10.99.2.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip addr add 10.99.3.1/24 dev veth1
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

echo "== starting router r1 (1.1.1.1, SRGB 16000/8000, SID 10.99.2.0/24 = 100 no-php) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
sr_receive = true
srgb_base = 16000
srgb_range = 8000

[[ospf.interface]]
name = "veth0"
hello_interval = 1
dead_interval = 4

[[ospf.prefix_sid]]
prefix = "10.99.2.0/24"
sid = 100
node = true
no_php = true
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, SRGB 16000/8000, SID 10.99.3.0/24 = 300 no-php) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
sr_receive = true
srgb_base = 16000
srgb_range = 8000

[[ospf.interface]]
name = "veth1"
hello_interval = 1
dead_interval = 4

[[ospf.prefix_sid]]
prefix = "10.99.3.0/24"
sid = 300
node = true
no_php = true
EOF
nsenter -t "$R2" -n "$BIN" --protocol ospf --router-id 2.2.2.2 \
    --config "$OUT/r2.toml" \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

echo "== waiting for Full adjacency on both routers =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 30
wait_log "$OUT/r2.log" "ospf neighbor 1.1.1.1 Full (area" 30
echo "   adjacency: OK"

echo "== waiting for stub-net propagation (Router-LSA + LSU flooding) =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 20
wait_log "$OUT/r2.log" "route installed 10.99.2.0/24" 20
echo "   propagation: OK"

echo "== SRDB → Loc-RIB labels (RFC 8665 §5 + §5 NP rule) =="
# Give the SR LSAs one flooding beat beyond the stub routes.
sleep 2
api_cmd "$OUT/r2.ctl" "routes" >"$OUT/r2.routes"
api_cmd "$OUT/r1.ctl" "routes" >"$OUT/r1.routes"
cat "$OUT/r2.routes"

fail=0
if ! grep "10.99.2.0/24" "$OUT/r2.routes" | grep -qF "label=16100"; then
    echo "FAIL: r2's route for 10.99.2.0/24 does not carry label=16100 (base 16000 + SID 100)"
    fail=1
fi
if ! grep "10.99.2.0/24" "$OUT/r2.routes" | grep -qF "via 10.99.1.1"; then
    echo "FAIL: r2's labelled route for 10.99.2.0/24 does not point at 10.99.1.1 (the originator's address)"
    fail=1
fi
if ! grep "10.99.3.0/24" "$OUT/r1.routes" | grep -qF "label=16300"; then
    echo "FAIL: r1's route for 10.99.3.0/24 does not carry label=16300 (base 16000 + SID 300)"
    fail=1
fi

kill "$DAEMON_A" "$DAEMON_B" 2>/dev/null || true
DAEMON_A=""
DAEMON_B=""
sleep 0.5

if [ "$fail" -eq 0 ]; then
    echo
    echo "OSPF SR two-daemon interop: PASS"
    echo "  - Full adjacency over raw multicast (224.0.0.5) both ways"
    echo "  - RI + Extended Prefix opaque LSAs flooded and decoded (SRDB)"
    echo "  - Prefix-SID labels resolved into Loc-RIB (base + index) with"
    echo "    the originator's address as the next hop (NP honoured)"
fi
exit $fail
INNER
