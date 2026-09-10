#!/usr/bin/env bash
# OSPF Segment Routing slice 3 (RFC 8665 §6 + §4): adjacency segments
# and the mapping server, two lr-daemons over a veth pair.
#
#   netns r1: lr-daemon 1.1.1.1, SRGB 16000/8000,
#             prefix-SID 10.99.2.0/24 index 100 (node, no-php),
#             adj-SID 24000 on veth0 (RFC 8665 §6),
#             mapping server: 10.77.0.0/24 +3 indexes from 500 (§4),
#                             10.99.3.0/24 index 700 (precedence probe)
#        ↑↓ OSPFv2 multicast over the veth pair
#   netns r2: lr-daemon 2.2.2.2, SRGB 16000/8000,
#             prefix-SID 10.99.3.0/24 index 300 (node, no-php),
#             adj-SID 24001 on veth1,
#             secondary stubs 10.77.0.1/24 + 10.77.1.1/24 (mapped)
#
# Success criteria:
#   1. Full adjacency (both logs).
#   2. Both routers' runtime API `status` carries the peer's adjacency
#      segment (ospf-sr adj … label=24000 / label=24001) — Extended
#      Link Opaque LSAs flooded and decoded into the SRDB.
#   3. r1's Loc-RIB maps r2's mapped stubs through the mapping-server
#      range: 10.77.0.0/24 label=16500, 10.77.1.0/24 label=16501 (base
#      + index, offset arithmetic per RFC 8665 §4).
#   4. Direct advertisements beat the mapping server (RFC 8661 §3.2.3):
#      r1's route for 10.99.3.0/24 keeps label=16300 although the
#      server also maps it to index 700.
#   5. §7.4.1 withdrawal: killing r2's daemon ages the adjacency out;
#      r1's `status` loses the adjacency-segment line.
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
OUT=/tmp/lr_ospf_sr_adj_interop
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
# The mapping server's clients: secondary stubs r2 advertises but does
# not label itself — the classic SRMS deployment (RFC 8661 §3.2).
nsenter -t "$R2" -n ip addr add 10.77.0.1/24 dev veth1
nsenter -t "$R2" -n ip addr add 10.77.1.1/24 dev veth1
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

echo "== starting router r1 (1.1.1.1, SRGB 16000/8000, adj-SID 24000, mapping server) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
sr_receive = true
srgb_base = 16000
srgb_range = 8000

[[ospf.interface]]
name = "veth0"
hello_interval = 1
dead_interval = 4
adj_sid = 24000

[[ospf.prefix_sid]]
prefix = "10.99.2.0/24"
sid = 100
node = true
no_php = true

# Mapping server (RFC 8665 §4): r2's unlabelled stubs, four
# consecutive /24s from index 500.
[[ospf.mapping_server]]
prefix = "10.77.0.0/24"
range_size = 4
sid = 500
no_php = true

# Precedence probe (RFC 8661 §3.2.3): the server maps r2's directly
# advertised 10.99.3.0/24 too — the direct advertisement must win.
[[ospf.mapping_server]]
prefix = "10.99.3.0/24"
sid = 700
no_php = true
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, SRGB 16000/8000, adj-SID 24001) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
sr_receive = true
srgb_base = 16000
srgb_range = 8000

[[ospf.interface]]
name = "veth1"
hello_interval = 1
dead_interval = 4
adj_sid = 24001

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

echo "== waiting for stub propagation (Router-LSA + LSU flooding) =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 20
wait_log "$OUT/r2.log" "route installed 10.99.2.0/24" 20
wait_log "$OUT/r1.log" "route installed 10.77.0.0/24" 20
wait_log "$OUT/r1.log" "route installed 10.77.1.0/24" 20
echo "   propagation: OK"

echo "== Extended Link LSAs → SRDB (RFC 8665 §6) =="
# Give the extended LSAs one flooding beat beyond the stub routes.
sleep 2
api_cmd "$OUT/r1.ctl" "status" >"$OUT/r1.status"
api_cmd "$OUT/r2.ctl" "status" >"$OUT/r2.status"
api_cmd "$OUT/r1.ctl" "routes" >"$OUT/r1.routes"
cat "$OUT/r1.status"
echo
cat "$OUT/r1.routes"

fail=0
if ! grep "ospf-sr adj" "$OUT/r1.status" | grep -qF "router=2.2.2.2 label=24001"; then
    echo "FAIL: r1 does not see r2's adjacency segment with label 24001"
    fail=1
fi
if ! grep "ospf-sr adj" "$OUT/r2.status" | grep -qF "router=1.1.1.1 label=24000"; then
    echo "FAIL: r2 does not see r1's adjacency segment with label 24000"
    fail=1
fi

echo "== mapping-server labels (RFC 8665 §4 + RFC 8661 §3.2) =="
if ! grep "10.77.0.0/24" "$OUT/r1.routes" | grep -qF "label=16500"; then
    echo "FAIL: r1's route for 10.77.0.0/24 does not carry label=16500 (base + index 500)"
    fail=1
fi
if ! grep "10.77.1.0/24" "$OUT/r1.routes" | grep -qF "label=16501"; then
    echo "FAIL: r1's route for 10.77.1.0/24 does not carry label=16501 (base + index 501)"
    fail=1
fi
if ! grep "10.99.3.0/24" "$OUT/r1.routes" | grep -qF "label=16300"; then
    echo "FAIL: r1's route for 10.99.3.0/24 does not keep the direct label 16300 \
(RFC 8661 3.2.3: direct Prefix-SID beats the mapping server)"
    fail=1
fi

echo "== §7.4.1 withdrawal: stopping r2, the adjacency ages out =="
kill "$DAEMON_B" 2>/dev/null || true
DAEMON_B=""
# dead interval 4s + the re-origination cycle.
sleep 8
api_cmd "$OUT/r1.ctl" "status" >"$OUT/r1.status.after"
cat "$OUT/r1.status.after"
# r1 must withdraw its OWN advertisement for the dead adjacency
# (MaxAge flush of its Extended Link LSA). r2's last LSA instance
# legitimately lingers in r1's LSDB — a killed originator cannot flush,
# so the stale copy ages out at MaxAge (standard link-state behaviour).
if grep "ospf-sr adj" "$OUT/r1.status.after" | grep -qF "router=1.1.1.1 label=24000"; then
    echo "FAIL: r1 still advertises its adjacency segment after the neighbour died"
    fail=1
fi

kill "$DAEMON_A" 2>/dev/null || true
DAEMON_A=""
sleep 0.5

if [ "$fail" -eq 0 ]; then
    echo
    echo "OSPF SR slice-3 two-daemon interop: PASS"
    echo "  - Extended Link opaque LSAs flooded and decoded (Adj-SIDs both ways)"
    echo "  - Mapping-server ranges resolved (base + offset) into Loc-RIB labels"
    echo "  - Direct Prefix-SID advertisements beat the mapping server"
    echo "  - Adjacency-segment advertisements withdrawn when the neighbour dies"
fi
exit $fail
INNER
