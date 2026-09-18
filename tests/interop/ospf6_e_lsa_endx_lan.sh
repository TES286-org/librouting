#!/usr/bin/env bash
# OSPFv3 SRv6 LAN End.X SID origination + reception (RFC 9513 §9.2,
# riding the RFC 8362 E-Router-LSA): three lr-daemons on one bridge
# broadcast segment, all running `extended_lsas`. The §9.4 election
# lands r3 (3.3.3.3) as DR, r2 (2.2.2.2) as BDR and r1 (1.1.1.1) as
# DR-Other — the role that exercises both §9 forms at once:
#
#   netns r1: lr-daemon 1.1.1.1 (DR-Other, the SRv6 originator)
#   netns r2: lr-daemon 2.2.2.2 (BDR, plain)
#   netns r3: lr-daemon 3.3.3.3 (DR, plain)
#        ↕ OSPFv3 multicast (ff02::5) over the shared bridge segment
#
# r1's Full set on the segment is {r3 (DR), r2 (BDR)} — RFC 2328 §A.4
# keeps DR-Others at 2-Way with each other. r1's transit Router-Link
# TLV therefore carries:
#   - the plain End.X sub-TLV (§9.1) for the DR adjacency:
#     srv6_end_x = 2001:db8:a:1::100
#   - one LAN End.X sub-TLV (§9.2) per Full BDR/DR-Other neighbor,
#     derived from srv6_end_x_lan = 2001:db8:a:1:ffff::/96 as
#     base | Router-ID: 2001:db8:a:1:ffff:0:202:202 for r2.
#
# Success criteria:
#   1. The election converges and every adjacency reaches Full (r1
#      with both peers; the E-Router-LSA with sub-TLVs breaks nothing).
#   2. Routes converge over the E-LSA topology: r1 installs both
#      peers' loopbacks, r2 installs r1's.
#   3. r3 (the DR) projects the §9.1 End.X SID:
#      `srv6-endx 2001:db8:a:1::100 ... neighbor=03030303` — no
#      `lan` marker (the plain form).
#   4. r2 (the BDR) projects the §9.2 LAN End.X SID:
#      `srv6-endx 2001:db8:a:1:ffff:0:202:202 ... neighbor=02020202
#      lan` — the derived per-neighbor SID with the LAN marker.
#   5. r1 self-projects both SIDs.
#
# Rootless: runs inside `unshare -Urn`; skips gracefully without user
# namespaces or iproute2 (same guards as ospf6.sh).
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
OUT=/tmp/lr_ospf6_endx_lan_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the three-router broadcast lab (bridge segment, r1 DR-Other with End.X) =="
ip link set lo up
ip link add br0 type bridge
ip link set br0 up
for r in 1 2 3; do
    ip link add veth$r type veth peer name veth-r$r
    ip link set veth$r master br0
    ip link set veth$r up
    unshare -n sleep 300 &
    eval "NR$r=$!"
done
cleanup() {
    kill "${DAEMON_R1:-}" "${DAEMON_R2:-}" "${DAEMON_R3:-}" 2>/dev/null || true
    kill "$NR1" "$NR2" "$NR3" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
for r in 1 2 3; do
    ip link set veth-r$r netns "$(eval "echo \$NR$r")"
done
nsenter -t "$NR1" -n ip link set lo up
nsenter -t "$NR2" -n ip link set lo up
nsenter -t "$NR3" -n ip link set lo up
nsenter -t "$NR1" -n ip addr add fd00:20::1/64 dev veth-r1
nsenter -t "$NR1" -n ip addr add fe80::11/64 dev lo
nsenter -t "$NR1" -n ip addr add 2001:db8:1::1/64 dev lo
nsenter -t "$NR1" -n ip link set veth-r1 up
nsenter -t "$NR2" -n ip addr add fd00:20::2/64 dev veth-r2
nsenter -t "$NR2" -n ip addr add fe80::22/64 dev lo
nsenter -t "$NR2" -n ip addr add 2001:db8:2::1/64 dev lo
nsenter -t "$NR2" -n ip link set veth-r2 up
nsenter -t "$NR3" -n ip addr add fd00:20::3/64 dev veth-r3
nsenter -t "$NR3" -n ip addr add fe80::33/64 dev lo
nsenter -t "$NR3" -n ip addr add 2001:db8:3::1/64 dev lo
nsenter -t "$NR3" -n ip link set veth-r3 up

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

echo "== starting r2 (2.2.2.2, BDR, plain extended mode) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
version = "v3"
extended_lsas = true

[[ospf.interface]]
name = "veth-r2"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$NR2" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 2.2.2.2 \
    --config "$OUT/r2.toml" --api-socket "$OUT/r2.ctl" \
    >"$OUT/r2.log" 2>&1 &
DAEMON_R2=$!

echo "== starting r3 (3.3.3.3, DR, plain extended mode) =="
cat >"$OUT/r3.toml" <<'EOF'
[ospf]
version = "v3"
extended_lsas = true

[[ospf.interface]]
name = "veth-r3"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4
EOF
nsenter -t "$NR3" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 3.3.3.3 \
    --config "$OUT/r3.toml" --api-socket "$OUT/r3.ctl" \
    >"$OUT/r3.log" 2>&1 &
DAEMON_R3=$!

# r1 joins LAST: the segment's §9.4 election settles r3 (DR) / r2
# (BDR) between the plain routers before the SRv6 originator appears,
# so r1's first election already sees the full elector set — no
# interim DR windows whose transitional E-Router-LSA shapes would
# race the assertions (the steady-state shapes are what the lab
# pins).
sleep 3

echo "== starting r1 (1.1.1.1, DR-Other: locator + End.X + LAN End.X, extended mode) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"
extended_lsas = true

[[ospf.interface]]
name = "veth-r1"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4
srv6_end_x = "2001:db8:a:1::100"
srv6_end_x_lan = "2001:db8:a:1:ffff::/96"

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4

[[ospf.srv6_locator]]
prefix = "2001:db8:a:1::/48"
EOF
nsenter -t "$NR1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" --api-socket "$OUT/r1.ctl" \
    >"$OUT/r1.log" 2>&1 &
DAEMON_R1=$!

echo "== waiting for the election + Full adjacencies (r1: both peers) =="
wait_log "$OUT/r1.log" "neighbor 2.2.2.2 Full" 30
wait_log "$OUT/r1.log" "neighbor 3.3.3.3 Full" 30
wait_log "$OUT/r2.log" "neighbor 1.1.1.1 Full" 30
wait_log "$OUT/r3.log" "neighbor 1.1.1.1 Full" 30
echo "PASS: Full adjacencies on the broadcast segment (r1 DR-Other with r2 BDR + r3 DR)"

echo "== waiting for route convergence over the E-LSA topology =="
wait_log "$OUT/r1.log" "route installed 2001:db8:2::/64" 30
wait_log "$OUT/r1.log" "route installed 2001:db8:3::/64" 30
wait_log "$OUT/r2.log" "route installed 2001:db8:1::/64" 30
echo "PASS: the E-LSA topology carries the routes through the network vertex"

echo "== runtime API: r3 (the DR) projects the plain §9.1 End.X (no lan marker) =="
STATUS3=""
for ((i = 0; i < 250; i++)); do
    STATUS3=$(api_cmd "$OUT/r3.ctl" status)
    echo "$STATUS3" | grep -qF "srv6-endx 2001:db8:a:1::100" && break
    sleep 0.1
done
echo "$STATUS3" | grep -qF "srv6-endx 2001:db8:a:1::100" || {
    echo "-- r3 status --"; echo "$STATUS3"; exit 1;
}
echo "$STATUS3" | grep -F "srv6-endx 2001:db8:a:1::100" | grep -qF "behavior=5" || {
    echo "-- r3 status --"; echo "$STATUS3"; exit 1;
}
echo "$STATUS3" | grep -F "srv6-endx 2001:db8:a:1::100" | grep -qF "neighbor=03030303" || {
    echo "-- r3 status --"; echo "$STATUS3"; exit 1;
}
echo "$STATUS3" | grep -F "srv6-endx 2001:db8:a:1::100" | grep -qF " lan" && {
    echo "-- r3 status --"; echo "$STATUS3"; exit 1;
}
echo "PASS: r3 projects the §9.1 End.X SID for its DR adjacency (neighbor=r3, no lan)"

echo "== runtime API: r2 (the BDR) projects the §9.2 LAN End.X (derived per-neighbor SID) =="
STATUS2=""
for ((i = 0; i < 250; i++)); do
    STATUS2=$(api_cmd "$OUT/r2.ctl" status)
    echo "$STATUS2" | grep -qF "srv6-endx 2001:db8:a:1:ffff:0:202:202" && break
    sleep 0.1
done
echo "$STATUS2" | grep -qF "srv6-endx 2001:db8:a:1:ffff:0:202:202" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "$STATUS2" | grep -F "srv6-endx 2001:db8:a:1:ffff:0:202:202" | grep -qF "neighbor=02020202" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "$STATUS2" | grep -F "srv6-endx 2001:db8:a:1:ffff:0:202:202" | grep -qF " lan" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "PASS: r2 projects the §9.2 LAN End.X SID (base | Router-ID, lan marker)"

echo "== runtime API: r1 self-projects both SIDs =="
STATUS1=""
for ((i = 0; i < 250; i++)); do
    STATUS1=$(api_cmd "$OUT/r1.ctl" status)
    echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1::100" \
        && echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1:ffff:0:202:202" && break
    sleep 0.1
done
echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1::100" || {
    echo "-- r1 status --"; echo "$STATUS1"; exit 1;
}
echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1:ffff:0:202:202" || {
    echo "-- r1 status --"; echo "$STATUS1"; exit 1;
}
echo "PASS: r1 self-projects both the §9.1 and §9.2 SIDs"

echo "ALL OSPFv3 LAN END.X (RFC 9513 §9.2 / RFC 8362) INTEROP CHECKS PASSED"
INNER
