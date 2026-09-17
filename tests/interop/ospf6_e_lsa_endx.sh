#!/usr/bin/env bash
# OSPFv3 SRv6 End.X SID origination + reception (RFC 9513 §9.1, riding
# the RFC 8362 E-Router-LSA): two lr-daemons over a veth pair. r1 runs
# the sparse-mode shape — legacy topology LSAs for the routing
# calculation plus an E-Router-LSA companion whose p2p Router-Link TLV
# carries the End.X sub-TLV (type 31); r2 runs plain legacy OSPFv3.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64, lo 2001:db8:1::1/64
#        ↑↓ OSPFv3 multicast (ff02::5) over the veth pair, link-local src
#   netns r2: lr-daemon 2.2.2.2 — veth1 fd00:10::2/64, lo 2001:db8:2::1/64
#
# r1 configuration: locator 2001:db8:a:1::/48 (End SID) and
# srv6_end_x = 2001:db8:a:1::100 on veth0 (inside the locator, §9's
# containment requirement).
#
# Success criteria:
#   1. Full adjacency on both sides — the extra E-Router-LSA (a U-bit
#      unknown to legacy speakers) breaks nothing.
#   2. r2's Loc-RIB still carries 2001:db8:1::/64 proto=Ospfv3 via the
#      LEGACY LSAs (r2 stays byte-compatible with plain OSPFv3).
#   3. r2's runtime status shows the projected End.X SID:
#      `srv6-endx 2001:db8:a:1::100 ... behavior=5 ... neighbor=<r1>`
#      — RFC 9513 §9 reception through the srv6db projection.
#   4. r1's own status shows the same SID (self-projection).
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
OUT=/tmp/lr_ospf6_endx_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, r1 sparse-mode End.X) =="
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

echo "== starting router r1 (1.1.1.1, v3 + locator + End.X, sparse mode) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"

[[ospf.interface]]
name = "veth0"
hello_interval = 1
dead_interval = 4
srv6_end_x = "2001:db8:a:1::100"

[[ospf.interface]]
name = "lo"
hello_interval = 1
dead_interval = 4

[[ospf.srv6_locator]]
prefix = "2001:db8:a:1::/48"
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" --api-socket "$OUT/r1.ctl" \
    >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, plain legacy v3) =="
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
    --config "$OUT/r2.toml" --api-socket "$OUT/r2.ctl" \
    >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

echo "== waiting for the v3 adjacency (the E-Router companion breaks nothing) =="
wait_log "$OUT/r1.log" "Full" 25
wait_log "$OUT/r2.log" "Full" 25
echo "PASS: OSPFv3 adjacency Full on both routers"

echo "== waiting for route convergence over the LEGACY LSAs =="
wait_log "$OUT/r2.log" "route installed 2001:db8:1::/64" 25
wait_log "$OUT/r1.log" "route installed 2001:db8:2::/64" 25
echo "PASS: the legacy topology still carries the routes (r2 ignores the E-Router-LSA for SPF)"

echo "== runtime API: r2 projected r1's End.X SID (RFC 9513 §9 reception) =="
STATUS2=""
for ((i = 0; i < 150; i++)); do
    STATUS2=$(api_cmd "$OUT/r2.ctl" status)
    echo "$STATUS2" | grep -qF "srv6-endx 2001:db8:a:1::100" && break
    sleep 0.1
done
echo "$STATUS2" | grep -qF "srv6-endx 2001:db8:a:1::100" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "$STATUS2" | grep -F "srv6-endx 2001:db8:a:1::100" | grep -qF "behavior=5" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "$STATUS2" | grep -F "srv6-endx 2001:db8:a:1::100" | grep -qiF "neighbor=" || {
    echo "-- r2 status --"; echo "$STATUS2"; exit 1;
}
echo "PASS: r2 projects the End.X SID (behavior=5, adjacency neighbor recorded)"

echo "== runtime API: r1 self-projects its own End.X SID =="
STATUS1=""
for ((i = 0; i < 150; i++)); do
    STATUS1=$(api_cmd "$OUT/r1.ctl" status)
    echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1::100" && break
    sleep 0.1
done
echo "$STATUS1" | grep -qF "srv6-endx 2001:db8:a:1::100" || {
    echo "-- r1 status --"; echo "$STATUS1"; exit 1;
}
echo "PASS: r1 self-projects the End.X SID"

echo "== killing r2: r1 must age out the learned routes (no E-LSA interaction) =="
kill "$DAEMON_B" 2>/dev/null || true
wait_log "$OUT/r1.log" "route withdrawn 2001:db8:2::/64" 25
echo "PASS: r1 withdrew 2001:db8:2::/64 after the neighbor died"

echo "ALL OSPFv3 END.X (RFC 9513 §9 / RFC 8362) INTEROP CHECKS PASSED"
INNER
