#!/usr/bin/env bash
# OSPFv3 Extended-LSA mode (RFC 8362): two lr-daemons over a veth pair,
# both running `[ospf] version = "v3"` + `extended_lsas = true` — the
# `ExtendedLSASupport` knob of Appendix A. This is the ROADMAP-v3 D13
# slice-2 acceptance gate: the daemons originate ONLY the Extended LSA
# forms (E-Router 0xA021, E-Link 0x8028, E-Intra-Area-Prefix 0xA029),
# so any route convergence at all proves the E-LSA exchange and the
# extended-mode SPF end to end.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64, lo 2001:db8:1::1/64
#        ↑↓ OSPFv3 multicast (ff02::5) over the veth pair, link-local src
#   netns r2: lr-daemon 2.2.2.2 — veth1 fd00:10::2/64, lo 2001:db8:2::1/64
#
# Success criteria:
#   1. Full adjacency on both sides over the same Hello/DBD/LSR
#      machinery (E-LSAs change no packet format — only LSA bodies).
#   2. r1's Loc-RIB carries 2001:db8:2::/64 proto=Ospfv3 via r2's
#      link-local (the E-Link-LSA resolution) learned through r2's
#      E-Router-LSA + E-Intra-Area-Prefix-LSA; r2 symmetrically.
#   3. Killing r2 retracts its prefixes on r1 (E-LSA MaxAge aging).
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
OUT=/tmp/lr_ospf6_e_lsa_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router, RFC 8362 mode) =="
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

echo "== starting router r1 (1.1.1.1, v3 + extended_lsas) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"
extended_lsas = true

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
    --config "$OUT/r1.toml" --api-socket "$OUT/r1.ctl" \
    >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (2.2.2.2, v3 + extended_lsas) =="
cat >"$OUT/r2.toml" <<'EOF'
[ospf]
version = "v3"
extended_lsas = true

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

echo "== waiting for the v3 adjacency (E-LSAs change no packet format) =="
wait_log "$OUT/r1.log" "Full" 25
wait_log "$OUT/r2.log" "Full" 25
echo "PASS: OSPFv3 adjacency Full on both routers (RFC 8362 mode)"

echo "== waiting for route convergence through the Extended LSAs =="
wait_log "$OUT/r1.log" "route installed 2001:db8:2::/64" 25
wait_log "$OUT/r2.log" "route installed 2001:db8:1::/64" 25
echo "PASS: the extended-mode SPF published the remote loopback prefixes (E-Router + E-IAP + E-Link)"

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
echo "PASS: r1 learned 2001:db8:2::/64 proto=Ospfv3 $NH1 (E-Link-LSA resolution)"

ROUTES2=$(api_cmd "$OUT/r2.ctl" routes)
echo "$ROUTES2" | grep -F "2001:db8:1::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r2 routes --"; echo "$ROUTES2"; exit 1;
}
echo "PASS: r2 learned 2001:db8:1::/64 proto=Ospfv3 symmetrically"

echo "== dead-timer withdrawal: killing r2 must age out its E-LSAs on r1 =="
kill "$DAEMON_B" 2>/dev/null || true
wait_log "$OUT/r1.log" "route withdrawn 2001:db8:2::/64" 25
echo "PASS: r1 withdrew 2001:db8:2::/64 after the neighbor died (E-LSA MaxAge)"

echo "ALL OSPFv3 EXTENDED-LSA (RFC 8362) INTEROP CHECKS PASSED"
INNER
