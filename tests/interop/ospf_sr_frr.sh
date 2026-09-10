#!/usr/bin/env bash
# OSPF Segment Routing interop (RFC 8665), both directions:
#
# Phase 1 — origination (slice 1): lr-daemon originates the area-scoped
# Router Information LSA (SR-Algorithm + SRGB TLVs) and Extended Prefix
# Opaque LSAs with Prefix-SID sub-TLVs; FRR's ospfd (segment-routing on,
# with zebra for the label manager) parses them into its SRDB. The
# decoded label in FRR's SRDB — SRGB base + SID index — is the
# wire-format gate.
#
# Phase 2 — reception (slice 2, kernel-MPLS gated): FRR originates its
# own prefix-SID (10.99.3.0/24 index 200, no-php-flag); lr (sr_receive
# on) resolves it into Loc-RIB label 16200 and — with install_kernel —
# installs the RFC 8660 encap route the kernel actually forwards
# through.
#
#   netns r1: lr-daemon 1.1.1.1, SRGB 16000/8000,
#             prefix-SID 10.99.2.0/24 index 100 (node)
#        ↑↓ OSPFv2 multicast over the veth pair
#   netns r2: FRR stack (zebra + ospfd), 2.2.2.2, segment-routing on,
#             loopback 10.99.3.1/24 with prefix-SID index 200
#
# Success criteria:
#   1. Full adjacency (lr log).
#   2. FRR's LSDB contains lr's Extended Prefix Opaque LSA.
#   3. FRR's SRDB carries the SR-Node 1.1.1.1 with the advertised
#      SRGB (16000/8000) and maps 10.99.2.0/24 to label 16100.
#   4. (MPLS) lr's Loc-RIB maps FRR's 10.99.3.0/24 to label=16200 and
#      the kernel FIB carries the encap mpls route (RFC 8660 head end).
#
# Rootless: runs inside `unshare -Urn` (CAP_NET_RAW); skips gracefully
# without user namespaces or FRR.
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
command -v unshare >/dev/null 2>&1 || { echo "SKIP: unshare (util-linux) not installed"; exit 0; }
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

# Locate the FRR binaries: system install first, extracted tree second.
FRRDIR=""
for cand in /usr/lib/frr /home/z/opt/frr/root/usr/lib/frr; do
    if [ -x "$cand/ospfd" ] && [ -x "$cand/zebra" ]; then
        FRRDIR="$cand"
        break
    fi
done
[ -n "$FRRDIR" ] || { echo "SKIP: FRR (ospfd/zebra) not found"; exit 0; }
MODDIR=""
for cand in /usr/lib/x86_64-linux-gnu/frr/modules "$FRRDIR/../x86_64-linux-gnu/frr/modules"; do
    if [ -d "$cand" ]; then
        MODDIR="$cand"
        break
    fi
done
[ -n "$MODDIR" ] || MODDIR="$FRRDIR/modules"

REPO=$(pwd)
export REPO BIN FRRDIR MODDIR

# FRR gates opaque-LSA handling (and SR) behind its opaque capability;
# the SRGB reservation additionally needs the kernel's MPLS support
# (the `mpls_router` module — a host-level operation, same gate as
# mpls_lsp.sh). Without kernel MPLS the lab still verifies adjacency
# and the opaque-LSA exchange; the SRDB label mapping phase skips.
if [ ! -e /proc/sys/net/mpls/platform_labels ]; then
    if [ "$(id -u)" -eq 0 ]; then
        modprobe mpls_router 2>/dev/null || true
        modprobe mpls_iptunnel 2>/dev/null || true
    elif sudo -n true 2>/dev/null; then
        sudo modprobe mpls_router 2>/dev/null || true
        sudo modprobe mpls_iptunnel 2>/dev/null || true
        if [ ! -e /proc/sys/net/mpls/platform_labels ]; then
            sudo apt-get install -y --no-install-recommends \
                "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
            sudo modprobe mpls_router 2>/dev/null || true
            sudo modprobe mpls_iptunnel 2>/dev/null || true
        fi
    fi
fi
MPLS=0
if [ -e /proc/sys/net/mpls/platform_labels ]; then
    MPLS=1
fi
export MPLS
# Whether FRR's own zebra can use the kernel MPLS data plane inside the
# netns — decided after zebra starts (see below); defaults to off so a
# crashy `segment-routing on` never slips through.
SR_READY=0
export SR_READY

exec unshare -Urn -m bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_sr_frr_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ospf_sr_frr_etc_group
PASSWDFILE=/tmp/lr_ospf_sr_frr_etc_passwd
cat >"$GROUPFILE" <<'EOF'
frrvty:x:501:root
frr:x:502:root
root:x:0:
EOF
cat >"$PASSWDFILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
frr:x:1001:502:frr:/nonexistent:/usr/sbin/nologin
nogroup:x:65534:
EOF
mount --bind "$GROUPFILE" /etc/group
mount --bind "$PASSWDFILE" /etc/passwd
mount -t tmpfs -o size=8m tmpfs /run
mkdir -p /run/frr
sysctl -q -w net.mpls.platform_labels=1048575 2>/dev/null || true

OSPFD="$FRRDIR/ospfd"
ZEBRA="$FRRDIR/zebra"
export LD_LIBRARY_PATH
for libdir in "$FRRDIR/../x86_64-linux-gnu/frr" "$FRRDIR/../x86_64-linux-gnu" "$FRRDIR"; do
    if [ -d "$libdir" ]; then
        LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$libdir"
    fi
done
export MODLD="--moduledir=$MODDIR"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 180 &
R1=$!
unshare -n sleep 180 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${OSPFD_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
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
nsenter -t "$R2" -n ip link set veth1 up
# FRR's prefix-SID target (phase 2): a loopback stub FRR announces with
# SID index 200. lr resolves the mapping into label 16000 + 200.
if [ "$MPLS" -eq 1 ] && [ "$SR_READY" -eq 1 ]; then
    nsenter -t "$R2" -n ip addr add 10.99.3.1/24 dev lo
fi

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-30} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

vty_cmd() { # <port> <command>
    nsenter -t "$R2" -n python3 - "$1" "$2" <<'PYEOF'
import socket, sys, time
port, cmd = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError:
    sys.exit(1)
s.settimeout(0.5)

def drain(idle_rounds=2):
    out = b""
    idle = 0
    while idle < idle_rounds:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
            idle = 0
        except socket.timeout:
            idle += 1
        except OSError:
            break
    return out

def send(line):
    try:
        s.sendall(line)
    except OSError:
        pass

banner = drain()
if b"Password:" in banner:
    send(b"zebra\r\n")
    time.sleep(0.2)
    drain(1)
send(cmd.encode() + b"\r\n")
time.sleep(0.8)
out = drain()
send(b"quit\r\n")
s.close()
sys.stdout.write(out.decode("utf-8", "replace"))
PYEOF
}

echo "== starting the FRR stack in r2 (zebra + ospfd, segment-routing on) =="
cat >"$OUT/zebra.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname zebra-frr
password zebra
!
line vty
!
EOF
SR_CONF=""
if [ "$MPLS" -eq 1 ] && [ "$SR_READY" -eq 1 ]; then
    SR_CONF=" segment-routing on
 segment-routing global-block 16000 8000
 segment-routing prefix 10.99.3.0/24 index 200 no-php-flag"
fi
cat >"$OUT/ospfd.conf" <<EOF
frr version 10
frr defaults traditional
hostname ospfd-frr
password zebra
!
interface veth1
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
!
router ospf
 ospf router-id 2.2.2.2
 network 10.99.1.0/24 area 0.0.0.0
 capability opaque
$SR_CONF
!
line vty
!
EOF
nsenter -t "$R2" -n "$ZEBRA" -i "$OUT/zebra.pid" \
    -f "$OUT/zebra.conf" -P 26101 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/zebra.log" "$MODLD" &
ZEBRA_PID=$!
sleep 1.5
# FRR's SR needs a working kernel MPLS data plane: when zebra cannot
# use it (e.g. inside a rootless user namespace), enabling
# `segment-routing on` makes FRR 8.x crash in its own SR code at
# adjacency bring-up - before any of lr's LSAs are exchanged. Trust
# zebra's own probe and keep the FRR SR phases gated on it.
if grep -q "Disabling MPLS support" "$OUT/zebra.log" 2>/dev/null; then
    echo "NOTE: zebra disabled MPLS support (rootless netns) - FRR SR phases skipped"
    SR_READY=0
else
    SR_READY=1
fi
nsenter -t "$R2" -n "$OSPFD" -i "$OUT/ospfd.pid" \
    -f "$OUT/ospfd.conf" -P 26110 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/ospfd.log" "$MODLD" &
OSPFD_PID=$!

vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd 26110 "show version" 2>/dev/null | grep -q "ospfd-frr"; then
        vty_ok=0
        break
    fi
    if ! kill -0 "$OSPFD_PID" 2>/dev/null; then
        echo "FAIL: ospfd died during startup"
        tail -15 "$OUT/ospfd.log" 2>/dev/null || true
        exit 1
    fi
done
if [ $vty_ok -ne 0 ]; then
    echo "FAIL: ospfd vty did not answer as our instance (ospfd-frr)"
    tail -15 "$OUT/ospfd.log" 2>/dev/null || true
    exit 1
fi

echo "== starting lr-daemon r1 (1.1.1.1, SRGB 16000/8000, SID 10.99.2.0/24 = 100) =="
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
srgb_base = 16000
srgb_range = 8000
sr_receive = true

[[ospf.interface]]
name = "veth0"
hello_interval = 1
dead_interval = 4

[[ospf.prefix_sid]]
prefix = "10.99.2.0/24"
sid = 100
node = true
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" \
    --install-kernel-routes \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency =="
if ! wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 40; then
    echo "-- r1 log --"; cat "$OUT/r1.log"
    echo "-- ospfd log (tail) --"; tail -20 "$OUT/ospfd.log" 2>/dev/null || true
    exit 1
fi
# Give FRR's SRDB a beat to process the extended LSAs.
sleep 3

echo "== FRR LSDB (opaque LSAs) =="
vty_cmd 26110 "show ip ospf database" >"$OUT/lsdb.txt" 2>/dev/null || true
cat "$OUT/lsdb.txt"
vty_cmd 26110 "show ip ospf database opaque-area 7.0.0.1" >"$OUT/lsdb_detail.txt" 2>/dev/null || true
cat "$OUT/lsdb_detail.txt" || true
if [ "$MPLS" -eq 1 ] && [ "$SR_READY" -eq 1 ]; then
    echo "== FRR SRDB =="
    vty_cmd 26110 "show ip ospf srdb" >"$OUT/srdb.txt" 2>/dev/null || true
    cat "$OUT/srdb.txt"
fi
echo "== FRR ospfd log (tail) =="
tail -15 "$OUT/ospfd.log" 2>/dev/null || true
echo "== lr-daemon log =="
cat "$OUT/r1.log"

fail=0
# Phase 2: lr receives FRR's prefix-SID (RFC 8665 reception). The API
# `routes` dump must map FRR's 10.99.3.0/24 to label 16200 (base + SID
# 200), and — with install_kernel — the kernel FIB must carry the RFC
# 8660 encap route.
if [ "$MPLS" -eq 1 ] && [ "$SR_READY" -eq 1 ]; then
    echo "== lr reception of FRR's prefix-SID (phase 2) =="
    api_cmd() {
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
    api_cmd "$OUT/r1.ctl" "routes" >"$OUT/r1.routes"
    cat "$OUT/r1.routes"
    if ! grep "10.99.3.0/24" "$OUT/r1.routes" | grep -qF "label=16200"; then
        echo "FAIL: lr's Loc-RIB does not map FRR's 10.99.3.0/24 to label=16200 (base + SID 200)"
        fail=1
    fi
    if ! nsenter -t "$R1" -n ip route show | grep -qF "encap mpls"; then
        echo "FAIL: kernel FIB carries no MPLS-encapped route (RFC 8660 head end)"
        fail=1
    fi
fi

kill "$LR_PID" 2>/dev/null || true
sleep 0.5

# The LSDB listing shows the opaque LSAs by Opaque-Type/Id: 4.0.0.0 is
# our Router Information LSA (SRGB), 7.0.0.1 the Extended Prefix LSA
# (prefix-SID for 10.99.2.0/24).
if ! grep -q "4.0.0.0" "$OUT/lsdb.txt" || ! grep -q "7.0.0.1" "$OUT/lsdb.txt"; then
    echo "FAIL: FRR's LSDB does not hold lr's RI (4.0.0.0) and Extended Prefix (7.0.0.1) LSAs"
    fail=1
fi
if [ "$MPLS" -eq 1 ] && [ "$SR_READY" -eq 1 ]; then
    if ! grep -q "16000" "$OUT/srdb.txt" || ! grep -q "8000" "$OUT/srdb.txt"; then
        echo "FAIL: FRR's SRDB does not carry lr's SRGB (16000/8000)"
        fail=1
    fi
    if ! grep -q "16100" "$OUT/srdb.txt"; then
        echo "FAIL: FRR's SRDB does not map 10.99.2.0/24 to label 16100 (base + SID 100)"
        fail=1
    fi
else
    echo "NOTE: kernel MPLS unavailable - the SRDB label-mapping phase was skipped"
    echo "      (same gate as mpls_lsp.sh phase 2; see tests/vm/README.md for the VM harness)"
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: OSPF SR interop - lr's RI + Extended Prefix LSAs flooded to and decoded by FRR"
fi
exit $fail
INNER
