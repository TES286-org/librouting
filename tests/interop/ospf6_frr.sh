#!/usr/bin/env bash
# OSPFv3 interop: lr-daemon (RFC 5340, `[ospf] version = "v3"`) versus
# FRR 10 ospf6d over a veth pair — the wire-level acceptance gate for
# the v3 daemon: FRR must parse lr's v3 Hellos/DBDs/LSUs (16-byte
# header, 24-bit options, 16-bit dead interval), form a Full
# adjacency, and both sides must exchange the v3 LSAs (Router + Link +
# Intra-Area-Prefix) into their route tables.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64 + fd00:20::1/64
#        ↑↓ OSPFv3 multicast (ff02::5), link-local sources, p2p network
#   netns r2: FRR zebra + ospf6d 2.2.2.2 — veth1 fd00:10::2/64 + fd00:30::1/64
#
# Success criteria:
#   1. Full adjacency: lr's log AND ospf6d's vty agree.
#   2. lr's Loc-RIB carries FRR's fd00:30::/64 (proto Ospfv3 via a
#      link-local) — lr's v3 SPF + Link-LSA next-hop resolution working
#      against a foreign LSA producer.
#   3. ospf6d's route table carries lr's fd00:20::/64 — FRR parsing
#      lr's Router/Link/Intra-Area-Prefix LSAs.
#   4. SIGKILL lr: ospf6d drops the neighbor (dead interval).
#
# Rootless: `unshare -Urn` (CAP_NET_RAW); skips gracefully without FRR.
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

FRRDIR=""
for cand in /usr/lib/frr /home/z/opt/frr/root/usr/lib/frr; do
    if [ -x "$cand/ospf6d" ] && [ -x "$cand/zebra" ]; then
        FRRDIR="$cand"
        break
    fi
done
[ -n "$FRRDIR" ] || { echo "SKIP: FRR (ospf6d/zebra) not found"; exit 0; }
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

exec unshare -Urn -m bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf6_frr_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ospf6_frr_etc_group
PASSWDFILE=/tmp/lr_ospf6_frr_etc_passwd
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

OSPF6="$FRRDIR/ospf6d"
ZEBRA="$FRRDIR/zebra"
export LD_LIBRARY_PATH
for libdir in "$FRRDIR/../x86_64-linux-gnu" "$FRRDIR/../x86_64-linux-gnu/frr" "$FRRDIR"; do
    if [ -d "$libdir" ]; then
        LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$libdir"
    fi
done
export MODLD="--moduledir=$MODDIR"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${OSPF6_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
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
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
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

echo "== starting the FRR OSPFv3 stack in r2 (router-id 2.2.2.2) =="
cat >"$OUT/zebra.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname zebra-frr
password zebra
!
line vty
!
EOF
cat >"$OUT/ospf6d.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname ospf6d-frr
password zebra
!
interface veth1
 ipv6 ospf6 area 0.0.0.0
 ipv6 ospf6 network point-to-point
 ipv6 ospf6 hello-interval 1
 ipv6 ospf6 dead-interval 4
!
router ospf6
 ospf6 router-id 2.2.2.2
!
line vty
!
EOF
nsenter -t "$R2" -n "$ZEBRA" -i "$OUT/zebra.pid" \
    -f "$OUT/zebra.conf" -P 26101 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/zebra.log" "$MODLD" &
ZEBRA_PID=$!
sleep 1.5
nsenter -t "$R2" -n "$OSPF6" -i "$OUT/ospf6d.pid" \
    -f "$OUT/ospf6d.conf" -P 26114 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/ospf6d.log" "$MODLD" &
OSPF6_PID=$!

vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd 26114 "show version" 2>/dev/null | grep -q "ospf6d-frr"; then
        vty_ok=0
        break
    fi
    if ! kill -0 "$OSPF6_PID" 2>/dev/null; then
        echo "FAIL: ospf6d died during startup"
        tail -15 "$OUT/ospf6d.log" 2>/dev/null || true
        exit 1
    fi
done
if [ $vty_ok -ne 0 ]; then
    echo "FAIL: ospf6d vty did not answer as our instance (ospf6d-frr)"
    tail -15 "$OUT/ospf6d.log" 2>/dev/null || true
    exit 1
fi

echo "== starting lr-daemon (1.1.1.1, v3, nets fd00:10::/64 + fd00:20::/64) =="
LR_OSPF_DEBUG=1 nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency on both routers =="
if ! wait_log "$OUT/r1.log" "ospf3 neighbor 2.2.2.2 Full (area" 30; then
    echo "=== ospf6d neighbor view ==="
    vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
    echo "=== ospf6d interface ==="
    vty_cmd 26114 "show ipv6 ospf6 interface veth1" || true
    echo "=== lr log tail ==="
    tail -20 "$OUT/r1.log"
    exit 1
fi
for i in $(seq 1 60); do
    if vty_cmd 26114 "show ipv6 ospf6 neighbor" 2>/dev/null | grep -q "1.1.1.1.*Full"; then
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FAIL: ospf6d never saw 1.1.1.1 Full"
        vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
        exit 1
    fi
    sleep 0.5
done
echo "PASS: adjacency Full on lr and ospf6d"

echo "== waiting for route propagation =="
wait_log "$OUT/r1.log" "route installed fd00:30::/64" 30
echo "PASS: lr learned FRR's fd00:30::/64"
ROUTES=$(python3 - "$OUT/r1.ctl" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sys.argv[1])
s.sendall(b"routes\n")
out = b""
try:
    while True:
        c = s.recv(4096)
        if not c:
            break
        out += c
except socket.timeout:
    pass
sys.stdout.write(out.decode(errors="replace"))
PYEOF
)
echo "$ROUTES" | grep -F "fd00:30::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r1 routes --"; echo "$ROUTES"; exit 1;
}
echo "$ROUTES" | grep -F "fd00:30::/64" | grep -oE "via fe80::[0-9a-f:]+" | head -1 | grep -qF "fe80::" || {
    echo "-- r1 routes --"; echo "$ROUTES"; exit 1;
}
echo "PASS: lr's route to fd00:30::/64 rides a link-local (proto=Ospfv3)"

ospf6_rib=""
for i in $(seq 1 60); do
    ospf6_rib=$(vty_cmd 26114 "show ipv6 ospf6 route" 2>/dev/null || true)
    if printf '%s' "$ospf6_rib" | grep -q "fd00:20::/64"; then
        break
    fi
    sleep 0.5
done
printf '%s\n' "$ospf6_rib" >"$OUT/ospf6d.routes" || true
grep -q "fd00:20::/64" "$OUT/ospf6d.routes" || {
    echo "FAIL: ospf6d does not carry our fd00:20::/64"
    cat "$OUT/ospf6d.routes"
    exit 1
}
echo "PASS: ospf6d learned lr's fd00:20::/64 (v3 LSAs interoperate)"

echo "== dead-timer teardown: SIGKILL lr, expect ospf6d to drop the neighbor =="
kill -9 "$LR_PID" 2>/dev/null || true
LR_PID=""
dropped=1
for i in $(seq 1 80); do
    if ! vty_cmd 26114 "show ipv6 ospf6 neighbor" 2>/dev/null | grep -q "1.1.1.1"; then
        dropped=0
        break
    fi
    sleep 0.5
done
if [ $dropped -ne 0 ]; then
    echo "FAIL: ospf6d still lists 1.1.1.1 after the dead interval"
    vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
    exit 1
fi
echo "PASS: ospf6d dropped lr after the dead interval"

echo "ALL PASS"
INNER
