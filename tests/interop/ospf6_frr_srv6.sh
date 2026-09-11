#!/usr/bin/env bash
# OSPFv3 SRv6 interop (RFC 9513 slice 3): lr-daemon originates the SRv6
# Router Information LSA + Locator LSA, FRR 10 ospf6d relays them, and a
# second lr-daemon receives them — over a 3-node lab:
#
#   netns r1: lr-daemon 1.1.1.1 (SRv6 originator) — veth0 fd00:10::1/64 + fd00:20::1/64
#        ↑↓ OSPFv3 multicast (ff02::5), area 0, p2p network
#   netns r2: FRR zebra + ospf6d 2.2.2.2 — veth1 fd00:10::2/64 + veth2 fd00:40::1/64
#        ↑↓
#   netns r3: lr-daemon 3.3.3.3 (SRv6 receiver) — veth3 fd00:40::2/64 + fd00:50::1/64
#
# ospf6d has no SRv6 support (FRR 10.3), so lr's Router Information LSA
# (0xA00C) and SRv6 Locator LSA (0xA02A) are unknown-but-U-bit-set
# area-scoped LSAs on its side: RFC 5340 §4.5.2 flooding means FRR must
# store and re-flood them verbatim.
#
# Success criteria:
#   1. Full adjacency on both links (SRv6 LSAs do not break interop).
#   2. FRR's LSDB holds all five of lr1's LSAs (Router + Link +
#      Intra-Area-Prefix + Router-Information + Locator) — the unknown
#      LSA transparency gate.
#   3. lr2 (srv6_receive) installs lr1's locator 2001:db8:a:1::/64 as
#      an Ospfv3 route via FRR's relay — RFC 9513 §5 route computation
#      over a foreign LSA relay.
#   4. lr2 also learns lr1's fd00:20::/64 (normal v3 propagation sanity).
#   5. SIGKILL lr1: ospf6d drops the neighbor (dead interval).
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
OUT=/tmp/lr_ospf6_frr_srv6_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ospf6_frr_srv6_etc_group
PASSWDFILE=/tmp/lr_ospf6_frr_srv6_etc_passwd
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

echo "== building the three-router lab (two veth pairs, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
unshare -n sleep 120 &
R3=$!
cleanup() {
    kill "${LR1_PID:-}" "${LR2_PID:-}" "${OSPF6_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
    kill "$R1" "$R2" "$R3" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0 netns "$R1"
ip link set veth1 netns "$R2"
ip link set veth2 netns "$R2"
ip link set veth3 netns "$R3"
nsenter -t "$R1" -n ip link set lo up
nsenter -t "$R2" -n ip link set lo up
nsenter -t "$R3" -n ip link set lo up
nsenter -t "$R1" -n ip addr add fd00:10::1/64 dev veth0
nsenter -t "$R1" -n ip addr add fd00:20::1/64 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add fd00:10::2/64 dev veth1
nsenter -t "$R2" -n ip addr add fd00:40::1/64 dev veth2
nsenter -t "$R2" -n ip link set veth1 up
nsenter -t "$R2" -n ip link set veth2 up
nsenter -t "$R3" -n ip addr add fd00:40::2/64 dev veth3
nsenter -t "$R3" -n ip addr add fd00:50::1/64 dev veth3
nsenter -t "$R3" -n ip link set veth3 up

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

api_routes() { # <socket-path>
    python3 - "$1" <<'PYEOF'
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
}

echo "== starting the FRR OSPFv3 relay in r2 (router-id 2.2.2.2) =="
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
interface veth2
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

echo "== starting lr1 (1.1.1.1, SRv6 originator, locator 2001:db8:a:1::/64) =="
# The locator rides the TOML surface (the CLI flags are exercised by
# the two-daemon FSM tests): O-flag + an SRH Max SL MSD limit + a §10
# SID Structure split (32/16/16/0 — a /64 locator = block+node+function).
cat >"$OUT/r1.toml" <<'EOF'
[ospf]
version = "v3"
srv6_o_flag = true
srv6_max_sl = 8

[[ospf.srv6_locator]]
prefix = "2001:db8:a:1::/64"
metric = 10
block_len = 32
node_len = 16
function_len = 16
argument_len = 0
EOF
nsenter -t "$R1" -n "$BIN" --protocol ospf --config "$OUT/r1.toml" \
    --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR1_PID=$!

echo "== starting lr2 (3.3.3.3, SRv6 receiver) =="
nsenter -t "$R3" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 3.3.3.3 \
    --ospf-interface veth3 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-srv6-receive \
    --api-socket "$OUT/r3.ctl" >"$OUT/r3.log" 2>&1 &
LR2_PID=$!

echo "== waiting for Full adjacency on both links =="
if ! wait_log "$OUT/r1.log" "ospf3 neighbor 2.2.2.2 Full (area" 30; then
    echo "=== ospf6d neighbor view ==="
    vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
    echo "=== lr1 log tail ==="
    tail -20 "$OUT/r1.log"
    exit 1
fi
if ! wait_log "$OUT/r3.log" "ospf3 neighbor 2.2.2.2 Full (area" 30; then
    echo "=== ospf6d neighbor view ==="
    vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
    echo "=== lr2 log tail ==="
    tail -20 "$OUT/r3.log"
    exit 1
fi
for i in $(seq 1 60); do
    if vty_cmd 26114 "show ipv6 ospf6 neighbor" 2>/dev/null | grep -q "3.3.3.3.*Full"; then
        break
    fi
    if [ "$i" = "60" ]; then
        echo "FAIL: ospf6d never saw 3.3.3.3 Full"
        vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
        exit 1
    fi
    sleep 0.5
done
echo "PASS: adjacency Full on lr1, ospf6d and lr2"

echo "== checking FRR's LSDB for lr1's SRv6 LSAs (transparency gate) =="
frr_db=""
for i in $(seq 1 60); do
    frr_db=$(vty_cmd 26114 "show ipv6 ospf6 database" 2>/dev/null || true)
    if [ "$(printf '%s\n' "$frr_db" | grep -cF '1.1.1.1')" -ge 5 ]; then
        break
    fi
    sleep 0.5
done
printf '%s\n' "$frr_db" >"$OUT/ospf6d.database" || true
db_count=$(printf '%s\n' "$frr_db" | grep -cF '1.1.1.1' || true)
if [ "$db_count" -lt 5 ]; then
    echo "FAIL: ospf6d holds only $db_count LSA(s) from 1.1.1.1 — expected at least 5"
    echo "      (Router + Link + Intra-Area-Prefix + Router-Information + Locator)"
    cat "$OUT/ospf6d.database"
    exit 1
fi
echo "PASS: ospf6d stores all 5 of lr1's LSAs — SRv6 LSAs (0xA00C + 0xA02A) are transparent"

echo "== waiting for route propagation through the relay =="
if ! wait_log "$OUT/r3.log" "route installed fd00:20::/64" 30; then
    echo "-- r3 log --"; cat "$OUT/r3.log"
    exit 1
fi
echo "PASS: lr2 learned lr1's fd00:20::/64"

lr2_routes=$(api_routes "$OUT/r3.ctl")
printf '%s\n' "$lr2_routes" >"$OUT/r3.routes" || true
echo "$lr2_routes" | grep -F "fd00:20::/64" | grep -qF "proto=Ospfv3" || {
    echo "-- r3 routes --"; echo "$lr2_routes"; exit 1;
}
echo "PASS: lr2's route to fd00:20::/64 is proto=Ospfv3"

echo "== checking lr2's SRv6 locator route (RFC 9513 §5 over the FRR relay) =="
locator_ok=""
for i in $(seq 1 60); do
    lr2_routes=$(api_routes "$OUT/r3.ctl")
    if printf '%s\n' "$lr2_routes" | grep -F "2001:db8:a:1::/64" | grep -qF "proto=Ospfv3"; then
        locator_ok=1
        break
    fi
    sleep 0.5
done
printf '%s\n' "$lr2_routes" >"$OUT/r3.routes" || true
if [ -z "$locator_ok" ]; then
    echo "FAIL: lr2 never installed lr1's locator 2001:db8:a:1::/64"
    echo "-- r3 routes --"
    cat "$OUT/r3.routes"
    echo "-- ospf6d database --"
    cat "$OUT/ospf6d.database"
    exit 1
fi
echo "$lr2_routes" | grep -F "2001:db8:a:1::/64" | grep -oE "via fe80::[0-9a-f:]+" | head -1 | grep -qF "fe80::" || {
    echo "FAIL: lr2's locator route does not ride a link-local next hop"
    echo "$lr2_routes" | grep -F "2001:db8:a:1::/64"
    exit 1
}
echo "PASS: lr2 installed lr1's locator via FRR's relay (link-local next hop, proto=Ospfv3)"

echo "== dead-timer teardown: SIGKILL lr1, expect ospf6d to drop the neighbor =="
kill -9 "$LR1_PID" 2>/dev/null || true
LR1_PID=""
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
echo "PASS: ospf6d dropped lr1 after the dead interval"

echo "ALL PASS"
INNER
