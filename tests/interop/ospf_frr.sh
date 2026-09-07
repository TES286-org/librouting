#!/usr/bin/env bash
# OSPF interop with FRR 10 ospfd: real Database Description / LS-Request
# exchange (RFC 2328 §7.2) over a veth pair, one network namespace per
# router.
#
#   netns r1: lr-daemon router-id 1.1.1.1
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub net A)
#        ↑↓ OSPFv2 multicast 224.0.0.5 — Hello / DBD / LSR / LSU / LSAck
#   netns r2: FRR stack (zebra + ospfd), router-id 2.2.2.2, ptp on veth1
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub net B)
#
# Success criteria:
#   1. ospfd's neighbor table shows 1.1.1.1 Full (vty).
#   2. lr-daemon reaches Full adjacency (session log).
#   3. lr-daemon installs FRR's stub net 10.99.3.0/24.
#   4. ospfd's OSPF RIB contains our stub net 10.99.2.0/24 (vty).
#
# Raw OSPF sockets need CAP_NET_RAW: the lab runs inside `unshare -Urn`
# (rootless). The FRR daemons run from an extracted (non-installed)
# tree when the system packages are absent; a mount namespace provides
# the frrvty group and a writable /run/frr they expect. Environments
# without unprivileged user namespaces, iproute2 or FRR SKIP gracefully.
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
command -v ip >/dev/null 2>&1 || {
    echo "SKIP: iproute2 (ip) not installed"
    exit 0
}
command -v nsenter >/dev/null 2>&1 || {
    echo "SKIP: nsenter (util-linux) not installed"
    exit 0
}
command -v unshare >/dev/null 2>&1 || {
    echo "SKIP: unshare (util-linux) not installed"
    exit 0
}
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

exec unshare -Urn -m bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_frr_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ospf_frr_interop_etc_group
PASSWDFILE=/tmp/lr_ospf_frr_interop_etc_passwd
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

OSPF="$FRRDIR/ospfd"
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
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${OSPF_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
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
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

# Query a vty over the loopback TCP interface (the same telnet-style
# access the other FRR interop scripts use).
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

echo "== starting the FRR OSPF stack in r2 (router-id 2.2.2.2) =="
cat >"$OUT/zebra.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname zebra-frr
password zebra
!
line vty
!
EOF
cat >"$OUT/ospfd.conf" <<'EOF'
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
 network 10.99.1.0/24 area 0
 network 10.99.3.0/24 area 0
!
line vty
!
EOF
# zebra serves the zserv socket at the default /run/frr/zserv.api (the
# tmpfs /run makes that path writable); ospfd connects to it by default.
nsenter -t "$R2" -n "$ZEBRA" -i "$OUT/zebra.pid" \
    -f "$OUT/zebra.conf" -P 26101 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/zebra.log" "$MODLD" &
ZEBRA_PID=$!
sleep 1.5
nsenter -t "$R2" -n "$OSPF" -i "$OUT/ospfd.pid" \
    -f "$OUT/ospfd.conf" -P 26113 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/ospfd.log" "$MODLD" &
OSPF_PID=$!

# The vty must answer as OUR ospfd before the session is expected.
vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd 26113 "show version" 2>/dev/null | grep -q "ospfd-frr"; then
        vty_ok=0
        break
    fi
    if ! kill -0 "$OSPF_PID" 2>/dev/null; then
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

echo "== starting lr-daemon (1.1.1.1, stub nets 10.99.1.0/24 + 10.99.2.0/24) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency on both routers =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 30
adjacency=Full
for i in $(seq 1 60); do
    if vty_cmd 26113 "show ip ospf neighbor" 2>/dev/null | grep -q "1.1.1.1.*Full"; then
        adjacency=Full
        break
    fi
    sleep 0.5
done
echo "   adjacency: OK (lr Full + ospfd Full)"

echo "== waiting for route propagation =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 30
echo "   lr knows FRR's stub net 10.99.3.0/24"
ospf_rib=""
for i in $(seq 1 60); do
    ospf_rib=$(vty_cmd 26113 "show ip ospf route" 2>/dev/null || true)
    if printf '%s' "$ospf_rib" | grep -q "10.99.2.0/24"; then
        break
    fi
    sleep 0.5
done
printf '%s\n' "$ospf_rib" >"$OUT/ospfd.routes" || true
grep -q "10.99.2.0/24" "$OUT/ospfd.routes" || {
    echo "FAIL: ospfd does not carry our stub net"
    cat "$OUT/ospfd.routes"
    exit 1
}
echo "   ospfd knows our stub net 10.99.2.0/24"

echo "== dead-timer teardown: SIGKILL lr, expect ospfd to drop the neighbor =="
kill -9 "$LR_PID" 2>/dev/null || true
LR_PID=""
dropped=1
for i in $(seq 1 80); do
    out=$(vty_cmd 26113 "show ip ospf neighbor" 2>/dev/null || true)
    # the neighbor must leave Full (either gone entirely or down)
    if ! printf '%s' "$out" | grep -q "1.1.1.1.*Full"; then
        dropped=0
        break
    fi
    sleep 0.5
done
[ $dropped -eq 0 ] || {
    echo "FAIL: ospfd kept the dead neighbor in Full"
    vty_cmd 26113 "show ip ospf neighbor" || true
    exit 1
}
echo "   dead timer: OK (neighbor left Full after lr died)"

echo
echo "OSPF x FRR interop: PASS"
echo "  - Full adjacency via real DBD/LSR exchange (RFC 2328 7.2)"
echo "  - stub nets propagated in both directions"
echo "  - dead-timer teardown observed by ospfd"
INNER
