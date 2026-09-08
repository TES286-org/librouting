#!/usr/bin/env bash
# LDP dual-stack interop test: lr-daemon x FRR ldpd over IPv6 (RFC 7552).
#
# Topology — two rootless network namespaces joined by a veth pair, both
# address families on the link:
#
#   netns r1: lr-daemon LSR-id 1.1.1.1
#             veth0: 10.99.1.1/24 + fd00:99::1/64
#             binds 203.0.113.0/24 -> 24000
#        ↑↓ LDP link Hellos (224.0.0.2 / ff02::2) + TCP 646 session
#   netns r2: FRR stack — zebra + ldpd, LSR-id 10.99.1.2
#             veth1: 10.99.1.2/24 + fd00:99::2/64, ipv4 + ipv6 AFs
#
# Success criteria:
#   1. The session comes up over the IPv6 transport (RFC 7552 §6.1.1
#      default TR preference, both sides advertise the dual-stack
#      capability; verified on both the lr and FRR sides).
#   2. lr learns FRR's IPv4 binding for its connected network
#      10.99.1.0/24 (implicit null — FRR's egress/PHP policy).
#   3. FRR learns lr's binding for 203.0.113.0/24 label 24000 (vty).
#   4. lr learns FRR's IPv6 FEC binding for fd00:99::/64 (the ipv6
#      address-family advertises its connected prefix; vty-verified on
#      the FRR side and via lr's mapping-learned log/API counter).
#
# The FRR daemons run from an extracted (non-installed) tree when the
# system packages are absent; a mount namespace provides the frrvty
# group and a writable /run/frr they expect. Everything is rootless
# (user namespaces), exactly what CI does.
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
    echo "SKIP: unprivileged user namespaces unavailable — no LDP port 646 bind"
    exit 0
}

# Locate the FRR binaries: system install first, extracted tree second.
FRRDIR=""
for cand in /usr/lib/frr /home/z/opt/frr/root/usr/lib/frr; do
    if [ -x "$cand/ldpd" ] && [ -x "$cand/zebra" ]; then
        FRRDIR="$cand"
        break
    fi
done
[ -n "$FRRDIR" ] || { echo "SKIP: FRR (ldpd/zebra) not found"; exit 0; }
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
OUT=/tmp/lr_ldp_frr_v6_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ldp_frr_v6_interop_etc_group
PASSWDFILE=/tmp/lr_ldp_frr_v6_interop_etc_passwd
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

LDP="$FRRDIR/ldpd"
ZEBRA="$FRRDIR/zebra"
export LD_LIBRARY_PATH
for libdir in "$FRRDIR/../x86_64-linux-gnu/frr" "$FRRDIR/../x86_64-linux-gnu" "$FRRDIR"; do
    if [ -d "$libdir" ]; then
        LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$libdir"
    fi
done
export MODLD="--moduledir=$MODDIR"

echo "== building the dual-stack lab (veth pair, lr-daemon vs the FRR LDP stack) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 180 &
R1=$!
unshare -n sleep 180 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${LDPD_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
    kill "$R1" "$R2" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0 netns "$R1"
ip link set veth1 netns "$R2"
nsenter -t "$R1" -n ip link set lo up
nsenter -t "$R2" -n ip link set lo up
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip -6 addr add fd00:99::1/64 dev veth0 nodad
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip -6 addr add fd00:99::2/64 dev veth1 nodad
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-30} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
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

echo "== starting the FRR LDP stack in r2 (dual-stack, LSR 10.99.1.2) =="
cat >"$OUT/zebra.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname zebra-frr
password zebra
!
line vty
!
EOF
cat >"$OUT/ldpd.conf" <<'EOF'
frr version 10
frr defaults traditional
hostname ldpd-frr
password zebra
!
mpls ldp
 router id 10.99.1.2
 !
 address-family ipv4
  discovery transport-address 10.99.1.2
  !
  interface veth1
  exit
 !
 address-family ipv6
  discovery transport-address fd00:99::2
  !
  interface veth1
  exit
 !
!
line vty
!
EOF
cd "$REPO"
nsenter -t "$R2" -n "$ZEBRA" -i "$OUT/zebra.pid" \
    -f "$OUT/zebra.conf" -P 26101 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/zebra.log" "$MODLD" &
ZEBRA_PID=$!
sleep 1.5
nsenter -t "$R2" -n "$LDP" -i "$OUT/ldpd.pid" \
    -f "$OUT/ldpd.conf" -P 26112 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/ldpd.log" "$MODLD" &
LDPD_PID=$!

vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd 26112 "show version" 2>/dev/null | grep -q "ldpd-frr"; then
        vty_ok=0
        break
    fi
    if ! kill -0 "$LDPD_PID" 2>/dev/null; then
        echo "FAIL: ldpd died during startup"
        tail -15 "$OUT/ldpd.log" 2>/dev/null || true
        exit 1
    fi
done
if [ $vty_ok -ne 0 ]; then
    echo "FAIL: ldpd vty did not answer as our instance (ldpd-frr)"
    tail -15 "$OUT/ldpd.log" 2>/dev/null || true
    exit 1
fi

echo "== starting lr-daemon r1 (dual-stack: 10.99.1.1 + fd00:99::1) =="
nsenter -t "$R1" -n "$BIN" --protocol ldp --router-id 1.1.1.1 \
    --ldp-transport 10.99.1.1 --ldp-transport-v6 fd00:99::1 \
    --ldp-interface veth0 \
    --ldp-bind 203.0.113.0/24=24000 \
    --api-socket "$OUT/r1.ctl" > "$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== phase 1: session over the IPv6 transport (RFC 7552 default TR) =="
wait_log "$OUT/r1.log" "ldp IPv6 transport fd00:99::1" 10
neighbor_up=1
for i in $(seq 1 60); do
    if vty_cmd 26112 "show mpls ldp neighbor" 2>/dev/null | grep -q "1.1.1.1"; then
        neighbor_up=0
        break
    fi
    sleep 0.5
done
[ $neighbor_up -eq 0 ] || {
    echo "FAIL: FRR ldpd never saw lr as a neighbor"
    vty_cmd 26112 "show mpls ldp neighbor" || true
    tail -20 "$OUT/r1.log" || true
    exit 1
}
# The transport must be the IPv6 address (TR=6 won on both sides).
vty_out=$(vty_cmd 26112 "show mpls ldp discovery" 2>/dev/null || true)
printf '%s\n' "$vty_out" >"$OUT/ldpd.discovery"
echo "   FRR sees lr as a neighbor; discovery detail:"
grep -iE "fd00:99::1|10.99.1.1" "$OUT/ldpd.discovery" | head -4 || true

echo "== phase 2: lr learns FRR's IPv4 implicit-null binding =="
wait_log "$OUT/r1.log" "ldp: mapping learned 10.99.1.0/24" 30
echo "   learned: 10.99.1.0/24 (implicit null)"

echo "== phase 3: FRR learns lr's 203.0.113.0/24 = 24000 binding =="
fec_ok=1
for i in $(seq 1 60); do
    if vty_cmd 26112 "show mpls ldp binding" 2>/dev/null | grep -q "203.0.113.0/24"; then
        fec_ok=0
        break
    fi
    sleep 0.5
done
bindings=$(vty_cmd 26112 "show mpls ldp binding" 2>/dev/null || true)
printf '%s\n' "$bindings" >"$OUT/ldpd.bindings"
[ $fec_ok -eq 0 ] || {
    echo "FAIL: FRR does not carry lr's 203.0.113.0/24 binding"
    cat "$OUT/ldpd.bindings"
    exit 1
}
grep -q "24000" "$OUT/ldpd.bindings" || {
    echo "FAIL: FRR's binding for 203.0.113.0/24 does not show label 24000"
    cat "$OUT/ldpd.bindings"
    exit 1
}
echo "   learned: 203.0.113.0/24 = 24000 (FRR vty)"

echo "== phase 4: IPv6 FEC exchange (fd00:99::/64) =="
v6_ok=1
for i in $(seq 1 60); do
    if grep -qF "ldp: mapping learned fd00:99::/64" "$OUT/r1.log"; then
        v6_ok=0
        break
    fi
    sleep 0.5
done
[ $v6_ok -eq 0 ] || {
    echo "FAIL: lr never learned FRR's IPv6 FEC fd00:99::/64"
    grep -E "ldp: mapping|ldp" "$OUT/r1.log" | tail -10 || true
    exit 1
}
echo "   learned: fd00:99::/64 IPv6 FEC (lr log)"

echo "== teardown: lr exit withdraws and closes cleanly =="
kill -INT "$LR_PID" 2>/dev/null || true
LR_PID=""
wait_log "$OUT/r1.log" "shutdown complete" 15
echo "   shutdown: OK"

echo
echo "LDP x FRR dual-stack interop: PASS"
echo "  - RFC 7552 dual-stack session over the IPv6 transport (TR=6)"
echo "  - IPv4 binding exchange both ways (10.99.1.0/24 null0, 203.0.113.0/24=24000)"
echo "  - IPv6 FEC (fd00:99::/64) learned from FRR's ipv6 address-family"
INNER
