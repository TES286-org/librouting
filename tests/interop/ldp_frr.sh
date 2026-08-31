#!/usr/bin/env bash
# LDP interop test: lr-daemon x FRR ldpd (RFC 5036).
#
# Topology — two rootless network namespaces joined by a veth pair:
#
#   netns r1: lr-daemon LSR-id 1.1.1.1 (10.99.1.1), binds 203.0.113.0/24 -> 24000
#        ↑↓ LDP link Hellos to 224.0.0.2 + TCP 646 session over veth0/veth1
#   netns r2: FRR stack — zebra + ldpd, LSR-id 10.99.1.2, link discovery
#             on veth1
#
# Success criteria:
#   1. FRR ldpd and lr-daemon form an adjacency and reach Operational.
#   2. lr learns FRR's binding for its connected network 10.99.1.0/24
#      (implicit null — FRR's egress/PHP policy for connected FECs).
#   3. FRR learns lr's binding for 203.0.113.0/24 label 24000 (verified
#      over the ldpd vty).
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

# The FRR daemons resolve the "frrvty" group when started as root and
# want a writable /run/frr. Inside the user namespace a mount namespace
# provides both: bind-mounted /etc/group,/etc/passwd and a tmpfs /run.
# When the host already runs the packaged FRR (installed frr group),
# the mounts simply mirror reality.
exec unshare -Urn -m bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ldp_frr_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ldp_frr_interop_etc_group
PASSWDFILE=/tmp/lr_ldp_frr_interop_etc_passwd
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
# Kernel MPLS support (label allocation works without it; dataplane
# installs would need it).
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

echo "== building the lab (veth pair, lr-daemon vs the FRR LDP stack) =="
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
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-30} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    return 1
}

# Query ldpd's vty inside r2 over the loopback TCP interface (the same
# telnet-style access `frr.sh` uses on the host).
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

echo "== starting the FRR LDP stack in r2 (LSR 10.99.1.2) =="
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
!
line vty
!
EOF
cd "$REPO"
# zebra serves the zserv socket at the default /run/frr/zserv.api (the
# tmpfs /run makes that path writable); ldpd connects to it by default.
nsenter -t "$R2" -n "$ZEBRA" -i "$OUT/zebra.pid" \
    -f "$OUT/zebra.conf" -P 26101 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/zebra.log" "$MODLD" &
ZEBRA_PID=$!
sleep 1.5
nsenter -t "$R2" -n "$LDP" -i "$OUT/ldpd.pid" \
    -f "$OUT/ldpd.conf" -P 26112 -A 127.0.0.1 -u root -g root \
    --vty_socket "$OUT/vty" --log file:"$OUT/ldpd.log" "$MODLD" &
LDPD_PID=$!

# The vty must answer as OUR ldpd before the session is expected.
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

echo "== starting lr-daemon in r1 (LSR 1.1.1.1, binds 203.0.113.0/24 -> 24000) =="
nsenter -t "$R1" -n "$BIN" --protocol ldp --router-id 1.1.1.1 \
    --ldp-interface veth0 --ldp-link-hold 15 --ldp-keepalive 10 \
    --ldp-bind 203.0.113.0/24=24000 \
    --api-socket "$OUT/r1.ctl" >"$OUT/lr.log" 2>&1 &
LR_PID=$!

# 1+2. Adjacency + session, then lr learns FRR's binding for its
# connected network (downstream unsolicited, §3.5.9 — implicit null
# per FRR's egress policy for connected FECs).
ok_lr=1
if wait_log "$OUT/lr.log" "session up peer 10.99.1.2:0" 45; then
    echo "PASS: LDP session up between lr-daemon and FRR ldpd"
    if wait_log "$OUT/lr.log" "mapping learned 10.99.1.0/24 label 3" 30; then
        echo "PASS: lr learned FRR's binding (10.99.1.0/24 implicit null)"
    else
        ok_lr=0
    fi
else
    echo "FAIL: lr-daemon did not establish the LDP session with FRR ldpd"
fi

# 3. FRR's view: the vty binding table must carry lr's FEC with the
# remote label.
ok_frr=1
vty_out=""
for i in $(seq 1 40); do
    vty_out=$(vty_cmd 26112 "show mpls ldp binding" 2>/dev/null || true)
    if printf '%s' "$vty_out" | grep -q "203.0.113.0/24"; then
        break
    fi
    sleep 0.5
done
if printf '%s' "$vty_out" | grep -q "203.0.113.0/24" \
    && printf '%s' "$vty_out" | grep -q "24000"; then
    echo "PASS: FRR ldpd learned lr's binding (203.0.113.0/24, remote label 24000)"
else
    ok_frr=0
fi

echo "== FRR ldpd bindings =="
printf '%s\n' "$vty_out" || true
echo "== lr-daemon log (tail) =="
tail -15 "$OUT/lr.log" || true
echo "== ldpd log (tail) =="
tail -8 "$OUT/ldpd.log" 2>/dev/null || true

kill "$LR_PID" "$LDPD_PID" "$ZEBRA_PID" 2>/dev/null || true
# Wait for the daemons only — the netns holder jobs die in the EXIT trap.
wait "$LR_PID" "$LDPD_PID" "$ZEBRA_PID" 2>/dev/null || true

fail=0
[ $ok_lr -eq 1 ] || { echo "FAIL: lr did not learn FRR's binding"; fail=1; }
[ $ok_frr -eq 1 ] || { echo "FAIL: FRR did not learn lr's binding"; fail=1; }
if [ $fail -eq 0 ]; then
    echo "PASS: LDP interop — lr-daemon x FRR ldpd, bidirectional binding exchange"
fi
exit $fail
INNER
