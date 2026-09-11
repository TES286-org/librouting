#!/usr/bin/env bash
# OSPFv3 Graceful Restart interop against FRR 10.3 ospf6d (RFC 5187):
# lr-daemon is the gracefully *restarting* router, ospf6d (helper mode
# enabled through `graceful-restart helper enable`) retains lr's
# adjacencies and LSAs across the restart.
#
#   netns r1: lr-daemon 1.1.1.1 — veth0 fd00:10::1/64 + fd00:20::1/64
#        ↑↓ OSPFv3 multicast (ff02::5), link-local sources, p2p network
#   netns r2: FRR zebra + ospf6d 2.2.2.2 — veth1 fd00:10::2/64 + fd00:30::1/64
#
# Success criteria:
#   1. Full adjacency both ways + both stub nets propagated.
#   2. SIGTERM lr → graceful shutdown floods the v3 Grace-LSAs
#      (LS type 0x000b, LS ID = the Interface ID, TLVs 1+2) →
#      ospf6d enters helper mode ("Number of Active neighbours in
#      graceful restart: 1" in `show ipv6 ospf6 graceful-restart
#      helper`).
#   3. lr silent past ospf6d's dead interval → ospf6d STILL carries
#      lr's fd00:20::/64 (the helper retention — FRR resets the
#      neighbour's inactivity timer while helping).
#   4. lr restarts (grace state file found) → recovery: DB exchange
#      against the helper, adjacency Full again, Grace-LSA flush →
#      ospf6d exits helper mode ("Last Helper exit Reason :
#      Completed") and the route never left its table.
#
# Rootless: `unshare -Urn -m` (CAP_NET_RAW + a private /etc for the
# FRR daemons); skips gracefully without FRR.
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
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
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
OUT=/tmp/lr_ospf6_gr_frr_interop
rm -rf "$OUT"; mkdir -p "$OUT/vty"

GROUPFILE=/tmp/lr_ospf6_gr_frr_etc_group
PASSWDFILE=/tmp/lr_ospf6_gr_frr_etc_passwd
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
unshare -n sleep 240 &
R1=$!
unshare -n sleep 240 &
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

echo "== starting the FRR OSPFv3 stack in r2 (router-id 2.2.2.2, GR helper on) =="
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
 graceful-restart helper enable
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
# The helper surface must be on before the restart happens.
vty_cmd 26114 "show ipv6 ospf6 graceful-restart helper" 2>/dev/null \
    | grep -q "Graceful restart helper support enabled" || {
    echo "FAIL: ospf6d helper support not enabled (config not applied)"
    vty_cmd 26114 "show ipv6 ospf6 graceful-restart helper" || true
    exit 1
}
echo "   helper support: enabled (graceful-restart helper enable)"

echo "== starting lr-daemon (1.1.1.1, v3, graceful restart, grace 60 s) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 60 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for Full adjacency on both routers =="
if ! wait_log "$OUT/r1.log" "ospf3 neighbor 2.2.2.2 Full (area" 30; then
    echo "=== ospf6d neighbor view ==="
    vty_cmd 26114 "show ipv6 ospf6 neighbor" || true
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
    echo "FAIL: ospf6d does not carry our fd00:20::/64 before the restart"
    cat "$OUT/ospf6d.routes"
    exit 1
}
echo "PASS: ospf6d learned lr's fd00:20::/64"

echo "== SIGTERM lr: the graceful shutdown floods the v3 Grace-LSAs =="
kill -TERM "$LR_PID"
wait_log "$OUT/r1.log" "graceful shutdown complete" 15
sleep 1
# The JSON form reports the helper session independent of any prior
# exit (the plain-text "Number of Active neighbours" line only appears
# after a first exit has already been recorded).
helper_view=""
for i in $(seq 1 40); do
    helper_view=$(vty_cmd 26114 "show ipv6 ospf6 graceful-restart helper json" 2>/dev/null || true)
    if printf '%s' "$helper_view" | grep -q '"activeRestarterCnt":1'; then
        break
    fi
    sleep 0.5
done
printf '%s\n' "$helper_view" >"$OUT/ospf6d.helper" || true
grep -q '"activeRestarterCnt":1' "$OUT/ospf6d.helper" || {
    echo "FAIL: ospf6d did not enter helper mode for lr's Grace-LSA"
    cat "$OUT/ospf6d.helper"
    tail -30 "$OUT/ospf6d.log" 2>/dev/null || true
    exit 1
}
echo "PASS: ospf6d is helping (FRR parsed the 0x000b Grace-LSA)"

echo "== lr silent past ospf6d's dead interval (4 s): the route must survive =="
sleep 7
ospf6_rib=$(vty_cmd 26114 "show ipv6 ospf6 route" 2>/dev/null || true)
printf '%s\n' "$ospf6_rib" >"$OUT/ospf6d.routes2" || true
grep -q "fd00:20::/64" "$OUT/ospf6d.routes2" || {
    echo "FAIL: ospf6d dropped fd00:20::/64 during the grace window (helper retention broken)"
    cat "$OUT/ospf6d.routes2"
    exit 1
}
helper_still=$(vty_cmd 26114 "show ipv6 ospf6 graceful-restart helper json" 2>/dev/null || true)
printf '%s\n' "$helper_still" | grep -q '"activeRestarterCnt":1' || {
    echo "FAIL: ospf6d left helper mode before lr returned"
    printf '%s\n' "$helper_still"
    exit 1
}
echo "PASS: helper retention — fd00:20::/64 still in ospf6d's table"

echo "== restarting lr: recovery against the FRR helper (RFC 5187 2.2) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --ospf-version 3 --router-id 1.1.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --ospf-graceful-restart --ospf-grace-period 60 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1b.log" 2>&1 &
LR_PID=$!
disown "$LR_PID"
wait_log "$OUT/r1b.log" "graceful restart recovery started" 10
wait_log "$OUT/r1b.log" "ospf3 neighbor 2.2.2.2 Full (area" 30
wait_log "$OUT/r1b.log" "recovery ended — all adjacencies re-established" 30
echo "PASS: lr's recovery re-established the adjacency through the helper"
# ospf6d must have left helper mode on the flush (the JSON
# lastExitReason string for OSPF6_GR_HELPER_COMPLETED).
helper_done=""
for i in $(seq 1 40); do
    helper_done=$(vty_cmd 26114 "show ipv6 ospf6 graceful-restart helper json" 2>/dev/null || true)
    if printf '%s' "$helper_done" | grep -q '"lastExitReason":"Successful graceful restart"'; then
        break
    fi
    sleep 0.5
done
printf '%s\n' "$helper_done" >"$OUT/ospf6d.helper2" || true
grep -q '"lastExitReason":"Successful graceful restart"' "$OUT/ospf6d.helper2" || {
    echo "FAIL: ospf6d's helper exit was not the completed flush"
    cat "$OUT/ospf6d.helper2"
    exit 1
}
echo "PASS: ospf6d exited helper mode on the flushed Grace-LSA (3.2 (1))"

echo "== post-restart state: routes intact on both sides =="
wait_log "$OUT/r1b.log" "route installed fd00:30::/64" 30
ospf6_rib=$(vty_cmd 26114 "show ipv6 ospf6 route" 2>/dev/null || true)
printf '%s\n' "$ospf6_rib" >"$OUT/ospf6d.routes3" || true
grep -q "fd00:20::/64" "$OUT/ospf6d.routes3" || {
    echo "FAIL: ospf6d lost fd00:20::/64 across the restart"
    cat "$OUT/ospf6d.routes3"
    exit 1
}
echo "PASS: fd00:20::/64 never left ospf6d's route table"

kill "${LR_PID:-}" "${OSPF6_PID:-}" "${ZEBRA_PID:-}" 2>/dev/null || true
LR_PID=""; OSPF6_PID=""; ZEBRA_PID=""
sleep 0.5

echo
echo "OSPFv3 graceful restart x FRR ospf6d interop: PASS"
echo "  - lr's v3 Grace-LSAs (0x000b, LS ID = Interface ID) engage FRR's helper"
echo "  - Helper retention: adjacency + routes survive the restart window"
echo "  - Restarting side: recovery re-sync through the helper, flush on exit"
INNER
