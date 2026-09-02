#!/usr/bin/env bash
# LDP two-daemon interop test: real multicast link discovery over a veth pair.
#
# Topology — each LSR in its own network namespace joined by a veth pair:
#
#   netns r1: lr-daemon LSR-id 1.1.1.1, binds 203.0.113.0/24 → label 24000
#             stub 203.0.113.1 on lo (dataplane phase)
#             veth0: 10.99.1.1/24
#        ↑↓ LDP link Hellos to 224.0.0.2 (TTL 1), TCP 646 session
#   netns r2: lr-daemon LSR-id 2.2.2.2, binds 198.51.100.0/24 → label 16
#             stub 198.51.100.1 on lo (dataplane phase)
#             veth1: 10.99.1.2/24
#
# Success criteria:
#   1. Both daemons form a link-Hello adjacency and reach Operational.
#   2. r1 learns r2's binding for 198.51.100.0/24 (and vice versa for
#      203.0.113.0/24).
#   3. With the kernel MPLS stack enabled (mpls_router loaded): r1
#      holds the pop route for in-label 24000 and the encap route for
#      198.51.100.0/24, r2 mirrors both, and a real ICMP echo crosses
#      the LSP (r2 pushes 24000 toward the learned FEC, r1 pops and
#      delivers locally).
#   4. r3 (3.3.3.3) joins behind r2 binding 192.0.2.0/24 → 20000: r2 —
#      the transit LSR — allocates its own label for the FEC and
#      re-advertises it upstream to r1 (RFC 5036 §3.5.7.1.1, DU +
#      independent control); with kernel MPLS a real ICMP echo crosses
#      the THREE-LSR LSP (r1 pushes r2's transit label, r2 swaps to
#      20000, r3 pops and delivers locally).
#   5. Killing r3 tears r2's transit LSP down (label released, upstream
#      withdrawn) and r1 unlearns the FEC.
#   6. Killing r2 expires the adjacency and tears r1's session down,
#      withdrawing the learned bindings and their kernel encap route.
#
# LDP uses port 646, which is privileged: the whole lab runs inside
# `unshare -Urn` (user + network namespace) where binding is allowed —
# rootless, exactly what CI does. Environments without unprivileged user
# namespaces (or without iproute2) SKIP gracefully.
#
# NOTE: log matching uses POSIX `grep -qF` — CI images do not guarantee
# `rg` on PATH.
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no LDP port 646 bind"
    exit 0
}

# The MPLS sysctl tree (/proc/sys/net/mpls) exists only once the
# `mpls_router` module is loaded — a host-level operation. Try to load
# it via root/sudo (CI runners have passwordless sudo); a host without
# the module just skips the dataplane phase.
if [ ! -e /proc/sys/net/mpls/platform_labels ]; then
    if [ "$(id -u)" -eq 0 ]; then
        modprobe mpls_router 2>/dev/null || true
        modprobe mpls_iptunnel 2>/dev/null || true
    elif sudo -n true 2>/dev/null; then
        sudo modprobe mpls_router 2>/dev/null || true
        sudo modprobe mpls_iptunnel 2>/dev/null || true
    fi
fi
MPLS=0
if [ -e /proc/sys/net/mpls/platform_labels ]; then
    MPLS=1
fi

REPO=$(pwd)
export REPO BIN MPLS

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ldp_interop
rm -rf "$OUT"; mkdir -p "$OUT"

if [ "$MPLS" -eq 1 ]; then
    echo "== dataplane phase enabled (kernel MPLS sysctls present) =="
else
    echo "== kernel MPLS unavailable — control-plane phases only =="
fi

echo "== building the two-LSR lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
# Holder processes keep the two router namespaces alive.
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
unshare -n sleep 120 &
R3=$!
cleanup() {
    kill "${DAEMON_A:-}" "${DAEMON_B:-}" "${DAEMON_C:-}" 2>/dev/null || true
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
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip addr add 10.99.2.2/24 dev veth2
nsenter -t "$R2" -n ip link set veth1 up
nsenter -t "$R2" -n ip link set veth2 up
nsenter -t "$R3" -n ip addr add 10.99.2.3/24 dev veth3
nsenter -t "$R3" -n ip link set veth3 up
# r2 is the multi-link LSR: its LDP transport address lives on lo (the
# FRR `mpls ldp router-id lo` convention); the spoke LSRs route to it.
nsenter -t "$R2" -n ip addr add 2.2.2.2/32 dev lo
nsenter -t "$R1" -n ip route add 2.2.2.2/32 via 10.99.1.2
nsenter -t "$R3" -n ip route add 2.2.2.2/32 via 10.99.2.2
# Dataplane phase: stub addresses behind each LSR (the FEC destinations).
if [ "$MPLS" -eq 1 ]; then
    nsenter -t "$R1" -n ip addr add 203.0.113.1/32 dev lo
    nsenter -t "$R2" -n ip addr add 198.51.100.1/32 dev lo
    nsenter -t "$R3" -n ip addr add 192.0.2.1/32 dev lo
    # platform_labels is per-netns; the rootless user namespace owns
    # its netns sysctls, so no host root is needed from here on.
    # 1048575 = the RFC 3032 platform maximum, so the default LDP label
    # range (16..=1048575) fits (24000 would exceed the 10000 the
    # BGP-LU lab uses and the kernel rejects out-of-range labels with
    # EINVAL).
    nsenter -t "$R1" -n sh -c 'echo 1048575 > /proc/sys/net/mpls/platform_labels'
    nsenter -t "$R2" -n sh -c 'echo 1048575 > /proc/sys/net/mpls/platform_labels'
    nsenter -t "$R3" -n sh -c 'echo 1048575 > /proc/sys/net/mpls/platform_labels'
    # Labelled packets arrive on the transit veth of every LSR.
    nsenter -t "$R1" -n sh -c 'echo 1 > /proc/sys/net/mpls/conf/veth0/input' 2>/dev/null || true
    nsenter -t "$R2" -n sh -c 'echo 1 > /proc/sys/net/mpls/conf/veth1/input' 2>/dev/null || true
    nsenter -t "$R2" -n sh -c 'echo 1 > /proc/sys/net/mpls/conf/veth2/input' 2>/dev/null || true
    nsenter -t "$R3" -n sh -c 'echo 1 > /proc/sys/net/mpls/conf/veth3/input' 2>/dev/null || true
fi

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

wait_log_re() { # <file> <regex> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qE "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

echo "== starting LSR r1 (1.1.1.1, binds 203.0.113.0/24 -> 24000) =="
if [ "$MPLS" -eq 1 ]; then FLAGS=(--ldp-install-kernel); else FLAGS=(); fi
nsenter -t "$R1" -n "$BIN" --protocol ldp --router-id 1.1.1.1 \
    --ldp-interface veth0 --ldp-link-hold 9 --ldp-keepalive 3 \
    --ldp-bind 203.0.113.0/24=24000 \
    "${FLAGS[@]}" \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting LSR r2 (2.2.2.2, binds 198.51.100.0/24 -> 16) =="
nsenter -t "$R2" -n "$BIN" --protocol ldp --router-id 2.2.2.2 \
    --ldp-transport 2.2.2.2 \
    --ldp-interface veth1 --ldp-interface veth2 --ldp-link-hold 9 --ldp-keepalive 3 \
    --ldp-bind 198.51.100.0/24=16 \
    "${FLAGS[@]}" \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

# 1. Adjacencies over multicast link Hellos, sessions Operational.
wait_log "$OUT/r1.log" "session up peer 2.2.2.2:0" || exit 1
wait_log "$OUT/r2.log" "session up peer 1.1.1.1:0" || exit 1
echo "PASS: link-Hello adjacency + LDP session established both ways"

# 2. Bindings exchanged in both directions (§3.5.9 downstream unsolicited).
wait_log "$OUT/r1.log" "mapping learned 198.51.100.0/24 label 16" || exit 1
wait_log "$OUT/r2.log" "mapping learned 203.0.113.0/24 label 24000" || exit 1
echo "PASS: FEC-label bindings exchanged in both directions"

# ---------------------------------------------------------------------------
# Phase 3: kernel dataplane ([ldp] install_kernel — gated on mpls_router).
# ---------------------------------------------------------------------------
if [ "$MPLS" -ne 1 ]; then
    echo "SKIP: phase 3 (dataplane) — load mpls_router to exercise it"
else
    echo "== asserting the mirrored LSP state in both daemons =="
    if ! grep -qF "ldp: in-label 24000 -> pop (local delivery) for 203.0.113.0/24" "$OUT/r1.log"; then
        echo "FAIL: r1 did not install the pop LSP:"
        cat "$OUT/r1.log"
        exit 1
    fi
    if ! grep -qF "ldp: 203.0.113.0/24 encap mpls [24000] via 10.99.1.1" "$OUT/r2.log"; then
        echo "FAIL: r2 did not install the encap LSP:"
        cat "$OUT/r2.log"
        exit 1
    fi

    echo "== asserting the kernel LSP state =="
    if ! nsenter -t "$R1" -n ip -f mpls route show | grep -qE "^24000"; then
        echo "FAIL: kernel MPLS table in r1 lacks the in-label 24000 route:"
        nsenter -t "$R1" -n ip -f mpls route show
        exit 1
    fi
    if ! nsenter -t "$R2" -n ip route show 203.0.113.0/24 | grep -qE "encap mpls"; then
        echo "FAIL: kernel route in r2 lacks the MPLS encap:"
        nsenter -t "$R2" -n ip route show 203.0.113.0/24
        exit 1
    fi
    # The mirror side of the same adjacency: r1 pushes 16 toward r2.
    if ! grep -qF "ldp: 198.51.100.0/24 encap mpls [16] via 10.99.1.2" "$OUT/r1.log"; then
        echo "FAIL: r1 did not install the encap LSP for r2's binding:"
        cat "$OUT/r1.log"
        exit 1
    fi
    if ! nsenter -t "$R1" -n ip route show 198.51.100.0/24 | grep -qE "encap mpls"; then
        echo "FAIL: kernel route in r1 lacks the MPLS encap:"
        nsenter -t "$R1" -n ip route show 198.51.100.0/24
        exit 1
    fi
    echo "PASS: phase 3a — kernel LSP state matches the LIB on both sides"

    echo "== pinging through the LSP (r2 -> label 24000 -> r1 -> stub) =="
    if nsenter -t "$R2" -n ping -c 3 -W 2 203.0.113.1 >"$OUT/ping.log" 2>&1; then
        echo "PASS: phase 3b — end-to-end labelled ping"
    else
        echo "FAIL: ping through the LSP failed:"
        cat "$OUT/ping.log"
        echo "== kernel state r1 =="
        nsenter -t "$R1" -n ip -f mpls route show
        echo "== kernel state r2 =="
        nsenter -t "$R2" -n ip route show 203.0.113.0/24
        echo "== r1 daemon log tail =="
        tail -25 "$OUT/r1.log"
        echo "== r2 daemon log tail =="
        tail -25 "$OUT/r2.log"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3c: transit LSR (RFC 5036 §3.5.7.1.1). r2 — the middle LSR —
# allocates its own label for the FEC r3 advertises and re-advertises
# it upstream to r1; killing r3 tears the transit LSP down in r2 and
# withdraws the FEC from r1.
# ---------------------------------------------------------------------------
echo "== starting LSR r3 (3.3.3.3, binds 192.0.2.0/24 -> 20000) =="
nsenter -t "$R3" -n "$BIN" --protocol ldp --router-id 3.3.3.3 \
    --ldp-interface veth3 --ldp-link-hold 9 --ldp-keepalive 3 \
    --ldp-bind 192.0.2.0/24=20000 \
    "${FLAGS[@]}" \
    --api-socket "$OUT/r3.ctl" >"$OUT/r3.log" 2>&1 &
DAEMON_C=$!

wait_log "$OUT/r2.log" "session up peer 3.3.3.3:0" || exit 1
wait_log "$OUT/r3.log" "session up peer 2.2.2.2:0" || exit 1
echo "PASS: r2/r3 adjacency + session established"

# r2 learns r3's binding, transit-allocates (16 is reserved by r2's own
# bind; the 203.0.113.0/24 transit allocation takes 17, so 192.0.2.0/24
# gets the next free label), and re-advertises upstream to r1.
wait_log_re "$OUT/r2.log" "transit swap for 192.0.2.0/24 in-label [0-9]+ via 10.99.2.3 out-label 20000" || exit 1
wait_log_re "$OUT/r1.log" "mapping learned 192.0.2.0/24 label [0-9]+" || exit 1
echo "PASS: transit LSR allocates and re-advertises the FEC upstream"

if [ "$MPLS" -eq 1 ]; then
    R2_TRANSIT=$(grep -oE "transit swap for 192.0.2.0/24 in-label [0-9]+" "$OUT/r2.log" | head -1 | grep -oE "[0-9]+$")
    R1_TRANSIT=$(grep -oE "mapping learned 192.0.2.0/24 label [0-9]+" "$OUT/r1.log" | head -1 | grep -oE "[0-9]+$")
    # iproute2 dumps a swap (RTA_NEWDST) op as "as to <label>" on every
    # version this suite runs on (5.x-6.x); accept "swap <label>" too in
    # case a future release renames the wording.
    if ! nsenter -t "$R2" -n ip -f mpls route show | grep -qE "^${R2_TRANSIT} .*(as to|swap) 20000"; then
        echo "FAIL: kernel MPLS table in r2 lacks the transit swap ${R2_TRANSIT}->20000:"
        nsenter -t "$R2" -n ip -f mpls route show
        exit 1
    fi
    echo "PASS: transit swap mirrored into the kernel (${R2_TRANSIT} -> 20000)"

    # r1's ingress half: push the transit label toward r2 (the Hello
    # source — r2's transport address is its loopback 2.2.2.2, which is
    # not an LSP next hop).
    if ! nsenter -t "$R1" -n ip route show 192.0.2.0/24 | grep -qE "encap mpls"; then
        echo "FAIL: kernel route in r1 lacks the MPLS encap for the transit FEC:"
        nsenter -t "$R1" -n ip route show 192.0.2.0/24
        tail -25 "$OUT/r1.log"
        exit 1
    fi

    # r3's return-direction LSP: the reply to a ping sourced from
    # r1's stub (203.0.113.1) rides r3's encap route for the FEC r1
    # originated — the two unidirectional LSPs make the round trip.
    if ! nsenter -t "$R3" -n ip route show 203.0.113.0/24 | grep -qE "encap mpls"; then
        echo "FAIL: kernel route in r3 lacks the return-direction MPLS encap:"
        nsenter -t "$R3" -n ip route show 203.0.113.0/24
        tail -25 "$OUT/r3.log"
        exit 1
    fi

    echo "== pinging through the three-LSR LSP (r1 -> r2 swap -> r3 -> stub) =="
    # Source on r1's stub: r3 has no route to r1's link address (no IGP
    # in the lab), but the stub FEC's LSP carries the reply back.
    if nsenter -t "$R1" -n ping -c 3 -W 2 -I 203.0.113.1 192.0.2.1 >"$OUT/ping3.log" 2>&1; then
        echo "PASS: end-to-end labelled ping across the transit LSR"
    else
        echo "FAIL: ping through the transit LSP failed:"
        cat "$OUT/ping3.log"
        echo "== kernel state r1 =="
        nsenter -t "$R1" -n ip -f mpls route show
        nsenter -t "$R1" -n ip route show 192.0.2.0/24
        echo "== kernel state r2 =="
        nsenter -t "$R2" -n ip -f mpls route show
        echo "== kernel state r3 =="
        nsenter -t "$R3" -n ip -f mpls route show
        echo "== r1 daemon log tail =="
        tail -25 "$OUT/r1.log"
        echo "== r2 daemon log tail =="
        tail -25 "$OUT/r2.log"
        echo "== r3 daemon log tail =="
        tail -25 "$OUT/r3.log"
        exit 1
    fi
fi

kill -9 "$DAEMON_C" 2>/dev/null || true
wait_log "$OUT/r2.log" "transit swap for 192.0.2.0/24 removed" 15 || exit 1
wait_log "$OUT/r1.log" "mapping withdrawn 192.0.2.0/24" 10 || exit 1
echo "PASS: r3 death releases the transit label and withdraws upstream"

# ---------------------------------------------------------------------------
# Phase 4: hold-time expiry tears the session down (and uninstalls the
# learned encap route with it).
# ---------------------------------------------------------------------------
kill -9 "$DAEMON_B" 2>/dev/null || true
wait_log "$OUT/r1.log" "adjacency down peer 2.2.2.2:0" 15 || exit 1
wait_log "$OUT/r1.log" "session down peer 2.2.2.2:0" 5 || exit 1
echo "PASS: hold-time expiry tears the session down after the peer dies"
if [ "$MPLS" -eq 1 ]; then
    if nsenter -t "$R1" -n ip route show 198.51.100.0/24 2>/dev/null | grep -qE "encap mpls"; then
        echo "FAIL: r1 kept the encap route after the session died:"
        nsenter -t "$R1" -n ip route show 198.51.100.0/24
        exit 1
    fi
    echo "PASS: session teardown reverts the kernel encap route"
fi

echo "PASS: LDP two-daemon interop — multicast discovery, session, bindings, dataplane, teardown"
INNER
