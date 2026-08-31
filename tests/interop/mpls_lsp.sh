#!/usr/bin/env bash
# RFC 8277 BGP-LU -> Linux MPLS dataplane interop (W3-extra.3 router-
# level integration): two lr-daemons in separate network namespaces
# exchange a labelled route, and each daemon mirrors its half of the
# LSP into the kernel.
#
# Topology — each router in its own network namespace joined by a veth
# pair (the same two-router lab as ospf.sh):
#
#   netns r1 (LSP tail / egress PE):
#     veth0: 10.99.1.1/24 (transit)  +  lo: 198.51.100.1/32 (stub)
#     originates 198.51.100.0/24 label 100
#     mirror: AF_MPLS in-label 100 -> pop, dev lo (local delivery)
#        ↑↓ BGP (AFI=1/SAFI=4) over the veth transit
#   netns r2 (LSP head / ingress PE):
#     veth1: 10.99.1.2/24
#     receives 198.51.100.0/24 label 100 via 10.99.1.1
#     mirror: 198.51.100.0/24 encap mpls 100 via 10.99.1.1
#
# Success criteria:
#   1. The labelled route propagates r1 -> r2 (control plane, always run).
#   2. With the kernel MPLS stack enabled, the kernel state matches the
#      Loc-RIB: r1 holds the pop route for in-label 100, r2 holds the
#      encap route for the prefix.
#   3. A real ICMP echo crosses the LSP: r2 pushes label 100, r1 pops it
#      and delivers the packet to the stub address on its loopback.
#
# Phase 2 needs the `mpls_router` kernel module (host-level `modprobe`;
# CI runners do this with sudo) plus per-netns sysctl writes — the
# rootless user namespace grants CAP_NET_ADMIN over its own netns, so
# the daemons stay unprivileged on the host. Environments without the
# module (or without unshare/iproute2) run phase 1 and SKIP phase 2,
# the same pattern as tcp_ao.sh.
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
    echo "SKIP: unprivileged user namespaces unavailable"
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
export REPO BIN PORT OUT MPLS
PORT=${PORT:-11796}
OUT=/tmp/lr_interop_mpls_lsp
rm -rf "$OUT"; mkdir -p "$OUT"

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
PORT=${PORT:-11796}
STUB=198.51.100.1

if [ "$MPLS" -eq 1 ]; then
    echo "== dataplane phase enabled (kernel MPLS sysctls present) =="
else
    echo "== kernel MPLS unavailable — control-plane phase only =="
fi

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
# Holder processes keep the two router namespaces alive.
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
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip addr add 198.51.100.1/32 dev lo
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

if [ "$MPLS" -eq 1 ]; then
    # platform_labels is per-netns; the rootless user namespace owns its
    # netns sysctls, so no host root is needed from here on.
    nsenter -t "$R1" -n sh -c 'echo 10000 > /proc/sys/net/mpls/platform_labels'
    nsenter -t "$R2" -n sh -c 'echo 10000 > /proc/sys/net/mpls/platform_labels'
    # Labelled packets arrive on the transit veth of r1 (r2 only pushes).
    nsenter -t "$R1" -n sh -c 'echo 1 > /proc/sys/net/mpls/conf/veth0/input' 2>/dev/null || true
fi

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-15} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

echo "== starting router r1 (tail: originates 198.51.100.0/24 label 100) =="
if [ "$MPLS" -eq 1 ]; then FLAGS=(--install-kernel-routes); else FLAGS=(); fi
nsenter -t "$R1" -n "$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast \
    --labeled-network "198.51.100.0/24 100" \
    --listen 10.99.1.1:$PORT --local-address 10.99.1.1 \
    "${FLAGS[@]}" \
    >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting router r2 (head: receives the labelled route) =="
nsenter -t "$R2" -n "$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --ebgp-policy accept-all \
    --mp-family ipv4-unicast --mp-family ipv4-labeled-unicast \
    --peer 10.99.1.1:$PORT --local-address 10.99.1.2 \
    "${FLAGS[@]}" \
    >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

# ---------------------------------------------------------------------------
# Phase 1: labelled route propagation (control plane).
# ---------------------------------------------------------------------------
echo "== waiting for labelled route propagation =="
wait_log "$OUT/r2.log" "route installed 198.51.100.0/24" 30
if ! grep -qF "session #1 → Established" "$OUT/r2.log"; then
    echo "FAIL: r2 never reached Established"
    exit 1
fi
if ! grep -qF "originating labelled 198.51.100.0/24" "$OUT/r1.log"; then
    echo "FAIL: r1 did not originate the labelled network"
    exit 1
fi
echo "PASS: phase 1 — labelled route propagated"

# ---------------------------------------------------------------------------
# Phase 2: kernel dataplane.
# ---------------------------------------------------------------------------
if [ "$MPLS" -ne 1 ]; then
    echo "SKIP: phase 2 (dataplane) — load mpls_router to exercise it"
    exit 0
fi

echo "== asserting the mirrored LSP state in both daemons =="
if ! grep -qF "lsp: in-label 100 -> pop (local delivery) for 198.51.100.0/24" "$OUT/r1.log"; then
    echo "FAIL: r1 did not install the pop LSP"; exit 1
fi
if ! grep -qF "lsp: 198.51.100.0/24 encap mpls [100] via 10.99.1.1" "$OUT/r2.log"; then
    echo "FAIL: r2 did not install the encap LSP"; exit 1
fi

echo "== asserting the kernel LSP state =="
if ! nsenter -t "$R1" -n ip -f mpls route show | grep -qE "^100"; then
    echo "FAIL: kernel MPLS table in r1 lacks the in-label 100 route:"
    nsenter -t "$R1" -n ip -f mpls route show
    exit 1
fi
if ! nsenter -t "$R2" -n ip route show 198.51.100.0/24 | grep -qE "encap mpls"; then
    echo "FAIL: kernel route in r2 lacks the MPLS encap:"
    nsenter -t "$R2" -n ip route show 198.51.100.0/24
    exit 1
fi
echo "PASS: phase 2a — kernel LSP state matches the Loc-RIB on both sides"

echo "== pinging through the LSP (r2 -> label 100 -> r1 -> stub) =="
if nsenter -t "$R2" -n ping -c 3 -W 2 "$STUB" >"$OUT/ping.log" 2>&1; then
    echo "PASS: phase 2b — end-to-end labelled ping"
else
    echo "FAIL: ping through the LSP failed:"
    cat "$OUT/ping.log"
    echo "== kernel state r1 =="
    nsenter -t "$R1" -n ip -f mpls route show
    echo "== kernel state r2 =="
    nsenter -t "$R2" -n ip route show 198.51.100.0/24
    exit 1
fi

kill "$DAEMON_A" "$DAEMON_B" 2>/dev/null || true
DAEMON_A=""; DAEMON_B=""

echo
echo "BGP-LU -> MPLS dataplane interop: PASS"
echo "  - labelled route propagated (AFI=1/SAFI=4) over the veth transit"
echo "  - r1 kernel: in-label 100 pop (local delivery); r2 kernel: encap push"
echo "  - ICMP echo crossed the LSP end to end"
INNER
