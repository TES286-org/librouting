#!/usr/bin/env bash
# OSPF two-daemon interop test — the new library-based form.
#
# Topology:
#   netns r1: lr-daemon router-id 1.1.1.1
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub A)
#        ↑↓ OSPFv2 multicast 224.0.0.5
#   netns r2: lr-daemon router-id 2.2.2.2
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub B)
#
# Verification chain (the user's "learn → install → forward" contract):
#   1. LEARNED:   daemon log shows "route installed 10.99.3.0/24".
#   2. INSTALLED: ip route show 10.99.3.0/24 on r1 returns the route.
#   3. DECISION:  ip route get 10.99.3.5 returns the OSPF gateway + dev.
#   4. FORWARD:   ping 10.99.3.1 from r1 succeeds (requires ip_forward
#                 on r1 + r2; only when running as root or in the VM
#                 harness — rootless unshare -Urn cannot set ip_forward).
#   5. TEARDOWN:  SIGKILL r2 → kernel route withdrawn from r1.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

# --- prerequisites ---
BIN=$(lr_resolve_daemon) || exit 0
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

# Rootful callers (CI's sudo step, the QEMU VM harness) get a plain net
# namespace: real root may write net.ipv4.ip_forward inside it, which is
# the one permission gating phase 4 below.
if [ "$(id -u)" -eq 0 ]; then
    echo "== running as root: plain net namespace, forwarding phase enabled =="
    LR_NS_FLAGS="-n"
else
    LR_NS_FLAGS="-Urn"
fi

REPO=$(pwd)
export REPO BIN
export LR_BIN="$BIN"

exec unshare $LR_NS_FLAGS bash -euo pipefail <<'INNER'
cd "$REPO"
source tests/interop/_lib.sh
OUT=/tmp/lr_ospf_interop
rm -rf "$OUT"; mkdir -p "$OUT"

# --- build the lab ---
echo "== building the two-router lab =="
lr_create_lab 2
lr_set_addr "$R1" "$VETH_R1" 10.99.1.1/24
lr_set_addr "$R1" "$VETH_R1" 10.99.2.1/24
lr_set_addr "$R2" "$VETH_R2" 10.99.1.2/24
lr_set_addr "$R2" "$VETH_R2" 10.99.3.1/24

# --- start daemons with --install-kernel-routes ---
echo "== starting r1 (1.1.1.1) =="
DAEMON_A=$(lr_start_daemon "$R1" "$OUT/r1.log" \
    --protocol ospf --router-id 1.1.1.1 \
    --ospf-interface "$VETH_R1" \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --install-kernel-routes \
    --api-socket "$OUT/r1.ctl")

echo "== starting r2 (2.2.2.2) =="
DAEMON_B=$(lr_start_daemon "$R2" "$OUT/r2.log" \
    --protocol ospf --router-id 2.2.2.2 \
    --ospf-interface "$VETH_R2" \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --install-kernel-routes \
    --api-socket "$OUT/r2.ctl")

# --- 1. LEARNED: adjacency + route propagation ---
echo "== 1. LEARNED: waiting for Full adjacency + route propagation =="
lr_wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 20
lr_wait_log "$OUT/r2.log" "ospf neighbor 1.1.1.1 Full (area" 20
lr_wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 20
lr_wait_log "$OUT/r2.log" "route installed 10.99.2.0/24" 20
echo "   PASS: adjacency + route propagation"

# --- 2. INSTALLED: kernel FIB mirror ---
echo "== 2. INSTALLED: kernel FIB carries the OSPF routes =="
lr_wait_kernel_route "$R1" "10.99.3.0/24" present 10 || {
    echo "FAIL: OSPF route 10.99.3.0/24 not in r1's kernel FIB"
    lr_ns_exec "$R1" ip route show; exit 1
}
lr_wait_kernel_route "$R2" "10.99.2.0/24" present 10 || {
    echo "FAIL: OSPF route 10.99.2.0/24 not in r2's kernel FIB"
    lr_ns_exec "$R2" ip route show; exit 1
}
echo "   r1 FIB: $(lr_ns_exec "$R1" ip route show 10.99.3.0/24)"
echo "   r2 FIB: $(lr_ns_exec "$R2" ip route show 10.99.2.0/24)"
echo "   PASS: kernel FIB install"

# --- 3. DECISION: ip route get ---
echo "== 3. DECISION: ip route get confirms OS forwarding decision =="
lr_verify_route_get "$R1" 10.99.3.5 "via 10.99.1.2" "dev $VETH_R1" || exit 1
lr_verify_route_get "$R2" 10.99.2.5 "via 10.99.1.1" "dev $VETH_R2" || exit 1
echo "   PASS: OS forwarding decision uses OSPF routes"

# --- 4. FORWARD: real packet forwarding (requires root) ---
echo "== 4. FORWARD: real packet forwarding =="
# Assign stub IPs to lo so pings are delivered locally.
lr_ns_exec "$R2" ip addr add 10.99.3.1/24 dev lo 2>/dev/null || true
lr_ns_exec "$R1" ip addr add 10.99.2.1/24 dev lo 2>/dev/null || true
# Enable ip_forward on both routers (this is the transit path).
# In a user namespace this fails — the rootless test can only do
# steps 1-3. The VM harness (tests/vm/run_vm.sh) runs as root and
# can do this step.
if lr_enable_forwarding "$R1" && lr_enable_forwarding "$R2"; then
    lr_disable_rp_filter "$R1" all
    lr_disable_rp_filter "$R1" "$VETH_R1"
    lr_disable_rp_filter "$R2" all
    lr_disable_rp_filter "$R2" "$VETH_R2"
    sleep 0.5
    if lr_verify_ping "$R1" 10.99.3.1 1 3; then
        echo "   PASS: r1 → r2 stub IP forwarded via OSPF route"
    else
        echo "   FAIL: r1 → 10.99.3.1 ping did not get a reply"
        lr_ns_exec "$R1" ip route show
        lr_ns_exec "$R2" ip route show
        exit 1
    fi
    if lr_verify_ping "$R2" 10.99.2.1 1 3; then
        echo "   PASS: r2 → r1 stub IP forwarded via OSPF route"
    else
        echo "   FAIL: r2 → 10.99.2.1 ping did not get a reply"
        exit 1
    fi
    echo "   PASS: real data forwarding verified"
else
    if [ "${LR_REQUIRE_FORWARD:-0}" = "1" ]; then
        echo "FAIL: LR_REQUIRE_FORWARD=1 but ip_forward is unavailable (this runner must run as root)"
        exit 1
    fi
    echo "   SKIP: ip_forward not available (rootless unshare) — steps 1-3 verified"
fi

# --- 5. TEARDOWN: dead-timer + kernel route withdrawal ---
echo "== 5. TEARDOWN: dead-timer + kernel route withdrawal =="
kill -9 "$DAEMON_B" 2>/dev/null || true
LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$DAEMON_B/}"
lr_wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 dead (area" 20
echo "   PASS: dead timer fired"
lr_wait_kernel_route "$R1" "10.99.3.0/24" absent 10 || {
    echo "FAIL: OSPF kernel route survived teardown"
    lr_ns_exec "$R1" ip route show; exit 1
}
echo "   PASS: kernel route withdrawn"

echo
echo "OSPF interop: PASS"
echo "  1. LEARNED   — adjacency + route propagation (Loc-RIB)"
echo "  2. INSTALLED — kernel FIB carries the OSPF routes"
echo "  3. DECISION  — ip route get confirms OS forwarding"
if lr_enable_forwarding "$R1" 2>/dev/null; then
    echo "  4. FORWARD   — real ICMP packets forwarded via OSPF routes"
else
    echo "  4. FORWARD   — skipped (rootless; ip_forward unavailable)"
fi
echo "  5. TEARDOWN  — dead-timer + kernel route withdrawal"
INNER
