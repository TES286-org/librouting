#!/usr/bin/env bash
# BGP transit interop — a route learned on one edge must survive a
# middle router's re-advertisement and stay forwardable on the far
# edge. Complements bgp_kernel_install.sh (two-router, same-chain):
# this is the three-router transit shape real deployments run.
#
#   netns r1: AS64510 edge, 10.97.1.1, originates 203.0.113.0/24
#        ↑↓ eBGP
#   netns r2: AS64520 transit ([[peer]] config, two inbound peers)
#        ↑↓ eBGP
#   netns r3: AS64530 edge, 10.97.2.2, learns 203.0.113.0/24 via r2
#
# Phases:
#   1. LEARNED        r3's Loc-RIB carries 203.0.113.0/24 through r2.
#   2. INSTALLED      r3's kernel FIB carries it with proto bgp.
#   3. DECISION       ip route get from r3 picks r2's egress address.
#   4. TRANSIT        (root only: the QEMU VM harness) a ping from r3
#                    to r1's stub is FORWARDED through r2 — r2 must
#                    have ip_forward, and both edges deliver locally.
#                    Rootless CI runs phases 1-3 and skips 4: writing
#                    net.ipv4.ip_forward is denied inside unprivileged
#                    user namespaces.
#   5. TEARDOWN       r1's death withdraws the route from r3 via r2.
#
# The transit router uses the [[peer]] TOML form (two inbound peers
# matched by source address) — the legacy single-peer flags cannot
# express it, and this exercises the multi-peer config path that the
# daemon_multi_peer.rs Rust tests pin on loopback.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11797}

command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO
exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
source tests/interop/_lib.sh
OUT=/tmp/lr_bgp_transit
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the three-router chain (r1 -- r2 -- r3) =="
lr_create_lab 3
# lr_create_lab names the veth chain R1:veth0a | R2:veth0b+veth1a | R3:veth1b
lr_set_addr "$R1" veth0a 10.97.1.1/24
lr_set_addr "$R2" veth0b 10.97.1.2/24
lr_set_addr "$R2" veth1a 10.97.2.1/24
lr_set_addr "$R3" veth1b 10.97.2.2/24

echo "== starting r2 (AS64520 transit, two inbound peers) =="
cat >"$OUT/r2.toml" <<'EOF'
[bgp]
local_as = 64520
router_id = "2.2.2.2"
ebgp_policy = "accept-all"
listen_addr = "0.0.0.0:11797"
networks = []

[[peer]]
name = "r1"
address = "10.97.1.1"
peer_as = 64510
local_address = "10.97.1.2"

[[peer]]
name = "r3"
address = "10.97.2.2"
peer_as = 64530
local_address = "10.97.2.1"
EOF
DAEMON_R2=$(lr_start_daemon "$R2" "$OUT/r2.log" \
    --config "$OUT/r2.toml" --install-kernel-routes)

echo "== starting r1 (AS64510, originates 203.0.113.0/24) =="
DAEMON_R1=$(lr_start_daemon "$R1" "$OUT/r1.log" \
    --local-as 64510 --peer-as 64520 --router-id 1.1.1.1 \
    --ebgp-policy accept-all \
    --peer 10.97.1.2:11797 --local-address 10.97.1.1 \
    --network 203.0.113.0/24)

echo "== starting r3 (AS64530, far edge) =="
DAEMON_R3=$(lr_start_daemon "$R3" "$OUT/r3.log" \
    --local-as 64530 --peer-as 64520 --router-id 3.3.3.3 \
    --ebgp-policy accept-all \
    --peer 10.97.2.1:11797 --local-address 10.97.2.2 \
    --install-kernel-routes)

# --- 1. LEARNED: transit re-advertisement ---
echo "== 1. LEARNED: waiting for the route to transit r2 into r3 =="
lr_wait_log "$OUT/r2.log" "session #1 → Established" 25
lr_wait_log "$OUT/r3.log" "route installed 203.0.113.0/24" 25 || {
    echo "FAIL: r3 never learned 203.0.113.0/24 through r2"
    cat "$OUT/r2.log" "$OUT/r3.log"
    exit 1
}
echo "   PASS: edge route re-advertised by the transit router"

# --- 2. INSTALLED: r3's kernel FIB ---
echo "== 2. INSTALLED: r3's kernel FIB carries the transit route =="
lr_wait_kernel_route "$R3" "203.0.113.0/24" present 10 || {
    echo "FAIL: transit route not in r3's kernel FIB"
    lr_ns_exec "$R3" ip route show; exit 1
}
echo "   r3 FIB: $(lr_ns_exec "$R3" ip route show 203.0.113.0/24)"
echo "   PASS: kernel FIB install on the far edge"

# --- 3. DECISION: ip route get ---
echo "== 3. DECISION: ip route get from r3 picks r2's egress =="
lr_verify_route_get "$R3" 203.0.113.9 "via 10.97.2.1" "dev veth1b" || exit 1
echo "   PASS: OS decision uses the transit next hop"

# --- 4. TRANSIT: forwarded data through r2 (root only) ---
echo "== 4. TRANSIT: data forwarded through r2 =="
lr_ns_exec "$R1" ip addr add 203.0.113.1/24 dev lo 2>/dev/null || true
# Reply-path infrastructure reachability: r3's ping carries source
# 10.97.2.2, and r1 has no BGP/connected route for that transit link
# (only the payload prefix 203.0.113.0/24 is announced). A real
# deployment's IGP carries the inter-router links; pin the static
# equivalent on r1 so the ICMP echo reply can return through r2.
lr_ns_exec "$R1" ip route add 10.97.2.0/24 via 10.97.1.2 2>/dev/null || true
lr_disable_rp_filter "$R1" all
lr_disable_rp_filter "$R2" all
lr_disable_rp_filter "$R2" veth0b
lr_disable_rp_filter "$R2" veth1a
lr_disable_rp_filter "$R3" all
lr_disable_rp_filter "$R3" veth1b
if lr_enable_forwarding "$R2"; then
    sleep 0.5
    if lr_verify_ping "$R3" 203.0.113.1 1 3; then
        echo "   PASS: r3 → r1 stub ping forwarded through the transit router"
    else
        echo "FAIL: transit ping r3 → 203.0.113.1 got no reply"
        lr_ns_exec "$R1" ip route show
        lr_ns_exec "$R2" ip route show
        lr_ns_exec "$R3" ip route show
        exit 1
    fi
    FORWARD="FORWARD   — real packets transit r2 (ip_forward on)"
else
    echo "   SKIP: ip_forward unavailable (rootless user namespace — the QEMU VM harness runs this phase)"
    FORWARD="FORWARD   — skipped rootless (runs in the QEMU VM harness)"
fi

# --- 5. TEARDOWN: edge death withdraws the far-side route ---
echo "== 5. TEARDOWN: r1's death withdraws the route from r3 =="
kill -9 "$DAEMON_R1" 2>/dev/null || true
LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$DAEMON_R1/}"
lr_wait_log "$OUT/r3.log" "route withdrawn 203.0.113.0/24" 25 || {
    echo "FAIL: r3 kept the route after the announcer died"
    cat "$OUT/r3.log"
    exit 1
}
lr_wait_kernel_route "$R3" "203.0.113.0/24" absent 10 || {
    echo "FAIL: transit kernel route survived teardown"
    lr_ns_exec "$R3" ip route show; exit 1
}
echo "   PASS: Loc-RIB + kernel route withdrawn on the far edge"

echo
echo "BGP transit interop: PASS"
echo "  1. LEARNED   — edge route re-advertised through r2"
echo "  2. INSTALLED — far-edge kernel FIB carries it (proto bgp)"
echo "  3. DECISION  — far-edge lookup uses the transit next hop"
echo "  $FORWARD"
echo "  5. TEARDOWN  — announcer death withdraws the far-edge route"
INNER
