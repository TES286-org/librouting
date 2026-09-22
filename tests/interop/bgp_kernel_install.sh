#!/usr/bin/env bash
# BGP kernel-install interop — the portable "real usage" verification:
# a BGP-learned route must be LEARNED, INSTALLED into the kernel FIB,
# used by the OS's forwarding DECISION, survive real data FORWARDING,
# and be withdrawn on TEARDOWN.
#
# The same five-step contract runs on every primary platform:
#
#   Linux   — two namespaces + veth pair (rootless via unshare -Urn):
#             full five steps; the FORWARD ping is locally-originated
#             traffic delivered on the peer's loopback stub, which
#             needs no ip_forward, so it works in the rootless CI job.
#   macOS   — two daemons on 127.0.0.1 / 127.0.0.2 loopback under
#             sudo (the BSD route(4) socket needs root): LEARNED +
#             INSTALLED + DECISION + TEARDOWN; the single host has no
#             second network stack, so packet transit cannot be proven
#             (the Linux netns path and the QEMU VM cover FORWARD).
#   Windows — same loopback shape in an Administrator Git-Bash shell
#             (the IP-Helper backend installs via CreateIpForwardEntry2):
#             LEARNED + INSTALLED + DECISION + TEARDOWN.
#
# Topology (Linux netns form):
#   netns r1: lr-daemon AS64512, 10.98.1.1/24, originates 203.0.113.0/24
#        ↑↓ eBGP over TCP
#   netns r2: lr-daemon AS64513, 10.98.1.2/24, originates 198.51.100.0/24
#
# Topology (macOS/Windows single-host form):
#   daemon A: AS64512, originates 203.0.113.0/24
#   daemon B: AS64513, originates 198.51.100.0/24
#   Both run --install-kernel-routes over a local TCP session. The
#   next hops are platform-adaptive (see the GW_A/GW_B selection in
#   the script): macOS uses 127.0.0.5/127.0.0.6 — the safety net only
#   rejects the exact 127.0.0.1 martian, and the BSD route socket
#   accepts 127/8 gateways on lo0; Windows uses the runner's primary
#   IPv4, because CreateIpForwardEntry2 rejects 127/8 next hops
#   outright (error 87). A's route 198.51.100.0/24 points at GW_B and
#   B's 203.0.113.0/24 at GW_A — a next hop equal to a local address
#   makes the OS deliver locally, so the FIB install + lookup + teardown
#   chain is fully real even though both daemons share one stack.
#
# Prefixes are RFC 5737 documentation blocks, so a stale route on a
# shared runner can never hijack real traffic.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11798}
OS=$(lr_os)
export PORT

case "$OS" in
linux)
    command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
    command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter not installed"; exit 0; }
    unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

    REPO=$(pwd)
    export REPO
exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
source tests/interop/_lib.sh
OUT=/tmp/lr_bgp_kernel_install
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
lr_create_lab 2
lr_set_addr "$R1" "$VETH_R1" 10.98.1.1/24
lr_set_addr "$R2" "$VETH_R2" 10.98.1.2/24

echo "== starting r1 (AS64512, originates 203.0.113.0/24) =="
DAEMON_A=$(lr_start_daemon "$R1" "$OUT/r1.log" \
    --local-as 64512 --peer-as 64513 --router-id 1.1.1.1 \
    --ebgp-policy accept-all \
    --listen 10.98.1.1:$PORT --local-address 10.98.1.1 \
    --network 203.0.113.0/24 --install-kernel-routes)

echo "== starting r2 (AS64513, originates 198.51.100.0/24) =="
DAEMON_B=$(lr_start_daemon "$R2" "$OUT/r2.log" \
    --local-as 64513 --peer-as 64512 --router-id 2.2.2.2 \
    --ebgp-policy accept-all \
    --peer 10.98.1.1:$PORT --local-address 10.98.1.2 \
    --network 198.51.100.0/24 --install-kernel-routes)

# --- 1. LEARNED: session + bidirectional route propagation ---
echo "== 1. LEARNED: waiting for Established + route propagation =="
lr_wait_log "$OUT/r1.log" "session #1 → Established" 20
lr_wait_log "$OUT/r2.log" "session #1 → Established" 20
lr_wait_log "$OUT/r1.log" "route installed 198.51.100.0/24" 20
lr_wait_log "$OUT/r2.log" "route installed 203.0.113.0/24" 20
echo "   PASS: eBGP session established + routes exchanged (Loc-RIB)"

# --- 2. INSTALLED: kernel FIB mirror ---
echo "== 2. INSTALLED: kernel FIB carries the BGP routes =="
lr_wait_kernel_route "$R1" "198.51.100.0/24" present 10 || {
    echo "FAIL: BGP route 198.51.100.0/24 not in r1's kernel FIB"
    lr_ns_exec "$R1" ip route show; exit 1
}
lr_wait_kernel_route "$R2" "203.0.113.0/24" present 10 || {
    echo "FAIL: BGP route 203.0.113.0/24 not in r2's kernel FIB"
    lr_ns_exec "$R2" ip route show; exit 1
}
echo "   r1 FIB: $(lr_ns_exec "$R1" ip route show 198.51.100.0/24)"
echo "   r2 FIB: $(lr_ns_exec "$R2" ip route show 203.0.113.0/24)"
echo "   PASS: kernel FIB install"

# --- 3. DECISION: ip route get ---
echo "== 3. DECISION: ip route get confirms the OS uses the BGP routes =="
lr_verify_route_get "$R1" 198.51.100.9 "via 10.98.1.2" "dev $VETH_R1" || exit 1
lr_verify_route_get "$R2" 203.0.113.9 "via 10.98.1.1" "dev $VETH_R2" || exit 1
echo "   PASS: OS forwarding decision uses the BGP routes"

# --- 4. FORWARD: real packets ride the BGP routes ---
echo "== 4. FORWARD: real packet delivery via the BGP routes =="
# Assign each announcer's stub address to its own loopback: pings
# are locally-originated on the sender and locally-delivered on the
# receiver, so no ip_forward is required and the step runs rootless.
lr_ns_exec "$R1" ip addr add 203.0.113.1/24 dev lo 2>/dev/null || true
lr_ns_exec "$R2" ip addr add 198.51.100.1/24 dev lo 2>/dev/null || true
lr_disable_rp_filter "$R1" all
lr_disable_rp_filter "$R1" "$VETH_R1"
lr_disable_rp_filter "$R2" all
lr_disable_rp_filter "$R2" "$VETH_R2"
sleep 0.5
if lr_verify_ping "$R2" 203.0.113.1 1 3; then
    echo "   PASS: r2 → r1 stub IP delivered via the BGP route"
else
    echo "FAIL: r2 → 203.0.113.1 ping did not get a reply"
    lr_ns_exec "$R1" ip route show
    lr_ns_exec "$R2" ip route show
    exit 1
fi
if lr_verify_ping "$R1" 198.51.100.1 1 3; then
    echo "   PASS: r1 → r2 stub IP delivered via the BGP route"
else
    echo "FAIL: r1 → 198.51.100.1 ping did not get a reply"
    exit 1
fi
echo "   PASS: real data delivery via BGP-installed routes"

# --- 5. TEARDOWN: peer loss withdraws the kernel route ---
echo "== 5. TEARDOWN: peer loss withdraws the kernel route =="
kill -9 "$DAEMON_B" 2>/dev/null || true
LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$DAEMON_B/}"
lr_wait_log "$OUT/r1.log" "route withdrawn 198.51.100.0/24" 20
echo "   PASS: Loc-RIB route withdrawn after peer loss"
lr_wait_kernel_route "$R1" "198.51.100.0/24" absent 10 || {
    echo "FAIL: BGP kernel route survived peer teardown"
    lr_ns_exec "$R1" ip route show; exit 1
}
echo "   PASS: kernel route withdrawn"

echo
echo "BGP kernel-install interop: PASS (Linux netns, all five steps)"
echo "  1. LEARNED   — eBGP session + route exchange (Loc-RIB)"
echo "  2. INSTALLED — kernel FIB carries the BGP routes"
echo "  3. DECISION  — ip route get uses the BGP gateway"
echo "  4. FORWARD   — real ICMP packets delivered via the routes"
echo "  5. TEARDOWN  — peer loss withdraws the kernel route"
INNER
    ;;

darwin | windows)
    # --- single-host loopback variant ---
    OUT=/tmp/lr_bgp_kernel_install
    rm -rf "$OUT"; mkdir -p "$OUT"

    if [ "$OS" = darwin ]; then
        command -v netstat >/dev/null 2>&1 || { echo "SKIP: netstat not installed"; exit 0; }
        command -v route >/dev/null 2>&1 || { echo "SKIP: route not installed"; exit 0; }
    else
        command -v route.exe >/dev/null 2>&1 || { echo "SKIP: route.exe not on PATH"; exit 0; }
        command -v powershell.exe >/dev/null 2>&1 || { echo "SKIP: powershell.exe not on PATH"; exit 0; }
    fi
    lr_have_elevation || {
        echo "SKIP: kernel route install needs root/sudo (macOS) or an Administrator shell (Windows)"
        exit 0
    }
    # Next-hop selection: the daemon's safety net rejects a NEXT_HOP
    # of exactly 127.0.0.1 (RFC martian), and Windows' IP-Helper API
    # rejects any 127/8 next hop outright (CreateIpForwardEntry2 error
    # 87). The platform-adaptive session addresses avoid both:
    #
    #   macOS   - 127.0.0.5 / 127.0.0.6 pass the martian check (only
    #             the exact 127.0.0.1 is listed) and the BSD route
    #             socket accepts 127/8 gateways on lo0.
    #   Windows - the runner's real primary IPv4 works as both the
    #             session address and the route gateway (a next hop
    #             equal to a local address makes Windows deliver
    #             locally, the classic route-add-to-self idiom).
    if [ "$OS" = darwin ]; then
        GW_A=127.0.0.5   # A's announced next hop (B's route gateway)
        GW_B=127.0.0.6   # B's announced next hop (A's route gateway)
        LISTEN_ADDR=127.0.0.1
        PEER_ADDR=127.0.0.1
    else
        # The runner's primary IPv4: the interface that owns the
        # default route. Get-NetIPConfiguration is the stable form
        # (Find-NetRoute's [0] element shape varies by PS version).
        GW_A=$(powershell.exe -NoProfile -Command \
            "(Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress" \
            2>/dev/null | tr -d '\r\n ')
        [ -n "$GW_A" ] || { echo "SKIP: no local IPv4 address found"; exit 0; }
        GW_B=$GW_A
        LISTEN_ADDR=$GW_A
        PEER_ADDR=$GW_A
        echo "== using the runner's primary IPv4 $GW_A as session + gateway =="
    fi

    # A stale route from a previous crashed run would make the absent
    # checks below lie about the teardown; start from a clean slate.
    lr_kernel_route_delete 203.0.113.0/24 "$GW_A"
    lr_kernel_route_delete 198.51.100.0/24 "$GW_B"

    if [ "$OS" = darwin ]; then
        # macOS: the route(4) socket needs root, so both daemons run
        # elevated with pidfile-tracked real pids (see _lib.sh).
        echo "== starting daemon A (AS64512, $GW_A, originates 203.0.113.0/24) =="
        PID_A=$(lr_daemon_spawn_elevated "$OUT/a.pid" "$OUT/a.log" \
            --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
            --ebgp-policy accept-all \
            --listen $LISTEN_ADDR:$PORT --local-address $GW_A \
            --network 203.0.113.0/24 --install-kernel-routes)
        echo "== starting daemon B (AS64513, $GW_B, originates 198.51.100.0/24) =="
        PID_B=$(lr_daemon_spawn_elevated "$OUT/b.pid" "$OUT/b.log" \
            --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
            --ebgp-policy accept-all \
            --peer $PEER_ADDR:$PORT --local-address $GW_B \
            --network 198.51.100.0/24 --install-kernel-routes)
    else
        # Windows admin shell: no elevation wrapper, direct spawn.
        echo "== starting daemon A (AS64512, $GW_A, originates 203.0.113.0/24) =="
        PID_A=$(lr_daemon_spawn "$OUT/a.log" \
            --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
            --ebgp-policy accept-all \
            --listen $LISTEN_ADDR:$PORT --local-address $GW_A \
            --network 203.0.113.0/24 --install-kernel-routes)
        echo "== starting daemon B (AS64513, $GW_B, originates 198.51.100.0/24) =="
        PID_B=$(lr_daemon_spawn "$OUT/b.log" \
            --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
            --ebgp-policy accept-all \
            --peer $PEER_ADDR:$PORT --local-address $GW_B \
            --network 198.51.100.0/24 --install-kernel-routes)
    fi

    # --- 1. LEARNED ---
    echo "== 1. LEARNED: waiting for Established + route propagation =="
    lr_wait_log "$OUT/a.log" "route installed 198.51.100.0/24" 30
    lr_wait_log "$OUT/b.log" "route installed 203.0.113.0/24" 30
    echo "   PASS: eBGP session established + routes exchanged (Loc-RIB)"

    # --- 2. INSTALLED ---
    echo "== 2. INSTALLED: kernel FIB carries the BGP routes =="
    lr_wait_kernel_route_host 203.0.113.0/24 present 10 || {
        echo "FAIL: BGP route 203.0.113.0/24 not in the kernel FIB"
        cat "$OUT/b.log"; _lr_fib_show; exit 1
    }
    lr_wait_kernel_route_host 198.51.100.0/24 present 10 || {
        echo "FAIL: BGP route 198.51.100.0/24 not in the kernel FIB"
        cat "$OUT/a.log"; _lr_fib_show; exit 1
    }
    echo "   FIB: $(_lr_fib_show | grep -E "$(_lr_fib_grep 203.0.113.0/24)|$(_lr_fib_grep 198.51.100.0/24)" | head -2 | tr '\n' '|')"
    echo "   PASS: kernel FIB install"

    # --- 3. DECISION ---
    echo "== 3. DECISION: the OS route lookup uses the BGP gateway =="
    lr_kernel_decision_uses 203.0.113.9 "$GW_A" 203.0.113.0/24 || exit 1
    lr_kernel_decision_uses 198.51.100.9 "$GW_B" 198.51.100.0/24 || exit 1
    echo "   PASS: OS forwarding decision uses the BGP routes"

    # --- 4. FORWARD ---
    # A single host has one network stack: packets "via 127.0.0.x" are
    # looped back, not transit-forwarded, so real transit cannot be
    # observed here. The Linux netns path above and the QEMU VM harness
    # (tests/vm) prove the full data plane; what this host CAN prove is
    # the decision chain 1-3 + the teardown lifecycle below.
    echo "== 4. FORWARD: covered on Linux (netns + VM); single host = one stack =="

    # --- 5. TEARDOWN ---
    echo "== 5. TEARDOWN: peer loss withdraws the kernel route =="
    # Crash-kill B by its real pid: A must notice the session loss and
    # withdraw B's route from the kernel FIB.
    if [ "$OS" = darwin ]; then
        lr_daemon_kill_elevated "$PID_B" KILL
        LR_ELEVATED_PIDS="${LR_ELEVATED_PIDS/$PID_B/}"
    else
        kill -9 "$PID_B" 2>/dev/null || true
        LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$PID_B/}"
    fi
    lr_wait_log "$OUT/a.log" "route withdrawn 198.51.100.0/24" 30
    echo "   PASS: Loc-RIB route withdrawn after peer loss"
    lr_wait_kernel_route_host 198.51.100.0/24 absent 10 || {
        echo "FAIL: BGP kernel route survived peer teardown"
        cat "$OUT/a.log"; _lr_fib_show; exit 1
    }
    echo "   PASS: kernel route withdrawn"

    # B was crash-killed: its own installed route (203.0.113.0/24 via
    # $GW_A) goes stale — crash semantics, nobody withdraws it. Stop A
    # gracefully and clean up any leftovers explicitly.
    if [ "$OS" = darwin ]; then
        lr_daemon_kill_elevated "$PID_A" TERM
        sleep 2
        lr_daemon_kill_elevated "$PID_A" KILL
        LR_ELEVATED_PIDS="${LR_ELEVATED_PIDS/$PID_A/}"
    else
        kill -TERM "$PID_A" 2>/dev/null || true
        sleep 2
        kill -9 "$PID_A" 2>/dev/null || true
        LR_DAEMON_PIDS="${LR_DAEMON_PIDS/$PID_A/}"
    fi
    lr_kernel_route_delete 203.0.113.0/24 "$GW_A"
    lr_kernel_route_delete 198.51.100.0/24 "$GW_B"
    lr_wait_kernel_route_host 203.0.113.0/24 absent 5 || {
        echo "FAIL: stale route 203.0.113.0/24 not cleaned up"
        _lr_fib_show; exit 1
    }

    echo
    echo "BGP kernel-install interop: PASS ($OS loopback, steps 1-3 + 5)"
    echo "  1. LEARNED   — eBGP session + route exchange (Loc-RIB)"
    echo "  2. INSTALLED — kernel FIB carries the BGP routes"
    echo "  3. DECISION  — OS route lookup uses the BGP gateway"
    echo "  4. FORWARD   — proven on Linux (netns + QEMU VM harness)"
    echo "  5. TEARDOWN  — peer loss withdraws the kernel route"
    ;;

*)
    echo "SKIP: unsupported platform $(uname -s) for kernel-route verification"
    exit 0
    ;;
esac
