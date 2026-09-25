#!/usr/bin/env bash
# Babel v6-only tunnel + extended_next_hop + blackhole routes e2e.
#
# Reproduces the user's reported Windows production issue on Linux:
#   - v6-only tunnel interface (no IPv4 transport)
#   - Loc-RIB contains both v4 and v6 static 'blackhole' routes
#   - Without extended_next_hop the v4 routes are silently dropped
#   - With the auto-enable inference (or explicit extended_next_hop
#     true) the v4 routes ride the v6 next-hop (RFC 5549 form)
#
# Topology (single shared netns, two loopback pseudo-interfaces):
#
#   lr (router-id 172.23.10.102)
#     ├── int6-1 (v6-only tunnel): fd00:286:11e:6::1/64, fe80::1
#     │   ↳ static route 172.23.10.102/32 blackhole metric 10
#     │   ↳ static route 10.127.32.0/24  blackhole metric 10
#     │   ↳ static route fd00:286:11e:6::/64 blackhole metric 10
#     │   ↳ static route 172.23.10.96/27 blackhole metric 10
#     │
#     └── BGP peers rr-hk01 (172.23.10.98), rr-de01 (172.23.10.101)
#         reachable only via Babel-learned routes from int6-1
#
# The reference side is a BIRD daemon with a Babel protocol on a peer
# v6 interface. The test verifies:
#   1. lr's startup banner shows the auto-enable warning OR
#      'extended_next_hop on (v4-over-v6)' (operator opted in).
#   2. The remote BIRD sees lr's v4 routes in 'show babel entries'.
#   3. packet capture on the v6 link confirms the Babel Update TLVs
#      carry AE=1 (IPv4) prefixes preceded by a NextHop TLV with AE=2
#      (IPv6 next-hop, the RFC 5549 form).
#   4. Blackhole routes (next_hop = None) are mirrored into the
#      kernel FIB as RTN_BLACKHOLE (verified via 'ip route show').
#
# The test gracefully SKIPs when any required tool is missing
# (birdc, python3, ip, unshare).
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
command -v birdc >/dev/null 2>&1 || { echo "SKIP: birdc not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_v6only_extended
rm -rf "$OUT"; mkdir -p "$OUT"

# Create the v6-only link: veth0a (lr side) <-> veth0b (BIRD side).
# Only IPv6 addresses assigned — this is what makes lr's interface
# v6-only and triggers the auto-enable path.
ip link add veth0a type veth peer name veth0b
ip link set veth0a up
ip link set veth0b up
# Disable DAD on the veth pair so the link-local addresses are
# immediately usable — otherwise the kernel marks them tentative
# for ~1 s and bind(2) returns EADDRNOTAVAIL (os error 99), which
# is the exact failure the CI interop job saw. BIRD and babeld
# test scripts do the same (`accept_dad=0`, `dad_transmits=0`).
sysctl -w net.ipv6.conf.veth0a.accept_dad=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth0a.dad_transmits=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth0b.accept_dad=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth0b.dad_transmits=0 >/dev/null 2>&1 || true
# Ensure IPv6 is enabled on the interfaces (some kernels default to
# disabled_ipv6=1 in new netns).
sysctl -w net.ipv6.conf.veth0a.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth0b.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
# Use 'nodad' flag so the addresses are immediately usable even if
# the sysctl above didn't take effect (some kernels restrict sysctl
# in user namespaces). The 'nodad' flag is the documented way to
# skip DAD per-address (iproute2 `ip addr add ... nodad`).
ip -6 addr add fe80::1/64 dev veth0a nodad 2>/dev/null || ip -6 addr add fe80::1/64 dev veth0a
ip -6 addr add fd00:286:11e:6::1/64 dev veth0a nodad 2>/dev/null || ip -6 addr add fd00:286:11e:6::1/64 dev veth0a
ip -6 addr add fe80::2/64 dev veth0b nodad 2>/dev/null || ip -6 addr add fe80::2/64 dev veth0b
ip -6 addr add fd00:286:11e:6::2/64 dev veth0b nodad 2>/dev/null || ip -6 addr add fd00:286:11e:6::2/64 dev veth0b
# Assign a dummy IPv4 address to veth0b (BIRD's side) ONLY — not to
# veth0a (lr's side). lr's interface stays v6-only (triggering the
# extended_next_hop auto-enable), but BIRD 2.0.x requires an IPv4
# address on the receiving interface to accept v4-over-v6 routes
# (RFC 5549). Without it BIRD logs 'Missing IPv4 next hop address'
# and silently drops every IPv4 Update TLV. This is a BIRD-side
# requirement, not a lr bug — lr correctly emits AE=1 Updates
# preceded by an AE=2 NextHop TLV.
ip addr add 10.0.0.2/32 dev veth0b
# Brief settle so the kernel finishes configuring the addresses.
sleep 0.5
# Add a static blackhole route to lr's own /32 (mirrors the user's
# static-route stanza) — both v4 and v6 forms.
ip route add blackhole 172.23.10.102/32 metric 10
ip route add blackhole 10.127.32.0/24 metric 10
ip route add blackhole fd00:286:11e:6::/64 metric 10
ip route add blackhole 172.23.10.96/27 metric 10

# Start the packet capture on veth0a (only Babel, UDP port 6696).
# tcpdump cannot run here: inside an unprivileged user+net namespace
# its mandatory privilege drop calls initgroups()/setgroups(), which
# the kernel denies ("Couldn't change to 'root' ... Operation not
# permitted") — it dies before capturing anything. pcap_sniff.py uses
# a plain AF_PACKET raw socket, which needs only CAP_NET_RAW — a
# capability every fresh user namespace grants — and writes the same
# classic-pcap output babel_decode.py parses.
python3 "$REPO/tests/interop/pcap_sniff.py" veth0a "$OUT/babel.pcap" 6696 2>"$OUT/sniff.log" &
SNIFF_PID=$!
trap "kill $SNIFF_PID 2>/dev/null || true" EXIT

# Start the reference BIRD daemon. Minimal config: Babel on veth0b,
# listening for lr's announcements. We accept all routes.
# Use <<EOF (not <<'EOF') so $OUT is expanded by the shell — BIRD
# needs the absolute path, not a shell variable.
cat > "$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
log stderr all;
router id 10.0.0.2;
ipv4 table lr_v4;
ipv6 table lr_v6;
protocol device { }
protocol direct {
    ipv4;
    ipv6;
}
protocol babel interconn {
    ipv4 { import all; export all; };
    ipv6 { import all; export all; };
    interface "veth0b" {
        type wireless;
        rxcost 192;
    };
}
EOF

bird -f -c "$OUT/bird.conf" -s "$OUT/bird.ctl" &
BIRD_PID=$!
trap "kill $BIRD_PID 2>/dev/null || true; kill $SNIFF_PID 2>/dev/null || true" EXIT

# Wait for BIRD to come up.
for i in $(seq 1 30); do
    if [ -S "$OUT/bird.ctl" ]; then break; fi
    # Check if BIRD died early (e.g. config error).
    if ! kill -0 "$BIRD_PID" 2>/dev/null; then
        echo "FAIL: BIRD exited early — log:"
        cat "$OUT/bird.log" 2>/dev/null || echo "(no log file)"
        exit 1
    fi
    sleep 0.5
done
if [ ! -S "$OUT/bird.ctl" ]; then
    echo "FAIL: BIRD control socket did not appear — log:"
    cat "$OUT/bird.log" 2>/dev/null || echo "(no log file)"
    exit 1
fi

# Start lr-daemon. The babel interface pattern matches 'veth0a' (or any
# 'veth*' — we use 'veth*' to also exercise the glob path).
cat > "$OUT/lr.lr" <<'EOF'
protocol "babel";
bgp {
    local_as 4242420078;
    router_id "172.23.10.102";
    listen_addr "0.0.0.0:179";
    local_address "172.23.10.102";
    hold_time 90s;
    graceful_restart_time 120s;
    mp_families [ipv4-unicast, ipv6-unicast];
    ebgp_policy "rfc8212";
    roa_validate true;
    roa_invalid_action "reject";
    soft_reconfig_inbound true;
}
babel {
    port 6696;
    interface "veth0a" {
        type "tunnel";
        rxcost 192;
        rtt_cost 100;
        rtt_min 10ms;
        rtt_max 120ms;
    }
    import_filter "babel-import-all";
    export_filter "babel-export-static-babel";
}
static {
    route "172.23.10.96/27" { next_hop "blackhole"; metric 10; }
    route "10.127.32.0/24" { next_hop "blackhole"; metric 10; }
    route "fd00:286:11e::/48" { next_hop "blackhole"; metric 10; }
    route "fd10:127:286::/48" { next_hop "blackhole"; metric 10; }
    route "172.23.10.102/32" { next_hop "blackhole"; metric 10; }
    route "10.127.32.102/32" { next_hop "blackhole"; metric 10; }
    route "fd00:286:11e:6::/64" { next_hop "blackhole"; metric 10; }
    route "fd10:127:286:6::/64" { next_hop "blackhole"; metric 10; }
}
filter "babel-import-all" {
    if proto != "babel" then accept;
    accept;
}
filter "babel-export-static-babel" {
    if proto == "static" then accept;
    if proto == "babel" then accept;
    reject;
}
EOF

# Run lr-daemon. We need CAP_NET_ADMIN for --install-kernel-routes;
# under unshare -Urn we have it (the new user+net ns grants it).
$BIN --config "$OUT/lr.lr" --install-kernel-routes > "$OUT/lr.log" 2>&1 &
LR_PID=$!
trap "kill $LR_PID 2>/dev/null || true; kill $BIRD_PID 2>/dev/null || true; kill $SNIFF_PID 2>/dev/null || true" EXIT

# Wait for lr's babel interface to come up.
for i in $(seq 1 30); do
    if grep -q "babel interface veth0a session" "$OUT/lr.log"; then break; fi
    sleep 0.5
done

echo "=== lr babel startup banner ==="
grep -E "babel interface veth0a|extended_next_hop|transports" "$OUT/lr.log" || true

# Phase 1: verify the auto-enable (or explicit opt-in) fired.
if ! grep -q "extended_next_hop" "$OUT/lr.log"; then
    echo "FAIL: lr did not log extended_next_hop status"
    cat "$OUT/lr.log"
    exit 1
fi
echo "PASS: lr logged extended_next_hop status"

# Phase 2: verify lr's blackhole routes reached the local kernel FIB.
# (Linux RTN_BLACKHOLE shows up as 'blackhole' in 'ip route show'.)
sleep 2  # let the daemon install the static routes
for prefix in "172.23.10.102/32" "10.127.32.0/24" "172.23.10.96/27"; do
    if ip route show "$prefix" | grep -q "blackhole"; then
        echo "PASS: kernel FIB has blackhole route for $prefix"
    else
        echo "FAIL: kernel FIB missing blackhole route for $prefix"
        ip route show "$prefix" || true
        exit 1
    fi
done

# Phase 3: wait for Babel convergence.
echo "=== Waiting for Babel convergence (max 30s) ==="
# BIRD 2.x uses 'show babel routes', BIRD 3.x uses 'show babel entries' —
# try both. The adjacency and the v6 routes are HARD requirements; the
# v4-over-v6 (RFC 9229 AE 4) routes are asserted on BIRD >= 3 — BIRD 2.x
# has no AE 4 support (silently ignored, no datagram abort) so there the
# emission is pcap-verified instead.
BIRD_VERSION=$(birdc -s "$OUT/bird.ctl" show status 2>/dev/null | grep -oE "BIRD [0-9]+\.[0-9]+" | head -1 || true)
echo "BIRD version: ${BIRD_VERSION:-unknown}"
BIRD_MAJOR=$(echo "$BIRD_VERSION" | grep -oE "[0-9]+" | head -1 || echo 0)
BIRD_BABEL_CMD="show babel entries"
ENTRIES=""
for i in $(seq 1 60); do
    ENTRIES=$(birdc -s "$OUT/bird.ctl" show babel entries 2>/dev/null || true)
    if [ -z "$ENTRIES" ]; then
        ENTRIES=$(birdc -s "$OUT/bird.ctl" show babel routes 2>/dev/null || true)
        if [ -n "$ENTRIES" ]; then BIRD_BABEL_CMD="show babel routes"; fi
    fi
    if echo "$ENTRIES" | grep -q "fd00:286:11e:6::/64"; then
        break
    fi
    sleep 0.5
done

BIRD_ENTRIES=$(birdc -s "$OUT/bird.ctl" $BIRD_BABEL_CMD 2>/dev/null || true)
echo "=== BIRD babel entries ($BIRD_BABEL_CMD) ==="
echo "$BIRD_ENTRIES"
echo "=== BIRD babel neighbors ==="
BIRD_NEIGHBORS=$(birdc -s "$OUT/bird.ctl" show babel neighbors 2>/dev/null || true)
echo "$BIRD_NEIGHBORS"
echo "=== BIRD log (last 20 lines) ==="
tail -20 "$OUT/bird.log" 2>/dev/null || echo "(no log file)"

# HARD: the adjacency must form. A v6-only veth pair delivers multicast
# reliably in the unshare -Urn environment (the earlier SKIP was hiding
# real regressions).
echo "$BIRD_NEIGHBORS" | grep -q "fe80::1" \
    || { echo "FAIL: BIRD has no Babel adjacency with lr"; cat "$OUT/lr.log"; exit 1; }
echo "PASS: babel adjacency formed on the v6-only link"

# HARD: the v6 routes must propagate.
echo "$BIRD_ENTRIES" | grep -q "fd00:286:11e:6::/64" \
    || { echo "FAIL: BIRD did not learn fd00:286:11e:6::/64 from lr"; exit 1; }
echo "PASS: BIRD learned the v6 routes from lr"

# HARD on BIRD >= 3 (AE 4 support), pcap-verified on BIRD 2.
if [ "$BIRD_MAJOR" -ge 3 ] 2>/dev/null; then
    for prefix in "172.23.10.102/32" "10.127.32.0/24" "172.23.10.96/27"; do
        echo "$BIRD_ENTRIES" | grep -q "$prefix" \
            || { echo "FAIL: BIRD 3 did not learn $prefix (v4-over-v6, AE 4)"; exit 1; }
    done
    echo "PASS: BIRD learned the v4-over-v6 routes (AE 4, RFC 9229)"
else
    echo "NOTE: BIRD 2 has no AE 4 support — the v4-over-v6 emission is pcap-verified below"
fi

# Phase 4: stop the daemons and analyse the pcap.
kill $LR_PID 2>/dev/null || true
kill $BIRD_PID 2>/dev/null || true
sleep 1
kill $SNIFF_PID 2>/dev/null || true
sleep 0.5
trap - EXIT

# Phase 5: full TLV-level pcap analysis with the babel_decode.py
# decoder (the same one babel_dualstack_bird.sh uses).
DECODE="$REPO/tests/interop/babel_decode.py"
DECODED=$(python3 "$DECODE" "$OUT/babel.pcap" 500 2>/dev/null || true)
echo "=== lr's first v6-transport announcement carrying Updates ==="
echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696" | grep "Update(" | head -1 || true

# HARD: lr is announcing on the v6-only link.
echo "$DECODED" | grep -q "fe80:0000:0000:0000:0000:0000:0000:0001:6696" \
    || { echo "FAIL: no Babel packets from lr in the capture"; exit 1; }
echo "PASS: lr emitted Babel packets on the v6-only link"

# HARD: the v4 routes ride the AE 4 (IPv4-via-IPv6, RFC 9229 2.4)
# encoding — the form BIRD 3 and babeld accept. The previous
# AE 1 + AE 2-NextHop pairing made BIRD abort the whole datagram
# ("Update must have next hop"), which is what the old soft-SKIP hid.
LR_AE4=$(echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696" | grep "Update(ae=v4via6 172.23.10.102/32" || true)
[ -n "$LR_AE4" ] || { echo "FAIL: no AE 4 v4 Update for 172.23.10.102/32 on the v6-only link"; exit 1; }
# On a v6-only interface every v4 Update must be AE 4 (there is no v4
# next hop to announce, so plain AE 1 is never legal here).
BAD_AE1=$(echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696" | grep "Update(ae=v4 " || true)
if [ -n "$BAD_AE1" ]; then
    echo "FAIL: plain AE 1 v4 Update on a v6-only link (must be AE 4, RFC 9229):"
    echo "$BAD_AE1" | head -2
    exit 1
fi
echo "PASS: v4-over-v6 Updates use the AE 4 encoding"

# The v6 next hop TLV precedes the Updates it carries.
V6_ANNOUNCE=$(echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696" | grep "Update(ae=v4via6 172.23.10.102/32" | head -1 || true)
echo "$V6_ANNOUNCE" | grep -q "NextHop(ae=v6 fe80:0000:0000:0000:0000:0000:0000:0001)" \
    || { echo "FAIL: no AE 2 NextHop TLV in the announcement"; exit 1; }
echo "PASS: AE 2 NextHop TLV carries the v4-over-v6 Updates"

echo "=== ALL CHECKS PASSED ==="
INNER
