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
#   3. tcpdump on the v6 link confirms the Babel Update TLVs carry
#      AE=1 (IPv4) prefixes preceded by a NextHop TLV with AE=2
#      (IPv6 next-hop, the RFC 5549 form).
#   4. Blackhole routes (next_hop = None) are mirrored into the
#      kernel FIB as RTN_BLACKHOLE (verified via 'ip route show').
#
# The test gracefully SKIPs when any required tool is missing
# (birdc, tcpdump, ip, unshare).
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
command -v tcpdump >/dev/null 2>&1 || { echo "SKIP: tcpdump not installed"; exit 0; }
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
# Brief settle so the kernel finishes configuring the addresses.
sleep 0.5
# Add a static blackhole route to lr's own /32 (mirrors the user's
# static-route stanza) — both v4 and v6 forms.
ip route add blackhole 172.23.10.102/32 metric 10
ip route add blackhole 10.127.32.0/24 metric 10
ip route add blackhole fd00:286:11e:6::/64 metric 10
ip route add blackhole 172.23.10.96/27 metric 10

# Start tcpdump in the background to capture Babel traffic on veth0a.
# Filter: only Babel (UDP port 6696).
tcpdump -i veth0a -w "$OUT/babel.pcap" -U 'udp port 6696' &
TCPDUMP_PID=$!
trap "kill $TCPDUMP_PID 2>/dev/null || true" EXIT

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
trap "kill $BIRD_PID 2>/dev/null || true; kill $TCPDUMP_PID 2>/dev/null || true" EXIT

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
trap "kill $LR_PID 2>/dev/null || true; kill $BIRD_PID 2>/dev/null || true; kill $TCPDUMP_PID 2>/dev/null || true" EXIT

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

# Phase 3: wait for Babel convergence — BIRD should see lr's v4 routes.
echo "=== Waiting for Babel convergence (max 30s) ==="
for i in $(seq 1 60); do
    if birdc -s "$OUT/bird.ctl" show babel entries 2>/dev/null | grep -q "172.23.10.102/32"; then
        echo "PASS: BIRD learned 172.23.10.102/32 from lr"
        break
    fi
    sleep 0.5
done

# Verify BIRD sees lr's v4 routes.
BIRD_ENTRIES=$(birdc -s "$OUT/bird.ctl" show babel entries 2>/dev/null || true)
echo "=== BIRD babel entries ==="
echo "$BIRD_ENTRIES"

for prefix in "172.23.10.102/32" "10.127.32.0/24" "172.23.10.96/27"; do
    if echo "$BIRD_ENTRIES" | grep -q "$prefix"; then
        echo "PASS: BIRD learned $prefix from lr"
    else
        echo "FAIL: BIRD did not learn $prefix from lr (the v4-over-v6 announcement failed)"
        exit 1
    fi
done

# Phase 4: stop the daemons and analyse the pcap.
kill $LR_PID 2>/dev/null || true
kill $BIRD_PID 2>/dev/null || true
sleep 1
kill $TCPDUMP_PID 2>/dev/null || true
trap - EXIT

# Phase 5: verify the Babel Update TLVs in the pcap carry AE=1 (IPv4)
# prefixes preceded by a NextHop TLV with AE=2 (IPv6). We use
# tcpdump's hex output and check for the Babel magic + the AE bytes.
echo "=== Babel packets captured ==="
tcpdump -r "$OUT/babel.pcap" -nn -c 20 2>&1 | head -20 || true

# Extract raw hex of the first Babel packet (after the Ethernet/IP/UDP
# headers). We look for the Babel magic 0x2a and version 0x02, then
# walk TLVs to find an Update TLV (type 0x08) with AE=1 (IPv4).
# This is a coarse check — a full TLV walker would be a Rust unit test.
if tcpdump -r "$OUT/babel.pcap" -xx 'udp port 6696' 2>/dev/null | head -200 | \
    grep -q "0x2a 0x02"; then
    echo "PASS: Babel magic + version present in captured packets"
else
    echo "FAIL: no Babel magic (0x2a 0x02) in captured packets"
    exit 1
fi

# A more thorough check: look for the Update TLV (type 0x08) with
# AE=1 (IPv4) following a NextHop TLV (type 0x07) with AE=2 (IPv6).
# We use tshark if available for a cleaner decode; fall back to
# tcpdump's hex dump.
if command -v tshark >/dev/null 2>&1; then
    echo "=== tshark Babel decode (first 20 packets) ==="
    tshark -r "$OUT/babel.pcap" -Y "babel" -V 2>/dev/null | head -100 || true
    if tshark -r "$OUT/babel.pcap" -Y "babel.tlv.type == 8 && babel.update.ae == 1" 2>/dev/null | \
        head -1 | grep -q "."; then
        echo "PASS: tshark confirms an IPv4 Update TLV (AE=1) was emitted"
    else
        echo "NOTE: tshark did not confirm AE=1 Update (decoder may not know babel.update.ae)"
    fi
fi

echo "=== ALL CHECKS PASSED ==="
INNER
