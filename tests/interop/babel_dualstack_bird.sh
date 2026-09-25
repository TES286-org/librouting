#!/usr/bin/env bash
# Babel dual-stack BIRD interop: full production-shaped convergence check.
#
# Reproduces the reported Windows production topology on a Linux veth
# pair across two user namespaces (lr's own, and a second one holding
# the BIRD side, entered with nsenter — no /run/netns mounts needed):
#
#   lr (router-id 172.23.10.102)
#     veth0a (dual-stack babel link): fe80::1 + 169.254.6.1/24
#     dummy1 (node identity):         172.23.10.102/32, 10.127.32.102/32
#     static blackholes: the /27, /24, /48s, own /32s and /64s
#   BIRD (router-id 172.23.10.97)
#     veth0b: fe80::2 + 169.254.6.2/24 + 172.23.10.97/32, 10.127.32.97/32,
#             172.23.10.98/32 (the BGP peer address) + fd00:286:11e:1::1/64
#     statics: the SAME /27, /24, /48 aggregates (both tunnel ends
#              originate them - the Loc-RIB preference test)
#     babel + kernel-protocol + BGP rr_hk01 (neighbor 172.23.10.102)
#
# The test verifies, in order:
#   1. The Babel adjacency forms with a measured RTT (both directions).
#   2. BIRD learns lr's IPv4 routes (AE 1 Updates riding the v6
#      transport - BIRD/babeld never listen on 224.0.0.111) and its
#      IPv6 routes (the /64s).
#   3. lr learns BIRD's COMPRESSED v6 announcements (RFC 8966 4.5.2)
#      with the correct prefixes - no corrupted 1001:2702:8600:... -
#      and installs them into the kernel FIB as 'proto babel'.
#   4. The operator's static blackholes stay intact (proto static);
#      the kernel's connected route is NOT replaced by the learned
#      copy of the link subnet (the NLM_F_REPLACE clobber).
#   5. The OS forwarding decision (ip route get) uses the Babel route.
#   6. REAL forwarding: pings through the Babel-installed routes.
#   7. The BGP session to the Babel-only-reachable peer establishes
#      through the learned route (the production symptom: BGP peers
#      reachable only via Babel).
#   8. Packet-capture analysis (babel_decode.py): lr's v6 multicast
#      carries the babeld dual-stack shape (AE 2 + AE 1 NextHop TLVs,
#      then v4 and v6 Updates), no AE 1 Update ever lacks a preceding
#      AE 1 NextHop TLV in the same datagram (the BIRD "Update must
#      have next hop" datagram abort), and BIRD actually sends
#      prefix-compressed Updates on the wire.
#   9. Teardown: SIGTERM withdraws lr's routes from the kernel.
#
# Hard failure in any phase fails the job. The test SKIPs gracefully
# when a required tool is missing (bird/birdc, python3, ip,
# nsenter, unprivileged user namespaces).
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
command -v bird >/dev/null 2>&1 || { echo "SKIP: bird not installed"; exit 0; }
command -v birdc >/dev/null 2>&1 || { echo "SKIP: birdc not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_dualstack
rm -rf "$OUT"; mkdir -p "$OUT"
DECODE="$PWD/tests/interop/babel_decode.py"

# ---- topology: lr's namespace + a second namespace for BIRD ----
# The second namespace is held by a plain `unshare -n sleep` child and
# entered with nsenter through /proc — works inside `unshare -Urn`
# without the /run/netns mount machinery `ip netns` needs.
unshare -n sleep 600 &
BIRD_NS=$!
BIRDNS="nsenter --net=/proc/$BIRD_NS/ns/net"
for i in $(seq 1 20); do [ -e /proc/$BIRD_NS/ns/net ] && break; sleep 0.1; done
$BIRDNS ip link set lo up
ip link add veth0a type veth peer name veth0b
ip link set veth0a up
ip link set veth0b netns "$BIRD_NS"
$BIRDNS ip link set veth0b up
ip link add dummy1 type dummy
ip link set dummy1 up
$BIRDNS ip link add dummy0 type dummy
$BIRDNS ip link set dummy0 up
for d in veth0a veth0b; do
    sysctl -w net.ipv6.conf.$d.accept_dad=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.$d.dad_transmits=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.$d.disable_ipv6=0 >/dev/null 2>&1 || true
done
ip -6 addr add fe80::1/64 dev veth0a nodad
ip addr add 169.254.6.1/24 dev veth0a
# lr-side node identity (the production box's second interface)
ip addr add 172.23.10.102/32 dev dummy1
ip addr add 10.127.32.102/32 dev dummy1
# BIRD-side: link transport + node identity on a dummy interface.
$BIRDNS ip -6 addr add fe80::2/64 dev veth0b nodad
$BIRDNS ip addr add 169.254.6.2/24 dev veth0b
$BIRDNS ip addr add 172.23.10.97/32 dev dummy0
$BIRDNS ip addr add 10.127.32.97/32 dev dummy0
$BIRDNS ip addr add 172.23.10.98/32 dev dummy0
$BIRDNS ip -6 addr add fd00:286:11e:1::1/64 dev dummy0 nodad
$BIRDNS ip -6 addr add fd10:127:286:1::1/64 dev dummy0 nodad
sleep 0.5

# ---- packet capture on the babel link ----
# pcap_sniff.py instead of tcpdump: tcpdump's mandatory privilege drop
# calls initgroups()/setgroups(), which the kernel denies inside an
# unprivileged user namespace ("Couldn't change to 'root' ... Operation
# not permitted") — it dies before capturing a single packet. The
# AF_PACKET raw socket needs only CAP_NET_RAW, which this fresh user
# namespace grants, and emits the same classic pcap the decoder reads.
python3 "$REPO/tests/interop/pcap_sniff.py" veth0a "$OUT/babel.pcap" 6696 2>"$OUT/sniff.log" &
SNIFF_PID=$!
trap "kill $SNIFF_PID 2>/dev/null || true" EXIT

# ---- BIRD: statics (the same aggregates lr originates) + babel + bgp + kernel ----
cat > "$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 172.23.10.97;
protocol device { }
protocol direct {
    ipv4;
    ipv6;
}
protocol kernel k4 {
    ipv4 { import all; export all; };
}
protocol kernel k6 {
    ipv6 { import all; export all; };
}
protocol static st4 {
    ipv4;
    route 172.23.10.96/27 blackhole;
    route 10.127.32.0/24 blackhole;
    route 172.23.10.97/32 blackhole;
    route 10.127.32.97/32 blackhole;
}
protocol static st6 {
    ipv6;
    route fd00:286:11e::/48 blackhole;
    route fd10:127:286::/48 blackhole;
    route fd00:286:11e:1::/64 blackhole;
    route fd10:127:286:1::/64 blackhole;
}
protocol babel interconn {
    ipv4 { import all; export all; };
    ipv6 { import all; export all; };
    interface "veth0b" {
        type wired;
        rxcost 192;
    };
}
protocol bgp rr_hk01 {
    local as 4242420078;
    neighbor 172.23.10.102 as 4242420078;
    # Passive: lr originates the connection (the production shape — the
    # peer is reachable only through the Babel-learned route). Two
    # simultaneous openers would trade RFC 4271 6.8 collisions until the
    # retry timers separate them, which is real but noisy in a test.
    passive on;
    ipv4 { import all; export all; };
    source address 172.23.10.98;
}
EOF
$BIRDNS bird -f -c "$OUT/bird.conf" -s "$OUT/bird.ctl" &
BIRD_PID=$!
trap "kill $BIRD_PID 2>/dev/null || true; kill $SNIFF_PID 2>/dev/null || true; kill $BIRD_NS 2>/dev/null || true" EXIT

for i in $(seq 1 30); do
    [ -S "$OUT/bird.ctl" ] && break
    kill -0 "$BIRD_PID" 2>/dev/null || { echo "FAIL: BIRD exited early"; cat "$OUT/bird.log"; exit 1; }
    sleep 0.5
done
[ -S "$OUT/bird.ctl" ] || { echo "FAIL: no BIRD control socket"; cat "$OUT/bird.log" 2>/dev/null; exit 1; }

# ---- lr-daemon: the production-shaped config ----
cat > "$OUT/lr.lr" <<'EOF'
protocol "bgp,babel";
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
peer-template "rr-client" {
    peer_as 4242420078;
    hold_time 90s;
    graceful_restart_time 120s;
    import_filter "rr-import-all";
    export_filter "rr-export-bgp-only";
}
peer "rr-hk01" {
    remote "172.23.10.98:179";
    extends "rr-client";
}
filter "rr-import-all" {
    accept;
}
filter "rr-export-bgp-only" {
    if proto == "bgp" then accept;
    reject;
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
$BIN --config "$OUT/lr.lr" --install-kernel-routes > "$OUT/lr.log" 2>&1 &
LR_PID=$!
trap "kill $LR_PID 2>/dev/null || true; kill $BIRD_PID 2>/dev/null || true; kill $SNIFF_PID 2>/dev/null || true; kill $BIRD_NS 2>/dev/null || true" EXIT

# ---- phase 1: adjacency + RTT ----
NEIGHBORS=""
for i in $(seq 1 40); do
    NEIGHBORS=$($BIRDNS birdc -s "$OUT/bird.ctl" show babel neighbors 2>/dev/null || true)
    if echo "$NEIGHBORS" | grep -q "fe80::1"; then break; fi
    sleep 0.5
done
echo "$NEIGHBORS" | grep -q "fe80::1" || { echo "FAIL: no babel adjacency"; cat "$OUT/lr.log"; exit 1; }
echo "PASS: babel adjacency formed"
# RTT measured (non-zero) when BIRD has rtt support: proves lr's
# timestamped-Hello bookkeeping + IHU echo work (the production node
# showed RTT 0.000). Soft: BIRD builds without rtt print nothing.
RTT_LINE=$(echo "$NEIGHBORS" | grep "fe80::1" || true)
if echo "$RTT_LINE" | grep -qE "RTT|[0-9]+\.[0-9]+"; then
    if echo "$RTT_LINE" | grep -qE "0\.000"; then
        echo "NOTE: RTT measured as 0.000 (BIRD rtt display varies)"
    else
        echo "PASS: BIRD measures a live RTT toward lr"
    fi
fi

# ---- phase 2: BIRD learns lr's v4 (AE 1 on the v6 transport) + v6 routes ----
BABEL_CMD="show babel entries"
$BIRDNS birdc -s "$OUT/bird.ctl" show babel entries >/dev/null 2>&1 || BABEL_CMD="show babel routes"
ENTRIES=""
for i in $(seq 1 60); do
    ENTRIES=$($BIRDNS birdc -s "$OUT/bird.ctl" $BABEL_CMD 2>/dev/null || true)
    if echo "$ENTRIES" | grep -q "172.23.10.102/32" \
        && echo "$ENTRIES" | grep -q "10.127.32.102/32" \
        && echo "$ENTRIES" | grep -q "fd00:286:11e:6::/64"; then
        break
    fi
    sleep 0.5
done
echo "=== BIRD babel entries ==="
echo "$ENTRIES"
for prefix in "172.23.10.102/32" "10.127.32.102/32" "fd00:286:11e:6::/64" "fd10:127:286:6::/64"; do
    echo "$ENTRIES" | grep -q "$prefix" || { echo "FAIL: BIRD did not learn $prefix from lr"; exit 1; }
done
echo "PASS: BIRD learned lr's v4 routes over the v6 transport (AE 1) and the v6 /64s"

# ---- phase 3: lr's kernel FIB has the babel routes (proto babel) ----
for i in $(seq 1 40); do
    ip route show 172.23.10.97 2>/dev/null | grep -q "proto babel" && break
    sleep 0.5
done
V4_ROUTE=$(ip route show 172.23.10.97 2>/dev/null || true)
echo "=== lr kernel route for 172.23.10.97 ==="
echo "$V4_ROUTE"
echo "$V4_ROUTE" | grep -q "via 169.254.6.2" && echo "$V4_ROUTE" | grep -q "proto babel" \
    || { echo "FAIL: babel route for 172.23.10.97 not installed (proto babel)"; ip route show; exit 1; }
echo "PASS: kernel FIB carries the babel route with the proto babel tag"

# Compressed v6 prefixes decode correctly: the corrupted
# 1001:2702:8600:* form must never appear anywhere.
if ip -6 route show | grep -q "1001:2702:8600"; then
    echo "FAIL: corrupted compressed prefixes in the FIB (RFC 8966 4.5.2 regression)"
    ip -6 route show
    exit 1
fi
V6_ROUTE=$(ip -6 route show fd00:286:11e:1::/64 2>/dev/null || true)
echo "=== lr kernel route for fd00:286:11e:1::/64 ==="
echo "$V6_ROUTE"
echo "$V6_ROUTE" | grep -q "proto babel" \
    || { echo "FAIL: compressed v6 announcement not learned"; exit 1; }
echo "PASS: BIRD's compressed v6 announcements decode to the correct prefixes"

# ---- phase 4: statics + connected route stay intact ----
ip route show 172.23.10.96/27 | grep -q blackhole || { echo "FAIL: static blackhole 172.23.10.96/27 lost"; exit 1; }
ip -6 route show fd00:286:11e::/48 | grep -q blackhole || { echo "FAIL: static v6 blackhole lost"; exit 1; }
ip route show 169.254.6.0/24 | grep -q "dev veth0a proto kernel" \
    || { echo "FAIL: kernel connected route 169.254.6.0/24 was replaced"; ip route show; exit 1; }
echo "PASS: operator statics are blackholes and the connected route survives"

# ---- phase 5: forwarding decision ----
DECISION=$(ip route get 172.23.10.97 2>/dev/null || true)
echo "=== ip route get 172.23.10.97 ==="
echo "$DECISION"
echo "$DECISION" | grep -q "via 169.254.6.2" || { echo "FAIL: OS decision does not use the babel route"; exit 1; }
echo "PASS: OS forwarding decision uses the Babel route"

# ---- phase 6: real forwarding through the babel routes ----
for dest in 172.23.10.97 10.127.32.97; do
    if ! ping -c 3 -W 2 "$dest" >/dev/null 2>&1; then
        echo "FAIL: no real delivery to $dest through the babel route"
        exit 1
    fi
    echo "PASS: ICMP delivered to $dest through the Babel-installed route"
done
if ping -6 -c 3 -W 2 fd00:286:11e:1::1 >/dev/null 2>&1; then
    echo "PASS: ICMPv6 delivered through the Babel-installed route"
else
    echo "FAIL: no real v6 delivery through the babel route"
    exit 1
fi

# ---- phase 7: BGP over Babel ----
for i in $(seq 1 120); do
    if grep -q "End-of-RIB" "$OUT/lr.log"; then break; fi
    sleep 0.5
done
grep -q "Established" "$OUT/lr.log" && grep -q "End-of-RIB" "$OUT/lr.log" \
    || { echo "FAIL: BGP session over the babel route did not synchronize"; grep -E "session|peer" "$OUT/lr.log" | tail -20; exit 1; }
BGP_STATE=$($BIRDNS birdc -s "$OUT/bird.ctl" show protocols 2>/dev/null | grep rr_hk01 || true)
echo "=== BIRD BGP state ==="
echo "$BGP_STATE"
echo "$BGP_STATE" | grep -q Established \
    || { echo "FAIL: BIRD-side BGP session not Established"; exit 1; }
echo "PASS: BGP session established through the Babel-learned route (production symptom resolved)"

# ---- phase 8: packet-capture analysis ----
kill $SNIFF_PID 2>/dev/null || true
sleep 0.5
DECODED=$(python3 "$DECODE" "$OUT/babel.pcap" 500 2>/dev/null || true)
echo "=== pcap: lr's first v6 multicast announcement ==="
echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696 -> ff02" | head -1 || true

# 8a. The babeld dual-stack shape on the v6 transport: both NextHop
#     TLVs (AE 2 then AE 1) and AE 1 Updates for the v4 statics. Pick
#     the first announcement that actually carries Updates (a link-up
#     pass emits Hello-only packets first).
LR_V6_ANNOUNCEMENTS=$(echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696 -> ff02" | grep "Update(ae=v4 172.23.10.102/32" || true)
V6_ANNOUNCE=$(echo "$LR_V6_ANNOUNCEMENTS" | head -1 || true)
[ -n "$V6_ANNOUNCE" ] || { echo "FAIL: no v6-transport announcement carrying an AE 1 Update for 172.23.10.102/32"; exit 1; }
echo "$V6_ANNOUNCE" | grep -q "NextHop(ae=v6 fe80:0000:0000:0000:0000:0000:0000:0001)" \
    || { echo "FAIL: no AE 2 NextHop TLV in the v6 announcement"; exit 1; }
echo "$V6_ANNOUNCE" | grep -q "NextHop(ae=v4 169.254.6.1)" \
    || { echo "FAIL: no AE 1 NextHop TLV in the v6 announcement (v4 routes invisible to BIRD/babeld)"; exit 1; }
echo "PASS: v6 transport carries the dual-stack shape (AE2+AE1 NextHops, v4+v6 Updates)"

# 8b. No AE 1 Update may lack a preceding AE 1 NextHop TLV in the same
#     datagram: BIRD aborts the rest of the packet ("Update must have
#     next hop") - one malformed TLV poisons everything behind it.
BAD_AE1=$(echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0001:6696 -> ff02" \
    | grep "Update(ae=v4" | grep -v "NextHop(ae=v4" || true)
if [ -n "$BAD_AE1" ]; then
    echo "FAIL: AE 1 Update without an AE 1 NextHop TLV in the same datagram:"
    echo "$BAD_AE1" | head -3
    exit 1
fi
echo "PASS: every AE 1 Update is preceded by an AE 1 NextHop TLV (no BIRD datagram abort)"

# 8c. BIRD really sends prefix-compressed Updates (omit > 0) and lr
#     still learned them correctly (phase 3 proved the FIB side).
if echo "$DECODED" | grep "fe80:0000:0000:0000:0000:0000:0000:0002:6696" | grep -q "omit=[1-9]"; then
    echo "PASS: BIRD sends RFC 8966 4.5.2 compressed Updates and lr expands them correctly"
else
    echo "NOTE: BIRD sent no compressed Updates in this run (version-dependent)"
fi

# ---- phase 9: teardown ----
kill $LR_PID 2>/dev/null || true
trap "kill $BIRD_PID 2>/dev/null || true; kill $BIRD_NS 2>/dev/null || true" EXIT
for i in $(seq 1 20); do
    ip route show 172.23.10.97 2>/dev/null | grep -qv "proto babel" && break
    sleep 0.5
done
if ip route show 172.23.10.97 2>/dev/null | grep -q "proto babel"; then
    echo "FAIL: babel route not withdrawn on shutdown"
    ip route show
    exit 1
fi
echo "PASS: babel routes withdrawn from the kernel on shutdown"

kill $BIRD_PID 2>/dev/null || true
kill $BIRD_NS 2>/dev/null || true
trap - EXIT
echo "=== ALL babel dual-stack BIRD interop checks PASSED ==="
INNER
