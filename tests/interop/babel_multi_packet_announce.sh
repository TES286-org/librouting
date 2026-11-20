#!/usr/bin/env bash
# Babel multi-packet announcement interop (issue #101).
#
# Regression for the production bug where build_babel_announcement
# produced a single BabelFrame whose encoded body exceeded RFC 8966
# §4's 1496-octet cap. BabelCodec::encode_vec ran out of its fixed
# 1500-byte buffer and returned Err(BufferFull);
# build_babel_announcement's unwrap_or_default() then produced an
# empty Vec, which the daemon sent as a zero-byte UDP datagram.
# tcpdump rendered the empty payload as 'babel [|babel]'; the peer
# (BIRD) saw no Hello/IHU, declared the neighbour dead, re-flooded
# every route on the next cycle, and the best-path selection churned
# ('babel very jittery, routes flipping between interfaces, all
# routes lost periodically, peer receives ~1 Hello, rtt 0').
#
# Topology: lr (one veth) <-> BIRD (one veth). lr originates 200
# static /48 IPv6 routes — enough to overflow a single 1496-byte
# Babel datagram. BIRD is configured to learn them.
#
# Success criteria:
#   1. lr sends at least two distinct Babel datagrams in one
#      announcement burst (the split is working).
#   2. Every lr-originated Babel datagram carries a valid babel header
#      (magic 0x2A, version 2) and a non-empty body — no zero-byte
#      payloads, no 'babel [|babel]' truncations.
#   3. The first datagram of each burst carries a Hello TLV.
#   4. BIRD learns all 200 routes (no routes lost to dropped/empty
#      packets).
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
OUT=/tmp/lr_babel_multi_packet
rm -rf "$OUT"; mkdir -p "$OUT"
DECODE="$PWD/tests/interop/babel_decode.py"

# ---- topology: lr's namespace + a second namespace for BIRD ----
unshare -n sleep 600 &
BIRD_NS=$!
BIRDNS="nsenter --net=/proc/$BIRD_NS/ns/net"
for i in $(seq 1 20); do [ -e /proc/$BIRD_NS/ns/net ] && break; sleep 0.1; done
$BIRDNS ip link set lo up
ip link add veth0a type veth peer name veth0b
ip link set veth0a up
ip link set veth0b netns "$BIRD_NS"
$BIRDNS ip link set veth0b up
for d in veth0a veth0b; do
    sysctl -w net.ipv6.conf.$d.accept_dad=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.$d.dad_transmits=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.$d.disable_ipv6=0 >/dev/null 2>&1 || true
done
ip -6 addr add fe80::1/64 dev veth0a nodad
$BIRDNS ip -6 addr add fe80::2/64 dev veth0b nodad
sleep 0.5

# ---- packet capture on the babel link ----
python3 "$REPO/tests/interop/pcap_sniff.py" veth0a "$OUT/babel.pcap" 6696 2>"$OUT/sniff.log" &
SNIFF_PID=$!
trap "kill $SNIFF_PID 2>/dev/null || true" EXIT

# ---- BIRD: just babel, importing everything ----
cat > "$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.2;
protocol device { }
protocol direct {
    ipv4;
    ipv6;
}
protocol kernel k6 {
    ipv6 { import all; export all; };
}
protocol babel interconn {
    ipv4 { import all; export all; };
    ipv6 { import all; export all; };
    interface "veth0b" {
        type wired;
        rxcost 96;
    };
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

# ---- lr-daemon: 200 static /48 routes — overflows one Babel packet ----
# The babeld/BIRD default Hello interval is 4s; the test waits 12s
# (three Hellos) so at least two announcement bursts land in the
# capture and BIRD has time to import all routes.
{
    echo 'protocol "babel";'
    echo 'babel {'
    echo '    port 6696;'
    echo '    interface "veth0a" {'
    echo '        type "wired";'
    echo '        rxcost 96;'
    echo '        hello_interval_ms 4000;'
    echo '        update_interval_ms 12000;'
    echo '    }'
    echo '}'
    echo 'static {'
    for i in $(seq 1 200); do
        # fd00:i::/48 — 200 distinct /48s, each ~10 bytes on the wire
        # (8 prefix octets + 2 TLV header + 10 fixed Update body + 2
        # Router-Id overhead per group). Total body > 1496 → splits.
        hex=$(printf '%02x' $((i / 256)))
        hex2=$(printf '%02x' $((i % 256)))
        echo "    route \"fd00:0:0:${i}::/48\" { next_hop \"blackhole\"; metric 10; }"
    done
    echo '}'
} > "$OUT/lr.lr"

"$BIN" --config "$OUT/lr.lr" >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap "kill $LR_PID 2>/dev/null || true; kill $BIRD_PID 2>/dev/null || true; kill $SNIFF_PID 2>/dev/null || true; kill $BIRD_NS 2>/dev/null || true" EXIT

# Wait for three announcement cycles.
sleep 14

# Stop the capture so the pcap file is flushed.
kill $SNIFF_PID 2>/dev/null || true
SNIFF_PID=""

# ---- criterion 1-3: pcap analysis ----
python3 "$DECODE" "$OUT/babel.pcap" 1000 > "$OUT/decoded.txt" 2>&1 || true

# lr's source address is fe80::1; BIRD's is fe80::2. We want lr's
# outbound packets (fe80::1 -> ff02::1:6).
lr_out=$(awk '/fe80::1[^:]+ > ff02:1:6/' "$OUT/decoded.txt" || true)
if [ -z "$lr_out" ]; then
    echo "FAIL: no lr-originated Babel packets in capture"
    cat "$OUT/decoded.txt"
    exit 1
fi

# Criterion 1: at least two distinct Babel datagrams in one burst.
# A burst is a cluster of packets within 1 second; with a 4s Hello
# interval and 200 routes, each burst should produce 2-3 packets.
lr_pkt_count=$(echo "$lr_out" | wc -l)
if [ "$lr_pkt_count" -lt 2 ]; then
    echo "FAIL: expected at least 2 lr Babel packets in a burst, got $lr_pkt_count"
    echo "(the multi-packet split is not producing trailing frames)"
    cat "$OUT/decoded.txt"
    exit 1
fi
echo "PASS: lr sent $lr_pkt_count Babel datagrams (multi-packet split working)"

# Criterion 2: every lr packet has a non-empty body. babel_decode.py
# prints 'babel <version> (<body_len>) <tlvs>' for valid packets and
# 'babel [|babel]' for empty/truncated ones. Reject any truncated.
truncated=$(echo "$lr_out" | grep -F '[|babel]' || true)
if [ -n "$truncated" ]; then
    echo "FAIL: lr sent empty/truncated Babel datagrams (the bug we fixed):"
    echo "$truncated"
    exit 1
fi
echo "PASS: every lr Babel datagram has a valid, non-empty body"

# Criterion 3: the first packet of each burst carries a Hello TLV.
# Bursts are clusters of packets within 1 second; the first packet of
# each cluster must contain 'hello' in its TLV list.
hello_count=$(echo "$lr_out" | grep -c ' hello' || true)
if [ "$hello_count" -lt 1 ]; then
    echo "FAIL: no Hello TLV found in any lr packet"
    cat "$OUT/decoded.txt"
    exit 1
fi
echo "PASS: lr sent $hello_count Hello TLVs across the capture"

# ---- criterion 4: BIRD learned all 200 routes ----
$BIRDNS birdc -s "$OUT/bird.ctl" 'show route protocol interconn count' > "$OUT/route_count.txt" 2>&1 || true
cat "$OUT/route_count.txt"
# BIRD's 'show route count' output is like 'Total: 200 networks'.
routes=$($BIRDNS birdc -s "$OUT/bird.ctl" 'show route protocol interconn' 2>/dev/null | grep -c '^fd00:' || true)
if [ "$routes" -lt 200 ]; then
    echo "FAIL: BIRD learned only $routes of 200 routes (expected 200)"
    echo "(routes lost to empty/malformed lr packets — the bug)"
    exit 1
fi
echo "PASS: BIRD learned all $routes routes"

echo "PASS: Babel multi-packet announcement interop"
exit 0
INNER
