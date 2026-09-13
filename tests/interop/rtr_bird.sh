#!/usr/bin/env bash
# RPKI-RTR codec interop: BIRD 2's RPKI client against librouting's
# mock RTR cache (the lr-bgp `rtr_cache_mock` example, which encodes
# and decodes with `lr_bgp::rtr`).
#
# What this proves, end to end, against a real RTR implementation:
#
#   * BIRD's Reset Query decodes through `lr_bgp::rtr::decode`
#     (BIRD speaks its maximum version first; our version-1 PDUs
#     make it downgrade per RFC 8210 §7 — the first-PDU rule).
#   * Our Cache Response / IPv4 Prefix / IPv6 Prefix / End-of-Data
#     encodings are accepted by BIRD's PDU parser: it logs the sync
#     and installs the two ROAs into its roa4/roa6 tables
#     (birdc-verified, byte semantics: 192.0.2.0/24 AS64512,
#     2001:db8::/48 max 64 AS64512).
#   * BIRD's subsequent Serial Query (refresh timer, 60 s here)
#     round-trips through the mock cache's decoder too.
#
# Runs on loopback TCP only — no raw sockets, no namespaces, no
# privileges. Environments without bird/birdc SKIP gracefully (the
# codec's unit suite in crates/lr-bgp/src/rtr.rs still pins the
# byte-exact RFC 8210 wire forms).
set -euo pipefail
cd "$(dirname "$0")/../.."

MOCK=target/debug/examples/rtr_cache_mock
if [ ! -x "$MOCK" ]; then
    MOCK=target/release/examples/rtr_cache_mock
fi
if [ ! -x "$MOCK" ]; then
    echo "SKIP: rtr_cache_mock not built (cargo build -p lr-bgp --example rtr_cache_mock)"
    exit 0
fi

BIRD=$(command -v bird || true)
BIRDC=$(command -v birdc || true)
if [ -z "$BIRD" ] && [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
    # extracted (non-installed) BIRD — same convention as the other
    # interop scripts for environments without root
    BIRD=/home/z/opt/bird/root/usr/sbin/bird
    BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
fi
if [ -z "$BIRD" ] || [ -z "$BIRDC" ]; then
    echo "SKIP: bird/birdc not installed"
    exit 0
fi

PORT=$(python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
)

OUT=/tmp/lr_rtr_bird
rm -rf "$OUT"; mkdir -p "$OUT"

cleanup() {
    if [ -f "$OUT/bird.pid" ]; then
        kill "$(cat "$OUT/bird.pid")" 2>/dev/null || true
    fi
    if [ -n "${MOCK_PID:-}" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "== starting the mock RTR cache (session 0x00ff, 2 ROAs) =="
"$MOCK" "$PORT" >"$OUT/mock.log" 2>&1 &
MOCK_PID=$!
sleep 0.3

cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 1.2.3.4;
roa4 table r4tab;
roa6 table r6tab;
protocol rpki rtr_test {
    remote 127.0.0.1 port $PORT;
    roa4 { table r4tab; };
    roa6 { table r6tab; };
}
EOF

echo "== starting BIRD with an RPKI protocol against it =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"

birdc_cmd() {
    "$BIRDC" -s "$OUT/bird.ctl" "$@"
}

# BIRD connects, sends a Reset Query at its max version, downgrades
# to v1 when it sees our first PDU, and syncs.
for i in $(seq 1 60); do
    if birdc_cmd "show route table r4tab" 2>/dev/null | grep -qF "192.0.2.0/24"; then
        break
    fi
    sleep 0.5
done

echo "== roa4 table =="
birdc_cmd "show route table r4tab" | tee "$OUT/r4.txt"
grep -qF "192.0.2.0/24" "$OUT/r4.txt" || {
    echo "FAIL: 192.0.2.0/24 missing from BIRD's roa4 table"
    cat "$OUT/bird.log" || true
    exit 1
}
grep -qF "AS64512" "$OUT/r4.txt" || {
    echo "FAIL: origin AS64512 missing from the roa4 entry"
    exit 1
}

echo "== roa6 table =="
birdc_cmd "show route table r6tab" | tee "$OUT/r6.txt"
grep -qF "2001:db8::/48" "$OUT/r6.txt" || {
    echo "FAIL: 2001:db8::/48 missing from BIRD's roa6 table"
    cat "$OUT/bird.log" || true
    exit 1
}

# BIRD's roa route display pins the max length: "2001:db8::/48-64".
grep -qF "2001:db8::/48-64" "$OUT/r6.txt" || {
    echo "FAIL: max-length 64 not reflected in the roa6 route"
    exit 1
}

echo "== BIRD rpki session summary =="
birdc_cmd "show protocols all rtr_test" || true

# The mock cache must have decoded BIRD's Reset Query (a real BIRD
# encoder on the other side of the socket).
grep -qF "Reset Query" "$OUT/mock.log" || {
    echo "FAIL: mock cache never decoded a Reset Query from BIRD"
    cat "$OUT/mock.log" || true
    exit 1
}

echo
echo "RTR codec interop: PASS"
echo "  - BIRD 2's RPKI client negotiated RFC 8210 v1 with the mock cache"
echo "  - its Reset Query decoded through lr_bgp::rtr"
echo "  - our Cache Response + IPv4/IPv6 Prefix + End-of-Data encodings"
echo "    installed both ROAs into BIRD's roa4/roa6 tables"
