#!/usr/bin/env bash
# BGP aggregation interop: lr-daemon `[[aggregate]]` (RFC 4271 §9.2.2.2)
# against BIRD 2 as the receiver and judge.
#
#   BIRD 2 (AS64513, passive listener)
#     - static 198.51.100.0/24 + 198.51.101.0/24 (the specifics)
#     - exports them to lr, imports whatever lr sends back
#        ↑↓ BGP on 127.0.0.1
#   lr-daemon (AS64512, connector, [[aggregate]] 198.51.100.0/23)
#
# Success criteria (all judged inside BIRD, on the wire):
#   1. BIRD's table holds 198.51.100.0/23 learned from lr.
#   2. The route carries ATOMIC_AGGREGATE and AGGREGATOR
#      (AS64512 + lr's router-id 10.0.0.1) — the exact attributes
#      RFC 4271 §9.2.2.2 requires on an aggregate.
#   3. The AS_PATH is exactly the lr AS (a locally originated
#      aggregate: zeroed Loc-RIB path + eBGP prepend).
#   4. After BIRD withdraws the specifics (soft reconfig of the
#      static protocol), lr withdraws the aggregate: it disappears
#      from BIRD's table while the direct specifics linger in the
#      static protocol.
#
# The flags bug this test pins: lr used to encode AGGREGATOR as
# well-known (0x40) instead of optional transitive (0xC0) — BIRD
# logged "Malformed aggregator attribute - conflicting flags" and
# dropped the whole route. Unit tests asserted presence, not wire
# flags; only a real receiver catches that class of error.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           lr-daemon listen port (default 17993)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
        BIRD=/home/z/opt/bird/root/usr/sbin/bird
        BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
    else
        echo "SKIP: bird/birdc not found"
        exit 0
    fi
fi
if [ ! -x "$BIN" ]; then
    echo "SKIP: build lr-daemon first (cargo build -p lr-cli)"
    exit 0
fi

PORT=${PORT:-17993}
OUT=/tmp/lr_aggregate_bird
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the aggregation interop test.
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
    route 198.51.101.0/24 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local port 17992 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

cat >"$OUT/lr.toml" <<EOF
[bgp]
local_as = 64512
peer_as = 64513
router_id = "10.0.0.1"
peer_addr = "127.0.0.1:17992"
local_address = "127.0.0.1"
ebgp_policy = "accept-all"

[[aggregate]]
prefix = "198.51.100.0/23"
EOF

echo "== starting BIRD (AS64513, two covering specifics) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, [[aggregate]] 198.51.100.0/23) =="
"$BIN" --config "$OUT/lr.toml" >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT

# 1. Wait for the aggregate to arrive at BIRD (up to 30 s on slow runners).
ok_route=1
for i in $(seq 1 120); do
    sleep 0.25
    if "$BIRDC" -s "$OUT/bird.ctl" show route 198.51.100.0/23 2>/dev/null \
        | grep -q "198.51.100.0/23"; then
        ok_route=0
        break
    fi
done

# 2. Attribute-level verification: ATOMIC_AGGREGATE + AGGREGATOR + AS_PATH.
ok_attrs=1
ok_path=1
if [ $ok_route -eq 0 ]; then
    DETAIL=$("$BIRDC" -s "$OUT/bird.ctl" show route 198.51.100.0/23 all 2>/dev/null)
    if echo "$DETAIL" | grep -q "BGP.atomic_aggr:"; then ok_attrs=0; fi
    if echo "$DETAIL" | grep -q "BGP.aggregator: 10.0.0.1 AS64512"; then :; else ok_attrs=1; fi
    if echo "$DETAIL" | grep -q "BGP.as_path: 64512$"; then ok_path=0; fi
fi

# 3. Withdraw the specifics at BIRD; the aggregate must disappear.
ok_withdraw=1
if [ $ok_route -eq 0 ] && [ $ok_attrs -eq 0 ]; then
    # Rewrite the same config path with an unrelated static route and
    # signal BIRD — SIGHUP re-reads the file (the classic reconfigure;
    # the session stays Established throughout).
    cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 203.0.113.77/32 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local port 17992 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF
    kill -HUP "$BIRD_PID"
    # Wait for lr to notice the withdrawals and retract the aggregate.
    for i in $(seq 1 120); do
        sleep 0.25
        if ! "$BIRDC" -s "$OUT/bird.ctl" show route 198.51.100.0/23 2>/dev/null \
            | grep -q "198.51.100.0/23"; then
            ok_withdraw=0
            break
        fi
    done
fi

echo "== BIRD routing table (aggregate detail) =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== lr-daemon log (aggregate lines) =="
grep -E "aggregate|route installed 198\.51\.100\.0/23|withdraw" "$OUT/lr.log" || true
echo "== BIRD log (tail) =="
tail -15 "$OUT/bird.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_route -ne 0 ]; then
    echo "FAIL: BIRD did not learn the aggregate 198.51.100.0/23 from lr-daemon"
    fail=1
fi
if [ $ok_attrs -ne 0 ]; then
    echo "FAIL: the aggregate is missing ATOMIC_AGGREGATE or AGGREGATOR (64512, 10.0.0.1)"
    fail=1
fi
if [ $ok_path -ne 0 ]; then
    echo "FAIL: the aggregate AS_PATH is not exactly AS64512"
    fail=1
fi
if [ $ok_withdraw -ne 0 ]; then
    echo "FAIL: the aggregate was not withdrawn after the specifics disappeared"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: aggregate interop — RFC 4271 §9.2.2.2 aggregate accepted and retracted with BIRD 2"
fi
exit $fail
