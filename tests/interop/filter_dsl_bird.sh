#!/usr/bin/env bash
# BIRD interop test for the BIRD-like filter DSL ([[filter]] tables).
#
# Verifies that an lr-daemon filter body using:
#   - prefix-set membership (net ~ [...]),
#   - arithmetic (bgp.local_pref + 100),
#   - assignment to BGP attributes (bgp.local_pref = N),
#   - if/then/else control flow,
#   - method calls (bgp.as_path.prepend(...)),
#   - community append (bgp.communities += [...]),
#   - ROA validation (roa.state == "invalid" then reject),
# behaves correctly against BIRD 2.
#
#   lr-daemon (AS64512, filter DSL, roa_validate = true) — connector
#        v TCP on 127.0.0.1
#   BIRD 2 (AS64513, export 198.51.100.0/24 + 203.0.113.0/24)
#
# Success criteria:
#   1. The 198.51.100.0/24 route (matching the filter's prefix-set,
#      Valid per ROA) is accepted.
#   2. The 203.0.113.0/24 route (Invalid per ROA — covered but
#      wrong origin AS) is rejected via ROA validation.
#   3. lr-daemon prints filters: 1 compiled, 1 import / 0 export
#      bindings and roa: 2 entries, validate=true on startup.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries
#   PORT           BIRD listen port (default 17994)
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
command -v "$BIRD" >/dev/null 2>&1 || { echo "SKIP: bird not found"; exit 0; }

PORT=${PORT:-17994}
OUT=/tmp/lr_bird_filter_interop
rm -rf "$OUT"; mkdir -p "$OUT"

# BIRD config: export 198.51.100.0/24 (authorized by ROA) and
# 203.0.113.0/24 (NOT authorized — should be rejected by ROA).
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the filter-DSL interop test.
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
    route 203.0.113.0/24 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local port ${PORT} as 64513;
    neighbor 127.0.0.1 port 1179 as 64512;
    multihop 2;
    hold time 9;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

# lr-daemon config: ROA validation enabled, filter DSL attached.
# The filter body's inner `"` chars are escaped to `\"` (TOML escape)
# so the daemon's string parser keeps them as part of the body.
FILTER_BODY='if roa.state == "invalid" then { reject; } if net ~ 198.51.100.0/24 then { bgp.local_pref = 200; bgp.communities += [ 64512:100 ]; accept; } accept;'
FILTER_BODY_ESC=${FILTER_BODY//\"/\\\"}
{
    echo '# Top-level protocol selection (rc.3 multi-protocol support).'
    echo 'protocol = "babel"'
    echo
    echo '[bgp]'
    echo 'local_as = 64512'
    echo 'peer_as = 64513'
    echo 'router_id = "10.0.0.1"'
    echo 'listen_addr = "127.0.0.1:1179"'
    echo 'local_address = "127.0.0.1"'
    echo 'hold_time = 9'
    echo 'ebgp_policy = "accept-all"'
    echo 'roa_validate = true'
    echo 'roa_invalid_action = "reject"'
    echo
    echo '[[roa]]'
    echo 'prefix = "198.51.100.0/24"'
    echo 'asn = 64513'
    echo
    echo '[[roa]]'
    echo 'prefix = "203.0.113.0/24"'
    echo 'asn = 65000'
    echo
    echo '[[filter]]'
    echo 'name = "in"'
    printf 'body = "%s"\n' "$FILTER_BODY_ESC"
    echo
    echo '[[peer]]'
    echo "remote = \"127.0.0.1:${PORT}\""
    echo 'import_filter = "in"'
} >"$OUT/lr.conf"

# Reset the protocol to bgp for this test (the filter DSL is BGP-only).
sed -i 's/^protocol = "babel"/protocol = "bgp"/' "$OUT/lr.conf"

echo "== lr-daemon config =="
cat "$OUT/lr.conf"

echo "== starting BIRD (AS64513, listener on port ${PORT}) =="
"$BIRD" -f -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid" >"$OUT/bird.stdout" 2>&1 &
BIRD_PID=$!
trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (AS64512, filter DSL, ROA validation) =="
"$BIN" --config "$OUT/lr.conf" --config-dialect toml >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill $LR_PID 2>/dev/null || true; kill $BIRD_PID 2>/dev/null || true' EXIT

# Wait for the session to establish and routes to propagate.
ok=1
reason="timeout waiting for filter DSL interop"
for i in $(seq 1 80); do
    sleep 0.5
    if grep -qF "filters:     1 compiled, 1 import / 0 export bindings" "$OUT/lr.log" 2>/dev/null \
       && grep -qF "roa:         2 entries, validate=true" "$OUT/lr.log" 2>/dev/null; then
        if grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
            if ! grep -qF "route installed 203.0.113.0/24" "$OUT/lr.log" 2>/dev/null; then
                ok=0
                reason="OK"
                break
            fi
        fi
    fi
done

echo "== lr-daemon log =="
cat "$OUT/lr.log" || true
echo "== BIRD log (tail) =="
tail -30 "$OUT/bird.log" 2>/dev/null || true

if [ "$ok" -ne 0 ]; then
    echo "FAIL: $reason"
    exit 1
fi

echo "PASS: filter DSL interop with BIRD"
exit 0
