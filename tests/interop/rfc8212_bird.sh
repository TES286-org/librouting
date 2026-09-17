#!/usr/bin/env bash
# RFC 8212 interop test: lr-daemon's default eBGP route-exchange
# policy against BIRD 2 (ROADMAP-v3 D10.6).
#
# RFC 8212 §3 (updating RFC 4271 §9.1/§9.1.3): routes from an
# external peer without an explicit Import Policy are not eligible
# for the decision process, and routes must not enter the Adj-RIB-Out
# of an external peer without an explicit Export Policy. The daemon
# enables the mode by default (`[bgp] ebgp_policy = "rfc8212"`);
# `accept-all` restores the legacy default-accept the RFC permits as
# a deviation (Appendix A "insecure-mode").
#
# Topology:
#   lr-daemon (AS64512, originates 203.0.113.0/24, connector)
#        ↑↓ TCP on 127.0.0.1
#   BIRD 2     (AS64513, exports static 198.51.100.0/24, listener)
#
# BIRD's side always carries explicit policy (`import all;
# export filter …`) so it is the RFC-compliant peer. The test
# exercises lr-daemon's two modes:
#
#   Phase 1 — default (RFC 8212): lr-daemon has NO explicit policy.
#     BIRD must NOT learn 203.0.113.0/24 (lr-daemon's export is
#     denied) and lr-daemon must NOT install 198.51.100.0/24
#     (lr-daemon's import is denied).
#
#   Phase 2 — explicit permit-all: lr-daemon attaches permit-all
#     route-maps on both sides. BIRD learns 203.0.113.0/24 and
#     lr-daemon installs 198.51.100.0/24.
#
# Success criteria:
#   1. Phase 1: BIRD's table does NOT contain 203.0.113.0/24 and
#      lr-daemon's log does NOT contain "route installed
#      198.51.100.0/24". The session itself reaches Established
#      (RFC 8212 filters routes, not transport).
#   2. Phase 2: BIRD's table contains 203.0.113.0/24 and lr-daemon's
#      log contains "route installed 198.51.100.0/24".
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           BIRD listen port (default 18012)
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
command -v "$BIRD" >/dev/null 2>&1 || { echo "SKIP: bird not found"; exit 0; }

PORT=${PORT:-18012}
OUT=/tmp/lr_rfc8212_bird
rm -rf "$OUT"; mkdir -p "$OUT"

# ---- BIRD config — the RFC-compliant peer. ------------------------------
# BIRD always carries explicit policy (`import all; export filter …`)
# so it is the side that adheres to RFC 8212 unconditionally. The
# test exercises lr-daemon's two modes against this fixed peer.
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the RFC 8212 interop test.
log "$OUT/bird.log" all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local port $PORT as 64513;
    neighbor 127.0.0.1 as 64512;
    multihop 2;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD (AS64513, listener :$PORT) =="
"$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT
sleep 1

# ---- Phase 1: default (RFC 8212) — no explicit policy on lr-daemon. ------
# lr-daemon starts with the default `ebgp_policy = rfc8212` and NO
# route-maps. The startup log must carry the RFC 8212 warnings
# ("no export route-map; announcing nothing" and "no import
# route-map; discarding received routes").
echo "== Phase 1: lr-daemon default (RFC 8212) — no explicit policy =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --peer "127.0.0.1:$PORT" --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    >"$OUT/lr-phase1.log" 2>&1 &
LR_PID=$!

# Wait for the session to come up (RFC 8212 filters routes, not
# transport) and for the policy-less warnings to fire.
ok_session=1
ok_warn_export=1
ok_warn_import=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_session -ne 0 ] && grep -qF "session #1 → Established" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_session=0
    fi
    if [ $ok_warn_export -ne 0 ] && grep -qF "no export route-map or filter; announcing nothing (RFC 8212)" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_warn_export=0
    fi
    if [ $ok_warn_import -ne 0 ] && grep -qF "no import route-map or filter; discarding received routes (RFC 8212)" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_warn_import=0
    fi
    if [ $ok_session -eq 0 ] && [ $ok_warn_export -eq 0 ] && [ $ok_warn_import -eq 0 ]; then
        break
    fi
done

# Give the route a few seconds to (not) propagate, then check.
sleep 3

# Phase 1 assertions: BIRD must NOT have learned 203.0.113.0/24
# (lr-daemon's export is denied), and lr-daemon must NOT have
# installed 198.51.100.0/24 (lr-daemon's import is denied).
phase1_bird_has_route=1
if "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null | grep -q "203.0.113.0/24"; then
    phase1_bird_has_route=0
fi
phase1_lr_has_route=1
if grep -qF "route installed 198.51.100.0/24" "$OUT/lr-phase1.log" 2>/dev/null; then
    phase1_lr_has_route=0
fi

echo "== Phase 1: BIRD routing table =="
"$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null || true
echo "== Phase 1: lr-daemon log =="
cat "$OUT/lr-phase1.log"

# Stop the Phase 1 daemon before starting Phase 2.
kill $LR_PID 2>/dev/null || true
wait $LR_PID 2>/dev/null || true
LR_PID=""

# ---- Phase 2: explicit permit-all route-maps restore flow. --------------
# lr-daemon attaches permit-all route-maps on both the export and
# import sides. This is the RFC-intended escape hatch: explicit
# policy restores the route flow while the default mode stays on.
echo "== Phase 2: lr-daemon with explicit permit-all route-maps =="
cat >"$OUT/lr-phase2.toml" <<EOF
[bgp]
local_as = 64512
router_id = "10.0.0.1"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24"]

[[route-map]]
name = "export-all"
entry = 10
permit = true

[[route-map]]
name = "import-all"
entry = 10
permit = true

[[peer]]
remote = "127.0.0.1:$PORT"
peer_as = 64513
export = "export-all"
import = "import-all"
EOF

"$BIN" --config "$OUT/lr-phase2.toml" >"$OUT/lr-phase2.log" 2>&1 &
LR_PID=$!

# Wait for the route to propagate both directions (up to 30 s).
ok_bird=1
ok_lr=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null \
        | grep -q "203.0.113.0/24"; then
        ok_bird=0
    fi
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr-phase2.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_bird -eq 0 ] && [ $ok_lr -eq 0 ]; then
        break
    fi
done

echo "== Phase 2: BIRD routing table =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== Phase 2: lr-daemon log =="
cat "$OUT/lr-phase2.log"

kill $LR_PID 2>/dev/null || true
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true

# ---- Verdict. -----------------------------------------------------------
fail=0

# Phase 1 — session must have established.
if [ $ok_session -ne 0 ]; then
    echo "FAIL: Phase 1 — BGP session did not reach Established (RFC 8212 filters routes, not transport)"
    fail=1
fi
# Phase 1 — startup warnings must have fired.
if [ $ok_warn_export -ne 0 ]; then
    echo "FAIL: Phase 1 — lr-daemon did not log 'no export route-map or filter; announcing nothing (RFC 8212)'"
    fail=1
fi
if [ $ok_warn_import -ne 0 ]; then
    echo "FAIL: Phase 1 — lr-daemon did not log 'no import route-map or filter; discarding received routes (RFC 8212)'"
    fail=1
fi
# Phase 1 — BIRD must NOT have learned the route.
if [ $phase1_bird_has_route -eq 0 ]; then
    echo "FAIL: Phase 1 — BIRD learned 203.0.113.0/24 from a policy-less lr-daemon (RFC 8212 export deny violated)"
    fail=1
fi
# Phase 1 — lr-daemon must NOT have installed BIRD's route.
if [ $phase1_lr_has_route -eq 0 ]; then
    echo "FAIL: Phase 1 — lr-daemon installed 198.51.100.0/24 from BIRD without an import policy (RFC 8212 import deny violated)"
    fail=1
fi
# Phase 2 — explicit policy must have restored the flow.
if [ $ok_bird -ne 0 ]; then
    echo "FAIL: Phase 2 — BIRD did not learn 203.0.113.0/24 from lr-daemon with explicit export policy"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: Phase 2 — lr-daemon did not learn 198.51.100.0/24 from BIRD with explicit import policy"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: RFC 8212 interop — default deny (Phase 1) + explicit policy restores flow (Phase 2) against BIRD 2"
fi
exit $fail
