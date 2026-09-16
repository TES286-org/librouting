#!/usr/bin/env bash
# RFC 8212 interop test: lr-daemon's default eBGP route-exchange
# policy against FRR's bgpd (ROADMAP-v3 D10.6).
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
#   lr-daemon (AS64512, originates 203.0.113.0/24, listener :PORT)
#        ↑↓ TCP on 127.0.0.1
#   FRR bgpd (AS64514, network 198.51.100.0/24, connector)
#
# FRR's side uses `no bgp ebgp-requires-policy` (the datacenter
# profile) so FRR is the permissive peer — it imports and exports
# unconditionally. The test exercises lr-daemon's two modes:
#
#   Phase 1 — default (RFC 8212): lr-daemon has NO explicit policy.
#     FRR must NOT learn 203.0.113.0/24 (lr-daemon's export is
#     denied) and lr-daemon must NOT install 198.51.100.0/24
#     (lr-daemon's import is denied). The session itself reaches
#     Established (RFC 8212 filters routes, not transport).
#
#   Phase 2 — explicit permit-all: lr-daemon attaches permit-all
#     route-maps on both sides. FRR learns 203.0.113.0/24 and
#     lr-daemon installs 198.51.100.0/24.
#
# Success criteria:
#   1. Phase 1: FRR's BGP table does NOT contain 203.0.113.0/24 and
#      lr-daemon's log does NOT contain "route installed
#      198.51.100.0/24". The session reaches Established.
#   2. Phase 2: FRR's BGP table contains 203.0.113.0/24 and
#      lr-daemon's log contains "route installed 198.51.100.0/24".
#
# Env overrides:
#   BGPD     path to the bgpd binary (default: from $PATH or extracted tree)
#   PORT     lr-daemon listen port (default 18013)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
BGPD=${BGPD:-bgpd}
if ! command -v "$BGPD" >/dev/null 2>&1; then
    for cand in /home/z/opt/frr/root/usr/lib/frr/bgpd /usr/lib/frr/bgpd; do
        if [ -x "$cand" ]; then BGPD="$cand"; break; fi
    done
fi
command -v "$BGPD" >/dev/null 2>&1 || { echo "SKIP: bgpd not found"; exit 0; }

# Resolve the shared-library path for an extracted (non-installed) bgpd.
case "$BGPD" in
    /home/z/opt/*) FRRROOT=${BGPD%/usr/lib/frr/bgpd}
        export LD_LIBRARY_PATH="$FRRROOT/usr/lib/x86_64-linux-gnu/frr:$FRRROOT/usr/lib/x86_64-linux-gnu:$FRRROOT/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ;;
esac

PORT=${PORT:-18013}
# Never default the vty port into FRR's well-known range (2600-2620):
# every FRR daemon owns one (zebra 2600, bgpd 2605, staticd 2616, ...)
# and `apt-get install frr` starts a system zebra+staticd pair. A
# squatted port makes bgpd silently skip its own vty listener.
VTY_PORT=${VTY_PORT:-26996}
OUT=/tmp/lr_rfc8212_frr
rm -rf "$OUT"; mkdir -p "$OUT" "$OUT/vty"

# ---- FRR bgpd config — the permissive peer. -----------------------------
# `no bgp ebgp-requires-policy` disables FRR's own RFC 8212
# enforcement (the datacenter profile) so FRR imports and exports
# unconditionally. The test exercises lr-daemon's two modes against
# this fixed permissive peer. The route-map on the export side pins
# the next hop so FRR does not reject the route as a martian (FRR
# rejects loopback next hops).
cat >"$OUT/bgpd.conf" <<EOF
frr version 10
frr defaults traditional
hostname bgpd-8212
password zebra
!
route-map lr-out permit 10
 set ip next-hop 192.0.2.20
!
router bgp 64514
 bgp router-id 10.0.0.3
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 127.0.0.1 remote-as 64512
 neighbor 127.0.0.1 port $PORT
 neighbor 127.0.0.1 ebgp-multihop 2
 neighbor 127.0.0.1 route-map lr-out out
 !
 address-family ipv4 unicast
  network 198.51.100.0/24
 exit-address-family
 !
!
line vty
!
EOF

echo "== starting FRR bgpd (AS64514, connects to lr-daemon :$PORT) =="
"$BGPD" -f "$OUT/bgpd.conf" -i "$OUT/bgpd.pid" \
    -Z -n -S \
    -p 18014 -A 127.0.0.1 -P $VTY_PORT --vty_socket "$OUT/vty" \
    --log "file:$OUT/bgpd.log" \
    >"$OUT/bgpd.stdout" 2>&1 &
BGPD_PID=$!
trap 'kill ${BGPD_PID:-} ${LR_PID:-} 2>/dev/null || true' EXIT

# Query a command over the vty TCP interface; output goes to stdout.
# Robust against peers that close the session at any point (a vty
# that rejects us may close mid-conversation; never traceback).
vty_cmd() {
    python3 - "$VTY_PORT" "$1" <<'PYEOF'
import socket, sys, time
port, cmd = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError:
    sys.exit(1)
s.settimeout(0.5)

def drain(idle_rounds=2):
    out = b""
    idle = 0
    while idle < idle_rounds:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
            idle = 0
        except socket.timeout:
            idle += 1
        except OSError:
            break
    return out

def send(line):
    try:
        s.sendall(line)
    except OSError:
        pass

banner = drain()
if b"Password:" in banner:
    send(b"zebra\r\n")
    time.sleep(0.2)
    drain(1)
send(cmd.encode() + b"\r\n")
time.sleep(0.8)
out = drain()
send(b"quit\r\n")
s.close()
sys.stdout.write(out.decode("utf-8", "replace"))
PYEOF
}

# Wait for the vty AND verify it answers as OUR bgpd: the configured
# hostname `bgpd-8212` appears in the vty prompt.
vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd "show version" 2>/dev/null | grep -q "bgpd-8212"; then
        vty_ok=0
        break
    fi
    if ! kill -0 $BGPD_PID 2>/dev/null; then
        echo "FAIL: bgpd died during startup"
        cat "$OUT/bgpd.stdout" || true
        cat "$OUT/bgpd.log" 2>/dev/null || true
        exit 1
    fi
done
if [ $vty_ok -ne 0 ]; then
    echo "FAIL: bgpd vty did not answer as our instance (bgpd-8212) on port $VTY_PORT"
    cat "$OUT/bgpd.stdout" 2>/dev/null || true
    tail -15 "$OUT/bgpd.log" 2>/dev/null || true
    exit 1
fi

# ---- Phase 1: default (RFC 8212) — no explicit policy on lr-daemon. ------
echo "== Phase 1: lr-daemon default (RFC 8212) — no explicit policy =="
"$BIN" --local-as 64512 --peer-as 64514 --router-id 10.0.0.1 \
    --listen "127.0.0.1:$PORT" --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    >"$OUT/lr-phase1.log" 2>&1 &
LR_PID=$!

# Wait for the session to come up and for the policy-less warnings.
ok_session=1
ok_warn_export=1
ok_warn_import=1
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_session -ne 0 ] && grep -qF "session #1 → Established" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_session=0
    fi
    if [ $ok_warn_export -ne 0 ] && grep -qF "no export route-map; announcing nothing (RFC 8212)" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_warn_export=0
    fi
    if [ $ok_warn_import -ne 0 ] && grep -qF "no import route-map; discarding received routes (RFC 8212)" "$OUT/lr-phase1.log" 2>/dev/null; then
        ok_warn_import=0
    fi
    if [ $ok_session -eq 0 ] && [ $ok_warn_export -eq 0 ] && [ $ok_warn_import -eq 0 ]; then
        break
    fi
done

# Give the route a few seconds to (not) propagate, then check.
sleep 3

# Phase 1 assertions: FRR must NOT have learned 203.0.113.0/24
# (lr-daemon's export is denied), and lr-daemon must NOT have
# installed 198.51.100.0/24 (lr-daemon's import is denied).
phase1_frr_has_route=1
if vty_cmd "show ip bgp" 2>/dev/null | grep -q "203.0.113.0/24"; then
    phase1_frr_has_route=0
fi
phase1_lr_has_route=1
if grep -qF "route installed 198.51.100.0/24" "$OUT/lr-phase1.log" 2>/dev/null; then
    phase1_lr_has_route=0
fi

echo "== Phase 1: FRR BGP table =="
vty_cmd "show ip bgp" || true
echo "== Phase 1: lr-daemon log =="
cat "$OUT/lr-phase1.log"

# Stop the Phase 1 daemon before starting Phase 2.
kill $LR_PID 2>/dev/null || true
wait $LR_PID 2>/dev/null || true
LR_PID=""

# ---- Phase 2: explicit permit-all route-maps restore flow. --------------
echo "== Phase 2: lr-daemon with explicit permit-all route-maps =="
cat >"$OUT/lr-phase2.toml" <<EOF
[bgp]
local_as = 64512
router_id = "10.0.0.1"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24"]
listen_addr = "127.0.0.1:$PORT"

[[route-map]]
name = "export-all"
entry = 10
permit = true

[[route-map]]
name = "import-all"
entry = 10
permit = true

[[peer]]
address = "127.0.0.1"
peer_as = 64514
export = "export-all"
import = "import-all"
EOF

"$BIN" --config "$OUT/lr-phase2.toml" >"$OUT/lr-phase2.log" 2>&1 &
LR_PID=$!

# Wait for the route to propagate both directions (up to 45 s).
ok_frr=1
ok_lr=1
for i in $(seq 1 180); do
    sleep 0.25
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr-phase2.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_frr -ne 0 ] && [ $((i % 8)) -eq 0 ]; then
        if vty_cmd "show ip bgp" >"$OUT/vty_table.txt" 2>/dev/null \
            && grep -q "203.0.113.0/24" "$OUT/vty_table.txt"; then
            ok_frr=0
        fi
    fi
    if [ $ok_frr -eq 0 ] && [ $ok_lr -eq 0 ]; then
        break
    fi
done

echo "== Phase 2: FRR BGP table =="
vty_cmd "show ip bgp" || true
echo "== Phase 2: FRR BGP summary =="
vty_cmd "show bgp summary" || true
echo "== Phase 2: lr-daemon log =="
cat "$OUT/lr-phase2.log"
echo "== bgpd log (tail) =="
tail -15 "$OUT/bgpd.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
kill $BGPD_PID 2>/dev/null || true
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
    echo "FAIL: Phase 1 — lr-daemon did not log 'no export route-map; announcing nothing (RFC 8212)'"
    fail=1
fi
if [ $ok_warn_import -ne 0 ]; then
    echo "FAIL: Phase 1 — lr-daemon did not log 'no import route-map; discarding received routes (RFC 8212)'"
    fail=1
fi
# Phase 1 — FRR must NOT have learned the route.
if [ $phase1_frr_has_route -eq 0 ]; then
    echo "FAIL: Phase 1 — FRR learned 203.0.113.0/24 from a policy-less lr-daemon (RFC 8212 export deny violated)"
    fail=1
fi
# Phase 1 — lr-daemon must NOT have installed FRR's route.
if [ $phase1_lr_has_route -eq 0 ]; then
    echo "FAIL: Phase 1 — lr-daemon installed 198.51.100.0/24 from FRR without an import policy (RFC 8212 import deny violated)"
    fail=1
fi
# Phase 2 — explicit policy must have restored the flow.
if [ $ok_frr -ne 0 ]; then
    echo "FAIL: Phase 2 — FRR did not learn 203.0.113.0/24 from lr-daemon with explicit export policy"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: Phase 2 — lr-daemon did not learn 198.51.100.0/24 from FRR with explicit import policy"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: RFC 8212 interop — default deny (Phase 1) + explicit policy restores flow (Phase 2) against FRR bgpd"
fi
exit $fail
