#!/usr/bin/env bash
# Redistribution interop: lr-daemon `[[redistribute]]` (ROADMAP-v3 D4.1)
# bridging BGP and OSPF inside one router, with BIRD 2 playing both
# sides — the BGP peer that injects routes and the OSPF neighbor that
# must receive them back as AS-external LSAs (and vice versa).
#
#   netns r1: lr-daemon (multi-protocol bgp,ospf, AS64512, rid 1.1.1.1)
#             veth0: 10.99.1.1/24
#        ↑↓ BGP TCP 10.99.1.1:1179       ↑↓ OSPFv2 multicast 224.0.0.5
#   netns r2: BIRD 2 (rid 2.2.2.2) — one daemon, two protocols
#             veth1: 10.99.1.2/24
#             - protocol bgp to_lr (AS64513): exports static
#               198.51.100.0/24 toward lr
#             - protocol ospf v2 (ptp): exports static 203.0.113.0/24
#               as an AS-external LSA
#
#   lr pipes (the feature under test):
#     [[redistribute]] source=bgp  target=ospf  allow 198.51.100.0/24
#     [[redistribute]] source=ospf  target=bgp  allow 203.0.113.0/24
#
# Success criteria (all judged inside BIRD, on the wire):
#   1. BIRD's table holds 198.51.100.0/24 from the OSPF protocol —
#      lr learned it over BGP, originated a type-5 LSA (metric 100 from
#      the pipe's `metric` knob), BIRD's ospf installed it. The prefix
#      must show an OSPF external route, not just the bgp one.
#   2. BIRD's BGP protocol receives 203.0.113.0/24 back from lr —
#      BIRD originated it as OSPF external, lr learned it via OSPF and
#      re-originated it into BGP (AS_PATH 64512).
#   3. The allow-list is visible: 198.51.101.0/24 (BIRD static, also
#      exported over BGP) never appears as an OSPF external — only the
#      covered prefix crosses the pipe.
#
# This mirrors what BIRD's own `pipe` protocol does between two of its
# tables — except the two protocols here run in *different* routers and
# the routes cross real BGP + OSPF wires in between.
#
# Raw OSPF sockets need CAP_NET_RAW: the lab runs inside `unshare -Urn`
# (rootless). Environments without unprivileged user namespaces or
# without bird/birdc SKIP gracefully.
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
command -v ip >/dev/null 2>&1 || {
    echo "SKIP: iproute2 (ip) not installed"
    exit 0
}
command -v nsenter >/dev/null 2>&1 || {
    echo "SKIP: nsenter (util-linux) not installed"
    exit 0
}
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

REPO=$(pwd)
export REPO BIN BIRD BIRDC

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_redistribute_bird
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 180 &
R1=$!
unshare -n sleep 180 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" 2>/dev/null || true
    kill "$(cat "$OUT/bird.pid" 2>/dev/null || echo 0)" 2>/dev/null || true
    kill "$R1" "$R2" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0 netns "$R1"
ip link set veth1 netns "$R2"
nsenter -t "$R1" -n ip link set lo up
nsenter -t "$R2" -n ip link set lo up
nsenter -t "$R1" -n ip addr add 10.99.1.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

# --- BIRD: one daemon, BGP (AS64513) + OSPFv2 on the same veth -------
cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;

protocol device {}

# Routes injected over BGP toward lr: 198.51.100.0/24 (piped into
# OSPF by lr) and 198.51.101.0/24 (must stay OUT of OSPF — the
# allow-list check).
protocol static bgp_static {
    ipv4;
    route 198.51.100.0/24 blackhole;
    route 198.51.101.0/24 blackhole;
}

# Route originated as OSPF external from BIRD's side: lr must pipe it
# back into BGP.
protocol static ospf_static {
    ipv4;
    route 203.0.113.0/24 blackhole;
}

filter export_bgp_to_lr {
    if proto = "bgp_static" then accept;
    reject;
}

filter export_ospf_to_lr {
    if proto = "ospf_static" then accept;
    reject;
}

protocol bgp to_lr {
    # Non-privileged port: BIRD dials lr's listener on the veth.
    neighbor 10.99.1.1 port 1179 as 64512;
    local 10.99.1.2 as 64513;
    ipv4 {
        import all;
        export filter export_bgp_to_lr;
        next hop address 10.99.1.2;
    };
}

protocol ospf v2 lr_ospf {
    ipv4 {
        import all;
        export filter export_ospf_to_lr;
    };
    area 0 {
        interface "veth1" {
            type ptp;
            hello 1;
            dead 4;
        };
    };
}
EOF

echo "== starting BIRD (r2: bgp AS64513 + ospf on veth1) =="
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
sleep 1

# --- lr-daemon: multi-protocol bgp,ospf + both redistribution pipes --
cat >"$OUT/lr.toml" <<EOF
protocols = ["bgp", "ospf"]

[bgp]
local_as = 64512
peer_as = 64513
router_id = "1.1.1.1"
local_address = "10.99.1.1"
ebgp_policy = "accept-all"
# Non-privileged listener so the lab needs no root for BGP.
listen_addr = "10.99.1.1:1179"

[ospf]
hello_interval = 1
dead_interval = 4

[[ospf.interface]]
name = "veth0"

# Forward pipe: BGP routes (from BIRD) re-originated as OSPF
# AS-external LSAs, gated by the allow-list.
[[redistribute]]
source = "bgp"
target = "ospf"
metric = 100
allow = ["198.51.100.0/24"]

# Reverse pipe: OSPF externals (BIRD's) re-originated into BGP.
[[redistribute]]
source = "ospf"
target = "bgp"
metric = 100
allow = ["203.0.113.0/24"]
EOF

echo "== starting lr-daemon (r1: bgp,ospf + redistribution pipes) =="
nsenter -t "$R1" -n "$BIN" --config "$OUT/lr.toml" --router-id 1.1.1.1 \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

echo "== waiting for the BGP session and the OSPF adjacency =="
wait_log "$OUT/lr.log" "session #1 → Established" 25
wait_log "$OUT/lr.log" "ospf neighbor 2.2.2.2 Full (area" 25
echo "   transport: OK (BGP Established + OSPF Full)"

# --- criterion 1: BGP → OSPF pipe -----------------------------------
echo "== waiting for 198.51.100.0/24 to come back through OSPF =="
ok_fwd=1
for i in $(seq 1 250); do
    sleep 0.1
    if "$BIRDC" -s "$OUT/bird.ctl" 'show route 198.51.100.0/24 protocol lr_ospf' 2>/dev/null \
        | grep -q "198.51.100.0/24"; then
        ok_fwd=0
        break
    fi
done
FWD_DETAIL=$("$BIRDC" -s "$OUT/bird.ctl" 'show route 198.51.100.0/24 protocol lr_ospf all' 2>/dev/null || true)

# --- criterion 3: the allow-list must hold ---------------------------
echo "== checking the allow-list (198.51.101.0/24 must not cross) =="
sleep 2
if "$BIRDC" -s "$OUT/bird.ctl" 'show route 198.51.101.0/24 protocol lr_ospf' 2>/dev/null \
    | grep -q "198.51.101.0/24"; then
    ok_allow=1
else
    ok_allow=0
fi

# --- criterion 2: OSPF → BGP pipe ------------------------------------
echo "== waiting for 203.0.113.0/24 to come back through BGP =="
ok_rev=1
for i in $(seq 1 250); do
    sleep 0.1
    if "$BIRDC" -s "$OUT/bird.ctl" 'show route 203.0.113.0/24 protocol to_lr' 2>/dev/null \
        | grep -q "203.0.113.0/24"; then
        ok_rev=0
        break
    fi
done
REV_DETAIL=$("$BIRDC" -s "$OUT/bird.ctl" 'show route 203.0.113.0/24 protocol to_lr all' 2>/dev/null || true)

echo "== BIRD routing table (all) =="
"$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null || true
echo "== forward pipe detail (198.51.100.0/24 via OSPF) =="
echo "$FWD_DETAIL"
echo "== reverse pipe detail (203.0.113.0/24 via BGP) =="
echo "$REV_DETAIL"
echo "== lr-daemon log (redistribute lines) =="
grep -E "redistribute|session|neighbor" "$OUT/lr.log" | head -30 || true

fail=0
if [ $ok_fwd -ne 0 ]; then
    echo "FAIL: 198.51.100.0/24 did not come back through OSPF (bgp→ospf pipe broken)"
    fail=1
fi
if [ $ok_allow -ne 0 ]; then
    echo "FAIL: 198.51.101.0/24 crossed into OSPF — the allow-list did not hold"
    fail=1
fi
if [ $ok_rev -ne 0 ]; then
    echo "FAIL: 203.0.113.0/24 did not come back through BGP (ospf→bgp pipe broken)"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: redistribution interop — BGP↔OSPF pipes verified against BIRD 2 on both wires"
fi
exit $fail
INNER
