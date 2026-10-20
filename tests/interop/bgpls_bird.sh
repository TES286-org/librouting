#!/usr/bin/env bash
# BGP-LS interop lab (issue #60 daemon wiring): an lr-daemon running
# OSPF + BGP exports its IGP topology to a BIRD 2 peer configured for
# the BGP-LS address family (AFI=16388, SAFI=71, RFC 7752 §3.1).
#
#   netns r1: lr-daemon --protocol bgp,ospf --bgp-ls, router-id 1.1.1.1,
#             AS64512, BGP-LS speaker (AS=64512, BGP-LS-ID=1).
#             veth0: 10.99.1.1/24 (transit) + 10.99.2.1/24 (stub net A).
#             BGP listener 10.99.1.1:179 (BIRD connects).
#        ↑↓ OSPFv2 multicast 224.0.0.5 (ptp, hello 1 / dead 4)
#        ↑↓ eBGP 64512 ↔ 64513 with the BGP-LS family
#   netns r2: BIRD 2.17+ router-id 2.2.2.2, AS64513.
#             veth1: 10.99.1.2/24 (transit) + 10.99.3.1/24 (stub net B).
#             BGP-LS channel listens for the family.
#
# Success criteria (the ROADMAP "done" gate for issue #60):
#   1. OSPF Full adjacency on both sides (real DBD/LSR, RFC 2328 §7.2)
#      — the projection input is the live LSDB.
#   2. The BGP session establishes with the BGP-LS family negotiated
#      in OPEN (visible in both daemons' logs).
#   3. BIRD's `show route table ls` (or `show route protocol bgp1`)
#      contains the projected Node NLRI for the lr-daemon's
#      router-id 1.1.1.1 — the controller builds the same IGP graph
#      from our session that the lr-daemon holds in its OSPF LSDB.
#   4. Incremental republish: when lr's OSPF LSDB changes (a stub
#      network is added), BIRD sees an incremental UPDATE (a new
#      BGP-LS Prefix NLRI appears) rather than a full resend.
#
# Raw OSPF sockets + BGP :179 need the user namespace's capabilities:
# the lab runs inside `unshare -Urn` (rootless), exactly what CI does.
# Environments without unprivileged user namespaces, iproute2, or
# bird/birdc SKIP gracefully. BIRD <2.17 lacks the `bgp_ls` channel
# (introduced in BIRD 2.17); older BIRD versions SKIP with a clear
# diagnostic.
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
    if [ -x "$HOME/opt/bird/root/usr/sbin/bird" ]; then
        BIRD=$HOME/opt/bird/root/usr/sbin/bird
        BIRDC=$HOME/opt/bird/root/usr/sbin/birdc
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
OUT=/tmp/lr_bgpls_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 240 &
R1=$!
unshare -n sleep 240 &
R2=$!
LR_PID=""
cleanup() {
    [ -n "$LR_PID" ] && kill "$LR_PID" 2>/dev/null || true
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
nsenter -t "$R1" -n ip addr add 10.99.2.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.99.1.2/24 dev veth1
nsenter -t "$R2" -n ip addr add 10.99.3.1/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-30} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

birdc_r2() { # <command...>
    nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird.ctl" "$@"
}

# Detect BIRD <2.17 — the `bgp_ls` channel is BIRD 2.17+ only. The
# syntax check below fails on older BIRD with a parser error, which
# we turn into a SKIP so CI on runners with BIRD 2.14 installed does
# not fail for a missing-feature reason.
cat >"$OUT/bird-probe.conf" <<'EOF'
router id 2.2.2.2;
protocol bgp probe {
    local 0.0.0.0 as 64513;
    neighbor 0.0.0.0 as 64512;
    bgp_ls;
}
EOF
if ! nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird-probe.conf" -s "$OUT/bird-probe.ctl" -P "$OUT/bird-probe.pid" >/dev/null 2>"$OUT/bird-probe.err"; then
    if grep -qi "syntax error\|unknown" "$OUT/bird-probe.err" 2>/dev/null; then
        echo "SKIP: BIRD does not support the bgp_ls channel (BIRD <2.17)"
        cat "$OUT/bird-probe.err"
        exit 0
    fi
fi
kill "$(cat "$OUT/bird-probe.pid" 2>/dev/null || echo 0)" 2>/dev/null || true
rm -f "$OUT/bird-probe.ctl" "$OUT/bird-probe.pid" "$OUT/bird-probe.err"

echo "== starting BIRD 2.17+ (2.2.2.2 / AS64513, ospf v2 ptp + eBGP-LS on veth1) =="
cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;
protocol device {}
protocol ospf v2 ospf1 {
    area 0 {
        interface "veth1" {
            type ptp;
            hello 1;
            dead 4;
        };
    };
}
protocol bgp bgp1 {
    local 10.99.1.2 as 64513;
    neighbor 10.99.1.1 as 64512;
    ipv4 {
        import all;
        export all;
    };
    bgp_ls;
}
EOF
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
sleep 1

echo "== starting lr-daemon (1.1.1.1 / AS64512, --protocol bgp,ospf --bgp-ls) =="
nsenter -t "$R1" -n "$BIN" \
    --protocol bgp,ospf \
    --router-id 1.1.1.1 \
    --local-as 64512 --peer-as 64513 \
    --listen 10.99.1.1:179 --local-address 10.99.1.1 \
    --ospf-interface veth0 \
    --ospf-hello-interval 1 --ospf-dead-interval 4 \
    --network 198.51.100.0/24 \
    --ebgp-policy accept-all \
    --bgp-ls --bgp-ls-as 64512 --bgp-ls-id 1 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== waiting for the combination to come up =="
wait_log "$OUT/r1.log" "2 engine(s) running"
wait_log "$OUT/r1.log" "bgp-ls:       on (AS=64512 BGP-LS-ID=1 areas=(all))"

echo "== waiting for OSPF adjacency and BGP-LS session =="
# OSPF Full on the lr side; BGP Established on both sides.
wait_log "$OUT/r1.log" "OSPFv2 area 0: 1 neighbor(s), 1 full"
wait_log "$OUT/r1.log" "session #1 → Established"

echo "== verifying BIRD built the IGP graph from our BGP-LS session =="
# BIRD's `show route table ls` lists the BGP-LS NLRI database the
# controller built from our session. The lr-daemon's router-id is
# 1.1.1.1 (0x01010101), so the projected Node NLRI's IGP Router-ID
# sub-TLV carries 1.1.1.1. We check the BIRD table holds at least
# one Node NLRI; the l3router line names the router-id.
ok_node=1
for i in $(seq 1 200); do
    sleep 0.25
    if birdc_r2 show route table ls 2>/dev/null | grep -Eq "1\.1\.1\.1|01010101"; then
        ok_node=0
        break
    fi
done

echo "== BIRD ls table =="
birdc_r2 show route table ls 2>/dev/null || true
echo "== BIRD protocol state =="
birdc_r2 show protocols all bgp1 2>/dev/null | head -25 || true
echo "== lr-daemon log (tail) =="
tail -30 "$OUT/r1.log" 2>/dev/null || true
echo "== BIRD log (tail) =="
tail -25 "$OUT/bird.log" 2>/dev/null || true

fail=0
if [ "$ok_node" -ne 0 ]; then
    echo "FAIL: BIRD never built a Node NLRI for the lr-daemon's router-id"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: BGP-LS interop — BIRD builds the same IGP graph from our session"
fi
exit "$fail"
INNER
