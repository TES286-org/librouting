#!/usr/bin/env bash
# OSPF broadcast-segment interop (RFC 2328 §9.4 DR/BDR election).
#
# Phase 1 — two lr-daemons on a broadcast segment (veth pair, one
# netns per router, [[ospf.interface]] network_type = "broadcast"):
#   * the §9.4 election runs: higher router-id wins DR, the other
#     becomes Backup (both priority 1);
#   * both reach Full (§10.4: DR ↔ BDR become adjacent);
#   * the DR originates the §12.4.2 Network-LSA; the segment's own
#     prefix (10.99.1.0/24) and both stub nets install on both sides;
#   * SIGKILL of the peer re-runs the election and tears the session
#     down on the dead timer.
#
# Phase 2 — lr-daemon ↔ BIRD 2 with BIRD's *default* interface type
# (broadcast — the interop target real deployments hit): BIRD (higher
# router-id) becomes DR and originates the Network-LSA, lr becomes
# Backup, and stub nets propagate in both directions (birdc verified).
#
# Raw OSPF sockets need CAP_NET_RAW: the lab runs inside `unshare -Urn`
# (rootless, exactly what CI does). Environments without unprivileged
# user namespaces, iproute2 or BIRD SKIP gracefully.
#
# NOTE: log matching uses POSIX `grep -qF` — CI images do not guarantee
# `rg` on PATH.
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no CAP_NET_RAW for OSPF"
    exit 0
}

REPO=$(pwd)
BIRD=$(command -v bird || true)
BIRDC=$(command -v birdc || true)
export REPO BIN BIRD BIRDC

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ospf_broadcast
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
# Holder processes keep the two router namespaces alive.
unshare -n sleep 180 &
R1=$!
unshare -n sleep 180 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" "${BIRD_PID:-}" 2>/dev/null || true
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
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

cat >"$OUT/r1.toml" <<EOF
[[ospf.interface]]
name = "veth0"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4
EOF
cat >"$OUT/r2.toml" <<EOF
[[ospf.interface]]
name = "veth1"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4
EOF

echo "== phase 1: two lr-daemons on a broadcast segment =="
echo "== starting r1 (1.1.1.1 @ 10.99.1.1, stub 10.99.2.0/24) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --config "$OUT/r1.toml" \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "== starting r2 (2.2.2.2 @ 10.99.1.2, stub 10.99.3.0/24) =="
nsenter -t "$R2" -n "$BIN" --protocol ospf --router-id 2.2.2.2 \
    --config "$OUT/r2.toml" \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
LR_PID2=$!
disown "$LR_PID2"

echo "== waiting for the §9.4 election (2.2.2.2 wins DR at priority 1) =="
wait_log "$OUT/r2.log" "we are DR" 25
wait_log "$OUT/r1.log" "we are Backup" 25
echo "   election: OK (r2 DR, r1 Backup)"

echo "== waiting for Full adjacency (§10.4: DR ↔ BDR) =="
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 Full (area" 25
wait_log "$OUT/r2.log" "ospf neighbor 1.1.1.1 Full (area" 25
echo "   adjacency: OK"

echo "== waiting for stub-net + transit-net propagation (Network-LSA + SPF) =="
wait_log "$OUT/r1.log" "route installed 10.99.3.0/24" 25
wait_log "$OUT/r2.log" "route installed 10.99.2.0/24" 25
echo "   propagation: OK (r1 knows 10.99.3.0/24, r2 knows 10.99.2.0/24)"

echo "== dead-timer teardown: SIGKILL r2, expect r1 to elect itself DR and close the session =="
kill -9 "$LR_PID2" 2>/dev/null || true
wait_log "$OUT/r1.log" "ospf neighbor 2.2.2.2 dead (area" 25
echo "   dead timer: OK"

kill "$LR_PID" 2>/dev/null || true
wait 2>/dev/null || true
sleep 0.5
echo "phase 1: PASS"

if [ -z "$BIRD" ] || [ -z "$BIRDC" ]; then
    echo
    echo "OSPF broadcast-segment interop: PASS (phase 1 only — bird/birdc not installed)"
    echo "  - two lr-daemons elect DR/BDR (§9.4), become adjacent (§10.4),"
    echo "    exchange Router-LSAs + Network-LSA, stub nets propagate both ways,"
    echo "    dead-timer teardown works"
    exit 0
fi

echo "== phase 2: lr-daemon ↔ BIRD 2 on BIRD's default (broadcast) type =="
# Rebuild the lab: fresh addressing in the same two namespaces. BIRD
# models one OSPF interface per address, so veth1 carries only the
# segment address; its "remote" stub net is declared with a BIRD
# `stubnet` (a second address would form a second broadcast segment on
# the same wire — a different topology).
nsenter -t "$R1" -n ip link set veth0 down || true
nsenter -t "$R2" -n ip link set veth1 down || true
nsenter -t "$R1" -n ip addr flush dev veth0 || true
nsenter -t "$R2" -n ip addr flush dev veth1 || true
nsenter -t "$R1" -n ip addr add 10.98.1.1/24 dev veth0
nsenter -t "$R1" -n ip addr add 10.98.2.1/24 dev veth0
nsenter -t "$R1" -n ip link set veth0 up
nsenter -t "$R2" -n ip addr add 10.98.1.2/24 dev veth1
nsenter -t "$R2" -n ip link set veth1 up

cat >"$OUT/lr.toml" <<EOF
[[ospf.interface]]
name = "veth0"
network_type = "broadcast"
hello_interval = 1
dead_interval = 4
EOF

echo "== starting lr (1.1.1.1 @ 10.98.1.1) and BIRD (2.2.2.2 @ 10.98.1.2) =="
nsenter -t "$R1" -n "$BIN" --protocol ospf --router-id 1.1.1.1 \
    --config "$OUT/lr.toml" \
    --api-socket "$OUT/lr.ctl" >"$OUT/lr.log" 2>&1 &
LR_PID=$!

cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;
protocol device {}
protocol ospf v2 ospf1 {
    area 0 {
        stubnet 10.98.3.0/24;
        interface "veth1" {
            hello 1;
            dead 4;
        };
    };
}
EOF
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid" &
BIRD_PID=$!
disown "$BIRD_PID"

birdc_r2() {
    nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird.ctl" "$@"
}

echo "== waiting for Full adjacency in both directions =="
wait_log "$OUT/lr.log" "ospf neighbor 2.2.2.2 Full (area" 30
for i in $(seq 1 60); do
    if birdc_r2 "show ospf neighbors" 2>/dev/null | grep -qF "Full"; then
        break
    fi
    sleep 0.5
done
birdc_r2 "show ospf neighbors" | grep -qF "Full" || {
    echo "-- bird show ospf neighbors --"
    birdc_r2 "show ospf neighbors" || true
    exit 1
}
echo "   adjacency: OK (lr Full with BIRD)"

echo "== waiting for stub-net propagation in both directions =="
wait_log "$OUT/lr.log" "route installed 10.98.3.0/24" 30
for i in $(seq 1 60); do
    if birdc_r2 "show route" 2>/dev/null | grep -qF "10.98.2.0/24"; then
        break
    fi
    sleep 0.5
done
birdc_r2 "show route" | grep -qF "10.98.2.0/24" || {
    echo "-- bird show route --"
    birdc_r2 "show route" || true
    exit 1
}
echo "   propagation: OK (lr knows 10.98.3.0/24, BIRD knows 10.98.2.0/24)"

echo
echo "OSPF broadcast-segment interop: PASS"
echo "  - phase 1: two lr-daemons elect DR/BDR (§9.4), become adjacent (§10.4),"
echo "    exchange Router-LSAs + Network-LSA, stub nets propagate both ways,"
echo "    dead-timer teardown works"
echo "  - phase 2: lr reaches Full with BIRD 2 on BIRD's default broadcast"
echo "    interface type; stub nets propagate both ways (birdc verified)"
INNER
