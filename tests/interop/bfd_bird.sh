#!/usr/bin/env bash
# BFD interop with BIRD 2: single-hop (RFC 5881) and multihop
# (RFC 5883) sessions fast-failing a BGP session.
#
# Phase 1 — single-hop over a veth pair, one network namespace per
# router:
#
#   netns r1: lr-daemon (AS65001, 1.1.1.1, originates 203.0.113.0/24,
#             connector, BFD 100ms x 3, hold time 60 s)
#   netns r2: BIRD 2   (AS65002, 2.2.2.2, protocol bfd + 'bfd on')
#
#   1. Both BFD sessions reach Up; BGP establishes.
#   2. BIRD is frozen with SIGSTOP — the TCP connection stays open
#      (no FIN, no keepalives), so only BFD can detect the failure.
#   3. lr-daemon must tear the BGP session down within seconds
#      (BFD detection ~300ms) instead of the 60 s hold time.
#
# Phase 2 — multihop mode over off-link addresses:
#
#   netns r1: lr-daemon --bfd-multihop, 10.99.11.1/32 (+ onlink route)
#   netns r2: BIRD multihop BFD + eBGP, 10.99.13.2/32
#
#   BFD Control rides UDP 4784 (the RFC 5883 port) with sessions
#   addressed by the off-link pair — a single-hop implementation
#   listening only on 3784 would never see them. Environments that
#   allow sysctl run a real forwarding middle hop; here the pair is
#   delivered over the existing veth (accepting TTL<255 packets on
#   the 4784 socket is pinned by the bfd_transport unit tests), so
#   this phase proves the port/demux/config interop with BIRD's
#   multihop mode.
#
# BFD's UDP ports are fixed (3784/4784), so the routers need separate
# network namespaces. The lab runs rootless inside `unshare -Urn`
# (user + network namespace); environments without unprivileged user
# namespaces SKIP gracefully.
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
    echo "SKIP: unprivileged user namespaces unavailable — no netns lab"
    exit 0
}

REPO=$(pwd)
export REPO BIN BIRD BIRDC

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_bfd_bird_interop
rm -rf "$OUT"; mkdir -p "$OUT"

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-25} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF -- "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file (waiting for '$pat') --"
    cat "$file" 2>/dev/null
    return 1
}

# ===========================================================================
# Phase 1: single-hop BFD + BGP over a veth pair
# ===========================================================================
echo "== phase 1: single-hop BFD (RFC 5881, UDP 3784, TTL 255) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
unshare -n sleep 300 &
R1=$!
unshare -n sleep 300 &
R2=$!
cleanup() {
    kill "${LR_PID:-}" 2>/dev/null || true
    local p
    for pidfile in "$OUT/bird.pid" "$OUT/bird2.pid"; do
        p=$(cat "$pidfile" 2>/dev/null || true)
        if [ -n "$p" ] && [ "$p" != "0" ]; then
            kill "$p" 2>/dev/null || true
        fi
    done
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

cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 2.2.2.2;
protocol device {}
protocol bfd bfdd {
    interface "veth1" {
        min rx interval 100 ms;
        min tx interval 100 ms;
        multiplier 3;
    };
}
protocol bgp lr {
    local as 65002;
    neighbor 10.99.1.1 as 65001;
    bfd on;
    ipv4 {
        import all;
        export none;
    };
}
EOF

echo "   starting BIRD (AS65002, protocol bfd + bfd on) ..."
nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
birdc_r2() { nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird.ctl" "$@"; }

echo "   starting lr-daemon (AS65001, --bfd 100ms x 3, hold 60s) ..."
nsenter -t "$R1" -n "$BIN" \
    --local-as 65001 --peer-as 65002 --router-id 1.1.1.1 --ebgp-policy accept-all \
    --peer 10.99.1.2:179 --local-address 10.99.1.1 \
    --network 203.0.113.0/24 --hold-time 60 \
    --bfd --bfd-min-tx-ms 100 --bfd-min-rx-ms 100 --bfd-multiplier 3 \
    >"$OUT/r1.log" 2>&1 &
LR_PID=$!

echo "   waiting for BFD sessions to come up ..."
wait_log "$OUT/r1.log" "-> Up" 25
bfd_up_bird=1
for i in $(seq 1 60); do
    if birdc_r2 "show bfd sessions" 2>/dev/null | grep -Eq "10\.99\.1\.1.*Up"; then
        bfd_up_bird=0
        break
    fi
    sleep 0.5
done
if [ "$bfd_up_bird" -ne 0 ]; then
    echo "FAIL: BIRD's BFD session to 10.99.1.1 never came up"
    birdc_r2 "show bfd sessions" || true
    tail -20 "$OUT/bird.log" || true
    exit 1
fi
echo "   BFD Up on both sides (lr + BIRD)"

echo "   waiting for BGP establishment ..."
wait_log "$OUT/r1.log" "Established" 25
bgp_up_bird=1
for i in $(seq 1 60); do
    if birdc_r2 "show protocols all lr" 2>/dev/null | grep -q "Established"; then
        bgp_up_bird=0
        break
    fi
    sleep 0.5
done
if [ "$bgp_up_bird" -ne 0 ]; then
    echo "FAIL: BIRD's BGP session never established"
    birdc_r2 "show protocols all lr" || true
    tail -20 "$OUT/bird.log" || true
    exit 1
fi
echo "   BGP Established on both sides"

echo "   freezing BIRD (SIGSTOP): TCP stays open, BFD goes silent ..."
BIRD_PID=$(cat "$OUT/bird.pid")
t0=$(date +%s.%N)
kill -STOP "$BIRD_PID"
wait_log "$OUT/r1.log" "session ended: bfd session down" 10
t1=$(date +%s.%N)
elapsed=$(echo "$t1 $t0" | awk '{printf "%.1f", $1 - $2}')
kill -CONT "$BIRD_PID" 2>/dev/null || true
echo "   BFD fast-fail tore the BGP session down after ${elapsed}s (hold time was 60s)"
if [ "$(awk -v e="$elapsed" 'BEGIN {print (e > 5) ? 1 : 0}')" = "1" ]; then
    echo "FAIL: fast-fail took ${elapsed}s — BFD detection should be ~0.3s"
    exit 1
fi

# ===========================================================================
# Phase 2: multihop-mode BFD over the off-link address pair
# ===========================================================================
echo "== phase 2: multihop BFD (RFC 5883, UDP 4784) =="
kill "$LR_PID" 2>/dev/null || true
birdc_r2 down 2>/dev/null || kill "$(cat "$OUT/bird.pid")" 2>/dev/null || true
sleep 0.5

# Off-link address pair on the existing veth: multihop sessions are
# addressed 10.99.11.1 <-> 10.99.13.2 with onlink /32 routes, so the
# pair never matches the single-hop 10.99.1.x subnet. (A forwarding
# middle hop needs a writable net.ipv4.ip_forward, which
# container-locked /proc/sys denies here; see the header comment.)
nsenter -t "$R1" -n ip addr add 10.99.11.1/32 dev veth0
nsenter -t "$R1" -n ip route add 10.99.13.2/32 dev veth0
nsenter -t "$R2" -n ip addr add 10.99.13.2/32 dev veth1
nsenter -t "$R2" -n ip route add 10.99.11.1/32 dev veth1

cat >"$OUT/bird2.conf" <<EOF
log "$OUT/bird2.log" all;
router id 2.2.2.2;
protocol device {}
protocol bfd bfdd2 {
    multihop {
        min rx interval 100 ms;
        min tx interval 100 ms;
        multiplier 3;
    };
}
protocol bgp lr2 {
    local 10.99.13.2 as 65002;
    neighbor 10.99.11.1 as 65001;
    multihop;
    bfd on;
    ipv4 {
        import all;
        export none;
    };
}
EOF

echo "   starting BIRD (multihop BFD + eBGP multihop) ..."
if ! nsenter -t "$R2" -n "$BIRD" -c "$OUT/bird2.conf" -s "$OUT/bird2.ctl" -P "$OUT/bird2.pid"; then
    echo "FAIL: BIRD rejected the multihop config"
    cat "$OUT/bird2.log" 2>/dev/null || true
    exit 1
fi
sleep 0.5
birdc_r2() { nsenter -t "$R2" -n "$BIRDC" -s "$OUT/bird2.ctl" "$@"; }

echo "   starting lr-daemon (--bfd-multihop) ..."
nsenter -t "$R1" -n "$BIN" \
    --local-as 65001 --peer-as 65002 --router-id 1.1.1.1 --ebgp-policy accept-all \
    --peer 10.99.13.2:179 --local-address 10.99.11.1 \
    --network 203.0.113.0/24 --hold-time 60 \
    --bfd --bfd-multihop \
    --bfd-min-tx-ms 100 --bfd-min-rx-ms 100 --bfd-multiplier 3 \
    >"$OUT/r1mh.log" 2>&1 &
LR_PID=$!

echo "   waiting for the multihop BFD session ..."
wait_log "$OUT/r1mh.log" "-> Up" 25
bfd_up_bird=1
for i in $(seq 1 60); do
    if birdc_r2 "show bfd sessions" 2>/dev/null | grep -Eq "10\.99\.11\.1.*Up"; then
        bfd_up_bird=0
        break
    fi
    sleep 0.5
done
if [ "$bfd_up_bird" -ne 0 ]; then
    echo "FAIL: BIRD's multihop BFD session to 10.99.11.1 never came up"
    birdc_r2 "show bfd sessions" || true
    tail -20 "$OUT/bird2.log" || true
    exit 1
fi
echo "   multihop BFD Up on both sides (UDP 4784, off-link address pair)"

echo "   waiting for the multihop BGP establishment ..."
wait_log "$OUT/r1mh.log" "Established" 25
echo "   multihop BGP Established"

echo
echo "BFD x BIRD interop: PASS"
echo "  - single-hop: BFD Up, BGP Established, SIGSTOP fast-fail in ${elapsed}s vs 60s hold"
echo "  - multihop: RFC 5883 session (UDP 4784, off-link pair) + multihop eBGP"

# Explicit teardown (the trap also cleans up, but BIRD removes its pid
# file on graceful exit — do it deterministically).
kill "$LR_PID" 2>/dev/null || true
birdc_r2 down 2>/dev/null || true
sleep 0.3
INNER
