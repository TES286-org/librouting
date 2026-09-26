#!/usr/bin/env bash
# RFC 4271 §6.8 collision zombie regression: the peer holds a live
# session to a DEAD instance of us (restart during a link flap — the
# RST never reached it), and every fresh dial of the restarted daemon
# bounces off the peer's Established-protection rule with Cease /
# Connection Collision Resolution (RFC 4486 subcode 7).
#
# The rc.4 defect: the connector redialed ~1 s after every loss (the
# backoff reset on every successful TCP connect) and the churn guard
# required a sibling session already in Established — which never
# happens while the peer's surviving session is the zombie — so the
# daemon hammered the peer once a second until the zombie's hold timer
# expired, each round pinning a bogus RFC 4724 retention. The fix:
# latch the loss, wait out the peer's hold window before dialing again,
# and stay passive once ANY sibling session establishes.
#
# Topology (mirrors the production report: iBGP RR + client):
#   netns r1: BIRD 2, router id 172.23.10.98, rr client, cluster id
#             172.23.10.96, connects to 172.23.10.102
#   netns r2: lr-daemon AS4242420078, router id 172.23.10.102,
#             bidirectional (remote + listener) like the production
#             config
#
# Success criteria:
#   1. fresh start converges to Established (one collision at most);
#   2. after the zombie is created, the restarted daemon accumulates at
#      most 2 collision losses (pre-fix: one per second, dozens) and
#      never enters RFC 4724 retention for a session that was never
#      established;
#   3. both sides converge to exactly one Established session again
#      once the zombie dies (first keepalive retransmission after the
#      link relight) and BIRD redials.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
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

PORT=${PORT:-11800}
export BIRD BIRDC
OS=$(lr_os)
export PORT

case "$OS" in
linux)
    command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
    command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter not installed"; exit 0; }
    unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

    REPO=$(pwd)
    export REPO
exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
source tests/interop/_lib.sh
OUT=/tmp/lr_bgp_collision_zombie
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (BIRD RR ↔ lr client) =="
lr_create_lab 2
lr_set_addr "$R1" "$VETH_R1" 172.23.10.98/24
lr_set_addr "$R2" "$VETH_R2" 172.23.10.102/24

cat > "$OUT/bird.conf" <<EOF
router id 172.23.10.98;
log "$OUT/bird.log" all;
protocol device {}
protocol bgp lr {
    local 172.23.10.98 port $PORT as 4242420078;
    neighbor 172.23.10.102 port $PORT as 4242420078;
    multihop;
    connect delay time 1;
    keepalive time 25;
    connect retry time 2;
    rr client;
    debug all;
    rr cluster id 172.23.10.96;
    ipv4 {
        next hop keep ibgp;
        import all;
        export where source = RTS_BGP;
    };
}
EOF

cat > "$OUT/lr.lr" <<EOF
protocol "bgp";
bgp {
    local_as 4242420078;
    router_id "172.23.10.102";
    listen_addr "172.23.10.102:$PORT";
    local_address "172.23.10.102";
    hold_time 30s;
    graceful_restart_time 120s;
    mp_families [ipv4-unicast];
    soft_reconfig_inbound true;
}
peer "rr-hk01" {
    remote "172.23.10.98:$PORT";
    peer_as 4242420078;
    hold_time 30s;
    import_filter "in-all";
    export_filter "out-all";
}
filter "in-all" { accept; }
filter "out-all" { accept; }
EOF

echo "== starting BIRD (RR side) then lr (client, bidirectional) =="
lr_ns_exec "$R1" "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
DAEMON=$(lr_start_daemon "$R2" "$OUT/lr-1.log" --config "$OUT/lr.lr")

echo "== 1. fresh start converges to Established =="
lr_wait_log "$OUT/lr-1.log" "→ Established" 25
BIRD_STATE=$("$BIRDC" -s "$OUT/bird.ctl" show protocols lr 2>/dev/null | tail -1 || true)
echo "   BIRD sees: $BIRD_STATE"
LOSSES=$(grep -cF "connection lost the RFC 4271 §6.8 collision resolution" "$OUT/lr-1.log" || true)
[ "$LOSSES" -le 2 ] || { echo "FAIL: fresh start lost $LOSSES collisions"; exit 1; }
echo "   PASS: fresh start converged ($LOSSES collision losses)"

echo "== 2. creating the zombie: link dark, SIGKILL lr, restart, link up =="
lr_ns_exec "$R1" ip link set "$VETH_R1" down
kill -9 "$DAEMON" 2>/dev/null || true
sleep 0.5
DAEMON=$(lr_start_daemon "$R2" "$OUT/lr-2.log" --config "$OUT/lr.lr")
sleep 1
lr_ns_exec "$R1" ip link set "$VETH_R1" up

echo "== 3. convergence after the zombie dies (<= 90 s), loop broken =="
lr_wait_log "$OUT/lr-2.log" "→ Established" 90 || {
    echo "FAIL: restarted daemon never converged"
    tail -40 "$OUT/lr-2.log"; "$BIRDC" -s "$OUT/bird.ctl" show protocols lr; exit 1
}
LOSSES=$(grep -cF "connection lost the RFC 4271 §6.8 collision resolution" "$OUT/lr-2.log" || true)
[ "$LOSSES" -le 2 ] || {
    echo "FAIL: $LOSSES collision losses — the connector is hammering"
    grep -cF "reconnecting in 1000ms" "$OUT/lr-2.log" || true
    exit 1
}
RETAINED=$(grep -cF "entered graceful-restart retention" "$OUT/lr-2.log" || true)
[ "$RETAINED" -eq 0 ] || {
    echo "FAIL: $RETAINED bogus RFC 4724 retentions for never-established sessions"
    exit 1
}
# Exactly one Established session, still alive after a settling window.
sleep 5
BIRD_STATE=$("$BIRDC" -s "$OUT/bird.ctl" show protocols lr 2>/dev/null | tail -1 || true)
echo "$BIRD_STATE" | grep -q "Established" || {
    echo "FAIL: BIRD did not re-establish after the zombie died: $BIRD_STATE"
    exit 1
}
EST=$(grep -c "→ Established" "$OUT/lr-2.log" || true)
[ "$EST" -ge 1 ] || { echo "FAIL: no Established session at lr"; exit 1; }
echo "   PASS: zombie recovered, $LOSSES collision loss(es), no bogus retention"
echo "   BIRD sees: $BIRD_STATE"

echo "PASS: RFC 4271 §6.8 collision zombie loop is broken (backoff +"
echo "      Established churn guard), convergence intact"
INNER
    ;;
*)
    echo "SKIP: linux-only lab (requires user namespaces + BIRD 2)"
    exit 0
    ;;
esac
