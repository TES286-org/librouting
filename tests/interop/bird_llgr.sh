#!/usr/bin/env bash
# BIRD LLGR interop test: RFC 9494 Long-Lived Graceful Restart against
# BIRD 2, covering the full lifecycle in BOTH directions:
#
#   Phase 1 — negotiation + route exchange
#   Phase 2 — BIRD as helper: lr-daemon dies; BIRD retains the route,
#             marks it LLGR_STALE after the RFC 4724 restart window and
#             purges it when the long-lived stale time expires.
#   Phase 3 — lr-daemon as helper: BIRD dies; lr-daemon retains the route
#             (log lines from the retention state machine), marks it
#             stale and purges at expiry.
#
# Timers are deliberately short: restart time 3 s, LLST 10 s → the whole
# suite settles in well under a minute.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries (default: from $PATH)
#   PORT           lr-daemon listen port (default 17995)
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

PORT=${PORT:-17995}
RESTART_TIME=3    # RFC 4724 restart time advertised by both sides
LLST=10           # RFC 9494 long-lived stale time advertised by both sides
OUT=/tmp/lr_bird_llgr_interop
rm -rf "$OUT"; mkdir -p "$OUT"

cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting RFC 9494 LLGR interop test.
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
    local port 17992 as 64513;
    neighbor 127.0.0.1 port $PORT as 64512;
    multihop 2;
    graceful restart time $RESTART_TIME;
    long lived graceful restart;
    long lived stale time $LLST;
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF

start_lr_daemon() {
    "$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
        --listen 127.0.0.1:$PORT --local-address 127.0.0.1 \
        --network 203.0.113.0/24 \
        --graceful-restart $RESTART_TIME --llgr $LLST \
        >>"$OUT/lr.log" 2>&1 &
    LR_PID=$!
}

start_bird() {
    "$BIRD" -c "$OUT/bird.conf" -s "$OUT/bird.ctl" -P "$OUT/bird.pid"
    BIRD_PID=$(cat "$OUT/bird.pid" 2>/dev/null || echo "")
}

wait_for_bird_route() {  # $1 = prefix to await
    for _ in $(seq 1 120); do
        sleep 0.25
        if "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null | grep -q "$1"; then
            return 0
        fi
    done
    return 1
}

fail=0
note_fail() { echo "FAIL: $1"; fail=1; }

echo "== phase 1: negotiation + route exchange =="
start_bird
trap 'kill ${LR_PID:-} ${BIRD_PID:-} 2>/dev/null || true' EXIT
sleep 1
start_lr_daemon
for i in $(seq 1 120); do
    sleep 0.25
    proto=$("$BIRDC" -s "$OUT/bird.ctl" show protocols all lr 2>/dev/null || true)
    neighbor_caps=$(printf '%s' "$proto" | sed -n '/Neighbor capabilities/,/^\s*Session:/p')
    printf '%s' "$neighbor_caps" | grep -q "Long-lived graceful restart" && \
    printf '%s' "$neighbor_caps" | grep -q "Graceful restart" && \
    grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null && \
    break
    [ "$i" = 120 ] && { note_fail "phase 1 convergence"; }
done
"$BIRDC" -s "$OUT/bird.ctl" show protocols all lr 2>/dev/null | head -45 || true

echo "== phase 2: BIRD as RFC 9494 helper (lr-daemon dies) =="
kill $LR_PID 2>/dev/null || true
wait $LR_PID 2>/dev/null || true
sleep 1
"$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null | grep -q "203.0.113.0/24" \
    || note_fail "BIRD did not retain 203.0.113.0/24 inside the restart window"
sleep $((RESTART_TIME + 2))
# Past the restart window the route must be retained AND marked LLGR_STALE
# (BIRD renders 0xFFFF0006 as community (65535,6) and prefers it with an
# 's' suffix).
stale=$("$BIRDC" -s "$OUT/bird.ctl" show route all 2>/dev/null | grep -A10 "203.0.113.0/24" || true)
echo "$stale" || true
printf '%s' "$stale" | grep -q "203.0.113.0/24" \
    || note_fail "BIRD purged 203.0.113.0/24 before the LLST expired"
printf '%s' "$stale" | grep -q "65535,6" \
    || note_fail "BIRD did not mark the retained route LLGR_STALE (community 0xFFFF0006)"
sleep $((LLST + 3))
if "$BIRDC" -s "$OUT/bird.ctl" show route 2>/dev/null | grep -q "203.0.113.0/24"; then
    note_fail "BIRD kept 203.0.113.0/24 past the long-lived stale time"
fi
"$BIRDC" -s "$OUT/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
wait 2>/dev/null || true
sleep 1

echo "== phase 3: lr-daemon as RFC 9494 helper (BIRD dies) =="
rm -f "$OUT/lr.log"
: >"$OUT/lr.log"
start_bird
start_lr_daemon
for i in $(seq 1 120); do
    sleep 0.25
    grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null && break
    [ "$i" = 120 ] && { note_fail "phase 3 convergence"; }
done
kill $BIRD_PID 2>/dev/null || true
sleep 1
grep -q "graceful-restart retention" "$OUT/lr.log" \
    || note_fail "lr-daemon did not enter graceful-restart retention"
grep -q "LLGR" "$OUT/lr.log" || note_fail "lr-daemon retention is not LLGR-aware"
grep -qF "route withdrawn 198.51.100.0/24" "$OUT/lr.log" \
    && note_fail "lr-daemon purged the peer routes on session loss (no retention)"
sleep $((RESTART_TIME + 2))
grep -q "LLGR stale state" "$OUT/lr.log" \
    || note_fail "lr-daemon did not mark the routes LLGR_STALE after the restart window"
sleep $((LLST + 3))
grep -qF "route withdrawn 198.51.100.0/24" "$OUT/lr.log" \
    || note_fail "lr-daemon kept the stale route past the long-lived stale time"
echo "== lr-daemon log (phase 3) =="
cat "$OUT/lr.log"

kill $LR_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD LLGR interop — RFC 9494 full lifecycle negotiated with BIRD 2"
fi
exit $fail
