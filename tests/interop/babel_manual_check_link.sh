#!/usr/bin/env bash
# Babel manual-path check-link e2e (issue #39: BIRD `check link` parity).
#
# Two speakers, one network namespace each (same veth-pair shape the
# babel_multihop lab uses):
#
#   netns A (veth0a 192.0.2.1/24) ── veth0b (192.0.2.2/24) M (this namespace)
#
# Both A and M are single-interface MANUAL-path daemons (the legacy
# `--local-address` shape, no `[[babel.interface]]` block). Before
# issue #39, the manual path hardcoded `check_link: false`, so a
# carrier loss on A's own interface was learned only through the RFC
# 8966 §3.2.5 route hold timer (30 s). After #39, the manual path
# resolves the device from the local address and enables the 1 s
# check-link poll — matching BIRD (`check link` defaults on) and the
# spec path (`babel_iface_from_spec`).
#
# Success criteria:
#   1. A learns M's prefix 10.99.1.0/24 and installs it in its FIB.
#   2. `ip link set veth0a down` (A's OWN interface): A's check-link
#      poll detects the carrier loss within ~1 s, logs
#      "link down — withdrawing its routes (check link)", flushes the
#      session, and the kernel route for 10.99.1.0/24 vanishes within
#      3 s — NOT the 30 s hold-timer floor the pre-#39 manual path
#      would have needed.
#   3. `ip link set veth0a up`: A's check-link poll detects the
#      carrier return, logs "link up — resuming announcements", and
#      re-learns 10.99.1.0/24 within 10 s.
#
# The 3 s / 10 s windows are the regression: the pre-#39 manual path
# would time out on the down case (30 s hold timer) and leave the
# route absent far longer on the up case too.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh) || {
    echo "SKIP: lr-daemon not built (cargo build -p lr-cli)"
    exit 0
}
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 (ip) not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter (util-linux) not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_manual_check_link
rm -rf "$OUT"; mkdir -p "$OUT"

PORT=16696
GROUP=224.0.0.111

# One veth pair: A's end in NS_A, M's end in this namespace.
ip link set lo up
ip link add veth0a type veth peer name veth0b
unshare -n sleep 600 &
NS_A=$!
cleanup() {
    for p in ${DAEMONS:-}; do kill "$p" 2>/dev/null || true; done
    kill "$NS_A" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0a netns "$NS_A"

# A's namespace: the manual-path daemon's own interface.
nsenter -t "$NS_A" -n ip link set lo up
nsenter -t "$NS_A" -n ip link set veth0a up
nsenter -t "$NS_A" -n ip addr add 192.0.2.1/24 dev veth0a
nsenter -t "$NS_A" -n ip route add 224.0.0.0/4 dev veth0a
# M's end (this namespace): the peer.
ip link set veth0b up
ip addr add 192.0.2.2/24 dev veth0b
ip route add 224.0.0.0/4 dev veth0b

DAEMONS=""
start() { # name netns args...
    local name=$1 netns=$2; shift 2
    if [ "$netns" = "-" ]; then
        "$BIN" "$@" >"$OUT/$name.log" 2>&1 &
    else
        nsenter -t "$netns" -n "$BIN" "$@" >"$OUT/$name.log" 2>&1 &
    fi
    echo $!
}

# A: manual single-interface daemon on veth0a, originating 10.99.2.0/24.
# --install-kernel-routes mirrors the kernel FIB so the check-link
# withdrawal is observable as a route removal (not just a log line).
A_PID=$(start a "$NS_A" --protocol babel \
    --local-address 192.0.2.1 --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.2.0/24 --install-kernel-routes)
DAEMONS="$DAEMONS $A_PID"
# M: manual single-interface daemon on veth0b, originating 10.99.1.0/24.
# A learns this prefix; the test asserts on its presence/absence in A's FIB.
M_PID=$(start m - --protocol babel \
    --local-address 192.0.2.2 --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.1.0/24 --install-kernel-routes)
DAEMONS="$DAEMONS $M_PID"

wait_log() { # <timeout-s> <file> <pattern>
    local timeout=$1 file=$2 pattern=$3
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        grep -qF "$pattern" "$OUT/$file" 2>/dev/null && return 0
        sleep 0.25
    done
    return 1
}

wait_route() { # <timeout-s> <netns-or-dash> <prefix> <present|absent>
    local timeout=$1 netns=$2 prefix=$3 expected=$4
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local route
        if [ "$netns" = "-" ]; then
            route=$(ip route show "$prefix")
        else
            route=$(nsenter -t "$netns" -n ip route show "$prefix")
        fi
        case "$expected" in
            present) [ -n "$route" ] && return 0 ;;
            absent)  [ -z "$route" ] && return 0 ;;
        esac
        sleep 0.25
    done
    return 1
}

echo "== phase 1: A learns M's prefix =="
if ! wait_log 20 a.log "babel listening on"; then
    echo "FAIL: A did not start"; exit 1
fi
if ! wait_log 20 m.log "babel listening on"; then
    echo "FAIL: M did not start"; exit 1
fi
if ! wait_route 20 "$NS_A" 10.99.1.0/24 present; then
    echo "FAIL: A did not learn 10.99.1.0/24 from M"
    echo "--- a.log ---"; cat "$OUT/a.log"
    echo "--- m.log ---"; cat "$OUT/m.log"
    exit 1
fi
echo "PASS: A learned 10.99.1.0/24 and installed it in its FIB"

echo "== phase 2: veth0a (A's own interface) goes down =="
# A's check-link poll runs every 1 s; the carrier loss must be
# detected and the route withdrawn within 3 s — NOT the 30 s hold
# timer the pre-#39 manual path would have needed.
nsenter -t "$NS_A" -n ip link set veth0a down
if ! wait_log 3 a.log "link down — withdrawing its routes (check link)"; then
    echo "FAIL: A's check-link poll did not fire within 3 s of carrier loss"
    echo "      (pre-#39 the manual path had no check-link at all)"
    echo "--- a.log ---"; cat "$OUT/a.log"
    exit 1
fi
if ! wait_route 3 "$NS_A" 10.99.1.0/24 absent; then
    echo "FAIL: A's kernel route for 10.99.1.0/24 survived the carrier loss"
    echo "      (check-link flushed the session but the FIB was not updated)"
    echo "--- a.log ---"; cat "$OUT/a.log"
    exit 1
fi
echo "PASS: check-link withdrew the learned route within the 3 s window"

echo "== phase 3: veth0a comes back up =="
nsenter -t "$NS_A" -n ip link set veth0a up
if ! wait_log 3 a.log "link up — resuming announcements"; then
    echo "FAIL: A's check-link poll did not detect the carrier return within 3 s"
    echo "--- a.log ---"; cat "$OUT/a.log"
    exit 1
fi
# A re-learns 10.99.1.0/24 from M's next announcement (M's update
# interval is 3 s on the manual path, so allow 10 s for the full
# reconvergence).
if ! wait_route 10 "$NS_A" 10.99.1.0/24 present; then
    echo "FAIL: A did not re-learn 10.99.1.0/24 after the link returned"
    echo "--- a.log ---"; cat "$OUT/a.log"
    echo "--- m.log ---"; cat "$OUT/m.log"
    exit 1
fi
echo "PASS: route returns when the link comes back"

echo "== all babel manual check-link phases passed =="
exit 0
INNER
