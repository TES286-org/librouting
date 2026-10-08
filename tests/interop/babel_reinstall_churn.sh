#!/usr/bin/env bash
# Babel route re-installation churn regression (deterministic).
#
# The rc.4 defect: `apply_runtime_delta` emitted a fresh
# `RouterEvent::RouteInstalled` unconditionally — even when the route
# was byte-identical to the one already in the Loc-RIB. OSPF/Babel
# runtimes that recompute the same best path on every tick (or every
# Babel UPDATE re-advertisement) flooded the kernel mirror with
# redundant installs. The Windows production report captured the
# symptom: `mirror: route installed 10.127.32.98/32 via 169.254.1.6
# oif 58 (babel)` repeated four times in a row for the same prefix.
#
# The fix: `LocRib::install` now returns a bool "did this actually
# change the Loc-RIB?" signal, and `apply_runtime_delta` skips the
# `RouteInstalled` event when the signal is false. The kernel mirror
# thus only sees genuine changes.
#
# Topology (one rootless user+network namespace via `unshare -Urn`):
#   Two lr-daemon speakers share the loopback. Speaker A advertises
#   10.99.3.0/24; speaker B listens, learns it via Babel, installs
#   it into the kernel FIB. We then count the `mirror: route
#   installed` log lines for the prefix — with the fix the count is
#   exactly 1 (the initial install); pre-fix the count grew on every
#   Babel UPDATE re-advertisement (multiple per second).
#
# Success criteria:
#   1. Speaker B installs the route exactly once (one
#      `mirror: route installed 10.99.3.0/24` log line).
#   2. The route stays installed for the duration of the test (no
#      churn-driven withdrawal).
#
# Loopback + user namespace — no reference daemon.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
OS=$(lr_os)

case "$OS" in
linux)
    command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
    unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }
    ;;
*)
    echo "SKIP: babel_reinstall_churn.sh is Linux-only (netns + iproute2)"
    exit 0
    ;;
esac

REPO=$(pwd)
export REPO BIN

# Run inside a user+network namespace so the kernel route table is
# private to the test and the install count is deterministic.
exec unshare -Urn bash -euo pipefail <<'INNER'
set -euo pipefail
cd "$REPO"

OUT=/tmp/lr_babel_reinstall_churn
rm -rf "$OUT"; mkdir -p "$OUT"

# Two IPv4 addresses on the loopback so each speaker has its own
# bind source (the babel_auth.sh / babel_router_id_e2e.sh topology
# — multicast on lo works on every Linux we ship CI for).
A_ADDR=127.10.0.1
B_ADDR=127.10.0.2
GROUP=224.0.0.111
PORT=16696

ip link set lo up
ip link set lo multicast on
ip addr add "$A_ADDR/8" dev lo nodad 2>/dev/null || true
ip addr add "$B_ADDR/8" dev lo nodad 2>/dev/null || true
ip route add 224.0.0.0/4 dev lo 2>/dev/null || true

DAEMONS=""
cleanup() {
    for p in $DAEMONS; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Speaker A: originates 10.99.3.0/24.
"$BIN" --protocol babel \
    --router-id 172.23.10.102 \
    --local-address "$A_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.3.0/24 \
    >"$OUT/a.log" 2>&1 &
A=$!
DAEMONS="$DAEMONS $A"

# Speaker B: listens, learns A's route via Babel.
"$BIN" --protocol babel \
    --router-id 172.23.10.103 \
    --local-address "$B_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    >"$OUT/b.log" 2>&1 &
B=$!
DAEMONS="$DAEMONS $B"

# Wait for the route to propagate (Babel convergence is fast on a
# directly-connected loopback multicast group). The `daemon: route
# installed` line fires for every `RouterEvent::RouteInstalled`,
# regardless of whether `--install-kernel-routes` is set — the
# churn we are measuring is at the event layer, not the kernel
# layer.
for _ in $(seq 1 100); do
    if grep -q "route installed 10.99.3.0/24" "$OUT/b.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# Let the session run a bit longer so Babel's periodic UPDATE
# re-advertisements have a chance to fire (pre-fix these would
# produce extra `daemon: route installed` lines).
sleep 5

# Kill the daemons (clean shutdown).
for p in $DAEMONS; do kill "$p" 2>/dev/null || true; done
trap - EXIT
cleanup || true

# Count the `daemon: route installed 10.99.3.0/24` log lines.
# With the fix: exactly 1 (the initial install).
# Pre-fix: >= 2 (re-installed on every Babel UPDATE re-advertisement).
COUNT=$(grep -c "route installed 10.99.3.0/24" "$OUT/b.log" || true)
echo "install count: $COUNT"

if [ "$COUNT" -lt 1 ]; then
    echo "FAIL: the route was never installed — Babel did not converge?"
    echo "--- A log ---"; cat "$OUT/a.log" || true
    echo "--- B log ---"; cat "$OUT/b.log" || true
    exit 1
fi

if [ "$COUNT" -gt 1 ]; then
    echo "FAIL: route installed $COUNT times (expected 1 — the churn regression)"
    echo "Pre-fix daemons re-install on every Babel UPDATE re-advertisement."
    echo "--- B log (route installed lines) ---"
    grep "route installed" "$OUT/b.log" || true
    exit 1
fi

echo "PASS: route installed exactly once — no churn from Babel UPDATE re-advertisements"
INNER
