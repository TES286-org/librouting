#!/usr/bin/env bash
# Babel wildcard-retraction withdraw-reason regression (end-to-end).
#
# The production-report defect: a BIRD peer whose BGP upstreams
# disconnected sent a wildcard retraction (RFC 8966 §4.6.9 — AE 0,
# metric 0xFFFF). lr's `apply_update` flushed the route table on this
# signal but returned without setting `last_withdraw_reason`, so
# `handle_frame` fell back to the misleading "babel best-path
# displacement" string. The operator (correctly) concluded the
# message was wrong: with one upstream, no "best-path election" can
# produce zero paths — the actual cause is an explicit peer-side
# retraction.
#
# This test crafts the stimulus bytes with `babel_send.py` (the
# daemon's own codec is the code under test, so we cannot use it to
# generate the stimulus) and feeds them to a running `lr-daemon` via
# UDP. The daemon's log must contain "wildcard retraction" and must
# NOT contain the "best-path displacement" fallback.
#
# Topology (one rootless user+network namespace via `unshare -Urn`):
#   The daemon binds babel on 127.0.0.1, the test sends UDP frames
#   to 127.0.0.1:<port>. The daemon's babel socket accepts unicast
#   on the same socket as multicast, so no multicast setup is needed.
#
# Success criteria:
#   1. After the teach frame, the daemon installs the route
#      (`daemon: route installed 10.99.4.0/24`).
#   2. After the wildcard-retraction frame, the daemon logs
#      `babel withdraw: babel peer wildcard retraction ...` and
#      withdraws the route.
#   3. The log does NOT contain the misleading `babel best-path
#      displacement` fallback for this withdrawal.
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
    command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
    ;;
*)
    echo "SKIP: babel_withdraw_reason.sh is Linux-only (netns + iproute2 + python3)"
    exit 0
    ;;
esac

REPO=$(pwd)
export REPO BIN

# Run inside a user+network namespace so the babel socket is private
# to the test and the daemon does not collide with a system babeld.
exec unshare -Urn bash -euo pipefail <<'INNER'
set -euo pipefail
cd "$REPO"

OUT=/tmp/lr_babel_withdraw_reason
rm -rf "$OUT"; mkdir -p "$OUT"

ip link set lo up
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
# Add a second loopback address so the test can send FROM 127.0.0.2 —
# the daemon's babel reception filters out datagrams whose source IP
# is one of its own interface addresses (the self-loop guard), so a
# packet from 127.0.0.1 → 127.0.0.1 is dropped. 127.0.0.2 is in the
# 127.0.0.0/8 loopback range (Linux delivers it locally) but is NOT
# the daemon's bind address, so the daemon accepts the frame as a
# genuine peer datagram.
ip addr add 127.0.0.2/32 dev lo 2>/dev/null || true

# The daemon's babel port — pick a high port to avoid collisions with
# a system babeld the test host might be running.
PORT=16696
# A documentation prefix the test teaches + retracts. /24 so the
# daemon's `--network` origination does not pick it up.
PREFIX_HEX="0a630400"  # 10.99.4.0
PLEN=24
RID_HEX="00000000ac170a61"  # 172.23.10.97 as a router-id

# Start the daemon in babel-only mode. --local-address pins the babel
# transport to loopback; the daemon's manual babel path derives the
# transport from the local address.
"$BIN" --protocol babel \
    --router-id 172.23.10.102 \
    --local-address 127.0.0.1 \
    --babel-port "$PORT" \
    >"$OUT/daemon.log" 2>&1 &
DAEMON=$!
echo "daemon pid: $DAEMON"

cleanup() {
    kill "$DAEMON" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the daemon to bind the babel port (up to 10 s).
for _ in $(seq 1 100); do
    if ss -lun 2>/dev/null | grep -q ":$PORT\b"; then
        break
    fi
    sleep 0.1
done
if ! ss -lun 2>/dev/null | grep -q ":$PORT\b"; then
    echo "FAIL: daemon did not bind babel port $PORT"
    echo "--- daemon log ---"; cat "$OUT/daemon.log" || true
    exit 1
fi
echo "daemon bound babel port $PORT"

# Helper: send a babel frame from 127.0.0.2:$PORT to 127.0.0.1:$PORT.
# The source port MUST equal the babel port (RFC 8966 §4.1) — the
# daemon filters on this. SO_REUSEADDR lets the source socket share
# the port with the daemon's babel sockets.
send_frame() {
    local file=$1 label=$2
    python3 - "$file" "$label" <<'PY'
import socket, sys
file, label = sys.argv[1], sys.argv[2]
with open(file, "rb") as f:
    data = f.read()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.2", 16696))
sock.sendto(data, ("127.0.0.1", 16696))
print(f"sent {len(data)} bytes ({label}) from 127.0.0.2:16696")
PY
}

# --- 1. Teach one route via a crafted babel frame ---
python3 tests/interop/babel_send.py teach \
    "$RID_HEX" 1 "$PLEN" "$PREFIX_HEX" 3 100 \
    >"$OUT/teach.bin"
send_frame "$OUT/teach.bin" "teach"

# Wait for the route to install (up to 10 s).
for _ in $(seq 1 100); do
    if grep -q "route installed 10.99.4.0/$PLEN" "$OUT/daemon.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "route installed 10.99.4.0/$PLEN" "$OUT/daemon.log" 2>/dev/null; then
    echo "FAIL: the route was never installed — babel did not converge?"
    echo "--- daemon log ---"; cat "$OUT/daemon.log" || true
    exit 1
fi
echo "route installed"

# Drain any pending log lines so the wildcard-retraction check does
# not match a stale line.
sleep 1

# --- 2. Send a wildcard retraction (AE 0, metric 0xFFFF) ---
python3 tests/interop/babel_send.py retract-wildcard >"$OUT/retract.bin"
send_frame "$OUT/retract.bin" "wildcard retraction"

# Wait for the daemon to log the withdraw reason (up to 10 s).
for _ in $(seq 1 100); do
    if grep -q "babel withdraw:" "$OUT/daemon.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "babel withdraw:" "$OUT/daemon.log" 2>/dev/null; then
    echo "FAIL: the daemon did not log a babel withdraw"
    echo "--- daemon log ---"; cat "$OUT/daemon.log" || true
    exit 1
fi

# --- 3. Verify the reason is "wildcard retraction", NOT the fallback ---
echo "--- babel withdraw lines ---"
grep "babel withdraw:" "$OUT/daemon.log" || true

if ! grep -q "wildcard retraction" "$OUT/daemon.log"; then
    echo "FAIL: the withdraw reason must mention 'wildcard retraction'"
    echo "Pre-fix the fallback 'babel best-path displacement' fired because"
    echo "the wildcard-retraction branch in apply_update returned without"
    echo "setting last_withdraw_reason."
    exit 1
fi

if grep -q "best-path displacement" "$OUT/daemon.log"; then
    echo "FAIL: the misleading 'best-path displacement' fallback fired for a"
    echo "wildcard retraction. The fallback is only correct for local"
    echo "best-path displacement (a better route pushed the previous best"
    echo "out of the feasible set), NOT for an explicit peer retraction."
    exit 1
fi

# The route must also have been withdrawn from the kernel FIB view.
for _ in $(seq 1 100); do
    if grep -q "route withdrawn 10.99.4.0/$PLEN" "$OUT/daemon.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "route withdrawn 10.99.4.0/$PLEN" "$OUT/daemon.log" 2>/dev/null; then
    echo "FAIL: the route was not withdrawn after the wildcard retraction"
    echo "--- daemon log ---"; cat "$OUT/daemon.log" || true
    exit 1
fi

echo
echo "PASS: wildcard retraction logs 'wildcard retraction' (not 'best-path displacement')"
INNER
