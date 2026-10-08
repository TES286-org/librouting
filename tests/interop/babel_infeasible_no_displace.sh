#!/usr/bin/env bash
# Babel infeasible-update displacement regression (end-to-end).
#
# The production-report defect: a single-upstream Babel tunnel
# flapped — routes installed, withdrawn with the misleading "babel
# best-path displacement" reason, re-installed, re-withdrawn — even
# though there was only ONE upstream and no competing path could
# possibly displace the route.
#
# Root cause (RFC 8966 §3.5.2): an infeasible update (same seqno,
# worse metric) was unconditionally inserted into the route table,
# overwriting the existing feasible route. `best_routes()` then
# skipped the infeasible entry, `diff()` produced a withdrawal, and
# the reason renderer logged the "best-path displacement" fallback.
#
# This test crafts the exact stimulus:
#   1. Teach one route (seqno 100, metric 192) — feasible, installs.
#   2. Re-advertise with the SAME seqno but a WORSE metric (44055) —
#      infeasible per RFC 8966 §3.5.1. The fix ignores this update;
#      the pre-fix bug overwrote the feasible route and withdrew it.
#   3. Assert: the route stays installed, and the log does NOT
#      contain "best-path displacement" for the withdrawal (there
#      must be no withdrawal at all).
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
    echo "SKIP: babel_infeasible_no_displace.sh is Linux-only (netns + iproute2 + python3)"
    exit 0
    ;;
esac

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
set -euo pipefail
cd "$REPO"

OUT=/tmp/lr_babel_infeasible
rm -rf "$OUT"; mkdir -p "$OUT"

ip link set lo up
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
# Second loopback address so the test can send FROM 127.0.0.2 — the
# daemon drops datagrams whose source IP is one of its own interface
# addresses (self-loop guard).
ip addr add 127.0.0.2/32 dev lo 2>/dev/null || true

PORT=16696
PREFIX_HEX="0a630400"  # 10.99.4.0
PLEN=24
RID_HEX="00000000ac170a61"  # 172.23.10.97 as a router-id

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

# --- 1. Teach one route (seqno 100, metric 192) ---
python3 tests/interop/babel_send.py teach \
    "$RID_HEX" 1 "$PLEN" "$PREFIX_HEX" 100 192 \
    >"$OUT/teach.bin"
send_frame "$OUT/teach.bin" "teach seqno=100 metric=192"

# Wait for the route to be installed.
for _ in $(seq 1 100); do
    if grep -q "route installed 10.99.4.0/24" "$OUT/daemon.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "route installed 10.99.4.0/24" "$OUT/daemon.log"; then
    echo "FAIL: route was not installed after the teach frame"
    echo "--- daemon log ---"; cat "$OUT/daemon.log" || true
    exit 1
fi
echo "route installed"

# --- 2. Re-advertise with the SAME seqno but a WORSE metric (44055) ---
# This is infeasible per RFC 8966 §3.5.1 (seqno == FD.seqno AND
# metric >= FD.metric). The fix ignores it; the pre-fix bug
# overwrote the feasible route and produced a withdrawal.
python3 tests/interop/babel_send.py teach \
    "$RID_HEX" 1 "$PLEN" "$PREFIX_HEX" 100 44055 \
    >"$OUT/infeasible.bin"
send_frame "$OUT/infeasible.bin" "infeasible seqno=100 metric=44055"

# Give the daemon a moment to process the frame and (pre-fix) emit
# the withdrawal.
sleep 1

# --- 3. Assertions ---
# (a) The route must NOT have been withdrawn.
if grep -q "route withdrawn 10.99.4.0/24" "$OUT/daemon.log"; then
    echo "FAIL: the infeasible update displaced the feasible route (RFC 8966 §3.5.2 violation)"
    echo "--- babel withdraw lines ---"
    grep "babel withdraw" "$OUT/daemon.log" || true
    echo "--- route withdrawn lines ---"
    grep "route withdrawn" "$OUT/daemon.log" || true
    exit 1
fi

# (b) The log must NOT contain the misleading "best-path displacement"
# reason for this prefix.
if grep -q "best-path displacement" "$OUT/daemon.log"; then
    echo "FAIL: log contains 'best-path displacement' — the infeasible-update displacement bug"
    grep "best-path displacement" "$OUT/daemon.log" || true
    exit 1
fi

echo "PASS: infeasible update ignored — feasible route retained, no spurious withdrawal"
echo "      (RFC 8966 §3.5.2: infeasible updates must not displace feasible routes)"
INNER
