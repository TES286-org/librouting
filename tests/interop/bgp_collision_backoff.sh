#!/usr/bin/env bash
# RFC 4271 §6.8 collision-loss backoff regression (deterministic).
#
# A fake BGP speaker accepts every connection and answers with a Cease /
# Connection Collision Resolution NOTIFICATION (RFC 4486 subcode 7) —
# exactly what a reference router sends when IT holds the surviving
# session (Established-protection rule) or its resolver picks the other
# transport. The rc.4 defect: lr-daemon redialed ~1 s after every loss
# (the reconnect backoff reset on every successful TCP connect) and
# hammered the peer indefinitely — the production Windows RR loop.
#
# The fix: the loss latches a collision backoff (the peer's hold window,
# clamped 10–120 s) before the next dial, so the attempt rate must
# collapse. With hold_time 10 s the daemon makes ~2 attempts in 16 s;
# the pre-fix daemon made ~16.
#
# Loopback only — no namespaces, no reference daemon.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11801}
OUT=/tmp/lr_bgp_collision_backoff
rm -rf "$OUT"; mkdir -p "$OUT"

python3 - "$PORT" >"$OUT/fake.log" 2>&1 <<'PYEOF' &
import socket, struct, sys, time

port = int(sys.argv[1])
marker = b"\xff" * 16
# NOTIFICATION: header (19) + code 6 (Cease) + subcode 7 (Connection
# Collision Resolution) = 21 bytes on the wire.
notify = marker + struct.pack(">H", 21) + bytes([3, 6, 7])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
print(f"fake peer listening on {port}", flush=True)
deadline = time.time() + 40
while time.time() < deadline:
    srv.settimeout(1.0)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        continue
    # No OPEN in return: the FSM sits in OpenSent, and the Cease/7 is
    # fatal from any state (RFC 4271 §6.7 / §6.8) — exactly the
    # peer-resolver-lost signature.
    try:
        conn.sendall(notify)
        time.sleep(0.05)
    except OSError:
        pass
    conn.close()
PYEOF
FAKE_PID=$!
trap 'kill $FAKE_PID 2>/dev/null || true' EXIT
sleep 0.5

echo "== starting lr-daemon (hold_time 10s → collision backoff 10s) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --hold-time 10 \
    --peer 127.0.0.1:$PORT >"$OUT/daemon.log" 2>&1 &
DAEMON_PID=$!
trap 'kill $FAKE_PID $DAEMON_PID 2>/dev/null || true' EXIT

# Observation window: with the fix the connector makes attempt #1 at
# ~0.2 s and attempt #2 at ~10.5 s; a third lands at ~20.5 s. The
# pre-fix daemon redialed ~1 s after every loss (~16 attempts).
sleep 16

ATTEMPTS=$(grep -cF "connecting to 127.0.0.1:$PORT" "$OUT/daemon.log" || true)
LOSSES=$(grep -cF "connection lost the RFC 4271 §6.8 collision resolution" "$OUT/daemon.log" || true)
echo "attempts: $ATTEMPTS, collision losses: $LOSSES"

if [ "$LOSSES" -lt 1 ]; then
    echo "FAIL: no collision loss was exercised — the fake peer did not run?"
    cat "$OUT/fake.log" "$OUT/daemon.log"
    exit 1
fi
if [ "$ATTEMPTS" -gt 4 ]; then
    echo "FAIL: $ATTEMPTS attempts in 16 s — the connector is hammering a"
    echo "      peer that keeps answering Cease/7 (rc.4 regression)"
    grep -F "reconnecting in" "$OUT/daemon.log" | head -20
    exit 1
fi
if [ "$ATTEMPTS" -lt 2 ]; then
    echo "FAIL: only $ATTEMPTS attempts — the connector stopped dialing entirely?"
    cat "$OUT/daemon.log"
    exit 1
fi

echo "PASS: collision losses back the connector off (attempts collapsed"
echo "      from ~1/s to the hold-window cadence, peer not hammered)"
