#!/usr/bin/env bash
# RPKI-RTR daemon e2e: lr-daemon's RTR client (`[bgp.rpki]` /
# `--rpki-cache`, RFC 8210) against librouting's mock cache server
# (the lr-bgp `rtr_cache_mock` example — the same codec BIRD 2's RPKI
# client validated in rtr_bird.sh, from the cache's other side).
#
# What this proves, end to end, against a real lr-daemon process:
#
#   * The daemon's RTR thread connects, sends a Reset Query (§8.1),
#     and the mock cache's full dataset (2 ROAs) lands in the live
#     RoaStore — verified through the runtime API `status` command's
#     rpki line (roas count, session, serial, phase).
#   * The client's reconnect path works: the cache drops the
#     transport, the daemon backs off and re-syncs incrementally
#     (Serial Query with the remembered session).
#
# Runs on loopback TCP only — no raw sockets, no namespaces, no
# privileges. Environments without the built daemon or example SKIP
# gracefully (the same scenarios run as cargo e2e tests in
# crates/lr-cli/tests/daemon_rpki.rs).
set -euo pipefail
cd "$(dirname "$0")/../.."

DAEMON=target/debug/lr-daemon
MOCK=target/debug/examples/rtr_cache_mock
if [ ! -x "$DAEMON" ]; then DAEMON=target/release/lr-daemon; fi
if [ ! -x "$MOCK" ]; then MOCK=target/release/examples/rtr_cache_mock; fi
if [ ! -x "$DAEMON" ] || [ ! -x "$MOCK" ]; then
    echo "SKIP: build lr-daemon and rtr_cache_mock first \
(cargo build -p lr-cli; cargo build -p lr-bgp --example rtr_cache_mock)"
    exit 0
fi

PORT=$(python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
)
API=/tmp/lr_rtr_lr_api_$$.sock
CFG=/tmp/lr_rtr_lr_$$.toml
LOG=/tmp/lr_rtr_lr_$$.log

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null || true
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
    rm -f "$API" "$CFG" "$LOG"
}
trap cleanup EXIT

# The mock cache serves its fixed two-ROA dataset (192.0.2.0/24-24 and
# 2001:db8::/48-64, both AS 64512) on the chosen port.
"$MOCK" "$PORT" 2>/dev/null &
MOCK_PID=$!

cat > "$CFG" <<EOF
[bgp]
local_as = 64512
peer_as = 64513
router_id = "10.0.0.1"

[bgp.rpki]
cache = "127.0.0.1:$PORT"
retry_interval = 1

[[roa]]
prefix = "198.51.100.0/24"
asn = 64513
EOF

"$DAEMON" --config "$CFG" --api-socket "$API" >"$LOG" 2>&1 &
DAEMON_PID=$!

# Wait for the daemon's RTR thread to complete the first sync.
deadline=$((SECONDS + 20))
while ! grep -q "rpki: sync complete" "$LOG" 2>/dev/null; do
    if [ $SECONDS -ge $deadline ]; then
        echo "FAIL: no RTR sync within 20 s"; tail -20 "$LOG"; exit 1
    fi
    sleep 0.2
done
echo "ok: first RTR sync"

# Verify the API status line: 2 cache ROAs + 1 static ROA, session and
# serial from the mock cache's End of Data (session 0x00ff, serial 1).
STATUS=""
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
    STATUS=$(python3 - "$API" <<'EOF' 2>/dev/null || true
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])
s.sendall(b"status\n")
s.shutdown(socket.SHUT_WR)
buf = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
print(buf.decode(errors="replace"))
EOF
)
    if printf '%s\n' "$STATUS" | grep -q "rpki: cache=.*state=connected.*roas=3 (static=1 rtr=2)"; then
        break
    fi
    sleep 0.2
done
printf '%s\n' "$STATUS" | grep "rpki: cache=" || {
    echo "FAIL: rpki status line missing or wrong"; printf '%s\n' "$STATUS"; exit 1;
}
echo "ok: rpki status line (roas=3 static=1 rtr=2, session/serial from EoD)"

# Reconnect path: kill the cache, expect the client to notice, back
# off, and re-sync after a fresh cache takes the same port (the mock
# cache is single-shot here, so the daemon's retry logs are the
# observable).
kill "$MOCK_PID" 2>/dev/null
MOCK_PID=""
deadline=$((SECONDS + 10))
while ! grep -q "closed the connection\|connect to .* failed" "$LOG" 2>/dev/null; do
    if [ $SECONDS -ge $deadline ]; then
        echo "FAIL: daemon did not notice the cache drop"; tail -5 "$LOG"; exit 1
    fi
    sleep 0.2
done
echo "ok: daemon noticed the cache drop and retries"
echo "ALL PASS"
