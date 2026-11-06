#!/usr/bin/env bash
# LDPoIPv6 GTSM receive-side enforcement (RFC 7552 §9).
#
# defects.txt `crates/lr-cli/src/daemon_ldp.rs:L698-L700` recorded that
# the LDP daemon set the outbound hop limit (255) on every IPv6 session
# socket but did NOT enforce the receive side — the listener had no
# `IPV6_MINHOPCOUNT = 255` filter, so a low-hop-limit IPv6 SYN was
# admitted (fail-open). The fix arms the listener with the kernel
# min-TTL filter, matching FRR ldpd's default for AF_INET6 sessions
# (`nbr_gtsm_enabled`).
#
# Topology — a single rootless network namespace with a non-loopback
# IPv6 address on `lo`, so the LDP daemon enables the dual-stack TCP
# listener (which is the path the GTSM arming runs on):
#
#   unshare -Urn:
#     lo: fd00:99::1/128 (non-loopback v6, so interface_v6_addrs returns it)
#     lr-daemon --protocol ldp --router-id 10.0.0.1 \
#               --ldp-interface lo --ldp-port 6460 \
#               --ldp-transport 10.0.0.1 --ldp-transport-v6 fd00:99::1
#
# Success criteria:
#   1. The daemon starts and binds the dual-stack listener on [::]:6460.
#   2. A plain (default hop-limit 64) IPv6 TCP connect to [fd00:99::1]:6460
#      is rejected by the kernel's IPV6_MINHOPCOUNT filter — the SYN
#      arrives with hop limit 64, well below 255, so no SYN-ACK is sent
#      and the connect either times out or the daemon's `accept()` never
#      sees the connection.
#   3. A high-hop-limit (255) IPv6 TCP connect reaches the daemon's
#      listener — proves the filter does not over-reject (a real peer
#      that also uses GTSM passes).
#
# Linux-only (IPV6_MINHOPCOUNT is Linux-specific). Environments without
# `unshare -Urn` (or without python3) SKIP gracefully.

set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh 2>/dev/null || true)
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "SKIP: lr-daemon not built (cargo build -p lr-cli)"
    exit 0
fi
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 (ip) not installed"; exit 0; }
command -v unshare >/dev/null 2>&1 || { echo "SKIP: unshare (util-linux) not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter (util-linux) not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no LDP port 6460 bind"
    exit 0
}

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ldp_v6_gtsm
rm -rf "$OUT"; mkdir -p "$OUT"

PORT=6460
LDP_LOG="$OUT/ldp.log"
LRD_PID=""

cleanup() {
    [ -n "$LRD_PID" ] && kill "$LRD_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Bring lo up and add a non-loopback v6 address so
# `interface_v6_addrs("lo")` returns a non-empty vector (the helper
# filters out `::1`). The LDP daemon's dual-stack listener is only set
# up when at least one configured interface has a non-loopback v6
# address.
ip link set lo up
ip -6 addr add fd00:99::1/128 dev lo nodad

# Start lr-daemon with the v6 transport pinned to fd00:99::1 (otherwise
# the daemon would derive the transport from the first interface's
# primary v4 address; the dual-stack listener still binds to [::]:port
# and arms the GTSM filter, but the engine's transport-addr comparison
# prefers the configured v6 transport).
"$BIN" --protocol ldp --router-id 10.0.0.1 \
    --ldp-interface lo --ldp-port "$PORT" \
    --ldp-transport 10.0.0.1 --ldp-transport-v6 fd00:99::1 \
    --api-socket "$OUT/api.sock" \
    >"$LDP_LOG" 2>&1 &
LRD_PID=$!

# Wait for the daemon's runtime API to come up — proves the listener
# is bound (the API socket is set up after the listener is bound, in the
# same startup sequence).
api_up=0
for i in $(seq 1 50); do
    if grep -qF "runtime API on" "$LDP_LOG" 2>/dev/null; then
        api_up=1
        break
    fi
    sleep 0.1
done
if [ "$api_up" -ne 1 ]; then
    echo "FAIL: daemon did not bring up the API socket (listener bind failed?)"
    cat "$LDP_LOG" >&2
    exit 1
fi

# Confirm the dual-stack listener is actually listening on the v6 port.
# `ss -6 -ltn` should show the daemon on [::]:$PORT.
if ! ss -6 -ltn 2>/dev/null | grep -q ":$PORT"; then
    echo "FAIL: no v6 listener on :$PORT (daemon did not enable v6 transport)"
    cat "$LDP_LOG" >&2
    exit 1
fi

echo "== listener bound on [::]:$PORT; testing GTSM receive-side filter =="

# (1) A plain (default hop-limit 64) IPv6 TCP connect to the daemon's
#     listener must be REJECTED by IPV6_MINHOPCOUNT=255. The kernel
#     drops the inbound SYN before the listener's accept queue ever
#     sees it, so the connect times out (no SYN-ACK is sent). Without
#     the fix, the listener has no min-TTL filter and the SYN-ACK is
#     sent, so the connect returns Ok — that is the regression shape.
python3 - "$PORT" "$OUT/plain_connect.out" <<'PYEOF'
import socket, sys
port = int(sys.argv[1])
out = sys.argv[2]
try:
    s = socket.create_connection(("fd00:99::1", port), timeout=2.0)
except OSError as e:
    # Connect timeout / refused — the kernel dropped the SYN; this is
    # the expected GTSM-reject path.
    with open(out, "w") as f:
        f.write(f"rejected: {e}\n")
    sys.exit(0)
# The kernel completed the 3-way handshake — the SYN arrived at the
# listener and the listener sent a SYN-ACK that the python socket
# ACK'd. This means the GTSM filter is NOT enforced (regression).
s.close()
with open(out, "w") as f:
    f.write("admitted\n")
PYEOF

PLAIN_RESULT=$(cat "$OUT/plain_connect.out")
echo "   plain connect (hop-limit 64): $PLAIN_RESULT"
case "$PLAIN_RESULT" in
    rejected:*)
        echo "   OK: low-hop-limit SYN rejected by IPV6_MINHOPCOUNT"
        ;;
    admitted)
        echo "FAIL: low-hop-limit SYN was admitted (GTSM filter not enforced)"
        # Confirm by checking the daemon log — the listener must have
        # fired an "accepted connection from" line for this peer.
        grep -E "accepted connection from \[fd00:99::1\]" "$LDP_LOG" >&2 || true
        cat "$LDP_LOG" >&2
        exit 1
        ;;
    *)
        echo "FAIL: unexpected plain-connect outcome: $PLAIN_RESULT"
        exit 1
        ;;
esac

# Sanity: the daemon must NOT have logged "accepted connection from"
# for the plain (low-hop-limit) attempt — the kernel must have dropped
# the SYN before it reached the listener.
if grep -qF "accepted connection from" "$LDP_LOG" 2>/dev/null; then
    echo "FAIL: daemon accepted a low-hop-limit connection (kernel did not filter the SYN)"
    cat "$LDP_LOG" >&2
    exit 1
fi

# (2) A high-hop-limit (255) IPv6 TCP connect must reach the daemon's
#     listener. This proves the GTSM filter does not over-reject.
#     We set IPV6_UNICAST_HOPS=255 on the connecting socket (mirrors
#     what a GTSM-enforcing peer like FRR ldpd does).
python3 - "$PORT" "$OUT/gtsm_connect.out" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
out = sys.argv[2]
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
# Mirror FRR ldpd's GTSM: outbound hop limit 255 so the SYN passes the
# listener's IPV6_MINHOPCOUNT=255 filter.
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
s.settimeout(2.0)
try:
    s.connect(("fd00:99::1", port))
except OSError as e:
    s.close()
    with open(out, "w") as f:
        f.write(f"connect-failed: {e}\n")
    sys.exit(0)
# The LDP daemon accepts the connection and waits for the LDP
# Initialization PDU. Hold the connection open for ~2 seconds so the
# daemon's main loop (100 ms cadence) has time to call accept() and
# log "accepted connection from <peer>". A real LDP peer would start
# the LDP handshake here; this test only verifies the TCP-level GTSM
# filter passes a high-hop-limit SYN through to the listener.
time.sleep(2.0)
s.close()
with open(out, "w") as f:
    f.write("connected\n")
PYEOF

GTSM_RESULT=$(cat "$OUT/gtsm_connect.out")
echo "   gtsm connect (hop-limit 255): $GTSM_RESULT"
case "$GTSM_RESULT" in
    connected)
        echo "   OK: high-hop-limit SYN admitted (GTSM filter passes GTSM peer)"
        ;;
    connect-failed:*)
        # The connect can fail if the daemon's listener is no longer
        # accepting (e.g. the daemon crashed during the test). Inspect
        # the daemon log for "accepted connection from" — if the
        # listener never fired, this is a regression.
        if grep -qF "accepted connection from" "$LDP_LOG" 2>/dev/null; then
            echo "   OK: high-hop-limit SYN reached the daemon (accept fired)"
        else
            echo "FAIL: high-hop-limit SYN was rejected (filter over-rejects)"
            cat "$LDP_LOG" >&2
            exit 1
        fi
        ;;
    *)
        echo "FAIL: unexpected gtsm-connect outcome: $GTSM_RESULT"
        exit 1
        ;;
esac

# Final check: the daemon must have accepted at least one connection
# from the high-hop-limit test (the "accepted connection from" log
# line). This is the strongest signal that the GTSM filter passes
# GTSM-enforcing peers.
if ! grep -qF "accepted connection from" "$LDP_LOG" 2>/dev/null; then
    echo "FAIL: daemon never accepted the high-hop-limit connection"
    cat "$LDP_LOG" >&2
    exit 1
fi

echo "== PASS: LDPoIPv6 GTSM receive-side filter is enforced =="
echo "   - low-hop-limit (64) SYN rejected by IPV6_MINHOPCOUNT=255"
echo "   - high-hop-limit (255) SYN admitted (FRR-parity GTSM peer)"
INNER
