#!/usr/bin/env bash
# LDP two-daemon interop test: real multicast link discovery over a veth pair.
#
# Topology — each LSR in its own network namespace joined by a veth pair:
#
#   netns r1: lr-daemon LSR-id 1.1.1.1, binds 203.0.113.0/24 → label 24000
#             veth0: 10.99.1.1/24
#        ↑↓ LDP link Hellos to 224.0.0.2 (TTL 1), TCP 646 session
#   netns r2: lr-daemon LSR-id 2.2.2.2, binds 198.51.100.0/24 → label 16
#             veth1: 10.99.1.2/24
#
# Success criteria:
#   1. Both daemons form a link-Hello adjacency and reach Operational.
#   2. r1 learns r2's binding for 198.51.100.0/24 (and vice versa for
#      203.0.113.0/24).
#   3. Killing r2 expires the adjacency and tears r1's session down.
#
# LDP uses port 646, which is privileged: the whole lab runs inside
# `unshare -Urn` (user + network namespace) where binding is allowed —
# rootless, exactly what CI does. Environments without unprivileged user
# namespaces (or without iproute2) SKIP gracefully.
#
# NOTE: log matching uses POSIX `grep -qF` — CI images do not guarantee
# `rg` on PATH.
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
command -v ip >/dev/null 2>&1 || {
    echo "SKIP: iproute2 (ip) not installed"
    exit 0
}
command -v nsenter >/dev/null 2>&1 || {
    echo "SKIP: nsenter (util-linux) not installed"
    exit 0
}
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable — no LDP port 646 bind"
    exit 0
}

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_ldp_interop
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-LSR lab (veth pair, one netns per router) =="
ip link set lo up
ip link add veth0 type veth peer name veth1
# Holder processes keep the two router namespaces alive.
unshare -n sleep 120 &
R1=$!
unshare -n sleep 120 &
R2=$!
cleanup() {
    kill "${DAEMON_A:-}" "${DAEMON_B:-}" 2>/dev/null || true
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

wait_log() { # <file> <pattern> [timeout-seconds]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" && return 0
        sleep 0.1
    done
    echo "-- $file --"
    cat "$file"
    return 1
}

echo "== starting LSR r1 (1.1.1.1, binds 203.0.113.0/24 -> 24000) =="
nsenter -t "$R1" -n "$BIN" --protocol ldp --router-id 1.1.1.1 \
    --ldp-interface veth0 --ldp-link-hold 9 --ldp-keepalive 3 \
    --ldp-bind 203.0.113.0/24=24000 \
    --api-socket "$OUT/r1.ctl" >"$OUT/r1.log" 2>&1 &
DAEMON_A=$!

echo "== starting LSR r2 (2.2.2.2, binds 198.51.100.0/24 -> 16) =="
nsenter -t "$R2" -n "$BIN" --protocol ldp --router-id 2.2.2.2 \
    --ldp-interface veth1 --ldp-link-hold 9 --ldp-keepalive 3 \
    --ldp-bind 198.51.100.0/24=16 \
    --api-socket "$OUT/r2.ctl" >"$OUT/r2.log" 2>&1 &
DAEMON_B=$!

# 1. Adjacencies over multicast link Hellos, sessions Operational.
wait_log "$OUT/r1.log" "session up peer 2.2.2.2:0" || exit 1
wait_log "$OUT/r2.log" "session up peer 1.1.1.1:0" || exit 1
echo "PASS: link-Hello adjacency + LDP session established both ways"

# 2. Bindings exchanged in both directions (§3.5.9 downstream unsolicited).
wait_log "$OUT/r1.log" "mapping learned 198.51.100.0/24 label 16" || exit 1
wait_log "$OUT/r2.log" "mapping learned 203.0.113.0/24 label 24000" || exit 1
echo "PASS: FEC-label bindings exchanged in both directions"

# 3. Kill r2: the Hello hold timer (9 s) expires and r1 tears the
#    session down with its learned mappings.
kill -9 "$DAEMON_B" 2>/dev/null || true
wait_log "$OUT/r1.log" "adjacency down peer 2.2.2.2:0" 15 || exit 1
wait_log "$OUT/r1.log" "session down peer 2.2.2.2:0" 5 || exit 1
echo "PASS: hold-time expiry tears the session down after the peer dies"

echo "PASS: LDP two-daemon interop — multicast discovery, session, bindings, teardown"
INNER
