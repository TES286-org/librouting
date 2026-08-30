#!/usr/bin/env bash
# Babel RFC 8967 MAC-authenticated transport e2e: two lr-daemon babel
# speakers over IPv4 multicast (224.0.0.111, RFC 8966 §5) inside one
# rootless user/network namespace, exercising:
#
#   phase 1 — same key on both sides: adjacency + bidirectional route
#             propagation through the RFC 8967 MAC/PC machinery;
#   phase 2 — speaker A restarts (fresh packet-counter Index AND fresh
#             router-id source key): B's Challenge Request resynchronizes
#             the peers (§4.3.1) and routes flow again;
#   phase 3 — mismatched keys: no route propagates (fail closed);
#   phase 4 — RFC 8967 §5 incremental deployment: unsigned A talks to
#             B configured with --babel-accept-unauthenticated.
#
# The lab runs inside `unshare -Urn` (user + network namespace): rootless,
# exactly what CI does. Environments without unprivileged user namespaces
# (or without iproute2) SKIP gracefully.
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
unshare -Urn true 2>/dev/null || {
    echo "SKIP: unprivileged user namespaces unavailable"
    exit 0
}

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_auth
rm -rf "$OUT"; mkdir -p "$OUT"

A_ADDR=127.10.0.1
B_ADDR=127.10.0.2
GROUP=224.0.0.111
PORT=16696

ip link set lo up
ip link set lo multicast on
ip addr add "$A_ADDR/8" dev lo nodad 2>/dev/null || true
ip addr add "$B_ADDR/8" dev lo nodad 2>/dev/null || true
# The multicast egress route some container kernels do not auto-install.
ip route add 224.0.0.0/4 dev lo 2>/dev/null || true

DAEMON_A=""; DAEMON_B=""
cleanup() {
    [ -n "$DAEMON_A" ] && kill "$DAEMON_A" 2>/dev/null || true
    [ -n "$DAEMON_B" ] && kill "$DAEMON_B" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

start_a() {  # speaker A: 127.10.0.1, key "link-secret", network 10.99.1.0/24
    "$BIN" --protocol babel \
        --local-address "$A_ADDR" \
        --babel-group "$GROUP" --babel-port "$PORT" \
        --babel-key "link-secret" \
        --network 10.99.1.0/24 \
        >"$OUT/a.log" 2>&1 &
    DAEMON_A=$!
}

start_b() {  # speaker B: 127.10.0.2, key "link-secret", network 10.99.2.0/24
    "$BIN" --protocol babel \
        --local-address "$B_ADDR" \
        --babel-group "$GROUP" --babel-port "$PORT" \
        --babel-key "link-secret" \
        --network 10.99.2.0/24 \
        >"$OUT/b.log" 2>&1 &
    DAEMON_B=$!
}

# wait_for <timeout-s> <count> <file> <fixed-string> [<file> <string>...]
# Every (file, string) pair must occur at least <count> times.
wait_for() {
    local timeout=$1 count=$2; shift 2
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local ok=1 i
        local -a args=("$@")
        for ((i = 0; i + 1 < ${#args[@]}; i += 2)); do
            local have=0
            have=$(grep -cF "${args[$((i + 1))]}" "${args[$i]}" 2>/dev/null || true)
            [ "${have:-0}" -ge "$count" ] || ok=0
        done
        [ "$ok" = 1 ] && return 0
        sleep 0.25
    done
    return 1
}

echo "== phase 1: RFC 8967-authenticated adjacency (same key) =="
start_a
start_b
wait_for 60 1 \
    "$OUT/a.log" "babel MAC auth enabled (1 key(s): hmac-sha256)" \
    "$OUT/b.log" "babel MAC auth enabled (1 key(s): hmac-sha256)" \
    "$OUT/a.log" "route installed 10.99.2.0/24" \
    "$OUT/b.log" "route installed 10.99.1.0/24"
echo "PASS: bidirectional route propagation with MAC auth"

echo "== phase 2: A restarts (fresh Index + router-id) -> challenge resync =="
kill "$DAEMON_A" 2>/dev/null; wait "$DAEMON_A" 2>/dev/null || true
DAEMON_A=""
sleep 1
"$BIN" --protocol babel \
    --local-address "$A_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --babel-key "link-secret" \
    --network 10.99.1.0/24 \
    >>"$OUT/a.log" 2>&1 &
DAEMON_A=$!
# B sees a brand-new (Index, router-id) source: it drops A's datagrams,
# sends a Challenge Request (§4.3.1.1), and accepts the reply — the route
# appears in B's Loc-RIB a second time.
wait_for 60 2 "$OUT/b.log" "route installed 10.99.1.0/24"
echo "PASS: challenge resynchronization after restart"

echo "== phase 3: mismatched keys fail closed =="
kill "$DAEMON_A" "$DAEMON_B" 2>/dev/null || true
wait 2>/dev/null || true
DAEMON_A=""; DAEMON_B=""
"$BIN" --protocol babel \
    --local-address "$A_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --babel-key "link-secret" \
    --network 10.99.1.0/24 \
    >"$OUT/c.log" 2>&1 &
DAEMON_A=$!
"$BIN" --protocol babel \
    --local-address "$B_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --babel-key "wrong-secret" \
    --network 10.99.2.0/24 \
    >"$OUT/d.log" 2>&1 &
DAEMON_B=$!
sleep 12
if grep -qF "route installed 10.99.1.0/24" "$OUT/d.log" 2>/dev/null; then
    echo "FAIL: a wrong key must not admit routes"
    exit 1
fi
if grep -qF "route installed 10.99.2.0/24" "$OUT/c.log" 2>/dev/null; then
    echo "FAIL: a wrong key must not admit routes (other direction)"
    exit 1
fi
echo "PASS: wrong-key datagrams dropped, no route installed"

echo "== phase 4: RFC 8967 5 incremental deployment =="
kill "$DAEMON_A" "$DAEMON_B" 2>/dev/null || true
wait 2>/dev/null || true
DAEMON_A=""; DAEMON_B=""
# A runs unsigned; B signs and accepts unauthenticated inbound.
"$BIN" --protocol babel \
    --local-address "$A_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.1.0/24 \
    >"$OUT/e.log" 2>&1 &
DAEMON_A=$!
"$BIN" --protocol babel \
    --local-address "$B_ADDR" \
    --babel-group "$GROUP" --babel-port "$PORT" \
    --babel-key "link-secret" --babel-accept-unauthenticated \
    --network 10.99.2.0/24 \
    >"$OUT/f.log" 2>&1 &
DAEMON_B=$!
wait_for 60 1 \
    "$OUT/f.log" "route installed 10.99.1.0/24" \
    "$OUT/e.log" "route installed 10.99.2.0/24"
echo "PASS: incremental deployment converges in both directions"

echo "== all babel auth phases passed =="
INNER
