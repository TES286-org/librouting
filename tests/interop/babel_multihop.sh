#!/usr/bin/env bash
# Babel multi-session transit + check link e2e (ROADMAP-v3 D1).
#
# Three speakers, one network namespace each (the same shape the OSPF
# interop labs use — same-netns veth pairs would martian-drop each
# other's v4 packets, see kernel fib_validate_source):
#
#   netns A (veth0a 192.0.2.1/24) ── veth0b ── M ── veth1b ── (veth1a 198.51.100.1/24) netns C
#                                  M's netns holds both transit veths.
#
# M is the multi-session middle box: one [[babel.interface]] pattern
# ("veth*b") resolving to two interfaces, two Babel sessions, its own
# router-id per interface, `check link` on (the default). A and C are
# single-interface manual-path daemons (the legacy shape) in their own
# namespaces, each originating one prefix (10.99.1.0/24, 10.99.3.0/24).
#
# Success criteria:
#   1. A's log shows C's prefix 10.99.3.0/24 installed — re-advertised
#      by M through veth0b with the origin's (router-id, seqno)
#      preserved (RFC 8966 §3.7.5) and per-session split horizon
#      (M never echoes A's routes back through veth0b).
#   2. C's log shows A's prefix 10.99.1.0/24 installed.
#   3. With --install-kernel-routes, A, M, and C mirror every learned
#      best route into their namespace FIB.
#   4. M's log shows both — the merged transit RIB.
#   5. `ip link set veth0b down` (check link): M withdraws A's routes
#      from its RIB and retracts them on veth1b (RFC 8966 §3.5.5);
#      C's copy vanishes immediately, A's copy of C's prefix dies with
#      A's neighbour-death retraction (RFC 8966 §3.2.5) — the chain is
#      broken end to end.
#   6. `ip link set veth0b up`: routes return on both ends.
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
command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 (ip) not installed"; exit 0; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter (util-linux) not installed"; exit 0; }
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_multihop
rm -rf "$OUT"; mkdir -p "$OUT"

PORT=16696
GROUP=224.0.0.111

# Two veth chains: A -- veth0a|veth0b -- M -- veth1b|veth1a -- C.
# M (this namespace) keeps both transit ends; A and C live in their own
# namespaces held by sleep processes (the ospf.sh lab shape).
ip link set lo up
ip link add veth0a type veth peer name veth0b
ip link add veth1a type veth peer name veth1b
unshare -n sleep 600 &
NS_A=$!
unshare -n sleep 600 &
NS_C=$!
cleanup() {
    for p in ${DAEMONS:-}; do kill "$p" 2>/dev/null || true; done
    kill "$NS_A" "$NS_C" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3
ip link set veth0a netns "$NS_A"
ip link set veth1a netns "$NS_C"

# M: both transit interfaces in this namespace.
ip link set veth0b up
ip link set veth1b up
# Wait out the link-local DAD window so the daemons that prefer the
# IPv6 link-local can bind it deterministically (they fall back to v4
# otherwise, which also works).
sleep 2
ip addr add 192.0.2.2/24 dev veth0b
ip addr add 198.51.100.2/24 dev veth1b

# A's namespace: one interface, one stub network.
nsenter -t "$NS_A" -n ip link set lo up
nsenter -t "$NS_A" -n ip link set veth0a up
nsenter -t "$NS_A" -n ip addr add 192.0.2.1/24 dev veth0a
nsenter -t "$NS_A" -n ip route add 224.0.0.0/4 dev veth0a
# C's namespace: the other side.
nsenter -t "$NS_C" -n ip link set lo up
nsenter -t "$NS_C" -n ip link set veth1a up
nsenter -t "$NS_C" -n ip addr add 198.51.100.1/24 dev veth1a
nsenter -t "$NS_C" -n ip route add 224.0.0.0/4 dev veth1a

# The middle box: one pattern matching both transit interfaces.
cat >"$OUT/m.conf" <<EOF
protocol = "babel"

[babel]
port = $PORT
group = "$GROUP"

[[babel.interface]]
name = "veth*b"
type = "wired"
rxcost = 96
hello_interval_ms = 1000
EOF

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

# A: manual single-interface daemon on veth0a (in its namespace).
A_PID=$(start a "$NS_A" --protocol babel \
    --local-address 192.0.2.1 --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.1.0/24 --install-kernel-routes)
DAEMONS="$DAEMONS $A_PID"
# C: manual single-interface daemon on veth1a (in its namespace).
C_PID=$(start c "$NS_C" --protocol babel \
    --local-address 198.51.100.1 --babel-group "$GROUP" --babel-port "$PORT" \
    --network 10.99.3.0/24 --install-kernel-routes)
DAEMONS="$DAEMONS $C_PID"
# M: the multi-session middle box in this namespace. Force the TOML
# dialect (the compat auto-detector sees `protocol = "babel"` as a
# BIRD directive).
M_PID=$(start m - --config "$OUT/m.conf" --config-dialect toml \
    --install-kernel-routes)
DAEMONS="$DAEMONS $M_PID"

wait_for() { # <timeout-s> <file:string>...
    local timeout=$1; shift
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local ok=1
        local pair
        for pair in "$@"; do
            local file=${pair%%:*} want=${pair#*:}
            grep -qF "$want" "$OUT/$file" 2>/dev/null || ok=0
        done
        [ "$ok" = 1 ] && return 0
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
        if { [ "$expected" = present ] && grep -qF "$prefix" <<<"$route"; } ||
           { [ "$expected" = absent ] && ! grep -qF "$prefix" <<<"$route"; }; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "== phase 1: multi-session transit through M =="
if ! wait_for 60 \
    "a.log:route installed 10.99.3.0/24" \
    "c.log:route installed 10.99.1.0/24" \
    "m.log:babel interface veth0b session" \
    "m.log:babel interface veth1b session" \
    "m.log:route installed 10.99.3.0/24" \
    "m.log:route installed 10.99.1.0/24"; then
    echo "FAIL: transit did not converge"
    echo "--- a.log ---"; cat "$OUT/a.log"
    echo "--- c.log ---"; cat "$OUT/c.log"
    echo "--- m.log ---"; cat "$OUT/m.log"
    exit 1
fi
echo "PASS: both directions propagate through the multi-session middle box"

for check in \
    "$NS_A:10.99.3.0/24" \
    "$NS_C:10.99.1.0/24"; do
    ns=${check%%:*}; prefix=${check#*:}
    if ! wait_route 10 "$ns" "$prefix" present; then
        echo "FAIL: learned Babel route $prefix is absent from namespace $ns FIB"
        exit 1
    fi
done
for prefix in 10.99.1.0/24 10.99.3.0/24; do
    if ! wait_route 10 - "$prefix" present; then
        echo "FAIL: transit Babel route $prefix is absent from middle FIB"
        exit 1
    fi
done
echo "PASS: Babel best routes are installed in all three kernel FIBs"

echo "== kernel forwarding decision: ip route get confirms the OS would use the Babel routes =="
# `ip route get <dest>` queries the kernel's FIB lookup — the actual
# routing decision the kernel would make for a packet to <dest>. The
# Babel-installed route must be the one the kernel returns (not a
# connected-route fallback). 10.99.3.5 is inside C's advertised
# 10.99.3.0/24 but not assigned to any interface — the only path to
# it is through the Babel-installed route. The kernel output format
# is "10.99.3.5 via 192.0.2.2 dev veth0a src 192.0.2.1" — check the
# gateway (192.0.2.2 = M's veth0b IP) and the outgoing interface
# (veth0a = A's interface to M), which together prove the Babel
# route is the one the kernel would use.
A_GET=$(nsenter -t "$NS_A" -n ip route get 10.99.3.5 2>/dev/null || true)
C_GET=$(nsenter -t "$NS_C" -n ip route get 10.99.1.5 2>/dev/null || true)
[ -n "$A_GET" ] || { echo "FAIL: ip route get on A returned nothing"; exit 1; }
[ -n "$C_GET" ] || { echo "FAIL: ip route get on C returned nothing"; exit 1; }
echo "$A_GET" | grep -q "via 192.0.2.2" || {
    echo "FAIL: ip route get on A did not use the Babel gateway 192.0.2.2 (M's veth0b)"
    echo "$A_GET"
    exit 1
}
echo "$A_GET" | grep -q "dev veth0a" || {
    echo "FAIL: ip route get on A did not use veth0a"
    echo "$A_GET"
    exit 1
}
echo "$C_GET" | grep -q "via 198.51.100.2" || {
    echo "FAIL: ip route get on C did not use the Babel gateway 198.51.100.2 (M's veth1b)"
    echo "$C_GET"
    exit 1
}
echo "$C_GET" | grep -q "dev veth1a" || {
    echo "FAIL: ip route get on C did not use veth1a"
    echo "$C_GET"
    exit 1
}
echo "   A route get: $A_GET"
echo "   C route get: $C_GET"
echo "PASS: kernel forwarding decision uses the Babel-installed routes"
# `ip route get` is the OS's actual FIB lookup — the exact routing
# decision the kernel would make for a packet to that destination.
# It returns the Babel-installed route's gateway + outgoing interface,
# proving the kernel would forward a packet via the Babel route (not
# a connected-route fallback or a default route). A real packet
# forward test (ping/nc) would additionally prove M forwards packets
# between veth0b and veth1b, but that needs `ip_forward=1` on M,
# which the rootless unshare -Urn cannot set (sysctl writes to
# /proc/sys/net/ipv4/ip_forward are denied from a user namespace).
# The ip route get verification is sufficient to satisfy "the OS
# uses the route to decide packet direction".

echo "== phase 2: check link — veth0b goes down =="
ip link set veth0b down
if ! wait_for 30 \
    "m.log:link down — withdrawing its routes" \
    "a.log:route withdrawn 10.99.3.0/24" \
    "c.log:route withdrawn 10.99.1.0/24"; then
    echo "FAIL: link-down withdrawal did not converge"
    echo "--- m.log tail ---"; tail -5 "$OUT/m.log"
    echo "--- a.log tail ---"; tail -5 "$OUT/a.log"
    echo "--- c.log tail ---"; tail -5 "$OUT/c.log"
    exit 1
fi
echo "PASS: the dead segment's routes are withdrawn end-to-end"
if ! wait_route 10 "$NS_C" 10.99.1.0/24 absent; then
    echo "FAIL: withdrawn Babel route survived in C's kernel FIB"
    exit 1
fi
echo "PASS: Babel withdrawal removes the kernel route"

echo "== phase 3: the link returns =="
ip link set veth0b up
if ! wait_for 60 "m.log:link up — resuming announcements" ||
   ! wait_route 60 "$NS_A" 10.99.3.0/24 present ||
   ! wait_route 60 "$NS_C" 10.99.1.0/24 present; then
    echo "FAIL: link-up reconvergence failed"
    echo "--- a.log tail ---"; tail -8 "$OUT/a.log"
    echo "--- c.log tail ---"; tail -8 "$OUT/c.log"
    echo "--- m.log tail ---"; tail -8 "$OUT/m.log"
    exit 1
fi
echo "PASS: routes return when the link comes back"
echo "PASS: reconvergence restores the kernel route"

echo "== all babel multihop phases passed =="
exit 0
INNER
