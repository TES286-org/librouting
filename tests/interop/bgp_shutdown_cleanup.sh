#!/usr/bin/env bash
# Graceful-shutdown cleanup interop: SIGINT (Ctrl+C) must leave the host
# exactly as it found it.
#
# The rc.4 Windows defect: Ctrl+C killed the process through the default
# console disposition, so the daemon never sent its session Cease and
# never withdrew the routes it had installed — the kernel FIB kept a
# silent blackhole until the next restart. This test pins the contract:
#
#   1. two lr-daemons (bgp,babel supervisor like the production config;
#      iBGP, one AS, bidirectional) exchange routes and install them
#      into the kernel FIB (--install-kernel-routes);
#   2. SIGINT daemon A (the signal Ctrl+C delivers on both Linux and
#      Windows console handlers);
#   3. A must exit 0, log "multi-protocol shutdown complete", withdraw
#      EVERY kernel route it installed (its own originated network AND
#      the route learned from B);
#   4. B must receive the RFC 4486 §4.1 Cease / Administrative Shutdown
#      NOTIFICATION (code 6 sub 2) — not a bare FIN — and withdraw A's
#      route immediately (no hold-timer wait).
#
# Linux-only lab (rootless via unshare -Urn). The kernel-route
# withdrawal half is covered portably on every primary platform by
# bgp_kernel_install.sh; the console handler itself can only be
# exercised inside a real console.
set -euo pipefail
cd "$(dirname "$0")/../.."

source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11799}
OS=$(lr_os)
export PORT

case "$OS" in
linux)
    command -v ip >/dev/null 2>&1 || { echo "SKIP: iproute2 not installed"; exit 0; }
    command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter not installed"; exit 0; }
    unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

    REPO=$(pwd)
    export REPO
exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
source tests/interop/_lib.sh
OUT=/tmp/lr_bgp_shutdown_cleanup
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building the two-router lab (veth pair, one netns per router) =="
lr_create_lab 2
lr_set_addr "$R1" "$VETH_R1" 10.98.2.1/24
lr_set_addr "$R2" "$VETH_R2" 10.98.2.2/24

# Daemon configs in the production DSL shape: bgp + babel in one
# supervisor, iBGP, bidirectional (both sides dial).
cat > "$OUT/a.lr" <<EOF
protocol "bgp,babel";
bgp {
    local_as 4242420078;
    router_id "172.23.10.102";
    listen_addr "10.98.2.1:$PORT";
    local_address "10.98.2.1";
    hold_time 30s;
    networks [203.0.113.0/24];
    install_kernel true;
}
babel {
    port 16696;
    interface "$VETH_R1" { type "tunnel"; }
}
peer "b" {
    remote "10.98.2.2:$PORT";
    peer_as 4242420078;
    hold_time 30s;
    import_filter "in-all";
    export_filter "out-all";
}
filter "in-all" { accept; }
filter "out-all" { accept; }
EOF

cat > "$OUT/b.lr" <<EOF
protocol "bgp,babel";
bgp {
    local_as 4242420078;
    router_id "172.23.10.98";
    listen_addr "10.98.2.2:$PORT";
    local_address "10.98.2.2";
    hold_time 30s;
    networks [198.51.100.0/24];
    install_kernel true;
}
babel {
    port 16696;
    interface "$VETH_R2" { type "tunnel"; }
}
peer "a" {
    remote "10.98.2.1:$PORT";
    peer_as 4242420078;
    hold_time 30s;
    import_filter "in-all";
    export_filter "out-all";
}
filter "in-all" { accept; }
filter "out-all" { accept; }
EOF

echo "== starting r1 (AS4242420078, originates 203.0.113.0/24) =="
DAEMON_A=$(lr_start_daemon "$R1" "$OUT/r1.log" --config "$OUT/a.lr" \
    --install-kernel-routes)

echo "== starting r2 (AS4242420078, originates 198.51.100.0/24) =="
DAEMON_B=$(lr_start_daemon "$R2" "$OUT/r2.log" --config "$OUT/b.lr" \
    --install-kernel-routes)

echo "== waiting for Established + kernel installs =="
lr_wait_log "$OUT/r1.log" "→ Established" 20
lr_wait_log "$OUT/r2.log" "→ Established" 20
lr_wait_kernel_route "$R1" "198.51.100.0/24" present 10 || {
    echo "FAIL: route learned from B never reached r1's kernel FIB"
    lr_ns_exec "$R1" ip route show; exit 1
}
lr_wait_kernel_route "$R2" "203.0.113.0/24" present 10 || {
    echo "FAIL: route learned from A never reached r2's kernel FIB"
    lr_ns_exec "$R2" ip route show; exit 1
}
echo "   PASS: sessions established, kernel routes installed on both sides"

echo "== sending SIGINT (Ctrl+C) to daemon A =="
kill -INT "$DAEMON_A"

# --- 1. A exits cleanly and says so ---
lr_wait_log "$OUT/r1.log" "shutdown complete" 10 || {
    echo "FAIL: daemon A never logged 'shutdown complete'"
    cat "$OUT/r1.log"; exit 1
}
# --- 2. A withdrew every kernel route it installed ---
lr_wait_kernel_route "$R1" "198.51.100.0/24" absent 10 || {
    echo "FAIL: learned route survived SIGINT (the rc.4 Ctrl+C defect)"
    lr_ns_exec "$R1" ip route show; exit 1
}
lr_wait_kernel_route "$R1" "203.0.113.0/24" absent 10 || {
    echo "FAIL: originated route survived SIGINT"
    lr_ns_exec "$R1" ip route show; exit 1
}
echo "   PASS: daemon A withdrew every installed kernel route"

# --- 3. B received the Cease / Administrative Shutdown, not a bare FIN ---
lr_wait_log "$OUT/r2.log" "peer sent NOTIFICATION code=6 sub=2" 10 || {
    echo "FAIL: peer B never received the Cease/Admin-Shutdown NOTIFICATION"
    cat "$OUT/r2.log"; exit 1
}
# --- 4. B withdrew A's route without waiting out any hold timer ---
lr_wait_kernel_route "$R2" "203.0.113.0/24" absent 10 || {
    echo "FAIL: route toward the shut-down peer survived its Cease"
    lr_ns_exec "$R2" ip route show; exit 1
}
echo "   PASS: peer got Cease 6/2 and converged immediately"

echo "PASS: SIGINT shutdown leaves the host clean (routes withdrawn,"
echo "      peer notified with Cease/Admin-Shutdown, daemon exits)"
INNER
    ;;
*)
    echo "SKIP: linux-only lab (kernel-route withdrawal on other platforms"
    echo "      is covered by bgp_kernel_install.sh)"
    exit 0
    ;;
esac
