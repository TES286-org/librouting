#!/usr/bin/env bash
# Shared library for lr interop tests. Source this file from any
# interop script to get the common helpers:
#
#   source tests/interop/_lib.sh
#
# The library provides:
#   lr_create_lab <n>      Create n network namespaces joined by a
#                         veth chain. Sets R1, R2, ... R<n> (PIDs of
#                         the namespace-holder sleep processes) and
#                         VETH_R1, VETH_R2, ... (the interface names
#                         inside each namespace). Also sets
#                         LR_NAMESPACES (space-separated PIDs for
#                         cleanup).
#   lr_ns_exec <pid> <cmd...>  Run a command inside namespace <pid>.
#   lr_set_addr <pid> <iface> <addr>  Assign an IP to an interface
#                         inside a namespace.
#   lr_start_daemon <pid> <args...>  Start lr-daemon inside a
#                         namespace. Sets LR_DAEMON_PIDS (space-
#                         separated PIDs for cleanup).
#   lr_wait_log <file> <pattern> [timeout-s]  Poll a log file for a
#                         pattern (default 20 s timeout).
#   lr_wait_kernel_route <pid> <prefix> <present|absent> [timeout-s]
#                         Poll ip route show for a prefix.
#   lr_verify_route_get <pid> <dest> <via> <dev>  Assert ip route get
#                         returns the expected gateway + device.
#   lr_verify_ping <pid> <dest> [count] [timeout]  Send a ping from a
#                         namespace and assert a reply (requires
#                         ip_forward on any transit routers; use
#                         lr_enable_forwarding for that).
#   lr_enable_forwarding <pid>  Enable net.ipv4.ip_forward in a
#                         namespace (requires root — fails in
#                         unshare -U user namespaces; the helper
#                         prints a SKIP message and returns 1).
#   lr_cleanup  Kill all daemons + namespace holders. Registered as
#                         an EXIT trap automatically.
#
# The library expects the caller to have already run `cd "$(dirname
# "$0")/../.."` (so $BIN resolves) and to have verified that `unshare
# -Urn true` works (for netns-based tests).
set -euo pipefail

# --- binary resolution ---
# Use BASH_SOURCE (not $0) so the path resolves correctly even when
# the library is sourced from another script.
_lr_lib_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_lr_repo="$(cd "$_lr_lib_root/../.." && pwd)"

lr_resolve_daemon() {
    for bin in \
        "$_lr_repo/target/debug/lr-daemon" \
        "$_lr_repo/target/debug/lr-daemon.exe" \
        "$_lr_repo/target/release/lr-daemon" \
        "$_lr_repo/target/release/lr-daemon.exe"
    do
        if [ -f "$bin" ]; then
            echo "$bin"
            return 0
        fi
    done
    echo "lr-daemon binary not found (run cargo build -p lr-cli)" >&2
    return 1
}

# --- namespace lab ---
LR_NAMESPACES=""
LR_DAEMON_PIDS=""
LR_VETH_NAMES=""

lr_ns_exec() { # <pid> <cmd...>
    nsenter -t "$1" -n "${@:2}"
}

lr_create_lab() { # <n_routers>
    local n=$1
    ip link set lo up
    # Create a chain of veth pairs: R1--veth0a|veth0b--R2--veth1b|veth1a--R3 ...
    # For n=2: one veth pair (veth0a in R1, veth0b in R2).
    # For n=3: two veth pairs (R1--R2--R3).
    local i
    for ((i = 1; i < n; i++)); do
        local a="veth$((i-1))a"
        local b="veth$((i-1))b"
        ip link add "$a" type veth peer name "$b"
        LR_VETH_NAMES="$LR_VETH_NAMES $a $b"
    done
    # Create namespace-holder processes.
    for ((i = 1; i <= n; i++)); do
        unshare -n sleep 600 &
        local pid=$!
        eval "R$i=$pid"
        LR_NAMESPACES="$LR_NAMESPACES $pid"
    done
    sleep 0.3
    # Move veth endpoints into namespaces.
    for ((i = 1; i < n; i++)); do
        local a="veth$((i-1))a"
        local b="veth$((i-1))b"
        local rp=$(eval "echo \"\$R$i\"")
        local rnp=$(eval "echo \"\$R$((i+1))\"")
        ip link set "$a" netns "$rp"
        ip link set "$b" netns "$rnp"
        eval "VETH_R$i=$a"
        eval "VETH_R$((i+1))=$b"
    done
    # Bring up loopback in every namespace.
    for ((i = 1; i <= n; i++)); do
        local pid=$(eval "echo \"\$R$i\"")
        nsenter -t "$pid" -n ip link set lo up
    done
}

lr_set_addr() { # <pid> <iface> <addr>
    local pid=$1 iface=$2 addr=$3
    nsenter -t "$pid" -n ip addr add "$addr" dev "$iface"
    nsenter -t "$pid" -n ip link set "$iface" up
}

lr_set_addr_v6() { # <pid> <iface> <addr>
    local pid=$1 iface=$2 addr=$3
    nsenter -t "$pid" -n ip addr add "$addr" dev "$iface"
    nsenter -t "$pid" -n ip link set "$iface" up
}

lr_start_daemon() { # <pid> <log_file> <args...>
    # Start lr-daemon inside a namespace. The daemon's stdout+stderr
    # go to <log_file> (the caller's stdout is NOT polluted). Returns
    # the daemon's PID via echo (capture with $()).
    local pid=$1 logfile=$2; shift 2
    local bin
    bin=$(lr_resolve_daemon)
    nsenter -t "$pid" -n "$bin" "$@" >"$logfile" 2>&1 &
    local dpid=$!
    LR_DAEMON_PIDS="$LR_DAEMON_PIDS $dpid"
    echo "$dpid"
}

# --- verification helpers ---
lr_wait_log() { # <file> <pattern> [timeout-s]
    local file=$1 pat=$2 tmo=${3:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "-- $file --" >&2
    cat "$file" >&2
    return 1
}

lr_wait_kernel_route() { # <pid> <prefix> <present|absent> [timeout-s]
    local pid=$1 prefix=$2 expected=$3 tmo=${4:-10} i
    for ((i = 0; i < tmo * 10; i++)); do
        local route
        route=$(nsenter -t "$pid" -n ip route show "$prefix" 2>/dev/null || true)
        if { [ "$expected" = present ] && [ -n "$route" ]; } || \
           { [ "$expected" = absent ] && [ -z "$route" ]; }; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

lr_wait_kernel_route6() { # <pid> <prefix> <present|absent> [timeout-s]
    local pid=$1 prefix=$2 expected=$3 tmo=${4:-10} i
    for ((i = 0; i < tmo * 10; i++)); do
        local route
        route=$(nsenter -t "$pid" -n ip -6 route show "$prefix" 2>/dev/null || true)
        if { [ "$expected" = present ] && [ -n "$route" ]; } || \
           { [ "$expected" = absent ] && [ -z "$route" ]; }; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

lr_verify_route_get() { # <pid> <dest> <via-grep> <dev-grep>
    local pid=$1 dest=$2 via_grep=$3 dev_grep=$4
    local get
    get=$(nsenter -t "$pid" -n ip route get "$dest" 2>/dev/null || true)
    [ -n "$get" ] || { echo "FAIL: ip route get $dest returned nothing"; return 1; }
    echo "$get" | grep -q "$via_grep" || {
        echo "FAIL: ip route get $dest did not match '$via_grep'"
        echo "$get"
        return 1
    }
    echo "$get" | grep -q "$dev_grep" || {
        echo "FAIL: ip route get $dest did not match '$dev_grep'"
        echo "$get"
        return 1
    }
    echo "   route get: $get"
    return 0
}

lr_verify_route6_get() { # <pid> <dest> <dev-grep>
    local pid=$1 dest=$2 dev_grep=$3
    local get
    get=$(nsenter -t "$pid" -n ip -6 route get "$dest" 2>/dev/null || true)
    [ -n "$get" ] || { echo "FAIL: ip -6 route get $dest returned nothing"; return 1; }
    echo "$get" | grep -q "$dev_grep" || {
        echo "FAIL: ip -6 route get $dest did not match '$dev_grep'"
        echo "$get"
        return 1
    }
    echo "   route6 get: $get"
    return 0
}

lr_enable_forwarding() { # <pid>
    local pid=$1
    # In a user namespace (unshare -U), /proc/sys is mounted read-only.
    # This only works when running as root (real or via the VM harness).
    if nsenter -t "$pid" -n sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        return 0
    fi
    echo "SKIP: cannot enable ip_forward (user namespace restriction — run as root or in the VM harness)" >&2
    return 1
}

lr_disable_rp_filter() { # <pid> [iface]
    local pid=$1 iface=${2:-all}
    nsenter -t "$pid" -n sysctl -w "net.ipv4.conf.$iface.rp_filter=0" >/dev/null 2>&1 || true
}

lr_verify_ping() { # <pid> <dest> [count] [timeout-s]
    local pid=$1 dest=$2 count=${3:-1} timeout=${4:-3}
    nsenter -t "$pid" -n ping -c "$count" -W "$timeout" "$dest" >/dev/null 2>&1
}

lr_cleanup() {
    for p in $LR_DAEMON_PIDS; do
        kill "$p" 2>/dev/null || true
    done
    for p in $LR_NAMESPACES; do
        kill "$p" 2>/dev/null || true
    done
}

# Auto-register cleanup on EXIT. The caller can override by setting
# LR_NO_AUTO_CLEANUP=1 before sourcing.
if [ -z "${LR_NO_AUTO_CLEANUP:-}" ]; then
    trap lr_cleanup EXIT
fi
