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
#                         cleanup). Linux only.
#   lr_ns_exec <pid> <cmd...>  Run a command inside namespace <pid>.
#   lr_set_addr <pid> <iface> <addr>  Assign an IP to an interface
#                         inside a namespace.
#   lr_start_daemon <pid> <args...>  Start lr-daemon inside a
#                         namespace. Sets LR_DAEMON_PIDS (space-
#                         separated PIDs for cleanup).
#   lr_wait_log <file> <pattern> [timeout-s]  Poll a log file for a
#                         pattern (default 20 s timeout).
#   lr_wait_kernel_route <pid> <prefix> <present|absent> [timeout-s]
#                         Poll ip route show for a prefix (Linux, in
#                         namespace <pid>).
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
# Portable helpers (Linux + macOS + Windows/Git-Bash) for tests that
# verify the daemon's kernel-FIB interaction on the host itself:
#   lr_os                  Print the host platform: linux | darwin |
#                         windows | other.
#   lr_have_elevation      Succeed when the test can reach the kernel
#                         route table: euid 0, passwordless sudo
#                         (Linux/macOS) or an Administrator shell
#                         (Windows).
#   lr_elevate <cmd...>    Run <cmd> with elevation when needed (sudo
#                         prefix on Unix; no-op on Windows admin).
#   lr_daemon_spawn <logfile> <args...>  Start lr-daemon on the host
#                         (no namespace) with output captured; prints
#                         the PID. Tracked for lr_cleanup.
#   lr_daemon_stop <pid>   Gracefully stop a spawned daemon (TERM,
#                         then KILL after a grace period).
#   lr_wait_kernel_route_host <prefix> <present|absent> [timeout-s]
#                         Poll the HOST kernel FIB for a prefix on any
#                         supported platform.
#   lr_route_decision <dest>  Print the OS's route decision for a
#                         destination (ip route get / route -n get /
#                         Find-NetRoute).
#   lr_kernel_decision_uses <dest> <gateway>  Assert the OS decision
#                         for <dest> points at <gateway>.
#   lr_kernel_route_delete <prefix> <gateway>  Best-effort manual FIB
#                         cleanup (platform route command).
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
LR_ELEVATED_PIDS=""
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
    for p in $LR_ELEVATED_PIDS; do
        lr_elevate kill -KILL "$p" 2>/dev/null || true
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

# ==========================================================================
# Portable helpers (Linux + macOS + Windows/Git-Bash)
#
# The netns helpers above build multi-router labs on Linux. The helpers
# below verify the "learn → install → decide → forward" contract on the
# host itself, so the same script runs on the GitHub macOS and Windows
# runners where the BSD route(4) / IP-Helper backends live.
# ==========================================================================

lr_os() { # print linux | darwin | windows | other
    case "$(uname -s)" in
        Linux*) echo linux ;;
        Darwin*) echo darwin ;;
        MINGW* | MSYS* | CYGWIN*) echo windows ;;
        *) echo other ;;
    esac
}

lr_have_elevation() { # can we touch the kernel route table?
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    case "$(lr_os)" in
        linux | darwin)
            sudo -n true 2>/dev/null && return 0
            ;;
        windows)
            # Git Bash: `net session` succeeds only in an elevated shell.
            net session >/dev/null 2>&1 && return 0
            ;;
    esac
    return 1
}

lr_elevate() { # <cmd...> — run with elevation when not already root
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo -n "$@"
    fi
}

# --- host daemons (no namespace) ---

lr_daemon_spawn() { # <logfile> <args...>
    # Start lr-daemon on the host with stdout+stderr captured. Prints
    # the PID; the daemon is tracked in LR_DAEMON_PIDS for lr_cleanup.
    local logfile=$1
    shift
    local bin
    bin=$(lr_resolve_daemon)
    "$bin" "$@" >"$logfile" 2>&1 &
    local pid=$!
    LR_DAEMON_PIDS="$LR_DAEMON_PIDS $pid"
    echo "$pid"
}

lr_daemon_spawn_elevated() { # <pidfile> <logfile> <args...>
    # Start lr-daemon with root privileges (macOS route(4) socket) and
    # print the daemon's REAL pid. `sudo <bin> ... &` would make $! the
    # sudo wrapper's pid: a `kill -9 $!` would only murder sudo and
    # orphan the daemon, and TERM relay is unreliable. Instead the
    # elevated shell writes its own pid (which `exec` turns into the
    # daemon's pid) to <pidfile> before exec'ing.
    #
    # The trailing </dev/null >/dev/null 2>&1 on the backgrounded
    # function call is load-bearing: a backgrounded FUNCTION runs in a
    # subshell that waits for its child, and that subshell inherits the
    # caller's stdout — inside `$(...)` that is the command-substitution
    # pipe, so the substitution would block until the daemon exits
    # (i.e. forever). Redirecting all three standard fds at the point
    # of backgrounding breaks the inheritance chain.
    #
    # The real pid is tracked in LR_ELEVATED_PIDS; lr_cleanup kills
    # those with elevation. Kill it directly via
    # lr_daemon_kill_elevated "$(cat <pidfile>)".
    local pidfile=$1 logfile=$2
    shift 2
    local bin
    bin=$(lr_resolve_daemon)
    lr_elevate bash -c 'echo $$ >"$1"; exec "$2" "${@:4}" >"$3" 2>&1' \
        _ "$pidfile" "$bin" "$logfile" "$@" </dev/null >/dev/null 2>&1 &
    local i
    for ((i = 0; i < 50; i++)); do
        [ -s "$pidfile" ] && break
        sleep 0.1
    done
    [ -s "$pidfile" ] || {
        echo "FAIL: elevated daemon never wrote its pidfile" >&2
        return 1
    }
    local pid
    pid=$(cat "$pidfile")
    LR_ELEVATED_PIDS="$LR_ELEVATED_PIDS $pid"
    echo "$pid"
}

lr_daemon_kill_elevated() { # <real-pid> [signal]
    # Kill an elevated daemon by its real pid (see
    # lr_daemon_spawn_elevated). Root-owned processes need an elevated
    # kill; the default signal is KILL (crash semantics).
    local pid=$1 sig=${2:-KILL}
    lr_elevate kill -"$sig" "$pid" 2>/dev/null || true
}

lr_daemon_stop() { # <pid>
    # Graceful TERM, then KILL after a grace period. A daemon that
    # installs kernel routes withdraws them while draining sessions
    # (the probe in tests/interop/_lib.sh history verified this), so
    # the TERM grace matters for FIB cleanliness.
    local pid=$1
    kill -TERM "$pid" 2>/dev/null || return 0
    local i
    for ((i = 0; i < 30; i++)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
}

# --- portable kernel-FIB inspection ---

_lr_fib_grep() { # <prefix> — platform FIB grep pattern for <prefix>
    # Linux `ip route show` prints the prefix verbatim.
    # macOS netstat compresses trailing zero octets ("10.0/8"), so
    # every trailing ".0" becomes an optional group.
    # Windows `route print` prints the full prefix + netmask.
    local prefix=$1
    case "$(lr_os)" in
        linux)
            printf '%s' "$prefix" | sed 's/\./\\./g'
            ;;
        darwin)
            # macOS netstat strips trailing zero octets: 10.0.0.0/8
            # prints as "10/8", 203.0.113.0/24 as "203.0.113/24".
            # Split the dotted quad, count the trailing zeros and emit
            # each as an optional group: "10(\.0){0,3}/8".
            local base len head n pat
            base=${prefix%/*}
            len=${prefix##*/}
            head=$base
            n=0
            while [[ "$head" == *.* ]] && [ "${head##*.}" = "0" ]; do
                head="${head%.*}"
                n=$((n + 1))
            done
            head=$(printf '%s' "$head" | sed 's/\./\\./g')
            pat="$head"
            if [ "$n" -gt 0 ]; then
                pat="$pat(\\.0){0,$n}"
            fi
            printf '%s/%s' "$pat" "$len"
            ;;
        windows)
            local mask
            mask=$(_lr_netmask "${prefix##*/}")
            printf '%s[[:space:]]+%s' \
                "$(printf '%s' "${prefix%/*}" | sed 's/\./\\./g')" \
                "$(printf '%s' "$mask" | sed 's/\./\\./g')"
            ;;
        *)
            printf '%s' "$prefix"
            ;;
    esac
}

_lr_netmask() { # <prefix-len> — dotted IPv4 netmask
    local len=$1 out="" i
    for ((i = 1; i <= 4; i++)); do
        local block=0 j
        for ((j = 0; j < 8; j++)); do
            if [ $(( (i - 1) * 8 + j )) -lt "$len" ]; then
                block=$((block + 2 ** (7 - j)))
            fi
        done
        if [ -n "$out" ]; then out="$out.$block"; else out="$block"; fi
    done
    printf '%s' "$out"
}

_lr_fib_show() { # print the host IPv4 FIB (platform tool)
    case "$(lr_os)" in
        linux) ip route show ;;
        darwin) netstat -rn -f inet ;;
        windows) route.exe print -4 ;;
        *) return 1 ;;
    esac
}

lr_kernel_route_present_once() { # <prefix> — single FIB check
    local prefix=$1
    _lr_fib_show 2>/dev/null | grep -Eq "$(_lr_fib_grep "$prefix")($|[[:space:]])"
}

lr_wait_kernel_route_host() { # <prefix> <present|absent> [timeout-s]
    local prefix=$1 expected=$2 tmo=${3:-10} i
    for ((i = 0; i < tmo * 10; i++)); do
        if lr_kernel_route_present_once "$prefix"; then
            [ "$expected" = present ] && return 0
        else
            [ "$expected" = absent ] && return 0
        fi
        sleep 0.1
    done
    return 1
}

lr_route_decision() { # <dest> — print the OS route decision for dest
    local dest=$1
    case "$(lr_os)" in
        linux)
            ip route get "$dest" 2>/dev/null
            ;;
        darwin)
            route -n get "$dest" 2>/dev/null
            ;;
        windows)
            # Find-NetRoute emits two objects: [0] the chosen source
            # address, [1] the MSFT_NetRoute. The route object's
            # NextHop is the OS's forwarding decision for <dest>.
            powershell.exe -NoProfile -Command \
                "\$r = Find-NetRoute -RemoteIPAddress '$dest'; \
                 if (\$r) { \$r[1].NextHop; \$r[1].DestinationPrefix }" \
                2>/dev/null | tr -d '\r'
            ;;
        *)
            return 1
            ;;
    esac
}

lr_kernel_decision_uses() { # <dest> <gateway>
    local dest=$1 gateway=$2
    local decision
    decision=$(lr_route_decision "$dest") || {
        echo "FAIL: no OS route decision for $dest"
        return 1
    }
    [ -n "$decision" ] || {
        echo "FAIL: empty OS route decision for $dest"
        return 1
    }
    printf '%s\n' "$decision" | grep -qF "$gateway" || {
        echo "FAIL: OS decision for $dest does not use gateway $gateway:"
        printf '%s\n' "$decision"
        return 1
    }
    echo "   OS decision for $dest: $(printf '%s' "$decision" | head -1) [gw $gateway]"
    return 0
}

lr_kernel_route_delete() { # <prefix> <gateway> — best-effort manual cleanup
    local prefix=$1 gateway=$2
    case "$(lr_os)" in
        linux)
            lr_elevate ip route del "$prefix" via "$gateway" 2>/dev/null || true
            ;;
        darwin)
            lr_elevate route delete -net "$prefix" "$gateway" 2>/dev/null || true
            ;;
        windows)
            route.exe delete "${prefix%/*}" mask "$(_lr_netmask "${prefix##*/}")" "$gateway" >/dev/null 2>&1 || true
            ;;
    esac
}
