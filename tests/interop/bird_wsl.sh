#!/usr/bin/env bash
# BIRD-in-WSL2 interop test: lr-daemon on the Windows host exchanges
# BGP with BIRD 2 running inside WSL2's pre-installed Ubuntu 22.04.
# Verifies cross-OS BGP interoperability — lr-daemon's TCP stack on
# Windows talking to BIRD's TCP stack on Linux via WSL2's automatic
# localhost forwarding.
#
# Architecture:
#   lr-daemon.exe (Windows host, AS64512, listener 127.0.0.1:$LR_PORT)
#        ↑↓ TCP via WSL2's localhost forwarding
#   BIRD 2 (WSL2 Ubuntu, AS64513, connector to 127.0.0.1:$LR_PORT)
#
# WSL2's automatic localhost forwarding makes any service bound to
# 0.0.0.0 inside WSL2 reachable from the Windows host at 127.0.0.1
# (and vice versa — WSL2 can reach Windows host services at 127.0.0.1).
# So BIRD inside WSL2 connecting to 127.0.0.1:$LR_PORT reaches the
# lr-daemon.exe listener on the Windows host directly.
#
# The script also runs on Linux (the regular `bird` package path),
# falling back to the host-installed BIRD binary when no WSL2 is
# available. This makes it a portable superset of bird.sh.
#
# SKIP gracefully when neither WSL2 nor a host BIRD is available.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh 2>/dev/null) || {
    echo "SKIP: lr-daemon not built (run \`cargo build -p lr-cli\` first)"
    exit 0
}

LR_PORT=${LR_PORT:-17997}
OUT=/tmp/lr_bird_wsl
rm -rf "$OUT"; mkdir -p "$OUT"

# BIRD config — shared between the WSL2 and host-installed paths.
# BIRD connects to 127.0.0.1:$LR_PORT (which works on Linux direct
# and inside WSL2 via the localhost-forwarding).
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting WSL2 interop test.
log stderr all;
router id 10.0.0.2;

protocol device {}

protocol static static_routes {
    ipv4;
    route 198.51.100.0/24 blackhole;
}

filter export_to_lr {
    if proto = "static_routes" then accept;
    reject;
}

protocol bgp lr {
    local as 64513;
    neighbor 127.0.0.1 port $LR_PORT as 64512;
    multihop 2;       # eBGP over loopback
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor
        # address (both ends are 127.0.0.1 here), so pin a distinct
        # one.
        next hop address 192.0.2.10;
    };
}
EOF

# Detect a usable BIRD runtime. The first match wins:
#   1. WSL2 + Ubuntu 22.04 (Windows GitHub Actions runner default).
#   2. Host-installed `bird` / `birdc` on PATH (Linux).
#   3. SKIP if neither is available.
BIRD_RUNTIME=""
if command -v wsl >/dev/null 2>&1; then
    # Make sure WSL2 has a usable distro. The windows-2022 runner
    # ships Ubuntu-22.04 by default, but forked runners might not.
    if wsl --list --quiet 2>/dev/null | tr -d '\0' | grep -qi ubuntu; then
        # WSL2 distros don't ship bird2 by default — install it now.
        # `apt-get install` is idempotent and quick on a warm WSL2
        # package cache; the install only runs once per runner lifetime
        # (the WSL2 distro persists for the duration of the job).
        echo "== ensuring bird2 is installed inside WSL2 =="
        wsl -- bash -c "command -v bird >/dev/null 2>&1 || \
            (sudo apt-get update -qq && sudo apt-get install -y -qq bird2)" \
            >/dev/null 2>&1 || true
        # Confirm bird is now available; if apt-get failed (no network,
        # no sudo), fall through to the host-installed path.
        if wsl -- bash -c "command -v bird" >/dev/null 2>&1; then
            BIRD_RUNTIME=wsl
        fi
    fi
fi
if [ -z "$BIRD_RUNTIME" ] && command -v bird >/dev/null 2>&1; then
    BIRD_RUNTIME=host
fi
if [ -z "$BIRD_RUNTIME" ]; then
    echo "SKIP: no BIRD runtime available (WSL2+Ubuntu not present, no host bird)"
    exit 0
fi

# Wrap the BIRD CLI invocation so the rest of the script is
# runtime-agnostic. `bird_run` starts BIRD in the background; the
# caller stores the resulting process handle in $BIRD_HANDLE for the
# cleanup trap. `birdc_cmd` runs birdc once and returns its output.
bird_run() { # <config-path>
    local cfg="$1"
    case "$BIRD_RUNTIME" in
        wsl)
            # Convert the Windows path of the config to a WSL2 path
            # (C:\... → /mnt/c/...). wslpath handles the translation.
            local wsl_cfg
            wsl_cfg=$(wsl -- wslpath -u "$(cygpath -w "$cfg" 2>/dev/null || echo "$cfg")" 2>/dev/null || echo "$cfg")
            # Run BIRD in foreground mode (-f) inside WSL2, in the
            # background of the bash subshell. The PID is the WSL2
            # process's PID; the trap below stops it via `wsl -- pkill`.
            wsl -- bird -f -c "$wsl_cfg" >"$OUT/bird.stdout" 2>"$OUT/bird.stderr" &
            BIRD_HANDLE=$!
            ;;
        host)
            bird -f -c "$cfg" >"$OUT/bird.stdout" 2>"$OUT/bird.stderr" &
            BIRD_HANDLE=$!
            ;;
    esac
}
birdc_cmd() { # <args...>
    case "$BIRD_RUNTIME" in
        wsl) wsl -- birdc "$@" 2>/dev/null ;;
        host) birdc "$@" 2>/dev/null ;;
    esac
}
bird_shutdown() {
    if [ -n "${BIRD_HANDLE:-}" ]; then
        case "$BIRD_RUNTIME" in
            wsl)
                # Kill the BIRD process inside WSL2.
                wsl -- pkill -TERM -x bird 2>/dev/null || true
                # And the bash subshell we spawned.
                kill "$BIRD_HANDLE" 2>/dev/null || true
                ;;
            host)
                kill "$BIRD_HANDLE" 2>/dev/null || true
                ;;
        esac
    fi
}

echo "== starting BIRD ($BIRD_RUNTIME) → connects to lr-daemon at 127.0.0.1:$LR_PORT =="
bird_run "$OUT/bird.conf"
trap 'bird_shutdown; kill $LR_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (host, AS64512, listener 127.0.0.1:$LR_PORT) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen 127.0.0.1:$LR_PORT --local-address 127.0.0.1 \
    --network 203.0.113.0/24 \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!

# Wait for the route to propagate in both directions (up to 30 s on
# slow runners: WSL2 adds latency on top of the BGP OPEN/KEEPALIVE/
# UPDATE cycle).
ok_lr=0
ok_bird=0
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_lr -eq 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=1
    fi
    if [ $ok_bird -eq 0 ]; then
        if birdc_cmd show route 2>/dev/null | grep -q "203.0.113.0/24"; then
            ok_bird=1
        fi
    fi
    if [ $ok_lr -eq 1 ] && [ $ok_bird -eq 1 ]; then
        break
    fi
    if ! kill -0 $LR_PID 2>/dev/null; then
        echo "lr-daemon died"
        break
    fi
done

echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD routing table =="
birdc_cmd show route all 2>/dev/null || true
echo "== BIRD protocol state =="
birdc_cmd show protocols all lr 2>/dev/null | head -25 || true
echo "== BIRD stderr (tail) =="
tail -25 "$OUT/bird.stderr" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
bird_shutdown
trap - EXIT

fail=0
if [ $ok_lr -eq 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from BIRD"
    fail=1
fi
if [ $ok_bird -eq 0 ]; then
    echo "FAIL: BIRD did not learn 203.0.113.0/24 from lr-daemon"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: BIRD-in-WSL2 interop — bidirectional route exchange"
fi
exit $fail
