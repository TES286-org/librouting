#!/usr/bin/env bash
# BIRD-in-WSL2 interop test: lr-daemon on the Windows host exchanges
# BGP with BIRD 2 running inside WSL2's pre-installed Ubuntu 22.04.
# Verifies cross-OS BGP interoperability — lr-daemon's TCP stack on
# Windows talking to BIRD's TCP stack on Linux via the WSL2 vETH
# gateway.
#
# Architecture:
#   lr-daemon.exe (Windows host, AS64512, listener 0.0.0.0:$LR_PORT)
#        ↑↓ TCP via the WSL2 NAT vETH gateway
#   BIRD 2 (WSL2 Ubuntu, AS64513, connector to <gateway-ip>:$LR_PORT)
#
# WSL2 NAT networking: the Linux side sees a default route via the
# host's WSL-side vEthernet address. `ip route show default` from
# inside WSL2 prints that gateway IP — Windows host's WSL NIC. BIRD
# connecting to that IP reaches lr-daemon bound to 0.0.0.0 on the
# Windows host directly.
#
# Earlier revisions relied on WSL2's `LocalhostForwarding`, which
# advertises services bound to 0.0.0.0 inside WSL2 on the Windows
# host's 127.0.0.1 (and the reverse). That mechanism was unreliable
# on Windows Server 2025 runners (the new `windows-latest` label
# resolves to `windows-2025-vs2026`): BIRD connecting to 127.0.0.1
# from inside WSL2 hit its own loopback, never the host's listener,
# and died with ECONNREFUSED. The vETH-gateway path is reliable on
# every WSL2 generation and works on mirrored-mode networking too.
#
# The script also runs on Linux (the regular `bird` package path),
# falling back to the host-installed BIRD binary when no WSL2 is
# available. This makes it a portable superset of bird.sh.
#
# Windows Server 2022 (the windows-2022 GitHub Actions runner base
# image) has no Microsoft Store, so `wsl --install -d Ubuntu` does
# not work. The script uses `wsl --import` with an Ubuntu
# cloud-images rootfs tarball — the canonical Windows Server 2022
# WSL2 distro install path.
#
# SKIP gracefully when neither WSL2 nor a host BIRD is available.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Git Bash for Windows auto-translates Unix-style paths to Windows
# paths when calling non-MSYS binaries (MSYS2's path mangling). This
# breaks wsl.exe invocations: paths like `/tmp/lr-bird.ctl` (a WSL2
# path) become `C:\Users\runneradmin\AppData\Local\Temp\lr-bird.ctl`
# before wsl.exe sees them, and BIRD inside WSL2 then receives the
# Windows path as a literal Linux path it cannot create.
#
# Setting `MSYS_NO_PATHCONV=1` inline before each `wsl` invocation
# disables the translation for that single command. The variable
# is *not* exported globally — other Windows binaries (curl, mkdir,
# tee) keep the MSYS translation so `/tmp/foo` still resolves to
# %TEMP%\foo for them.
#
# `WSL_INVOKES` is a tiny wrapper that prefixes the env var. Defining
# it as a function would shadow the real `wsl` binary and break
# `command -v wsl` detection, so we use a different name.
wsl_no_pathconv() {
    MSYS_NO_PATHCONV=1 command wsl "$@"
}

BIN=$(./tests/interop/_lr_daemon.sh 2>/dev/null) || {
    echo "SKIP: lr-daemon not built (run \`cargo build -p lr-cli\` first)"
    exit 0
}

LR_PORT=${LR_PORT:-17997}
OUT=/tmp/lr_bird_wsl
rm -rf "$OUT"; mkdir -p "$OUT"

# Detect a usable BIRD runtime. The first match wins:
#   1. WSL2 + Ubuntu (Windows GitHub Actions runner — WSL2 is enabled
#      but no distro is registered. The windows-2022 runner runs
#      Windows Server 2022 which has no Microsoft Store, so
#      `wsl --install -d Ubuntu` does not work. Use `wsl --import`
#      with an Ubuntu cloud-images rootfs tarball instead — the
#      canonical Windows Server 2022 WSL2 install path).
#   2. Host-installed `bird` / `birdc` on PATH (Linux).
#   3. SKIP if neither is available.
BIRD_RUNTIME=""
WSL_DISTRO=lr-bird  # the name we register the imported rootfs under
if command -v wsl >/dev/null 2>&1; then
    # If a previously-imported distro exists, reuse it; otherwise
    # download the Ubuntu 22.04 base rootfs and import it. The
    # tarball is ~100 MB (the minimal `ubuntu-base` image — same
    # rootfs Docker's official `ubuntu:22.04` image is built from,
    # with apt sources pre-configured so `apt-get install` works
    # after `apt-get update`).
    if ! wsl_no_pathconv -l -q 2>/dev/null | tr -d '\0' | grep -qi "^$WSL_DISTRO$"; then
        echo "== downloading the Ubuntu 22.04 base rootfs tarball =="
        TARBALL="$OUT/ubuntu-22.04-base.tar.gz"
        curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 5 \
            -fL -o "$TARBALL" \
            "https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04-base-amd64.tar.gz" \
            2>&1 | tail -3 || true
        if [ -s "$TARBALL" ]; then
            echo "== importing the rootfs as WSL2 distro '$WSL_DISTRO' =="
            # `--import <name> <install-path> <tarball>` registers the
            # distro. The install path is a Windows-style directory
            # that WSL2 creates; we put it under $OUT so it gets
            # cleaned up with the test artifacts. NB: this call uses
            # plain `wsl` (NOT `wsl_no_pathconv`) because both
            # <install-path> and <tarball> are Windows paths that
            # need MSYS translation from the host's `/tmp/...` form
            # to the Windows `%TEMP%\...` form before wsl.exe can
            # consume them.
            wsl --import "$WSL_DISTRO" "$OUT/wsl-install" "$TARBALL" \
                2>&1 | tail -5 || true
        fi
    fi
    if wsl -l -q 2>/dev/null | tr -d '\0' | grep -qi "^$WSL_DISTRO$"; then
        # Install bird2 and wslu inside the imported distro. The
        # default user for `wsl --import` is root, so no sudo needed.
        # `wslu` provides `wslpath` — the Windows ↔ WSL2 path
        # translator — which the ubuntu-base image does not ship by
        # default. Without it, the script cannot translate the host's
        # /tmp path of bird.conf to the /mnt/c/... form BIRD inside
        # WSL2 needs. Check BOTH binaries so a half-installed state
        # (bird present but wslu missing) triggers a re-install.
        echo "== ensuring bird2 + wslu are installed inside WSL2 =="
        wsl_no_pathconv -d "$WSL_DISTRO" -- bash -c \
            "command -v bird >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1 || \
            (apt-get update -qq && apt-get install -y -qq bird2 wslu)" \
            >/dev/null 2>&1 || true
        # Confirm bird is now available; if apt-get failed (no network,
        # package mirror issue), fall through to the host-installed path.
        if wsl_no_pathconv -d "$WSL_DISTRO" -- bash -c "command -v bird" >/dev/null 2>&1; then
            BIRD_RUNTIME=wsl
        fi
    fi
fi
if [ -z "$BIRD_RUNTIME" ] && command -v bird >/dev/null 2>&1; then
    BIRD_RUNTIME=host
fi
if [ -z "$BIRD_RUNTIME" ]; then
    echo "SKIP: no BIRD runtime available (WSL2+Ubuntu import failed, no host bird)"
    exit 0
fi

# BIRD needs to connect to lr-daemon. The destination IP and the
# lr-daemon listen address depend on the runtime:
#   * host (Linux)  — both sides are on the same loopback, so 127.0.0.1
#     on both ends. lr-daemon binds 127.0.0.1.
#   * wsl (Windows) — BIRD inside WSL2 cannot reach the Windows host's
#     127.0.0.1; WSL2 NAT networking routes via the host's WSL-side
#     vEthernet address. Compute that gateway IP from inside WSL2
#     with `ip route show default`, and bind lr-daemon to 0.0.0.0 so
#     the WSL gateway connection lands on the listener.
#
# `LR_NEIGHBOR_IP`  is the address BIRD dials.
# `LR_LISTEN_ADDR`  is the address lr-daemon binds (`--listen` and
#   `--local-address`). 0.0.0.0 means "all interfaces".
LR_NEIGHBOR_IP=127.0.0.1
LR_LISTEN_ADDR=127.0.0.1
if [ "$BIRD_RUNTIME" = wsl ]; then
    # The WSL2 host gateway IP is the default route's next hop from
    # inside the namespace. We avoid `wsl ... -- bash -c 'awk ...'`
    # (nested shell quoting through wsl.exe is fragile — Windows
    # Server 2025's wsl.exe mangled the inner `awk '{print $2}'`
    # program into something that printed the whole `nameserver
    # 10.255.255.254` line, killing BIRD with a config syntax
    # error). Instead we run a single flat command inside WSL
    # (`ip route show default` or `cat /etc/resolv.conf`) and parse
    # the captured stdout client-side with the local bash. Both
    # `awk` and `tr` are available on Git Bash for Windows, so the
    # client-side pipe is portable across Windows hosts and Linux
    # hosts alike.
    #
    # The `|| true` guards are load-bearing: this script runs under
    # `set -euo pipefail`, and `ip route show default` returns
    # non-zero when the ubuntu-base rootfs has no default route yet
    # (networking still coming up) or when `iproute2` is not
    # installed. With `pipefail`, that non-zero ripples through the
    # `awk | tr` pipe and the `LR_NEIGHBOR_IP=$(...)` assignment,
    # which `set -e` then turns into a hard script exit (exit 127
    # in the 2026-10-19 CI run). The fallback then never gets a
    # chance to run. `|| true` on the assignment statement lets
    # `set -e` skip it; the empty-output check on the next line
    # drives the fallback.
    LR_NEIGHBOR_IP=$(wsl_no_pathconv -d "$WSL_DISTRO" -- ip route show default 2>/dev/null \
        | awk '/^default/ {print $3; exit}' \
        | tr -d '\r\n') || true
    if [ -z "$LR_NEIGHBOR_IP" ]; then
        # Fall back to /etc/resolv.conf's nameserver — the WSL2
        # init writes the host gateway IP there too. ubuntu-base
        # may not have a populated resolv.conf until networking is
        # up, so this is a true last-resort.
        LR_NEIGHBOR_IP=$(wsl_no_pathconv -d "$WSL_DISTRO" -- cat /etc/resolv.conf 2>/dev/null \
            | awk '/^nameserver/ {print $2; exit}' \
            | tr -d '\r\n') || true
    fi
    if [ -z "$LR_NEIGHBOR_IP" ]; then
        echo "SKIP: could not determine WSL2 host gateway IP"
        exit 0
    fi
    LR_LISTEN_ADDR=0.0.0.0
    echo "== WSL2 host gateway IP: $LR_NEIGHBOR_IP (lr-daemon will bind $LR_LISTEN_ADDR)"
fi

# BIRD config — emitted after the runtime+gateway detection so the
# `neighbor` line uses the WSL2 host gateway IP on Windows and
# 127.0.0.1 on Linux host. `multihop 2` is kept so the eBGP session
# tolerates the cross-namespace next hop.
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
    neighbor $LR_NEIGHBOR_IP port $LR_PORT as 64512;
    multihop 2;       # eBGP over loopback / cross-netns
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor
        # address, so pin a distinct one.
        next hop address 192.0.2.10;
    };
}
EOF

# Wrap the BIRD CLI invocation so the rest of the script is
# runtime-agnostic. `bird_run` starts BIRD in the background; the
# caller stores the resulting process handle in $BIRD_HANDLE for the
# cleanup trap. `birdc_cmd` runs birdc once and returns its output.
#
# Control socket: BIRD's default control socket at /run/bird/bird.ctl
# fails because the ubuntu-base image does not ship the /run/bird/
# directory. Pin the path explicitly:
#   * WSL2: /tmp/lr-bird.ctl (WSL2's own /tmp, always exists, no
#     path translation needed).
#   * Host: $OUT/bird.ctl (Linux host's /tmp/lr_bird_wsl/bird.ctl).
BIRD_CTL_HOST="$OUT/bird.ctl"
BIRD_CTL_WSL="/tmp/lr-bird.ctl"
bird_run() { # <config-path>
    local cfg="$1"
    case "$BIRD_RUNTIME" in
        wsl)
            # Convert the Windows path of the config to a WSL2 path
            # (C:\... → /mnt/c/...). wslpath (from the wslu package,
            # installed above) handles the translation. As a manual
            # fallback if wslpath is somehow still missing, sed-
            # translate the Windows path: replace backslashes with
            # forward slashes and prefix the drive letter with
            # /mnt/<lowercase-drive-letter>.
            local wsl_cfg win_cfg
            win_cfg=$(cygpath -w "$cfg" 2>/dev/null || echo "$cfg")
            wsl_cfg=$(wsl_no_pathconv -d "$WSL_DISTRO" -- wslpath -u "$win_cfg" 2>/dev/null || true)
            if [ -z "$wsl_cfg" ] || [ "$wsl_cfg" = "$win_cfg" ]; then
                # Manual fallback: C:\Users\... → /mnt/c/Users/...
                wsl_cfg=$(echo "$win_cfg" | sed 's|\\|/|g' | sed 's|^\([A-Za-z]\):|/mnt/\L\1|')
            fi
            wsl_no_pathconv -d "$WSL_DISTRO" -- bird -f -c "$wsl_cfg" -s "$BIRD_CTL_WSL" \
                >"$OUT/bird.stdout" 2>"$OUT/bird.stderr" &
            BIRD_HANDLE=$!
            ;;
        host)
            bird -f -c "$cfg" -s "$BIRD_CTL_HOST" \
                >"$OUT/bird.stdout" 2>"$OUT/bird.stderr" &
            BIRD_HANDLE=$!
            ;;
    esac
}
birdc_cmd() { # <args...>
    case "$BIRD_RUNTIME" in
        wsl) wsl_no_pathconv -d "$WSL_DISTRO" -- birdc -s "$BIRD_CTL_WSL" "$@" 2>/dev/null ;;
        host) birdc -s "$BIRD_CTL_HOST" "$@" 2>/dev/null ;;
    esac
}
bird_shutdown() {
    if [ -n "${BIRD_HANDLE:-}" ]; then
        case "$BIRD_RUNTIME" in
            wsl)
                # Kill the BIRD process inside WSL2.
                wsl_no_pathconv -d "$WSL_DISTRO" -- pkill -TERM -x bird 2>/dev/null || true
                # And the bash subshell we spawned.
                kill "$BIRD_HANDLE" 2>/dev/null || true
                ;;
            host)
                kill "$BIRD_HANDLE" 2>/dev/null || true
                ;;
        esac
    fi
}

echo "== starting BIRD ($BIRD_RUNTIME) → connects to lr-daemon at $LR_NEIGHBOR_IP:$LR_PORT =="
bird_run "$OUT/bird.conf"
trap 'bird_shutdown; kill $LR_PID 2>/dev/null || true' EXIT
sleep 1

echo "== starting lr-daemon (host, AS64512, listener $LR_LISTEN_ADDR:$LR_PORT) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen $LR_LISTEN_ADDR:$LR_PORT --local-address $LR_LISTEN_ADDR \
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
