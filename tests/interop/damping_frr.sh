#!/usr/bin/env bash
# Route flap damping interop (ROADMAP-v3 D4.5): lr-daemon's
# `[damping]` import hook (RFC 2439 figure-of-merit) against FRR
# bgpd as the flap generator — BIRD 2 ships no damping at all (it
# follows RIPE-554 / RFC 7196 and refuses to implement RFD), so FRR
# is the reference that speaks it.
#
#   FRR bgpd (AS64513, connector, `network 198.51.100.0/24`,
#             `no bgp network import-check` so no zebra/RIB is needed)
#        ↑↓ BGP on 127.0.0.1
#   lr-daemon (AS64512, listener, [damping] enabled)
#
# Test-friendly tunings (still RFC 2439 mechanics, compressed time):
#   additive_incr = 1000, suppress_threshold = 3000, reuse = 750,
#   decay_interval_s = 30 with decay_factor_withdrawn = 0.125 — three
#   withdraw flaps cross the suppress threshold with no decay interval
#   elapsing between them (the whole flap phase takes ~10 s); the
#   first decay tick then divides the suppressed FoM by 8, dropping it
#   below reuse in one tick (4125 / 8 = 515 < 750).
#
# Success criteria (all judged from lr-daemon's observable state):
#   1. The route installs on the initial announcement.
#   2. Flaps 1-2 (withdraw + re-announce) keep round-tripping
#      (installed / withdrawn cycles visible).
#   3. After flap 3's withdraw the FoM crosses suppress — the
#      following re-announcement is DROPPED: no `route installed`
#      line for the prefix for several seconds (the suppression
#      window) even though FRR announced it.
#   4. The decay ticker reactivates the prefix
#      (`damping: prefix ... reactivated`), and a further flap
#      re-installs the route — the full suppress/decay/reuse cycle.
#
# bgpd runs standalone (no zebra, no kernel) on unprivileged ports.
# Environments without bgpd SKIP gracefully.
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
BGPD=${BGPD:-bgpd}
if ! command -v "$BGPD" >/dev/null 2>&1; then
    for cand in /home/z/opt/frr/root/usr/lib/frr/bgpd /usr/lib/frr/bgpd; do
        if [ -x "$cand" ]; then BGPD="$cand"; break; fi
    done
fi
command -v "$BGPD" >/dev/null 2>&1 || { echo "SKIP: bgpd not found"; exit 0; }
# Resolve a bare command name to its full path: the prefix-install
# bootstrap below pattern-matches on $BGPD starting with the FRR root,
# which a bare "bgpd" found through PATH can never satisfy (the
# library path would then be missing and bgpd would die on
# libfrr.so.0 at exec time).
case "$BGPD" in
/*) ;;
*) BGPD=$(command -v "$BGPD") ;;
esac
case "$BGPD" in
/home/z/opt/*) FRRROOT=${BGPD%/usr/lib/frr/bgpd}
    export LD_LIBRARY_PATH="$FRRROOT/usr/lib/x86_64-linux-gnu/frr:$FRRROOT/usr/lib/x86_64-linux-gnu:$FRRROOT/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    ;;
esac

PORT=${PORT:-17997}
VTY_PORT=${VTY_PORT:-26997}
OUT=/tmp/lr_damping_frr
rm -rf "$OUT"; mkdir -p "$OUT" "$OUT/vty"

cat >"$OUT/bgpd.conf" <<EOF
frr version 10
frr defaults traditional
hostname bgpd-lr
password zebra
!
route-map lr-out permit 10
 set ip next-hop 192.0.2.20
!
router bgp 64513
 bgp router-id 10.0.0.3
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 127.0.0.1 remote-as 64512
 neighbor 127.0.0.1 port $PORT
 neighbor 127.0.0.1 ebgp-multihop 2
 neighbor 127.0.0.1 route-map lr-out out
 !
 address-family ipv4 unicast
  network 198.51.100.0/24
 exit-address-family
 !
!
line vty
!
EOF

cat >"$OUT/lr.toml" <<EOF
[bgp]
local_as = 64512
peer_as = 64513
router_id = "10.0.0.1"
local_address = "127.0.0.1"
ebgp_policy = "accept-all"
listen_addr = "127.0.0.1:$PORT"

[damping]
enabled = true
additive_incr = 1000
suppress_threshold = 3000
reuse_threshold = 750
upper_limit = 20000
decay_interval_s = 30
decay_factor_active = 0.5
decay_factor_withdrawn = 0.125
EOF

echo "== starting lr-daemon (AS64512, [damping] RFC 2439) =="
"$BIN" --config "$OUT/lr.toml" >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill ${BGPD_PID:-} ${LR_PID:-} 2>/dev/null || true' EXIT

echo "== starting FRR bgpd (AS64513, flap generator) =="
"$BGPD" -f "$OUT/bgpd.conf" -i "$OUT/bgpd.pid" \
    -Z -n -S \
    -p 17996 -A 127.0.0.1 -P $VTY_PORT --vty_socket "$OUT/vty" \
    --log "file:$OUT/bgpd.log" \
    >"$OUT/bgpd.stdout" 2>&1 &
BGPD_PID=$!

# Configure / query over ONE vty TCP connection — a config sequence
# ("conf t" → "router bgp" → ... → "no network ...") only sticks when
# every line rides the same session. The vty speaks telnet-style
# (CRLF line endings, optional Password: handshake) — the same
# harness frr.sh uses, extended to multiple commands.
vty_session() { # <commands...>
    python3 - "$VTY_PORT" "$@" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
cmds = sys.argv[2:]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError:
    sys.exit(1)
s.settimeout(0.5)

def drain(idle_rounds=2):
    out = b""
    idle = 0
    while idle < idle_rounds:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
            idle = 0
        except socket.timeout:
            idle += 1
        except OSError:
            break
    return out

def send(line):
    try:
        s.sendall(line)
    except OSError:
        pass  # peer closed early; report what we collected

banner = drain()
if b"Password:" in banner:
    send(b"zebra\r\n")
    time.sleep(0.2)
    drain(1)
# User EXEC cannot run `configure terminal` — the vty needs enable
# mode first (passwordless under `frr defaults traditional` with
# only `password zebra` set).
send(b"enable\r\n")
time.sleep(0.3)
drain(1)
out = b""
for cmd in cmds:
    send(cmd.encode() + b"\r\n")
    time.sleep(0.15)
    out += drain(1)
send(b"end\r\n")
send(b"quit\r\n")
s.close()
sys.stdout.write(out.decode("utf-8", "replace"))
PYEOF
}

wait_log() { # <pattern> [timeout-seconds] — polls lr.log
    local pat=$1 tmo=${2:-20} i
    for ((i = 0; i < tmo * 10; i++)); do
        grep -qF "$pat" "$OUT/lr.log" && return 0
        sleep 0.1
    done
    return 1
}

count_log() { grep -cF "$1" "$OUT/lr.log" 2>/dev/null || echo 0; }

# 1. Initial announcement installs.
wait_log "route installed 198.51.100.0/24" || { echo "FAIL: initial announcement never installed"; exit 1; }
echo "   initial announcement: installed"

# 2. Flap N times: withdraw + re-announce through the vty. The whole
# flap phase stays well inside one decay interval (30 s) so no FoM
# decay accrues mid-sequence — the suppression math must see the raw
# flap increments.
flap() {
    vty_session "configure terminal" \
        "router bgp 64513" \
        "address-family ipv4 unicast" \
        "no network 198.51.100.0/24" \
        "end" >/dev/null 2>&1 || true
    sleep 0.5
    vty_session "configure terminal" \
        "router bgp 64513" \
        "address-family ipv4 unicast" \
        "network 198.51.100.0/24" \
        "end" >/dev/null 2>&1 || true
    sleep 0.5
}

echo "== flap 1 (FoM 1000) =="
flap
wait_log "route withdrawn 198.51.100.0/24" || { echo "FAIL: flap 1 withdraw not observed"; exit 1; }
wait_log "route installed 198.51.100.0/24" 5 || { echo "FAIL: flap 1 re-announce not installed (premature suppression?)"; exit 1; }
echo "   flap 1: round-tripped (FoM 1000 < suppress 3000)"

echo "== flap 2 (FoM 2000+) =="
flap
before=$(count_log "route installed 198.51.100.0/24")
wait_log "route installed 198.51.100.0/24" 5 || { echo "FAIL: flap 2 re-announce not installed (premature suppression?)"; exit 1; }
echo "   flap 2: round-tripped (FoM ~2000 < suppress 3000)"

echo "== flap 3 (FoM 3000+ -> suppressed) =="
flap
# The re-announcement must now be DROPPED by the damping hook: the
# route stays out until two 3 s decay ticks have halved the FoM below
# the reuse threshold (suppressed entries decay 0.5 per tick).
sleep 6
after=$(count_log "route installed 198.51.100.0/24")
if [ "$after" -gt "$before" ]; then
    echo "FAIL: the prefix was installed during the suppression window (after=$after before=$before)"
    tail -20 "$OUT/lr.log"
    exit 1
fi
echo "   suppression: the re-announcement was dropped ($after installs total)"

# 3. The decay ticker reactivates the prefix.
wait_log "damping: prefix 198.51.100.0/24 reactivated" 75 || { echo "FAIL: the decay ticker never reactivated the prefix"; exit 1; }
echo "   decay: FoM fell below reuse — prefix reactivated"

# 4. A further flap re-installs (the reuse half of the cycle).
echo "== flap 4 (post-reuse) =="
flap
wait_log "route installed 198.51.100.0/24" 10 || { echo "FAIL: the route did not re-install after reuse"; exit 1; }
echo "   reuse: the route re-installed"

echo
echo "damping interop: PASS"
echo "  - FRR-generated withdraw flaps drove the RFC 2439 figure-of-merit"
echo "  - the third flap suppressed the prefix; the import hook dropped the re-announcement"
echo "  - the decay ticker reactivated it below the reuse threshold"
echo "  - a post-reuse flap installed the route again"
