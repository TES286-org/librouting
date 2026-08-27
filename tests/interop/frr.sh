#!/usr/bin/env bash
# FRR interop test: exchange real BGP between lr-daemon and FRR's bgpd.
#
#   lr-daemon (AS64512, originates 203.0.113.0/24, listener :17996)
#        ↑↓ TCP on 127.0.0.1
#   FRR bgpd (AS64514, network 198.51.100.0/24, connector)
#
# bgpd runs standalone (no zebra, no kernel) on unprivileged ports, so the
# test works as any user with any FRR >= 7.4. The routing table is read
# back over the vty TCP interface (telnet-style).
#
# Note on addresses: FRR rejects loopback next hops as martian, so
# lr-daemon advertises 192.0.2.1 (RFC 5737 documentation address) and FRR
# pins its export next hop to 192.0.2.20 via a route-map. Neither needs to
# be assigned to an interface — BGP carries the reachability information,
# it does not require the next hop to be resolvable on the wire.
#
# Success criteria:
#   1. FRR's BGP table contains 203.0.113.0/24 learned from lr-daemon.
#   2. lr-daemon's log shows 198.51.100.0/24 installed from FRR.
#
# Env overrides:
#   BGPD     path to the bgpd binary (default: from $PATH or extracted tree)
#   PORT     lr-daemon listen port (default 17996)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
BGPD=${BGPD:-bgpd}
if ! command -v "$BGPD" >/dev/null 2>&1; then
    for cand in /home/z/opt/frr/root/usr/lib/frr/bgpd /usr/lib/frr/bgpd; do
        if [ -x "$cand" ]; then BGPD="$cand"; break; fi
    done
fi
command -v "$BGPD" >/dev/null 2>&1 || { echo "SKIP: bgpd not found"; exit 0; }

# Resolve the shared-library path for an extracted (non-installed) bgpd.
case "$BGPD" in
    /home/z/opt/*) FRRROOT=${BGPD%/usr/lib/frr/bgpd}
        export LD_LIBRARY_PATH="$FRRROOT/usr/lib/x86_64-linux-gnu/frr:$FRRROOT/usr/lib/x86_64-linux-gnu:$FRRROOT/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ;;
esac

PORT=${PORT:-17996}
# Never default the vty port into FRR's well-known range (2600-2620):
# every FRR daemon owns one (zebra 2600, bgpd 2605, staticd 2616, ...) and
# `apt-get install frr` starts a system zebra+staticd pair. A squatted
# port makes bgpd silently skip its own vty listener, and the test would
# interrogate whichever daemon owns the port instead of bgpd.
VTY_PORT=${VTY_PORT:-26995}
OUT=/tmp/lr_frr_interop
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
router bgp 64514
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

echo "== starting FRR bgpd (AS64514, connects to lr-daemon :$PORT) =="
"$BGPD" -f "$OUT/bgpd.conf" -i "$OUT/bgpd.pid" \
    -Z -n -S \
    -p 17995 -A 127.0.0.1 -P $VTY_PORT --vty_socket "$OUT/vty" \
    --log "file:$OUT/bgpd.log" \
    >"$OUT/bgpd.stdout" 2>&1 &
BGPD_PID=$!
trap 'kill ${BGPD_PID:-} ${LR_PID:-} 2>/dev/null || true' EXIT

# Query a command over the vty TCP interface; output goes to stdout.
# Robust against peers that close the session at any point (a vty that
# rejects us may close mid-conversation; never traceback).
vty_cmd() {
    python3 - "$VTY_PORT" "$1" <<'PYEOF'
import socket, sys, time
port, cmd = int(sys.argv[1]), sys.argv[2]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError:
    sys.exit(1)
s.settimeout(0.5)

def drain(idle_rounds=2):
    # Read until EOF or `idle_rounds` consecutive 0.5 s silences.
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
send(cmd.encode() + b"\r\n")
time.sleep(0.8)
out = drain()
send(b"quit\r\n")
s.close()
sys.stdout.write(out.decode("utf-8", "replace"))
PYEOF
}

# Wait for the vty AND verify it answers as OUR bgpd: the configured
# hostname `bgpd-lr` appears in the vty prompt. bgpd silently skips its
# vty TCP listener when the port is already bound, so a squatter (e.g.
# a system staticd on its well-known port) would otherwise be
# interrogated instead of bgpd and the failure would be confusing.
vty_ok=1
for i in $(seq 1 40); do
    sleep 0.25
    if vty_cmd "show version" 2>/dev/null | grep -q "bgpd-lr"; then
        vty_ok=0
        break
    fi
    if ! kill -0 $BGPD_PID 2>/dev/null; then
        echo "FAIL: bgpd died during startup"
        cat "$OUT/bgpd.stdout" || true
        cat "$OUT/bgpd.log" 2>/dev/null || true
        exit 1
    fi
done
if [ $vty_ok -ne 0 ]; then
    echo "FAIL: bgpd vty did not answer as our instance (bgpd-lr) on port $VTY_PORT"
    echo "      another daemon may be holding the port; set VTY_PORT to a free one"
    cat "$OUT/bgpd.stdout" 2>/dev/null || true
    tail -15 "$OUT/bgpd.log" 2>/dev/null || true
    kill $BGPD_PID 2>/dev/null || true
    wait 2>/dev/null || true
    exit 1
fi

echo "== starting lr-daemon (AS64512, listener) =="
"$BIN" --local-as 64512 --peer-as 64514 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!
trap 'kill ${BGPD_PID:-} ${LR_PID:-} 2>/dev/null || true' EXIT

# Wait for both directions to converge (up to 45 s on slow runners). The
# lr-daemon side is polled cheaply via its log; the FRR side is polled over
# the vty only every ~2 s to keep the loop fast.
ok_frr=1
ok_lr=1
for i in $(seq 1 180); do
    sleep 0.25
    if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=0
    fi
    if [ $ok_frr -ne 0 ] && [ $((i % 8)) -eq 0 ]; then
        if vty_cmd "show ip bgp" >"$OUT/vty_table.txt" 2>/dev/null \
            && grep -q "203.0.113.0/24" "$OUT/vty_table.txt"; then
            ok_frr=0
        fi
    fi
    if [ $ok_frr -eq 0 ] && [ $ok_lr -eq 0 ]; then
        break
    fi
done

echo "== FRR BGP table =="
vty_cmd "show ip bgp" || true
echo "== FRR BGP summary =="
vty_cmd "show bgp summary" || true
echo "== lr-daemon log (tail) =="
tail -15 "$OUT/lr.log" || true
echo "== bgpd log (tail) =="
tail -15 "$OUT/bgpd.log" 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
kill $BGPD_PID 2>/dev/null || true
wait 2>/dev/null || true

fail=0
if [ $ok_frr -ne 0 ]; then
    echo "FAIL: FRR did not learn 203.0.113.0/24 from lr-daemon"
    fail=1
fi
if [ $ok_lr -ne 0 ]; then
    echo "FAIL: lr-daemon did not learn 198.51.100.0/24 from FRR"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "PASS: FRR interop — bidirectional route exchange with FRR bgpd"
fi
exit $fail
