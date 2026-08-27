#!/usr/bin/env bash
# RFC 2385 (TCP MD5) session-authentication interop:
#
#   phase 1: two lr-daemons, same MD5 key  — session MUST establish
#   phase 2: two lr-daemons, wrong MD5 key — session MUST NOT establish
#   phase 3: BIRD 2 with `password`        — authenticated route exchange
#   phase 4: FRR bgpd with `neighbor ... password` — authenticated exchange
#
# Phases 3/4 skip when the reference daemons are not installed.
#
# Env overrides:
#   BIRD / BIRDC   paths to the bird / birdc binaries
#   BGPD           path to the FRR bgpd binary
#   PORT1..PORT4   TCP ports for the four phases (default 11811-11814)
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi
PORT1=${PORT1:-11811}
PORT2=${PORT2:-11812}
PORT3=${PORT3:-11813}
PORT4=${PORT4:-11814}
# Never default the vty port into FRR's well-known range (2600-2620):
# every FRR daemon owns one (zebra 2600, bgpd 2605, staticd 2616, ...) and
# `apt-get install frr` starts a system zebra+staticd pair. A squatted
# port makes bgpd silently skip its own vty listener, and the test would
# interrogate whichever daemon owns the port instead of bgpd.
VTY_PORT=${VTY_PORT:-26998}
OUT=/tmp/lr_md5_interop
rm -rf "$OUT"; mkdir -p "$OUT"

BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
if ! command -v "$BIRD" >/dev/null 2>&1; then
    if [ -x /home/z/opt/bird/root/usr/sbin/bird ]; then
        BIRD=/home/z/opt/bird/root/usr/sbin/bird
        BIRDC=/home/z/opt/bird/root/usr/sbin/birdc
    else
        BIRD=""
    fi
fi
BGPD=${BGPD:-bgpd}
if ! command -v "$BGPD" >/dev/null 2>&1; then
    for cand in /home/z/opt/frr/root/usr/lib/frr/bgpd /usr/lib/frr/bgpd; do
        if [ -x "$cand" ]; then BGPD="$cand"; break; fi
    done
    [ -x "$BGPD" ] || BGPD=""
fi

fail=0

# ---------------------------------------------------------------------------
# Phase 1: same key on both daemons — must establish and propagate a route.
# ---------------------------------------------------------------------------
echo "== phase 1: two lr-daemons, same MD5 key =="
mkdir -p "$OUT/p1"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT1 --local-address 192.0.2.1 \
    --md5-key alpha --network 203.0.113.0/24 \
    >"$OUT/p1/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT1 --local-address 192.0.2.2 \
    --md5-key alpha \
    >"$OUT/p1/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

ok=1
for i in $(seq 1 120); do
    sleep 0.25
    if grep -qF "route installed 203.0.113.0/24" "$OUT/p1/b.log" 2>/dev/null; then
        ok=0
        break
    fi
    if ! kill -0 $A_PID 2>/dev/null || ! kill -0 $B_PID 2>/dev/null; then
        break
    fi
done
kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ $ok -ne 0 ] || ! grep -qF "session #1 → Established" "$OUT/p1/b.log"; then
    echo "FAIL: authenticated session did not establish (same MD5 key)"
    cat "$OUT/p1/a.log" "$OUT/p1/b.log"
    fail=1
else
    echo "PASS: phase 1 — MD5-authenticated session established + route propagated"
fi

# ---------------------------------------------------------------------------
# Phase 2: mismatched keys — must NOT establish within the wait window.
# ---------------------------------------------------------------------------
echo "== phase 2: two lr-daemons, mismatched MD5 keys =="
mkdir -p "$OUT/p2"
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:$PORT2 --local-address 192.0.2.1 \
    --md5-key alpha --network 203.0.113.0/24 \
    >"$OUT/p2/a.log" 2>&1 &
A_PID=$!
trap 'kill $A_PID 2>/dev/null || true' EXIT
sleep 1
"$BIN" --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
    --peer 127.0.0.1:$PORT2 --local-address 192.0.2.2 \
    --md5-key beta \
    >"$OUT/p2/b.log" 2>&1 &
B_PID=$!
trap 'kill $A_PID $B_PID 2>/dev/null || true' EXIT

# Give the wrong-key handshake ~8 s to (wrongly) establish.
sleep 8
leaked=0
if grep -qF "session #1 → Established" "$OUT/p2/b.log" 2>/dev/null; then
    leaked=1
fi
if grep -qF "route installed 203.0.113.0/24" "$OUT/p2/b.log" 2>/dev/null; then
    leaked=1
fi
kill $B_PID $A_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ $leaked -ne 0 ]; then
    echo "FAIL: session established despite mismatched MD5 keys"
    cat "$OUT/p2/a.log" "$OUT/p2/b.log"
    fail=1
else
    echo "PASS: phase 2 — wrong MD5 key rejected (no session, no route)"
fi

# ---------------------------------------------------------------------------
# Phase 3: BIRD 2 with password — authenticated bidirectional exchange.
# ---------------------------------------------------------------------------
if [ -z "$BIRD" ]; then
    echo "== phase 3: SKIP (bird/birdc not found) =="
else
    echo "== phase 3: BIRD 2 with 'password' (MD5) =="
    mkdir -p "$OUT/p3"
    cat >"$OUT/p3/bird.conf" <<EOF
# BIRD 2 configuration: MD5-authenticated BGP with lr-daemon.
log "$OUT/p3/bird.log" all;
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
    local port $((PORT3 + 10000)) as 64513;
    neighbor 127.0.0.1 port $PORT3 as 64512;
    multihop 2;
    password "alpha";
    ipv4 {
        import all;
        export filter export_to_lr;
        next hop address 192.0.2.10;
    };
}
EOF
    "$BIRD" -c "$OUT/p3/bird.conf" -s "$OUT/p3/bird.ctl" -P "$OUT/p3/bird.pid" \
        >"$OUT/p3/bird.stdout" 2>&1 &
    BIRD_PID=$(cat "$OUT/p3/bird.pid" 2>/dev/null || echo "")
    trap 'kill $BIRD_PID 2>/dev/null || true' EXIT
    sleep 1

    "$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
        --listen 127.0.0.1:$PORT3 --local-address 127.0.0.1 \
        --md5-key alpha --network 203.0.113.0/24 \
        >"$OUT/p3/lr.log" 2>&1 &
    LR_PID=$!
    trap 'kill $LR_PID $BIRD_PID 2>/dev/null || true' EXIT

    ok_bird=1
    ok_lr=1
    for i in $(seq 1 120); do
        sleep 0.25
        if [ $ok_bird -ne 0 ] && "$BIRDC" -s "$OUT/p3/bird.ctl" show route 2>/dev/null \
            | grep -q "203.0.113.0/24"; then
            ok_bird=0
        fi
        if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/p3/lr.log" 2>/dev/null; then
            ok_lr=0
        fi
        if [ $ok_bird -eq 0 ] && [ $ok_lr -eq 0 ]; then
            break
        fi
    done

    echo "== BIRD routing table (phase 3) =="
    "$BIRDC" -s "$OUT/p3/bird.ctl" show route all 2>/dev/null | head -12 || true
    echo "== lr-daemon log (phase 3) =="
    cat "$OUT/p3/lr.log"

    kill $LR_PID 2>/dev/null || true
    "$BIRDC" -s "$OUT/p3/bird.ctl" down 2>/dev/null || kill $BIRD_PID 2>/dev/null || true
    wait 2>/dev/null || true

    if [ $ok_bird -ne 0 ] || [ $ok_lr -ne 0 ]; then
        echo "FAIL: BIRD MD5 interop did not converge (bird=$ok_bird lr=$ok_lr)"
        tail -20 "$OUT/p3/bird.log" 2>/dev/null || true
        fail=1
    else
        echo "PASS: phase 3 — MD5-authenticated route exchange with BIRD 2"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 4: FRR bgpd with `neighbor ... password`.
# ---------------------------------------------------------------------------
if [ -z "$BGPD" ]; then
    echo "== phase 4: SKIP (bgpd not found) =="
else
    echo "== phase 4: FRR bgpd with 'neighbor ... password' (MD5) =="
    mkdir -p "$OUT/p4" "$OUT/p4/vty"
    case "$BGPD" in
        /home/z/opt/*) FRRROOT=${BGPD%/usr/lib/frr/bgpd}
            export LD_LIBRARY_PATH="$FRRROOT/usr/lib/x86_64-linux-gnu/frr:$FRRROOT/usr/lib/x86_64-linux-gnu:$FRRROOT/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            ;;
    esac

    cat >"$OUT/p4/bgpd.conf" <<EOF
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
 neighbor 127.0.0.1 port $PORT4
 neighbor 127.0.0.1 ebgp-multihop 2
 neighbor 127.0.0.1 password alpha
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
    "$BGPD" -f "$OUT/p4/bgpd.conf" -i "$OUT/p4/bgpd.pid" \
        -Z -n -S \
        -p 17998 -A 127.0.0.1 -P $VTY_PORT --vty_socket "$OUT/p4/vty" \
        --log "file:$OUT/p4/bgpd.log" \
        >"$OUT/p4/bgpd.stdout" 2>&1 &
    BGPD_PID=$!
    trap 'kill $BGPD_PID 2>/dev/null || true' EXIT

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
    # hostname `bgpd-lr` appears in the vty prompt. bgpd silently skips
    # its vty TCP listener when the port is already bound, so a squatter
    # (e.g. a system staticd on its well-known port 2616) would otherwise
    # be interrogated instead of bgpd and the failure would be confusing.
    vty_ok=1
    for i in $(seq 1 40); do
        sleep 0.25
        if vty_cmd "show version" 2>/dev/null | grep -q "bgpd-lr"; then
            vty_ok=0
            break
        fi
        if ! kill -0 $BGPD_PID 2>/dev/null; then
            break
        fi
    done
    if [ $vty_ok -ne 0 ]; then
        echo "FAIL: bgpd vty did not answer as our instance (bgpd-lr) on port $VTY_PORT"
        echo "      another daemon may be holding the port; set VTY_PORT to a free one"
        cat "$OUT/p4/bgpd.stdout" 2>/dev/null || true
        tail -15 "$OUT/p4/bgpd.log" 2>/dev/null || true
        kill $BGPD_PID 2>/dev/null || true
        wait 2>/dev/null || true
        fail=1
    else
        "$BIN" --local-as 64512 --peer-as 64514 --router-id 10.0.0.1 \
            --listen 127.0.0.1:$PORT4 --local-address 192.0.2.1 \
            --md5-key alpha --network 203.0.113.0/24 \
            >"$OUT/p4/lr.log" 2>&1 &
        LR_PID=$!
        trap 'kill $BGPD_PID $LR_PID 2>/dev/null || true' EXIT

        ok_frr=1
        ok_lr=1
        for i in $(seq 1 180); do
            sleep 0.25
            if [ $ok_lr -ne 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/p4/lr.log" 2>/dev/null; then
                ok_lr=0
            fi
            if [ $ok_frr -ne 0 ] && [ $((i % 8)) -eq 0 ]; then
                if vty_cmd "show ip bgp" >"$OUT/p4/vty_table.txt" 2>/dev/null \
                    && grep -q "203.0.113.0/24" "$OUT/p4/vty_table.txt"; then
                    ok_frr=0
                fi
            fi
            if [ $ok_frr -eq 0 ] && [ $ok_lr -eq 0 ]; then
                break
            fi
        done

        echo "== FRR BGP table (phase 4) =="
        vty_cmd "show ip bgp" || true
        echo "== lr-daemon log (phase 4) =="
        cat "$OUT/p4/lr.log"

        kill $LR_PID 2>/dev/null || true
        kill $BGPD_PID 2>/dev/null || true
        wait 2>/dev/null || true

        if [ $ok_frr -ne 0 ] || [ $ok_lr -ne 0 ]; then
            echo "FAIL: FRR MD5 interop did not converge (frr=$ok_frr lr=$ok_lr)"
            tail -15 "$OUT/p4/bgpd.log" 2>/dev/null || true
            fail=1
        else
            echo "PASS: phase 4 — MD5-authenticated route exchange with FRR bgpd"
        fi
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: MD5 (RFC 2385) interop suite complete"
fi
exit $fail
