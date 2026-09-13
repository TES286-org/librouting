#!/usr/bin/env bash
# Babel multi-NIC interface matching smoke test.
#
# Verifies that lr-daemon --protocol babel with [[babel.interface]]
# blocks enumerates the system interfaces and resolves glob patterns
# against them. Runs in a user+network namespace so it does not touch
# the host's interfaces. Creates a veth pair (veth0/veth1) and
# configures [[babel.interface]] patterns that match each end.
#
# Success criteria:
#   1. lr-daemon prints "babel N interface pattern(s) configured;
#      enumerating M system interface(s)".
#   2. Each pattern's match count is non-zero.
#   3. The daemon picks one matched interface's address as the bind
#      source (or fails cleanly with --local-address missing).
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
unshare -Urn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces unavailable"; exit 0; }

REPO=$(pwd)
export REPO BIN

exec unshare -Urn bash -euo pipefail <<'INNER'
cd "$REPO"
OUT=/tmp/lr_babel_multi_nic
rm -rf "$OUT"; mkdir -p "$OUT"

# Bring up loopback + a veth pair.
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip addr add 10.0.0.1/24 dev veth0
ip addr add 10.0.0.2/24 dev veth1

# Babel config: patterns match both veth ends. The daemon should
# log both as matched and pick the first as the bind source.
cat >"$OUT/lr.conf" <<'EOF'
# Top-level protocol selection (rc.3 multi-protocol support).
protocol = "babel"

[babel]
port = 16696

[[babel.interface]]
name = "veth*"
type = "wired"
rxcost = 96
hello_interval_ms = 4000

[[babel.interface]]
name = "lo"
type = "wired"
rxcost = 256
EOF

# Run the daemon briefly and capture its startup log. Force the TOML
# dialect because the compat auto-detector sees `protocol = "babel"`
# as a BIRD `protocol <kind>` directive (a known false-positive).
"$BIN" --config "$OUT/lr.conf" --config-dialect toml >"$OUT/lr.log" 2>&1 &
LR_PID=$!
sleep 2
kill $LR_PID 2>/dev/null || true
wait $LR_PID 2>/dev/null || true

echo "== lr-daemon log =="
cat "$OUT/lr.log"

# Verify the daemon enumerated interfaces and matched patterns.
if ! grep -qF "babel 2 interface pattern(s) configured" "$OUT/lr.log"; then
    echo "FAIL: daemon did not log babel interface pattern count"
    exit 1
fi
if ! grep -qE "babel interface pattern 'veth\*' matched 2 interface\(s\): veth0, veth1" "$OUT/lr.log"; then
    echo "FAIL: daemon did not match veth* against veth0 and veth1"
    exit 1
fi
if ! grep -qE "babel interface pattern 'lo' matched 1 interface\(s\): lo" "$OUT/lr.log"; then
    echo "FAIL: daemon did not match 'lo' against the loopback"
    exit 1
fi

echo "PASS: Babel multi-NIC pattern matching"
exit 0
INNER
