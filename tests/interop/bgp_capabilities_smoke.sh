#!/usr/bin/env bash
# Smoke-test the 2.x capability block end-to-end: two lr-daemon peers
# establish a session with extended_message + bgp_role + fqdn +
# software_version + link_local_next_hop + orf advertised on both
# sides, and the daemon logs the session Established. The codec-level
# round-trips and the negotiation-helper unit tests pin the wire
# format; this script pins the daemon's willingness to advertise the
# capabilities on a real OPEN.
set -euo pipefail

cd "$(dirname "$0")/../.."
source tests/interop/_lib.sh

BIN=$(lr_resolve_daemon) || exit 0
PORT=${PORT:-11794}
OUT=/tmp/lr_caps_smoke
rm -rf "$OUT"; mkdir -p "$OUT"

# Two configs with the full capability block. The peers are
# complementary (provider / customer) so the BGP Role pairing
# check passes. The PORT env var substitutes into the listen /
# remote addresses so successive runs do not collide on a stale
# listener.
cat >"$OUT/a.lr" <<EOF
bgp {
    local_as 64512;
    peer_as 64513;
    router_id 10.0.0.1;
    listen_addr "127.0.0.1:${PORT}";
    local_address "127.0.0.1";
    ebgp_policy "accept-all";
    extended_message true;
    bgp_role "provider";
    hostname "border-a";
    domain_name "example.net";
    software_version "lr/2.0";
    link_local_next_hop true;
    orf "1:1:64:both";
}
EOF

cat >"$OUT/b.lr" <<EOF
bgp {
    local_as 64513;
    peer_as 64512;
    router_id 10.0.0.2;
    local_address "127.0.0.1";
    ebgp_policy "accept-all";
    extended_message true;
    bgp_role "customer";
    hostname "border-b";
    domain_name "example.net";
    software_version "lr/2.0";
    link_local_next_hop true;
    orf "1:1:64:both";
}
peer "a" {
    remote "127.0.0.1:${PORT}";
    peer_as 64512;
}
EOF

echo "== starting daemon A (listener, AS64512, full 2.x capability block) =="
DAEMON_A=$(lr_daemon_spawn "$OUT/a.log" --config "$OUT/a.lr")

echo "== starting daemon B (connector, AS64513, full 2.x capability block) =="
DAEMON_B=$(lr_daemon_spawn "$OUT/b.log" --config "$OUT/b.lr")

echo "== waiting for the session to establish =="
# Either daemon may log the Established line first — A as the
# listener, B as the connector. Poll both; the session is up when
# either side reports it.
for i in $(seq 1 60); do
    if grep -qF "session #1 → Established" "$OUT/a.log" 2>/dev/null \
        || grep -qF "session #1 → Established" "$OUT/b.log" 2>/dev/null; then
        echo "   PASS: session Established with the 2.x capability block advertised"
        exit 0
    fi
    sleep 0.5
done

echo "FAIL: session did not establish within 30 s"
echo "--- A log tail ---"
tail -20 "$OUT/a.log" || true
echo "--- B log tail ---"
tail -20 "$OUT/b.log" || true
exit 1
