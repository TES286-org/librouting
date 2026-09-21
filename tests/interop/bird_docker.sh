#!/usr/bin/env bash
# BIRD-in-Docker interop test: lr-daemon on the host exchanges BGP
# with BIRD 2 running inside a Linux Docker container. Verifies
# cross-OS BGP interoperability — lr-daemon's TCP stack on Windows
# talking to BIRD's TCP stack on Linux via Docker's port forwarding.
#
# On Linux this is a redundant check (the regular bird.sh covers the
# same wire protocol with BIRD on the host), but on Windows this is
# the only way to run lr-daemon against BIRD without setting up WSL2.
#
# Architecture:
#   lr-daemon (host, AS64512, listener on 127.0.0.1:$LR_PORT)
#        ↑↓ TCP via Docker port forwarding + host.docker.internal
#   BIRD 2 (container, AS64513, connector to host.docker.internal:$LR_PORT)
#
# The container is started with `--add-host=host.docker.internal:host-gateway`
# so BIRD can resolve the host's loopback inside the container. The
# image is built from ubuntu:22.04 + bird2 (matching the version the
# Linux CI installs via apt-get).
#
# Success criteria:
#   1. lr-daemon's log shows 198.51.100.0/24 installed from BIRD.
#   2. BIRD's routing table contains 203.0.113.0/24 learned from lr.
#   3. The BGP session reaches Established on both sides.
#
# SKIP gracefully when Docker or lr-daemon is unavailable.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=$(./tests/interop/_lr_daemon.sh 2>/dev/null) || {
    echo "SKIP: lr-daemon not built (run \`cargo build -p lr-cli\` first)"
    exit 0
}
command -v docker >/dev/null 2>&1 || {
    echo "SKIP: docker not installed"
    exit 0
}
# Sanity-check the daemon actually starts (Docker engine down → SKIP).
docker info >/dev/null 2>&1 || {
    echo "SKIP: docker engine not reachable (docker info failed)"
    exit 0
}

LR_PORT=${LR_PORT:-17996}
OUT=/tmp/lr_bird_docker
IMAGE_TAG=lr-bird-interop:latest
CONTAINER=lr-bird-interop
rm -rf "$OUT"; mkdir -p "$OUT"

# Build the BIRD image. Cached after the first run; the layer cache
# means subsequent runs skip the apt-get install. Building this way
# (rather than depending on a third-party image like pierky/bird2)
# keeps the BIRD version aligned with what the Linux CI installs
# (Ubuntu 22.04's bird2 package).
echo "== building the BIRD Docker image ($IMAGE_TAG) =="
docker build --tag "$IMAGE_TAG" -f - . <<'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends bird2 \
    && rm -rf /var/lib/apt/lists/*
# bird writes its log to /bird.log and reads config from /bird.conf
# (the runtime mounts both as volumes). birdc is on PATH for the
# post-run route verification step.
ENTRYPOINT ["/usr/sbin/bird", "-f", "-c"]
DOCKERFILE

# BIRD config: BIRD connects to host.docker.internal:$LR_PORT (which
# Docker Desktop / Docker Engine 20.10+ resolves to the host's
# loopback via the --add-host flag below).
cat >"$OUT/bird.conf" <<EOF
# BIRD 2 configuration for the librouting Docker interop test.
log "/bird.log" all;
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
    neighbor host.docker.internal port $LR_PORT as 64512;
    multihop 2;       # eBGP over the Docker bridge (not directly connected)
    ipv4 {
        import all;
        export filter export_to_lr;
        # BIRD refuses to export a next hop equal to the neighbor
        # address (host.docker.internal resolves to the Docker
        # gateway, which BIRD would reject as a martian), so pin a
        # distinct one.
        next hop address 192.0.2.10;
    };
}
EOF

echo "== starting BIRD in a Docker container =="
# --add-host: host.docker.internal → the Docker host's loopback
#   (Docker Engine 20.10+ supports the host-gateway alias).
# -v: mount the BIRD config read-only (Windows host → Linux container
#   volume mount; Docker Desktop translates the path automatically).
docker run --rm -d \
    --name "$CONTAINER" \
    --add-host=host.docker.internal:host-gateway \
    -v "$OUT/bird.conf:/bird.conf:ro" \
    "$IMAGE_TAG" /bird.conf
trap 'docker rm -f "$CONTAINER" 2>/dev/null || true; kill $LR_PID 2>/dev/null || true' EXIT

echo "== starting lr-daemon (host, AS64512, listener 127.0.0.1:$LR_PORT) =="
"$BIN" --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --ebgp-policy accept-all \
    --listen 127.0.0.1:$LR_PORT --local-address 127.0.0.1 \
    --network 203.0.113.0/24 \
    >"$OUT/lr.log" 2>&1 &
LR_PID=$!

# Wait for the route to propagate in both directions (up to 30 s on
# slow runners: Docker networking adds latency on top of the BGP
# OPEN/KEEPALIVE/UPDATE cycle).
ok_lr=0
ok_bird=0
for i in $(seq 1 120); do
    sleep 0.25
    if [ $ok_lr -eq 0 ] && grep -qF "route installed 198.51.100.0/24" "$OUT/lr.log" 2>/dev/null; then
        ok_lr=1
    fi
    if [ $ok_bird -eq 0 ]; then
        # birdc returns the routing table; the BIRD control socket is
        # at /run/bird/bird.ctl inside the container by default.
        if docker exec "$CONTAINER" /usr/sbin/birdc show route 2>/dev/null \
            | grep -q "203.0.113.0/24"; then
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
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        echo "BIRD container died"
        break
    fi
done

echo "== lr-daemon log =="
cat "$OUT/lr.log"
echo "== BIRD routing table =="
docker exec "$CONTAINER" /usr/sbin/birdc show route all 2>/dev/null || true
echo "== BIRD protocol state =="
docker exec "$CONTAINER" /usr/sbin/birdc show protocols all lr 2>/dev/null | head -25 || true
echo "== BIRD log (tail) =="
docker exec "$CONTAINER" tail -25 /bird.log 2>/dev/null || true

kill $LR_PID 2>/dev/null || true
docker rm -f "$CONTAINER" 2>/dev/null || true
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
    echo "PASS: BIRD-in-Docker interop — bidirectional route exchange"
fi
exit $fail
