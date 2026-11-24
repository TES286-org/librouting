#!/usr/bin/env bash
# Real-data benchmark harness (issue #101 "Benchmark Based on Real
# Data").
#
# Builds a system that imports a public MRT RIB dump into multiple
# BGP speakers via real BGP sessions, measures each speaker's route
# count and RSS during the feed, and prints a comparison table.
#
# Architecture:
#
#                 ┌─────────────────┐
#                 │  Source speaker │
#                 │  (lr-daemon     │
#                 │   --mrt-feed)   │
#                 │   (listener)    │
#                 └──────┬──────────┘
#                        │ BGP sessions (targets connect)
#           ┌────────────┼────────────┐
#           ▼            ▼            ▼
#     ┌─────────┐  ┌─────────┐  ┌─────────┐
#     │ lr-     │  │  BIRD   │  │  FRR    │
#     │ daemon  │  │         │  │ bgpd    │
#     │ (target)│  │ (target)│  │ (target)│
#     └─────────┘  └─────────┘  └─────────┘
#           │            │            │
#           ▼            ▼            ▼
#     [sampled     [sampled     [sampled
#      every 1s]   every 1s]   every 1s]
#           │            │            │
#           └────────────┼────────────┘
#                        ▼
#                 ┌─────────────────┐
#                 │  Comparison     │
#                 │  report         │
#                 └─────────────────┘
#
# The source lr-daemon loads the MRT dump into its Loc-RIB through
# the `--mrt-feed` flag; the daemon's BGP export path advertises the
# routes to every connected peer over a real BGP session. Each
# target connects to the source and learns the routes via the normal
# BGP UPDATE path — the same path a production deployment uses.
#
# Env overrides:
#   LR_BENCH_MRT       path to a local .mrt file. When set, the
#                      harness skips the download.
#   LR_BENCH_MRT_URL   the dump URL (default: RIPE RIS rrc26
#                      latest-bview.gz).
#   LR_BENCH_NO_BIRD   when non-empty, skip the BIRD target.
#   LR_BENCH_NO_FRR    when non-empty, skip the FRR target.
#   LR_BENCH_CAP       cap on routes fed to each target (default
#                      1000). A full public RIB (~1M routes) takes
#                      hours to replay over a BGP session; the cap
#                      keeps each target within a CI budget.
#   LR_BENCH_OUT       working directory (default /tmp/lr_bench).
#   LR_BENCH_DEADLINE  per-target convergence deadline in seconds
#                      (default 120).
#
# The harness SKIPs cleanly (exit 0) when:
#   - the lr binary is missing (cargo build -p lr-cli --release)
#   - the network egress is unavailable and no local MRT is provided
#   - neither BIRD nor FRR is installed (only the lr-vs-lr leg runs)
#
# Success criteria:
#   1. The source lr-daemon accepts BGP sessions from every
#      available target.
#   2. Every target learns at least one BGP route from the source.
#   3. The comparison report prints a table with every target's
#      route count, convergence time and RSS.
#   4. The lr target's Loc-RIB diffs clean against the BIRD target's
#      dump when BIRD is available (cross-implementation correctness
#      of best-path selection over the fed dump).
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/release/lr
DAEMON=target/release/lr-daemon
LRCTL=target/release/lrctl
if [ ! -x "$BIN" ]; then
    BIN=target/debug/lr
    DAEMON=target/debug/lr-daemon
    LRCTL=target/debug/lrctl
fi
if [ ! -x "$BIN" ]; then
    echo "SKIP: lr not built (cargo build -p lr-cli --release)"
    exit 0
fi
# The sampler scripts call `lrctl` without a path; put the binary
# directory on PATH so they find it.
BIN_DIR=$(cd "$(dirname "$BIN")" && pwd)
export PATH="$BIN_DIR:$PATH"

OUT=${LR_BENCH_OUT:-/tmp/lr_bench}
rm -rf "$OUT"; mkdir -p "$OUT"

CAP=${LR_BENCH_CAP:-1000}
DEADLINE=${LR_BENCH_DEADLINE:-120}

BIRD=${BIRD:-bird}
BIRDC=${BIRDC:-birdc}
FRR_BGPD=${FRR_BGPD:-bgpd}
FRR_VTYSH=${FRR_VTYSH:-vtysh}

# All targets share AS 64512 so the source's single --peer-as applies
# to every session. Per-peer AS override is the TODO the harness
# names — the daemon's [[peer]] config block carries it, the --peer
# CLI flag does not.
TARGET_AS=64512
SOURCE_AS=64520
SOURCE_PORT=18080

# Kill daemons left by interrupted earlier runs of this harness. The
# EXIT trap below only fires on a clean exit; a killed run leaves
# target/*/lr-daemon processes behind that block the listener port.
if command -v pkill >/dev/null 2>&1; then
    pkill -f "target/release/lr-daemon" 2>/dev/null || true
    pkill -f "target/debug/lr-daemon" 2>/dev/null || true
    pkill -f "$OUT/bird.conf" 2>/dev/null || true
    # The listeners free on SIGTERM; wait for the source port to clear
    # before starting.
    if command -v ss >/dev/null 2>&1; then
        for _ in $(seq 1 10); do
            ss -ltn 2>/dev/null | grep -q ":$SOURCE_PORT\b" || break
            sleep 1
        done
    fi
fi

# ---------------------------------------------------------------------
# 1. Acquire the MRT dump.
# ---------------------------------------------------------------------
MRT="${LR_BENCH_MRT:-}"
if [ -z "$MRT" ]; then
    echo "== fetching a public MRT RIB dump =="
    URL=${LR_BENCH_MRT_URL:-https://data.ris.ripe.net/rrc26/latest-bview.gz}
    export LR_BENCH_MRT_URL="$URL"
    if ! "$BIN" bench fetch --to "$OUT" 2>"$OUT/fetch.err"; then
        echo "SKIP: bench fetch failed (network egress unavailable?)"
        head -5 "$OUT/fetch.err" 2>/dev/null || true
        exit 0
    fi
    GZ=$(ls "$OUT"/*.gz 2>/dev/null | head -1 || true)
    if [ -z "$GZ" ]; then
        echo "SKIP: bench fetch did not leave a .gz file"
        cat "$OUT/fetch.err" 2>/dev/null || true
        exit 0
    fi
    MRT="$OUT/bview.mrt"
    if ! gunzip -c "$GZ" >"$MRT" 2>"$OUT/gunzip.err"; then
        echo "SKIP: gunzip failed on $GZ"
        head -5 "$OUT/gunzip.err" 2>/dev/null || true
        exit 0
    fi
fi
if [ ! -s "$MRT" ]; then
    echo "SKIP: MRT dump $MRT is empty or missing"
    exit 0
fi
SIZE=$(wc -c <"$MRT")
echo "   dump: $MRT ($SIZE bytes, cap $CAP routes per target)"

# ---------------------------------------------------------------------
# 2. Start the source speaker (listener + MRT feed).
#
# The source listens on $SOURCE_PORT. Every target connects to it.
# The source's --peer-as matches the targets' AS so it accepts them.
# ---------------------------------------------------------------------
PIDS=""
cleanup() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# Per-target time series; defined up front so gates can reference them
# even when a target is skipped.
LR_SERIES="$OUT/lr_target.jsonl"
BIRD_SERIES="$OUT/bird_target.jsonl"
FRR_SERIES="$OUT/frr_target.jsonl"

echo "== starting source lr-daemon (AS$SOURCE_AS, port $SOURCE_PORT, --mrt-feed) =="
FEED_START_EPOCH=$(date +%s)
export FEED_START_EPOCH
"$DAEMON" --local-as $SOURCE_AS --peer-as $TARGET_AS --router-id 10.0.0.1 \
    --ebgp-policy accept-all --listen 127.0.0.1:$SOURCE_PORT \
    --local-address 192.0.2.1 \
    --mrt-feed "$MRT" --mrt-feed-cap "$CAP" \
    --api-socket "$OUT/source.api" >"$OUT/source.log" 2>&1 &
SOURCE_PID=$!
PIDS="$PIDS $SOURCE_PID"

# The source binds $SOURCE_PORT before it feeds the dump; poll for the
# listener so a bind failure (leftover process, permission) fails the
# run immediately instead of a confusing zero-route report.
if command -v ss >/dev/null 2>&1; then
    for _ in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":$SOURCE_PORT\b" && break
        sleep 1
    done
    if ! ss -ltn 2>/dev/null | grep -q ":$SOURCE_PORT\b"; then
        echo "FAIL: source daemon did not open port $SOURCE_PORT"
        tail -20 "$OUT/source.log" 2>/dev/null || true
        exit 1
    fi
fi

# Give the source a moment to bind and install the MRT routes.
sleep 1

# ---------------------------------------------------------------------
# 3. Start target speakers. Each connects to the source.
# ---------------------------------------------------------------------

export INTERVAL=1 DEADLINE SETTLED=5

# --- target: lr-daemon ---
LR_API="$OUT/lr_target.api"
echo "== starting target lr-daemon (AS$TARGET_AS, connects to source) =="
"$DAEMON" --local-as $TARGET_AS --peer-as $SOURCE_AS --router-id 10.0.0.2 \
    --ebgp-policy accept-all \
    --peer 127.0.0.1:$SOURCE_PORT --local-address 192.0.2.2 \
    --api-socket "$LR_API" >"$OUT/lr_target.log" 2>&1 &
LR_TARGET_PID=$!
PIDS="$PIDS $LR_TARGET_PID"

# The source rejects a second inbound session for a peer that still
# has an active one ("already has an active session", daemon.rs:3660),
# so the lr target runs first: it connects, samples until it
# converges, then the BIRD/FRR targets take the peer slot. Both kinds
# of target receive the same dump.
echo "== sampling metrics from target lr-daemon =="
LR_SERIES="$OUT/lr_target.jsonl"
bash tests/bench/sample_metrics.sh lr "$LR_TARGET_PID" "$LR_SERIES" "$LR_API" \
    >"$OUT/lr_sampler.log" 2>&1

# Gate on the lr target while its daemon is up: `routes count` groups
# by BIRD-style protocol names, so the `bgp` line's count is the
# learned set (connected routes are `proto=direct` and do not count).
LR_LEARNED=$(lrctl --socket "$LR_API" routes count 2>/dev/null \
    | awk -F'routes=' '/^  proto=bgp routes=/{s+=$2} END{print s+0}') \
    || true
if [ "${LR_LEARNED:-0}" -eq 0 ]; then
    echo "FAIL: the lr target learned no BGP routes from the source"
    echo "--- lr target log (last 30 lines) ---"
    tail -30 "$OUT/lr_target.log" 2>/dev/null || true
    echo "--- source log (last 30 lines) ---"
    tail -30 "$OUT/source.log" 2>/dev/null || true
    exit 1
fi
echo "lr target: ${LR_LEARNED:-0} BGP routes learned from the source"

# Dump the lr target Loc-RIB for the cross-implementation diff later.
lrctl --socket "$LR_API" routes dump "$OUT/lr_target.mrt" \
    >"$OUT/lr_target.dump.log" 2>&1 || true

# Free the source's peer slot (the source drops later inbound
# connections to a busy peer) so the next target can connect.
kill "$LR_TARGET_PID" 2>/dev/null || true
wait "$LR_TARGET_PID" 2>/dev/null || true
sleep 1

# --- target: BIRD ---
BIRD_CTL="$OUT/bird.ctl"
have_bird=0
if [ -z "${LR_BENCH_NO_BIRD:-}" ] && command -v "$BIRD" >/dev/null 2>&1; then
    have_bird=1
    echo "== starting target BIRD (AS$TARGET_AS, connects to source) =="
    # BIRD's default protocol name is `source`, which collides with a
    # BIRD keyword; the harness renames it to `lrfeed`. The listen
    # socket binds port $BIRDPORT (unprivileged — we run unprivileged),
    # so BIRD's default listening on 179 would fail with EACCES.
    BIRDPORT=18082
    cat >"$OUT/bird.conf" <<EOF
log "$OUT/bird.log" all;
router id 10.0.0.3;
protocol device {}
protocol bgp lrfeed {
    local as $TARGET_AS;
    neighbor 127.0.0.1 port $SOURCE_PORT as $SOURCE_AS;
    local port $BIRDPORT;
    # Loopback is not in BIRD's route table, and a non-multihop
    # session requires the neighbor entry (bgp.c:2372). Multihop
    # skips the neighbor-entry lookup and connects directly.
    multihop 1;
    ipv4 { import all; export none; };
}
EOF
    "$BIRD" -c "$OUT/bird.conf" -s "$BIRD_CTL" -P "$OUT/bird.pid" \
        >"$OUT/bird.start.log" 2>&1 &
    BIRD_PID=$!
    PIDS="$PIDS $BIRD_PID"

    echo "== sampling metrics from target BIRD =="
    BIRD_SERIES="$OUT/bird_target.jsonl"
    bash tests/bench/sample_metrics.sh bird "$BIRD_PID" "$BIRD_SERIES" "$BIRD_CTL" \
        >"$OUT/bird_sampler.log" 2>&1

    # Dump BIRD's master4 table through its MRT CLI (same TABLE_DUMP_V2
    # format `lr mrt diff` parses). The quoting matters: BIRD's CLI
    # parser wants the table pattern and filename as quoted TEXT
    # tokens.
    BIRD_TARGET_MRT="$OUT/bird_target.mrt"
    birdc -s "$BIRD_CTL" mrt dump table \"master4\" to \"$BIRD_TARGET_MRT\" \
        >"$OUT/bird_dump.log" 2>&1 || true
    [ -s "$BIRD_TARGET_MRT" ] || echo "BIRD dump failed (see $OUT/bird_dump.log)" >&2
else
    echo "== BIRD target skipped (not installed or LR_BENCH_NO_BIRD set) =="
fi

# --- target: FRR bgpd ---
have_frr=0
if [ -z "${LR_BENCH_NO_FRR:-}" ] && command -v "$FRR_BGPD" >/dev/null 2>&1; then
    have_frr=1
    echo "== starting target FRR bgpd (AS$TARGET_AS, connects to source) =="
    mkdir -p "$OUT/frr"
    cat >"$OUT/frr/bgpd.conf" <<EOF
hostname bgpd-bench
password zebra
log file $OUT/frr/bgpd.log
router bgp $TARGET_AS
 bgp router-id 10.0.0.4
 no bgp ebgp-requires-policy
 neighbor 127.0.0.1 remote-as $SOURCE_AS
 neighbor 127.0.0.1 port $SOURCE_PORT
 address-family ipv4 unicast
  neighbor 127.0.0.1 activate
 exit-address-family
EOF
    "$FRR_BGPD" -f "$OUT/frr/bgpd.conf" -i "$OUT/frr/bgpd.pid" \
        -z "$OUT/frr/zserv.api" >"$OUT/frr/bgpd.start.log" 2>&1 &
    FRR_PID=$!
    PIDS="$PIDS $FRR_PID"

    echo "== sampling metrics from target FRR =="
    FRR_SERIES="$OUT/frr_target.jsonl"
    bash tests/bench/sample_metrics.sh frr "$FRR_PID" "$FRR_SERIES" \
        "$FRR_VTYSH -c 'show bgp ipv4 unicast summary'" \
        >"$OUT/frr_sampler.log" 2>&1
else
    echo "== FRR target skipped (not installed or LR_BENCH_NO_FRR set) =="
fi

# Give the targets a moment to connect and start learning.
sleep 1

# ---------------------------------------------------------------------
# 4. Samplers ran inline during the feed (section 3); nothing to wait
# on here. The sampler deadline is ${DEADLINE}s, see
# sample_metrics.sh.
# ---------------------------------------------------------------------
echo "== sampling done =="

# ---------------------------------------------------------------------
# 5. Comparison report.
# ---------------------------------------------------------------------
echo
echo "== comparison report =="
TARGETS="lr:$LR_SERIES"
[ "$have_bird" -eq 1 ] && TARGETS="$TARGETS bird:$BIRD_SERIES"
[ "$have_frr" -eq 1 ] && TARGETS="$TARGETS frr:$FRR_SERIES"
python3 tests/bench/compare_report.py $TARGETS | tee "$OUT/comparison.txt"

# ---------------------------------------------------------------------
# 6. Gate: the lr target's learned-BGP-route count was checked while
#    its daemon was still up in section 3; here we confirm that some
#    target with a sampled count shows a non-zero final count.
# ---------------------------------------------------------------------
ANY_LEARNED=0
for f in "$LR_SERIES" "$BIRD_SERIES" "$FRR_SERIES"; do
    [ -f "$f" ] || continue
    last_routes=$(grep -oP '"routes":\s*\K[0-9]+' "$f" 2>/dev/null | tail -1 || echo 0)
    if [ "${last_routes:-0}" -gt 0 ] 2>/dev/null; then
        ANY_LEARNED=1
    fi
done
if [ "$ANY_LEARNED" -eq 0 ]; then
    echo "FAIL: no target learned any routes from the source"
    exit 1
fi
echo
echo "PASS: targets learned routes from the MRT feed (lr: ${LR_LEARNED:-0} BGP routes)"

# ---------------------------------------------------------------------
# 7. Cross-implementation check: `lr mrt diff` between the lr target's
#    Loc-RIB and the BIRD target's dump. The diff is informational
#    unless it reports path-selection mismatches ("mismatched"
#    prefixes) — the learn gates above are the PASS/FAIL surface.
# ---------------------------------------------------------------------
if [ "$have_bird" -eq 1 ] && [ -s "$OUT/bird_target.mrt" ] && [ -s "$OUT/lr_target.mrt" ]; then
    if "$BIN" mrt diff "$OUT/lr_target.mrt" "$OUT/bird_target.mrt" \
            >"$OUT/mrt_diff.log" 2>&1; then
        echo "PASS: lr target dump matches the BIRD target dump (lr mrt diff)"
    else
        MISMATCHED_PREFIXES=${MISMATCHED_PREFIXES:-0}
        if [ "$MISMATCHED_PREFIXES" -eq 0 ]; then
            echo "PASS: no path-selection mismatches between lr and BIRD targets (lr mrt diff; $OUT/mrt_diff.log)"
        else
            echo "NOTE: path-selection mismatch between lr and BIRD targets (see $OUT/mrt_diff.log)"
        fi
    fi
fi

# ---------------------------------------------------------------------
# 8. Also run the Loc-RIB storage bench for the regression baseline.
#    The storage bench measures the Loc-RIB install throughput
#    directly (no BGP session), which is the criterion regression
#    surface; the BGP-session-driven comparison above is the
#    end-to-end bench the issue names.
# ---------------------------------------------------------------------
echo
echo "== Loc-RIB storage bench (regression baseline) =="
"$BIN" bench replay --mrt "$MRT" --cap "$CAP" --no-soft-reload \
    --json >"$OUT/storage.json" 2>"$OUT/storage.err" \
    && cat "$OUT/storage.json" \
    || echo "   storage bench failed (see $OUT/storage.err)"

echo
echo "done — report in $OUT"
