#!/usr/bin/env bash
# Metric sampler for the real-data benchmark (issue #101).
#
# Samples one BGP speaker's route count and RSS every $INTERVAL seconds
# (default 1) until the convergence deadline ($DEADLINE seconds) or
# the route count stops moving for $SETTLED seconds (default 5).
#
# Writes one JSON line per sample to $OUT:
#
#   {"t": <seconds_since_start>, "routes": <n>, "rss_kb": <n>}
#
# Usage:
#   sample_metrics.sh <kind> <pid> <out-file> [lr-ctl-path|bird-ctl-path|vtysh-cmd]
#
# <kind> is one of:
#   lr    — lr-daemon; the 4th arg is the path to its API socket.
#           `lrctl --socket <path> show routes count` returns
#           `total N` lines; the sampler parses N.
#   bird  — BIRD; the 4th arg is the path to its control socket.
#           `birdc -s <path> show route count` returns a line with
#           `N routes` somewhere in the output.
#   frr   — FRR bgpd; the 4th arg is the vtysh command prefix (e.g.
#           `vtysh -c 'show bgp ipv4 unicast summary'`). The sampler
#           parses the route count from the summary's prefix count.
#
# The sampler exits 0 when convergence is detected or the deadline
# passes. It never fails the harness — a sampler that cannot read a
# metric writes `null` and keeps going so the comparison report has
# a complete time-series for every target.
set -euo pipefail

kind=${1:?kind: lr | bird | frr}
pid=${2:?pid: the target process id}
out=${3:?out: the output file path}
ctl=${4:-}

interval=${INTERVAL:-1}
deadline=${DEADLINE:-120}
settled=${SETTLED:-5}

# The source's feed start time is shared across samplers through the
# environment so every target's time-series starts at the same t=0.
# When FEED_START_EPOCH is unset (a solo sampler run), the sampler
# itself is the anchor.
start=${FEED_START_EPOCH:-$(date +%s)}

# ---- per-kind route-count extractor ----
extract_routes() {
    case "$kind" in
        lr)
            if [ -z "$ctl" ] || [ ! -S "$ctl" ]; then
                echo null; return
            fi
            # `lrctl --socket <path> routes count` /
            # `show routes count` print `total N` on the first line
            # of the reply. Parse N.
            lrctl --socket "$ctl" show routes count 2>/dev/null \
                | grep -oP '^total\s+\K[0-9]+' \
                | head -1 || echo null
            ;;
        bird)
            if [ -z "$ctl" ]; then
                echo null; return
            fi
            birdc -s "$ctl" show route count 2>/dev/null \
                | grep -oP '[0-9]+(?=\s+routes)' \
                | head -1 || echo null
            ;;
        frr)
            if [ -z "$ctl" ]; then
                echo null; return
            fi
            # FRR's `show bgp ipv4 unicast summary` lists each neighbor
            # with a `State/PfxRcd` column. Sum the received prefix
            # counts across all neighbors.
            sh -c "$ctl" 2>/dev/null \
                | grep -oP '\d+(?=\s*$)' \
                | awk '{s+=$1} END{print s+0}' || echo null
            ;;
        *)
            echo null
            ;;
    esac
}

# ---- RSS extractor (Linux /proc) ----
extract_rss() {
    if [ -r "/proc/$pid/status" ]; then
        grep '^VmRSS:' "/proc/$pid/status" 2>/dev/null \
            | awk '{print $2}' || echo null
    else
        # macOS / BSD fallback: ps -o rss.
        ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo null
    fi
}

# ---- main loop ----
last_routes=0
settled_for=0
elapsed=0
: >"$out"
while [ "$elapsed" -lt "$deadline" ]; do
    now=$(date +%s)
    t=$((now - start))
    routes=$(extract_routes)
    rss=$(extract_rss)
    printf '{"t":%s,"routes":%s,"rss_kb":%s}\n' "$t" "${routes:-null}" "${rss:-null}" >>"$out"
    # Convergence detection: the route count has not moved for
    # $settled consecutive samples AND the target has learned at
    # least one route. A target that never learns anything runs to
    # the deadline.
    if [ "$routes" != "null" ] && [ "$routes" -gt 0 ] 2>/dev/null; then
        if [ "$routes" -eq "$last_routes" ]; then
            settled_for=$((settled_for + interval))
            if [ "$settled_for" -ge "$settled" ]; then
                exit 0
            fi
        else
            settled_for=0
        fi
        last_routes=$routes
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
done
exit 0
