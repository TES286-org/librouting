# Real-data benchmark

Import a public MRT RIB dump into multiple BGP speakers via real BGP
sessions, measure each speaker's route count and RSS during the feed,
and compare the results. This is the issue #101 "Benchmark Based on
Real Data" bench: a system that feeds the same routes to lr-daemon,
BIRD and FRR over BGP, not just a self-test of lr.

Read this page if you are running the bench locally, wiring it into a
continuous-benchmark pipeline, or triaging a regression the criterion
harness flagged.

## Architecture

```
                ┌─────────────────┐
                │  Source speaker │
                │  (lr-daemon     │
                │   --mrt-feed)   │
                │   (listener)    │
                └──────┬──────────┘
                       │ BGP sessions (targets connect)
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    ┌─────────┐  ┌─────────┐  ┌─────────┐
    │ lr-     │  │  BIRD   │  │  FRR    │
    │ daemon  │  │         │  │ bgpd    │
    │ (target)│  │ (target)│  │ (target)│
    └─────────┘  └─────────┘  └─────────┘
          │            │            │
          ▼            ▼            ▼
    [sampled     [sampled     [sampled
     every 1s]   every 1s]   every 1s]
          │            │            │
          └────────────┼────────────┘
                       ▼
                ┌─────────────────┐
                │  Comparison     │
                │  report         │
                └─────────────────┘
```

The source lr-daemon loads the MRT dump into its Loc-RIB through the
`--mrt-feed` flag; the daemon's BGP export path advertises the
routes to every connected peer over a real BGP session. Each target
connects to the source and learns the routes via the normal BGP
UPDATE path — the same path a production deployment uses.

Because the source drops a second inbound session for a peer that
still has an active one, the targets run sequentially: the lr
target connects first and converges, then the BIRD and FRR targets
take the peer slot. The harness gates on the lr target holding at
least one learned BGP route.

## Cross-implementation diff

After the comparison table, the harness dumps both target Loc-RIBs:
`lrctl --socket <lr-target> routes dump <lr_target.mrt>` and, when
BIRD is present, `birdc -s <bird.ctl> mrt dump table "master4" to
"<bird_target.mrt>"`. `lr mrt diff` between the two dumps compares
per-prefix path sets (AS_PATH, next hop, MED, communities); a
non-zero exit surfaces every prefix that diverged. Differences in
prefixes the lr target holds only because the source daemon also
installs its connected routes are expected and informational.

## What the bench measures

Each target is sampled every second during the feed. The comparison
report computes, per target:

- **routes_final** — the last non-null route count.
- **convergence_s** — time from the first sample to the last sample
  whose route count changed.
- **routes_per_sec** — `routes_final / convergence_s`.
- **rss_peak_kb** — the maximum RSS across the series.
- **rss_final_kb** — the last RSS sample.

The comparison table prints one row per target and a summary with
the fastest convergence and the highest throughput.

## Running the bench

```sh
cargo build --release -p lr-cli --bin lr --bin lr-daemon --bin lrctl
bash tests/bench/real_data.sh
```

Env overrides:

- `LR_BENCH_MRT` — path to a local `.mrt` file. When set, the
  harness skips the download.
- `LR_BENCH_MRT_URL` — the dump URL (default: RIPE RIS RRC26
  `latest-bview.gz`).
- `LR_BENCH_NO_BIRD` — when non-empty, skip the BIRD target.
- `LR_BENCH_NO_FRR` — when non-empty, skip the FRR target.
- `LR_BENCH_CAP` — cap on *prefixes read* from the dump by the
  source feed and the storage bench (default 1000). A full public
  RIB (~1M routes) takes hours to replay over a BGP session; the
  cap keeps each target within a CI budget.
- `LR_BENCH_OUT` — working directory (default `/tmp/lr_bench`).
- `LR_BENCH_DEADLINE` — per-target convergence deadline in seconds
  (default 120).

The harness SKIPs cleanly (exit 0) when the network egress is
unavailable, when no local MRT is provided, or when BIRD and FRR are
not installed (only the lr-vs-lr leg runs).

## The source speaker

`lr-daemon --mrt-feed <file> [--mrt-feed-cap N]` loads the MRT dump
into the daemon's Loc-RIB at startup. The loader streams the dump
through `MrtReader`, groups entries by prefix, ranks each prefix
with the BGP decision process (`BestPath::rank`) and installs the
ranked set via `LocRib::install_set`. Route semantics mirror a
real speaker: entries are external BGP paths (`origin.proto = 0`),
and `--mrt-feed-cap N` caps the prefixes read, not entries. The
daemon's existing BGP export path advertises the best path to
peers.

```sh
target/release/lr-daemon \
    --local-as 64520 --peer-as 64512 --router-id 10.0.0.1 \
    --ebgp-policy accept-all --listen 127.0.0.1:18080 \
    --local-address 192.0.2.1 \
    --mrt-feed /tmp/bview.mrt --mrt-feed-cap 1000
```

`--mrt-feed-cap N` caps the number of prefixes read from the dump —
the harness uses a non-zero cap to keep the BGP session within a CI
budget.

## The Loc-RIB storage bench

`lr bench replay --mrt <file> [--cap N]` measures the Loc-RIB install
throughput directly (no BGP session). It is the criterion regression
surface — the storage layer the BGP-session-driven bench builds on.
The harness runs it at the end as a baseline (with the same `--cap`
as the feed).

```sh
target/release/lr bench replay --mrt /tmp/bview.mrt --cap 1000
```

The replay parses through the streaming reader and ranks each prefix
with the BGP decision process. `correctness.matched` counts prefixes
whose stored ranked set equals the expected set; `mismatched` /
`missing` / `extra` count the rest — the storage-side
path-selection check (the cross-implementation check is the
`lr mrt diff` step in the harness).

The criterion bench `cargo bench -p lr-mrt --bench mrt_replay`
tracks the install throughput against either a real dump
(`LR_BENCH_MRT` env) or a synthetic 1000-prefix fallback.

## Reference data sources

The default dump URL points at RIPE RIS RRC26's `latest-bview.gz`.
RouteViews collectors (<https://archive.routeviews.org/>) and other
Mirror sites carry the same TABLE_DUMP_V2 format; point
`LR_BENCH_MRT_URL` at any of them.

A full IPv4 RIB dump is ~300 MB compressed, ~1.5 GB uncompressed,
and carries ~1M routes with many candidates per prefix. The replay
bench defaults to a `--cap` (no cap on `lr bench replay` itself) to
stay within CI budgets; for a full dump the metrics worth tracking
are parse_ms, install_ms and memory.
