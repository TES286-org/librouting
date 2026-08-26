# BIRD Interop Test Harness

This directory contains a Docker-based BIRD interop test harness. It is
**not** run during local development (requires Docker); it runs in CI on
`ubuntu-22.04` runners that have Docker available.

## Running locally

```
docker build -t librouting-bird-interop tests/interop/bird
docker run --rm --network=host librouting-bird-interop
```

## What it tests

1. **BGP OPEN exchange**: BIRD listens on `127.0.0.1:1179`; librouting
   connects and sends an OPEN with capabilities. BIRD accepts and replies
   with its own OPEN. Both sides should reach `Established`.

2. **KEEPALIVE exchange**: Both sides emit keepalives; hold timers do not
   fire.

3. **Route advertisement**: BIRD advertises `10.0.0.0/8` via UPDATE.
   librouting parses the UPDATE and installs the route.

## Why not in this repo's CI?

The CI pipeline in `.github/workflows/ci.yml` runs the same assertions via
the Rust integration tests in `crates/lr-tests/tests/tcp_smoke.rs`. The
BIRD test is reserved for verification against a reference implementation
and runs on PRs that touch codec or FSM code (label: `interop`).

## Bird configuration reference

The `bird.conf` file in this directory is what BIRD launches with. It
peers with `127.0.0.1` (librouting's TCP listener) and advertises one
static route (`10.0.0.0/8`).
