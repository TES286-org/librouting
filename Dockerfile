# librouting container image (ROADMAP-v3 D12.3).
#
# Multi-stage build:
#   1. Builder stage — `rust:1.88-slim-bookworm` (matches the
#      workspace MSRV in Cargo.toml). Installs only the C toolchain
#      `lr-ffi`'s cbindgen build script needs (cbindgen itself is
#      vendored as a Cargo build-dependency, so no system cbindgen).
#      Builds the whole workspace in release mode with all features.
#      BuildKit mount caches keep the cargo registry + target dir
#      across builds (so a no-op rebuild is seconds, not minutes).
#   2. Runtime stage — `debian:bookworm-slim`. The runtime glibc
#      matches the builder's (both bookworm), so the dynamically
#      linked `liblr_ffi.so` and the CLI binaries load without a
#      compatibility shim. Copies the three CLI binaries (`lr`,
#      `lr-daemon`, `lrctl`), the shared library, the C / C++
#      headers, and a non-root `lr` user. The entrypoint is
#      `lr-daemon`; `--api-socket` and `--metrics-addr` are the
#      operator's responsibility (pass them as CMD args or a
#      Kubernetes command/args override).
#
# Quick start:
#   docker build -t librouting:rc.3 .
#   docker run --rm --network host \
#       librouting:rc.3 \
#       --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
#       --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
#       --api-socket /run/lr-daemon/api.sock \
#       --metrics-addr 127.0.0.1:9119
#
# The image does NOT ship a default config — operators are expected
# to mount one at `/etc/lr-daemon/daemon.toml` or pass CLI flags.
# See `docs/RUNBOOK.md` for the lifecycle and `templates/daemon.toml`
# for the full config reference.
#
# Helm chart: out of scope for this image. A Helm chart lives in a
# separate repository per Kubernetes packaging convention; the
# Dockerfile here is the foundation the chart would reference.

# ---------------------------------------------------------------------------
# Stage 1 — builder.
# ---------------------------------------------------------------------------

# The workspace `rust-version` is 1.88; `rust:1.88-slim-bookworm`
# pins both the toolchain and the glibc baseline. Bookworm ships
# glibc 2.36, which is new enough for every desktop platform we
# target in release.yml except Windows (which uses its own MSVC
# runtime, not glibc).
FROM rust:1.88-slim-bookworm AS builder

# The build needs a C compiler for the `cc` crate (lr-ffi's build
# script compiles a tiny C shim) and for any C deps the workspace
# pulls in transitively. `g++` is included because some C deps
# (e.g. via `bindgen`) expect a C++ compiler to be present even
# when the final link is C-only; it is cheap to install and saves
# a confusing build failure on a future dep add.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libc6-dev \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the manifest first so the cargo dependency fetch is cached
# across source-only changes. `Cargo.lock` is committed (the
# workspace is a binary crate, not a library published to crates.io)
# so the versions are pinned.
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY crates/ crates/
COPY include/ include/
COPY templates/ templates/
COPY tests/ tests/
COPY fuzz/ fuzz/
COPY yang/ yang/
COPY docs/ docs/
COPY bindings/ bindings/

# Build the whole workspace in release mode with all features. The
# `--all-features` flag matches what release.yml builds and what CI
# tests; omitting it here would produce a different binary (e.g.
# without the exchange-plane prototype) and surprise an operator.
#
# BuildKit mount caches: the cargo registry + git checkouts and the
# target dir are cached across builds so a no-op rebuild (only
# source files changed) is fast. The `--mount=type=cache` syntax
# requires `DOCKER_BUILDKIT=1` (default on Docker 23.0+ and on every
# GitHub Actions runner).
#
# IMPORTANT: the cache mount targets `/usr/local/cargo/registry` and
# `/usr/local/cargo/git` — NOT `/usr/local/cargo` itself. The rust
# image installs `cargo` at `/usr/local/cargo/bin/cargo`; a cache
# mount on the parent dir would shadow the toolchain binaries and
# `cargo` would vanish (`/bin/sh: 1: cargo: not found`).
#
# After the build, copy the artifacts to `/out` (a stable location
# outside the cache mount) so the runtime stage can `COPY --from`
# them. The cache mount itself is not visible to the next stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --all-features --workspace \
    && mkdir -p /out/include \
    && cp /build/target/release/lr /build/target/release/lr-daemon /build/target/release/lrctl /out/ \
    && cp /build/target/release/liblr_ffi.so /out/ \
    && cp include/lr_ffi.h include/librouting.hpp /out/include/

# ---------------------------------------------------------------------------
# Stage 2 — runtime.
# ---------------------------------------------------------------------------

# `debian:bookworm-slim` matches the builder's glibc baseline. A
# smaller base (e.g. `alpine`) would require a musl build, which the
# workspace does not currently target — release.yml only ships glibc
# Linux binaries, so the container matches that surface.
FROM debian:bookworm-slim AS runtime

# `ca-certificates` is needed for the RPKI-RTR client (RFC 8210) to
# verify a TLS connection to a cache server; the daemon does not
# make outbound TLS today, but the dep is cheap and the moment a
# future feature does (e.g. an HTTPS RPKI cache), the cert bundle
# is already present. `libgcc-s1` is the runtime lib the cdylib
# links against (Debian ships it separately from the dev package).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. The daemon's `--user` / `--group` flags handle
# privilege drop when the operator wants to run on a privileged
# port (179/tcp); in a container the operator typically publishes
# to a high port and the in-container bind is unprivileged.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin lr

# Copy the binaries, the shared library, and the headers. The
# library goes to `/usr/lib/` so `ldconfig` picks it up; the
# `lr-ffi` cdylib is loaded by the Go / Python bindings when an
# embedder runs the bindings inside the container.
COPY --from=builder /out/lr /out/lr-daemon /out/lrctl /usr/local/bin/
COPY --from=builder /out/liblr_ffi.so /usr/lib/
COPY --from=builder /out/include/ /usr/include/librouting/

# Refresh the linker cache so `liblr_ffi.so` is discoverable by name
# (not just by full path). Embedders running Python cffi / Go cgo
# inside the container expect `dlopen("liblr_ffi.so")` to work.
RUN ldconfig

# API socket directory. The daemon's `--api-socket` path is
# operator-configurable; `/run/lr-daemon/api.sock` is the
# conventional location matching `templates/daemon.toml`'s
# commented default. The directory is owned by the non-root user
# so the socket file can be created without elevation.
RUN mkdir -p /run/lr-daemon /etc/lr-daemon \
    && chown -R lr:lr /run/lr-daemon /etc/lr-daemon

# BGP (179/tcp) and the metrics endpoint (9119/tcp — the example
# address in docs/RUNBOOK.md and templates/daemon.toml). BGP is
# only exposed when the operator publishes it; the metrics port
# is exposed by default so a sidecar Prometheus can scrape without
# host networking.
EXPOSE 179/tcp
EXPOSE 9119/tcp

# Config + API socket volumes. The config volume lets an operator
# mount a `daemon.toml`; the API socket volume lets `lrctl` (in a
# sidecar container) talk to the daemon without sharing the network
# namespace.
VOLUME ["/etc/lr-daemon", "/run/lr-daemon"]

USER lr

# The entrypoint is `lr-daemon` with no default args — operators
# pass CLI flags via `docker run ... librouting:rc.3 --local-as
# ... --peer-as ...` or a Kubernetes `args:` override. The
# `--config /etc/lr-daemon/daemon.toml` form is the recommended
# production deployment (mount the config as a ConfigMap).
ENTRYPOINT ["lr-daemon"]
CMD ["--help"]
