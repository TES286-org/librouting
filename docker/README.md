# librouting container image

A multi-stage Dockerfile that builds the librouting daemon (`lr-daemon`),
the inspection CLI (`lr`), the operational CLI (`lrctl`), and the C ABI
shared library (`liblr_ffi.so`) into a single container image. The
image is the foundation for Kubernetes deployment (a Helm chart would
live in a separate repository per packaging convention).

## Build

```sh
docker build -t librouting:rc.3 .
```

The build uses BuildKit mount caches for the cargo registry and the
target directory, so a no-op rebuild (only source files changed) takes
seconds, not minutes. Docker 23.0+ enables BuildKit by default; on
older Docker set `DOCKER_BUILDKIT=1`.

The builder stage pins `rust:1.88-slim-bookworm` (the workspace MSRV
in `Cargo.toml`), and the runtime stage is `debian:bookworm-slim`
(matching the builder's glibc baseline so the dynamically linked
`liblr_ffi.so` loads without a compatibility shim).

## Run

The entrypoint is `lr-daemon`; pass CLI flags via `docker run` args or
a Kubernetes `args:` override. The default `CMD` is `--help` so a
bare `docker run librouting:rc.3` prints the usage banner instead of
crashing.

### Quick start — single-peer BGP on loopback

```sh
docker run --rm --network host \
    librouting:rc.3 \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --api-socket /run/lr-daemon/api.sock \
    --metrics-addr 127.0.0.1:9119
```

`--network host` is the simplest way to get BGP on port 179 without a
port-forwarding dance; on a production host you would instead publish
the port explicitly (`-p 179:179`) and run the container without host
networking. The `--api-socket` and `--metrics-addr` flags are
operator-configurable — the image does not force them.

### Production — config file mount

```sh
docker run --rm -d \
    --name lr-daemon \
    -p 179:179 \
    -p 9119:9119 \
    -v /etc/lr-daemon/daemon.toml:/etc/lr-daemon/daemon.toml:ro \
    -v lr-daemon-run:/run/lr-daemon \
    librouting:rc.3 \
    --config /etc/lr-daemon/daemon.toml
```

The config file lives on the host (or as a Kubernetes ConfigMap); the
API socket lives in a named volume so a sidecar `lrctl` container can
mount it and talk to the daemon without sharing the network namespace.

### Sidecar `lrctl`

```sh
docker run --rm \
    --volumes-from lr-daemon \
    librouting:rc.3 \
    lrctl --socket /run/lr-daemon/api.sock status
```

The `lrctl` binary is in the same image (`/usr/local/bin/lrctl`), so
the sidecar pattern reuses the image without a separate build. Override
the entrypoint with `lrctl` (or `lr`) and pass the same `--socket` flag.

## Image layout

| Path                              | Contents                                       |
| --------------------------------- | ---------------------------------------------- |
| `/usr/local/bin/lr`               | The inspection CLI (decode, mrt, parity-replay) |
| `/usr/local/bin/lr-daemon`        | The reference daemon (entrypoint)              |
| `/usr/local/bin/lrctl`            | The operational CLI                            |
| `/usr/lib/liblr_ffi.so`           | The C ABI shared library                       |
| `/usr/include/librouting/lr_ffi.h`      | The C header                              |
| `/usr/include/librouting/librouting.hpp` | The C++ RAII wrapper header              |
| `/etc/lr-daemon/`                 | Config volume mount point (empty by default)   |
| `/run/lr-daemon/`                 | API socket volume mount point (empty by default) |

The non-root `lr` user owns `/etc/lr-daemon/` and `/run/lr-daemon/` so
the daemon can create the API socket file without elevation.

## Exposed ports

| Port  | Protocol | Purpose                                   |
| ----- | -------- | ----------------------------------------- |
| 179   | TCP      | BGP listener (RFC 4271). Publish when the daemon should accept inbound peers. |
| 9119  | TCP      | Prometheus `/metrics` endpoint (ROADMAP-v3 D12.2). Matches the example address in `docs/RUNBOOK.md` and `templates/daemon.toml`. |

The metrics port is exposed by default so a sidecar Prometheus can
scrape without host networking. The BGP port is only useful when the
operator publishes it (`-p 179:179` or a Kubernetes `Service`).

## Volumes

| Volume             | Purpose                                                          |
| ------------------ | ---------------------------------------------------------------- |
| `/etc/lr-daemon`   | Config file mount point. Mount a `daemon.toml` here and start with `--config /etc/lr-daemon/daemon.toml`. |
| `/run/lr-daemon`   | API socket volume. Shared with the `lrctl` sidecar so it can reach the daemon's management plane. |

## Image size

The runtime image is approximately 100 MB:
- `debian:bookworm-slim` base: ~80 MB
- `lr`, `lr-daemon`, `lrctl` binaries: ~15 MB (release LTO build)
- `liblr_ffi.so` + headers: ~3 MB
- `ca-certificates` + `libgcc-s1`: ~2 MB

A smaller base (e.g. `alpine` + a musl build) would shrink the image
to ~30 MB but the workspace does not currently target musl —
`release.yml` only ships glibc Linux binaries, so the container matches
that surface. A future `lr-osroute` musl port would unlock the smaller
base.

## What the image does NOT include

- **A default config.** The image ships no `daemon.toml`; operators
  must mount one or pass CLI flags. This matches the daemon's
  fail-closed stance (a bare `lr-daemon` with no config prints the
  usage banner and exits).
- **A Helm chart.** A Helm chart is a separate packaging concern and
  conventionally lives in its own repository (so it can version
  independently of the image). The Dockerfile here is the foundation
  a chart would reference via `image: librouting:rc.3`.
- **BIRD / FRR.** The image is librouting only; interop tests against
  BIRD / FRR run in CI (`.github/workflows/ci.yml`'s interop job) and
  are not part of the production image.
- **A process supervisor.** The entrypoint is `lr-daemon` directly, not
  `tini` or `s6-overlay`. The daemon handles SIGTERM/SIGINT cleanly
  (sessions are closed with a NOTIFICATION before the FIN — see
  `docs/RUNBOOK.md`); a supervisor is unnecessary for the common
  case. Operators who want one can override the entrypoint.

## CI verification

The `.github/workflows/docker.yml` workflow builds the image on every
push and pull request to `main` (and nightly on `schedule`). The job
does not push to a registry — that is a release-event concern (the
`release.yml` workflow handles `v*` tag pushes). The CI job catches
Dockerfile drift early: a source change that breaks the build, a
dependency add that needs a new system package, or a `COPY` line that
references a path that no longer exists.
