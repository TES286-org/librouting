# librouting container image

The repository-root [`Dockerfile`](../Dockerfile) builds a multi-stage image
carrying the daemon (`lr-daemon`), the inspection CLI (`lr`), the operational
CLI (`lrctl`) and the C ABI library (`liblr_ffi.so`). Read this page to build
and run it.

## Build

```sh
docker build -t librouting:latest .
```

Both stages are pinned in the `Dockerfile`; the MSRV lives in `Cargo.toml`.

## Run

The entrypoint is `lr-daemon` and the default command is `--help`, so
`docker run librouting:latest` prints the daemon usage. The example listens
on an unprivileged port; a real peer needs `-p 179:179` or host networking.

```sh
docker run --rm --network host \
    librouting:latest \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --metrics-addr 127.0.0.1:9119
```

### Mount a configuration

[`templates/daemon.lr`](../templates/daemon.lr) is the configuration to start
from; the TOML dialect (`daemon.toml`) is deprecated and
`lr-daemon config to-dsl` converts it.

```sh
docker run --rm -d \
    --name lr-daemon \
    -p 179:179 -p 9119:9119 \
    -v /etc/lr-daemon/daemon.lr:/etc/lr-daemon/daemon.lr:ro \
    -v lr-daemon-run:/run/lr-daemon \
    librouting:latest \
    --config /etc/lr-daemon/daemon.lr \
    --api-socket /run/lr-daemon/api.sock
```

### Sidecar `lrctl`

The API socket lives in the named volume. The entrypoint is `lr-daemon`, so
override it:

```sh
docker run --rm \
    --volumes-from lr-daemon \
    --entrypoint lrctl \
    librouting:latest \
    --socket /run/lr-daemon/api.sock status
```

## Layout

| Path or port | Contents |
| --- | --- |
| `/usr/local/bin/` | `lr`, `lr-daemon` (entrypoint), `lrctl` |
| `/usr/lib/liblr_ffi.so` | C ABI shared library |
| `/usr/include/librouting/` | `lr_ffi.h`, `librouting.hpp` |
| `/etc/lr-daemon/` | Configuration mount point, owned by `lr` |
| `/run/lr-daemon/` | API socket mount point, owned by `lr` |
| 179/tcp | BGP listener (RFC 4271), `EXPOSE`d |
| 9119/tcp | Prometheus `/metrics`, `EXPOSE`d |

The image ships no configuration file, no Helm chart and no BIRD or FRR; the
entrypoint is `lr-daemon` directly and it handles SIGTERM/SIGINT itself.

## Verification

`.github/workflows/docker.yml` builds the image on every push and pull
request, and nightly on a schedule; it checks that the CLI binaries and
`liblr_ffi.so` are present, and reports the image size. It never pushes to a
registry — `release.yml` handles release tags.
