# Dockerfile for the BIRD interop test.
# Builds a BIRD image, copies bird.conf, and starts BIRD with the config.
# A small helper script then drives the librouting side (Rust integration test).

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bird2 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY bird.conf /etc/bird/bird.conf

EXPOSE 179

CMD ["bird", "-f", "-c", "/etc/bird/bird.conf"]
