# ── Build stage ─────────────────────────────────────────────────────────
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build the binary
COPY . .
RUN cargo build --release

# ── Runtime stage (Chainguard — minimal glibc, no shell, CVE-scanned) ──
FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /build/target/release/amail-gateway /usr/local/bin/amail-gateway

VOLUME ["/data"]
EXPOSE 8080 25

ENTRYPOINT ["amail-gateway"]
