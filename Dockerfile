# ── Build stage ─────────────────────────────────────────────────────────
# GIT_COMMIT drives the version string embedded by build.rs (there is no .git in
# the build context, so it must be passed explicitly).
ARG GIT_COMMIT=unknown
FROM rust:slim-bookworm AS builder

# cc/gcc ship with the Rust image; rusqlite is compiled with bundled SQLCipher,
# whose vendored OpenSSL needs perl + make.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency layer first: source edits below do not invalidate it.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && : > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > src/bin/health.rs \
    && (cargo build --release --locked --bins || true)

COPY . .
RUN cargo build --release --locked --bins

# ── Runtime stage (Chainguard — minimal glibc, no shell, CVE-scanned) ──
FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /build/target/release/aimail-gateway /usr/local/bin/aimail-gateway
# Self-contained probe: the image has no shell/curl, so HEALTHCHECK cannot use them.
COPY --from=builder /build/target/release/aimail-gateway-health /usr/local/bin/aimail-gateway-health

# cwd stays "/" so the default storage path "./data" resolves to /data (the volume).
WORKDIR /
VOLUME ["/data"]

# Defaults only — the real binds come from config.toml or AIMAILGW_{HTTP,SMTP}_ADDR.
EXPOSE 8080 25

# Reads [http].bind (or AIMAILGW_HTTP_ADDR) and GETs /health: 0 healthy, 1 unhealthy,
# 2 configuration error. Mount the config at this path or the probe fails closed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["aimail-gateway-health", "--config", "/etc/aimail/config.toml"]

ENTRYPOINT ["aimail-gateway"]
