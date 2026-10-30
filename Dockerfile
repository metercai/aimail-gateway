# ── Build stage ─────────────────────────────────────────────────────────
# GIT_COMMIT drives the version string embedded by build.rs (there is no .git in
# the build context, so it must be passed explicitly).
ARG GIT_COMMIT=unknown
# Restricted build environments: point APT_MIRROR at a reachable Debian mirror,
# e.g. --build-arg APT_MIRROR=mirrors.aliyun.com (default = the image's own sources).
ARG APT_MIRROR=
FROM rust:slim-bookworm AS builder

# The Rust image ships cc/gcc and only perl-base (no FindBin); the vendored
# OpenSSL build needs the full `perl` package plus make. pkg-config keeps
# openssl-sys happy on hosts that provide a system OpenSSL.
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|$APT_MIRROR|g; s|security.debian.org|$APT_MIRROR|g" \
            /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i "s|deb.debian.org|$APT_MIRROR|g; s|security.debian.org|$APT_MIRROR|g" \
            /etc/apt/sources.list 2>/dev/null || true; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends make pkg-config perl \
    && rm -rf /var/lib/apt/lists/*

# build.rs reads GIT_VERSION (no .git in the context) — without this the version
# string would fall back to "unknown". ARG must be re-declared inside the stage:
# a global ARG is not visible to ENV after FROM.
ARG GIT_COMMIT
ENV GIT_VERSION=$GIT_COMMIT

WORKDIR /build

# Dependency layer first: source edits below do not invalidate it. `vendor/` must
# come along — `mailin` is a path dependency and cargo fails to resolve the
# workspace without it even for the warm-up build.
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
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
