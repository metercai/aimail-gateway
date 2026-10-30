# ── Build stage ─────────────────────────────────────────────────────────
# GIT_COMMIT drives the version string embedded by build.rs (there is no .git in
# the build context, so it must be passed explicitly).
ARG GIT_COMMIT=unknown
FROM rust:slim-bookworm AS builder

# build.rs reads GIT_VERSION; a global ARG is not visible after FROM, so the
# ARG has to be re-declared inside the stage before ENV can use it.
ARG GIT_COMMIT=unknown
ENV GIT_VERSION=$GIT_COMMIT

WORKDIR /build

# Dependency layer first: source edits below do not invalidate it. `vendor/` must
# come along — `mailin` is a path dependency and cargo fails to resolve the
# workspace without it, even for the warm-up build.
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
RUN mkdir -p src/bin \
    && : > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > src/bin/health.rs \
    && (cargo build --release --locked --bins || true)

COPY . .
# Default feature set on purpose: bundled SQLite only, no OpenSSL, no extra
# C toolchain packages. `--features sqlcipher` is opt-in for encrypted storage.
RUN cargo build --release --locked --bins

# ── Runtime stage (Chainguard — minimal glibc, no shell, CVE-scanned) ──
FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /build/target/release/aimail-gateway /usr/local/bin/aimail-gateway
COPY --from=builder /build/target/release/aimail-gateway-health /usr/local/bin/aimail-gateway-health

# Relative defaults (`./data`) resolve against the working directory.
WORKDIR /

VOLUME ["/data"]

# Defaults only — the real binds come from config.toml / AIMAILGW_*_ADDR.
EXPOSE 8080 25

# The runtime image has no shell and no curl, hence the dedicated probe binary.
# It reads [http].bind from the mounted config, so a custom port still works.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["aimail-gateway-health", "--config", "/etc/aimail/config.toml"]

ENTRYPOINT ["aimail-gateway"]
