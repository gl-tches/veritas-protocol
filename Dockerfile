# =============================================================================
# VERITAS Protocol - Multi-stage Docker Build
# =============================================================================
# Build: docker build -t veritas-node .
# Run:   docker run -d -p 9000:9000 -p 8080:8080 veritas-node
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Environment
# -----------------------------------------------------------------------------
FROM rust:1.85-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Create a new user for building (security best practice)
RUN useradd --create-home --uid 1000 builder
USER builder
WORKDIR /home/builder

# =============================================================================
# OOM Prevention Settings for CI environments (GitHub Actions has ~7GB RAM)
# =============================================================================
# Limit parallel codegen units to reduce peak memory
ENV CARGO_BUILD_JOBS=2
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
# Use less memory-intensive linker settings
ENV RUSTFLAGS="-C link-arg=-Wl,--no-keep-memory"

# Copy manifests first for better layer caching
COPY --chown=builder:builder Cargo.toml Cargo.lock ./

# Copy all crate manifests
COPY --chown=builder:builder crates/veritas-crypto/Cargo.toml crates/veritas-crypto/
COPY --chown=builder:builder crates/veritas-identity/Cargo.toml crates/veritas-identity/
COPY --chown=builder:builder crates/veritas-protocol/Cargo.toml crates/veritas-protocol/
COPY --chown=builder:builder crates/veritas-chain/Cargo.toml crates/veritas-chain/
COPY --chown=builder:builder crates/veritas-net/Cargo.toml crates/veritas-net/
COPY --chown=builder:builder crates/veritas-store/Cargo.toml crates/veritas-store/
COPY --chown=builder:builder crates/veritas-reputation/Cargo.toml crates/veritas-reputation/
COPY --chown=builder:builder crates/veritas-core/Cargo.toml crates/veritas-core/
COPY --chown=builder:builder crates/veritas-ffi/Cargo.toml crates/veritas-ffi/
COPY --chown=builder:builder crates/veritas-wasm/Cargo.toml crates/veritas-wasm/
COPY --chown=builder:builder crates/veritas-py/Cargo.toml crates/veritas-py/
COPY --chown=builder:builder crates/veritas-node/Cargo.toml crates/veritas-node/

# Create dummy source files for dependency caching
RUN mkdir -p crates/veritas-crypto/src && echo "pub fn dummy() {}" > crates/veritas-crypto/src/lib.rs && \
    mkdir -p crates/veritas-identity/src && echo "pub fn dummy() {}" > crates/veritas-identity/src/lib.rs && \
    mkdir -p crates/veritas-protocol/src && echo "pub fn dummy() {}" > crates/veritas-protocol/src/lib.rs && \
    mkdir -p crates/veritas-chain/src && echo "pub fn dummy() {}" > crates/veritas-chain/src/lib.rs && \
    mkdir -p crates/veritas-net/src && echo "pub fn dummy() {}" > crates/veritas-net/src/lib.rs && \
    mkdir -p crates/veritas-store/src && echo "pub fn dummy() {}" > crates/veritas-store/src/lib.rs && \
    mkdir -p crates/veritas-reputation/src && echo "pub fn dummy() {}" > crates/veritas-reputation/src/lib.rs && \
    mkdir -p crates/veritas-core/src && echo "pub fn dummy() {}" > crates/veritas-core/src/lib.rs && \
    mkdir -p crates/veritas-ffi/src && echo "pub fn dummy() {}" > crates/veritas-ffi/src/lib.rs && \
    mkdir -p crates/veritas-wasm/src && echo "pub fn dummy() {}" > crates/veritas-wasm/src/lib.rs && \
    mkdir -p crates/veritas-py/src && echo "pub fn dummy() {}" > crates/veritas-py/src/lib.rs && \
    mkdir -p crates/veritas-node/src && echo "fn main() {}" > crates/veritas-node/src/main.rs

# Build dependencies only (this layer is cached)
RUN cargo build --release --package veritas-node 2>/dev/null || true

# Remove dummy source files
RUN find crates -name "*.rs" -type f -delete

# Copy actual source code
COPY --chown=builder:builder crates/ crates/

# Build the actual binary
RUN cargo build --release --package veritas-node

# Verify the binary exists
RUN ls -la target/release/veritas-node

# -----------------------------------------------------------------------------
# Stage 2: Runtime Environment
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for runtime
RUN groupadd --gid 1000 veritas \
    && useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home veritas

# Create data directory with proper permissions
RUN mkdir -p /var/lib/veritas /var/log/veritas \
    && chown -R veritas:veritas /var/lib/veritas /var/log/veritas

# Copy binary from builder stage
COPY --from=builder --chown=veritas:veritas \
    /home/builder/target/release/veritas-node /usr/local/bin/veritas-node

# Make binary executable
RUN chmod +x /usr/local/bin/veritas-node

# Switch to non-root user
USER veritas
WORKDIR /home/veritas

# Environment variables (can be overridden)
ENV VERITAS_DATA_DIR=/var/lib/veritas \
    VERITAS_LISTEN_ADDR=/ip4/0.0.0.0/tcp/9000 \
    VERITAS_LOG_LEVEL=info \
    VERITAS_LOG_FORMAT=plain \
    VERITAS_HEALTH_PORT=8080 \
    VERITAS_RELAY_MODE=true \
    VERITAS_VALIDATOR_MODE=false \
    VERITAS_MAX_CONNECTIONS=1000 \
    RUST_BACKTRACE=1

# Expose ports
# 9000 - P2P TCP
# 8080 - Health check
# 9090 - Metrics (optional)
EXPOSE 9000 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Volume for persistent data
VOLUME ["/var/lib/veritas"]

# Entrypoint
ENTRYPOINT ["/usr/local/bin/veritas-node"]

# Default command (can be overridden)
CMD []

# -----------------------------------------------------------------------------
# Labels for metadata
# -----------------------------------------------------------------------------
LABEL org.opencontainers.image.title="VERITAS Node" \
      org.opencontainers.image.description="Post-quantum secure decentralized messaging node" \
      org.opencontainers.image.vendor="VERITAS Protocol" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/gl-tches/veritas-protocol" \
      org.opencontainers.image.documentation="https://github.com/gl-tches/veritas-protocol/blob/main/docs/DOCKER.md"