# VERITAS Setup Guide

Installation, configuration, and running guide for the VERITAS Protocol.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building from Source](#building-from-source)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Docker Setup](#docker-setup)
- [Running Tests](#running-tests)
- [Platform-Specific Notes](#platform-specific-notes)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux, macOS, Windows | Linux (Ubuntu 22.04+) |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 1 GB | 10+ GB |
| Network | Optional | Broadband recommended |

### Required Software

#### Rust Toolchain

VERITAS requires Rust 1.85 or later.

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
# rustc 1.85.0 or later

# Update if needed
rustup update stable
```

#### System Dependencies

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake
```

**macOS:**

```bash
# Install Xcode command line tools
xcode-select --install

# Install additional dependencies via Homebrew
brew install openssl cmake
```

**Windows:**

1. Install Visual Studio Build Tools with C++ support
2. Install OpenSSL (via vcpkg or prebuilt binaries)
3. Set `OPENSSL_DIR` environment variable

#### Optional Dependencies

For WASM development:

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Or via cargo
cargo install wasm-pack
```

For Python bindings:

```bash
# Install maturin
pip install maturin
```

---

## Building from Source

### Clone the Repository

```bash
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol
```

### Build All Crates

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

### Build Specific Crates

```bash
# Build only the core library
cargo build -p veritas-core

# Build with specific features
cargo build -p veritas-core --features "full"
```

### Build Bindings

#### C/FFI Bindings

```bash
cd crates/veritas-ffi
cargo build --release

# Header file generated at target/veritas.h
# Library at target/release/libveritas_ffi.so (Linux)
#           target/release/libveritas_ffi.dylib (macOS)
#           target/release/veritas_ffi.dll (Windows)
```

#### WebAssembly

```bash
cd crates/veritas-wasm

# For web browsers
wasm-pack build --target web --release

# For Node.js
wasm-pack build --target nodejs --release

# Output in pkg/ directory
```

#### Python

```bash
cd crates/veritas-py

# Development build (installs in current environment)
maturin develop

# Release wheel
maturin build --release

# Install wheel
pip install target/wheels/veritas_py-*.whl
```

---

## Quick Start

### Minimal Example

Create a new Rust project and add VERITAS:

```bash
cargo new my-veritas-app
cd my-veritas-app
```

Add to `Cargo.toml`:

```toml
[dependencies]
veritas-core = { git = "https://github.com/gl-tches/veritas-protocol" }
tokio = { version = "1", features = ["full"] }
```

Create `src/main.rs`:

```rust
use veritas_core::{VeritasClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with default config
    let client = VeritasClient::new(ClientConfig::default()).await?;

    // Unlock with password
    client.unlock(b"my_secure_password").await?;

    // Create an identity
    let identity = client.create_identity(Some("Primary")).await?;
    println!("Created identity: {}", identity);

    // Get public keys to share
    let public_keys = client.public_keys().await?;
    println!("Public keys available for sharing");

    // Lock when done
    client.lock().await?;

    Ok(())
}
```

Run:

```bash
cargo run
```

### In-Memory Testing

For testing without persistent storage:

```rust
let client = VeritasClient::in_memory().await?;
client.unlock(b"test_password").await?;

// All data is ephemeral - lost when client is dropped
```

---

## Configuration

### Configuration File

VERITAS can be configured via a TOML file:

```toml
# veritas.toml

[storage]
data_dir = "~/.veritas"
in_memory = false
encrypt_database = true

[network]
enable_internet = true
enable_local_discovery = true
enable_bluetooth = true
bootstrap_peers = [
    "/dns4/bootstrap1.veritas.network/tcp/4001",
    "/dns4/bootstrap2.veritas.network/tcp/4001",
]
listen_addresses = [
    "/ip4/0.0.0.0/tcp/4001",
]
connection_timeout_secs = 30

[reputation]
enabled = true
enable_collusion_detection = true
decay_rate_percent = 1.0

[features]
timing_jitter = true
auto_queue_offline = true
max_queued_messages = 1000
delivery_receipts = true
read_receipts = false
```

### Programmatic Configuration

```rust
use veritas_core::config::{ClientConfig, ClientConfigBuilder};
use std::time::Duration;

let config = ClientConfigBuilder::new()
    // Storage
    .with_data_dir("/custom/path".into())
    .with_encrypted_database()

    // Network
    .disable_bluetooth()
    .with_bootstrap_peer("/dns4/peer.example.com/tcp/4001".into())
    .with_listen_address("/ip4/0.0.0.0/tcp/4001".into())
    .with_connection_timeout(Duration::from_secs(60))

    // Reputation
    .enable_collusion_detection()
    .with_decay_rate(1.5)

    // Features
    .enable_timing_jitter()
    .with_max_queued_messages(500)
    .enable_delivery_receipts()
    .disable_read_receipts()

    .build();

// Validate before use
config.validate()?;

let client = VeritasClient::new(config).await?;
```

### Data Directory

Default data directories by platform:

| Platform | Path |
|----------|------|
| Linux | `~/.local/share/veritas` |
| macOS | `~/Library/Application Support/veritas` |
| Windows | `C:\Users\<User>\AppData\Roaming\veritas` |

Structure:

```
~/.local/share/veritas/
├── db/                 # sled database
│   ├── conf
│   ├── db
│   └── blobs/
├── cache/              # Temporary cache
└── logs/               # Application logs
```

---

## Environment Variables

### Configuration Overrides

| Variable | Description | Example |
|----------|-------------|---------|
| `VERITAS_DATA_DIR` | Override data directory | `/custom/path` |
| `VERITAS_CONFIG_FILE` | Config file path | `/etc/veritas/config.toml` |
| `VERITAS_LOG_LEVEL` | Logging level | `debug`, `info`, `warn`, `error` |

### Testing Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `VERITAS_TEST_STORAGE_PATH` | Test storage directory | `/tmp/veritas-test` |
| `VERITAS_TEST_BOOTSTRAP_NODES` | Test bootstrap peers | `peer1,peer2` |

### Example Usage

```bash
# Set data directory
export VERITAS_DATA_DIR=/opt/veritas/data

# Enable debug logging
export VERITAS_LOG_LEVEL=debug

# Run with overrides
cargo run
```

---

## Docker Setup

### Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
# Build stage
FROM rust:1.85-bookworm as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release
RUN cargo build --release -p veritas-core

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/release/veritas-node /app/

# Create data directory
RUN mkdir -p /data

# Set environment
ENV VERITAS_DATA_DIR=/data
ENV VERITAS_LOG_LEVEL=info

EXPOSE 4001

VOLUME ["/data"]

ENTRYPOINT ["/app/veritas-node"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  veritas-node:
    build: .
    ports:
      - "4001:4001"
    volumes:
      - veritas-data:/data
    environment:
      - VERITAS_LOG_LEVEL=info
    restart: unless-stopped

volumes:
  veritas-data:
```

### Running with Docker

```bash
# Build image
docker build -t veritas-node .

# Run container
docker run -d \
    --name veritas \
    -p 4001:4001 \
    -v veritas-data:/data \
    veritas-node

# View logs
docker logs -f veritas

# Stop
docker stop veritas
```

---

## Running Tests

### All Tests

```bash
# Run all tests
cargo test --all

# Run with output
cargo test --all -- --nocapture

# Run in release mode (faster, more optimizations)
cargo test --all --release
```

### Specific Crate Tests

```bash
# Test crypto crate
cargo test -p veritas-crypto

# Test protocol crate
cargo test -p veritas-protocol

# Test core crate
cargo test -p veritas-core
```

### Test Categories

```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'

# Documentation tests
cargo test --doc
```

### Property Tests

```bash
# Run property tests (may take longer)
cargo test --all -- --ignored

# With more iterations
PROPTEST_CASES=1000 cargo test --all
```

### Code Coverage

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Generate coverage report
cargo llvm-cov --all --html

# Open report
open target/llvm-cov/html/index.html
```

### Linting and Formatting

```bash
# Check formatting
cargo fmt --all -- --check

# Apply formatting
cargo fmt --all

# Run clippy lints
cargo clippy --all-targets -- -D warnings

# Run security audit
cargo audit
```

### Benchmarks

```bash
# Run benchmarks (when available)
cargo bench

# Specific benchmark
cargo bench -p veritas-crypto
```

---

## Platform-Specific Notes

### Linux

**Ubuntu 22.04+ / Debian 12+:**

```bash
# Install all dependencies
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    libbluetooth-dev  # For Bluetooth support
```

**Fedora:**

```bash
sudo dnf install -y \
    gcc \
    openssl-devel \
    clang-devel \
    cmake \
    bluez-libs-devel
```

### macOS

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install openssl cmake

# Set OpenSSL path for compilation
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

### Windows

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Select "Desktop development with C++"

2. Install OpenSSL:
   ```powershell
   # Using vcpkg
   git clone https://github.com/microsoft/vcpkg
   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg install openssl:x64-windows
   ```

3. Set environment:
   ```powershell
   $env:OPENSSL_DIR = "C:\vcpkg\installed\x64-windows"
   ```

### WebAssembly

```bash
# Install wasm32 target
rustup target add wasm32-unknown-unknown

# Install wasm-pack
cargo install wasm-pack

# Build
cd crates/veritas-wasm
wasm-pack build --target web
```

### Cross-Compilation

```bash
# Install cross
cargo install cross

# Build for ARM64 Linux
cross build --target aarch64-unknown-linux-gnu --release

# Build for ARM64 macOS
cross build --target aarch64-apple-darwin --release
```

---

## Troubleshooting

### Common Issues

#### Build Fails: OpenSSL Not Found

**Linux:**
```bash
sudo apt install libssl-dev pkg-config
```

**macOS:**
```bash
brew install openssl
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

**Windows:**
```powershell
# Set OPENSSL_DIR to your OpenSSL installation
$env:OPENSSL_DIR = "C:\path\to\openssl"
```

#### Build Fails: Clang Not Found

**Linux:**
```bash
sudo apt install libclang-dev
```

**macOS:**
```bash
xcode-select --install
```

#### Runtime Error: Database Locked

The database can only be opened by one process at a time.

```bash
# Check for existing processes
ps aux | grep veritas

# Remove stale lock file (if process crashed)
rm ~/.local/share/veritas/db/lock
```

#### Network: Cannot Connect to Bootstrap Nodes

1. Check internet connectivity
2. Verify firewall allows outbound connections on port 4001
3. Try alternative bootstrap nodes

```rust
let config = ClientConfigBuilder::new()
    .with_bootstrap_peers(vec![
        "/dns4/alt-bootstrap.veritas.network/tcp/4001".into(),
    ])
    .build();
```

#### WASM: "Cannot find module" Error

Ensure you're using the correct build target:

```bash
# For web browsers
wasm-pack build --target web

# For Node.js
wasm-pack build --target nodejs
```

#### Python: Import Error

Rebuild the Python bindings:

```bash
cd crates/veritas-py
maturin develop --release
```

### Debug Logging

Enable verbose logging for troubleshooting:

```bash
# Set log level
export VERITAS_LOG_LEVEL=debug
export RUST_LOG=veritas=debug

# Or in code
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_env_filter("veritas=debug")
    .init();
```

### Getting Help

1. Check the [GitHub Issues](https://github.com/gl-tches/veritas-protocol/issues)
2. Search existing discussions
3. Open a new issue with:
   - OS and version
   - Rust version (`rustc --version`)
   - Full error message
   - Steps to reproduce

---

## See Also

- [API Documentation](API.md) - Complete API reference
- [Architecture Guide](ARCHITECTURE.md) - System design and data flow
- [Security Guide](SECURITY.md) - Threat model and cryptographic design
