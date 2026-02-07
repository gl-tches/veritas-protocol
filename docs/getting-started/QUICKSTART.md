# VERITAS Quick Start Guide

Get up and running with VERITAS in 5 minutes.

## Prerequisites

- **Rust 1.85+** - Install from [rustup.rs](https://rustup.rs)
- **Git** - For cloning the repository

## Option 1: Run with Docker (Fastest)

```bash
# Clone the repository
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Start a node with Docker Compose
docker-compose up -d

# Check the node is running
curl http://localhost:8080/health
# Output: {"status":"ok"}
```

## Option 2: Build from Source

### Step 1: Clone and Build

```bash
# Clone the repository
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Build in release mode
cargo build --release

# Run tests to verify
cargo test --all
```

### Step 2: Run a Node

```bash
# Run the VERITAS node
./target/release/veritas-node --data-dir ./data

# Or with cargo
cargo run --release --bin veritas-node -- --data-dir ./data
```

### Step 3: Verify It's Running

```bash
# Check health endpoint
curl http://localhost:8080/health
# Output: {"status":"ok"}

# Check readiness
curl http://localhost:8080/ready
# Output: {"ready":"true"}
```

## Option 3: Use as a Library

### Add to Cargo.toml

```toml
[dependencies]
veritas-core = "0.4.0-beta"
tokio = { version = "1", features = ["full"] }
```

### Basic Usage

```rust
use veritas_core::{VeritasClient, ClientConfigBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an in-memory client (for testing)
    let client = VeritasClient::in_memory().await?;

    // Unlock with a password
    client.unlock(b"my_secure_password").await?;

    // Create an identity
    let identity_hash = client.create_identity(Some("Alice")).await?;
    println!("Your identity: {}", identity_hash);

    // Get your public keys (share these with contacts)
    let public_keys = client.public_keys().await?;
    println!("Public keys: {} bytes", public_keys.len());

    // Lock when done
    client.lock().await?;

    Ok(())
}
```

## Try the CLI Chat Example

```bash
# Build and run the CLI chat example
cd examples/cli-chat
cargo run --release

# Available commands:
# /identity - Show your identity hash
# /contacts - List your contacts
# /add <hash> - Add a contact by their identity hash
# /msg <name> <message> - Send a message
# /safety <name> - Show safety number for a contact
# /quit - Exit the application
```

## Try the Web Demo

```bash
# Install wasm-pack if not installed
cargo install wasm-pack

# Build the WASM bindings
cd crates/veritas-wasm
wasm-pack build --target web

# Serve the web demo
cd ../../examples/web-demo
python3 -m http.server 8000
# Open http://localhost:8000 in your browser
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_DATA_DIR` | `~/.local/share/veritas` | Data storage directory |
| `VERITAS_LISTEN_ADDR` | `/ip4/0.0.0.0/tcp/9000` | P2P listen address |
| `VERITAS_LOG_LEVEL` | `info` | Log level (trace, debug, info, warn, error) |
| `VERITAS_HEALTH_PORT` | `8080` | Health check HTTP port |
| `RUST_MIN_STACK` | `16777216` | Minimum stack size (16MB, required for ML-DSA) |

## What's Next?

- **[Installation Guide](INSTALLATION.md)** - Detailed installation instructions
- **[Configuration Guide](CONFIGURATION.md)** - All configuration options
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment
- **[API Examples](API_EXAMPLES.md)** - More code examples

## Troubleshooting

### Build Fails

```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

### Port Already in Use

```bash
# Check what's using port 9000
lsof -i :9000

# Use a different port
./target/release/veritas-node --listen-addr /ip4/0.0.0.0/tcp/9001
```

### Permission Denied

```bash
# The default data directory is ~/.local/share/veritas (user-writable)
# If using a custom directory, ensure proper permissions:
mkdir -p /path/to/custom/data
./target/release/veritas-node --data-dir /path/to/custom/data
```

For more help, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
