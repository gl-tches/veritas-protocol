# VERITAS Development Guide

Guide for developers contributing to the VERITAS Protocol.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Contributing](#contributing)
- [Debugging](#debugging)
- [Release Process](#release-process)

## Development Setup

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install additional tools
cargo install cargo-watch cargo-audit cargo-tarpaulin

# Install wasm-pack (for WASM development)
cargo install wasm-pack

# Install maturin (for Python bindings)
pip install maturin

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Clone and Build

```bash
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Build all crates
cargo build

# Run tests
cargo test --all

# Check for issues
cargo clippy --all-targets
cargo fmt --all -- --check
cargo audit
```

## Project Structure

```
veritas/
├── Cargo.toml              # Workspace configuration
├── CLAUDE.md               # Development instructions
├── TASKS.md                # Task tracking
├── VERSION_HISTORY.md      # Changelog
│
├── crates/                 # Rust crates
│   ├── veritas-crypto/     # Cryptographic primitives
│   ├── veritas-identity/   # Identity management
│   ├── veritas-protocol/   # Wire protocol
│   ├── veritas-chain/      # Blockchain layer
│   ├── veritas-net/        # P2P networking
│   ├── veritas-store/      # Storage layer
│   ├── veritas-reputation/ # Reputation system
│   ├── veritas-core/       # High-level API
│   ├── veritas-node/       # Node daemon
│   ├── veritas-ffi/        # C bindings
│   ├── veritas-wasm/       # WASM bindings
│   └── veritas-py/         # Python bindings
│
├── docs/                   # Technical documentation
├── documentation/          # User documentation
├── examples/               # Example applications
│   ├── cli-chat/           # CLI chat example
│   └── web-demo/           # Web demo
│
├── fuzz/                   # Fuzz testing
│   ├── Cargo.toml
│   └── fuzz_targets/
│
└── docker/                 # Docker configuration
```

### Crate Dependencies

```
veritas-core
├── veritas-protocol
│   ├── veritas-crypto
│   ├── veritas-identity
│   │   └── veritas-crypto
│   └── veritas-reputation
├── veritas-chain
│   ├── veritas-protocol
│   └── veritas-crypto
├── veritas-net
│   ├── veritas-protocol
│   └── veritas-reputation
└── veritas-store
    ├── veritas-protocol
    └── veritas-crypto
```

## Building

### Development Build

```bash
# Fast build (unoptimized)
cargo build

# Build specific crate
cargo build -p veritas-core

# Build with all features
cargo build --all-features
```

### Release Build

```bash
# Optimized build
cargo build --release

# Build specific binary
cargo build --release --bin veritas-node
```

### WASM Build

```bash
cd crates/veritas-wasm

# For web
wasm-pack build --target web

# For Node.js
wasm-pack build --target nodejs

# For bundlers (webpack, etc.)
wasm-pack build --target bundler
```

### Python Build

```bash
cd crates/veritas-py

# Development build
maturin develop

# Release build
maturin build --release

# Build wheel
maturin build --release --strip
```

### Cross-Compilation

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64
cargo build --release --target aarch64-unknown-linux-gnu
```

## Testing

### Unit Tests

```bash
# Run all tests
cargo test --all

# Run specific crate tests
cargo test -p veritas-crypto

# Run specific test
cargo test -p veritas-core test_client_lifecycle

# Run with output
cargo test --all -- --nocapture

# Run ignored tests
cargo test --all -- --ignored
```

### Integration Tests

```bash
# Run integration tests
cargo test -p veritas-core --test integration_tests
cargo test -p veritas-core --test phase10_integration
```

### Property Tests

```bash
# Run property tests (included in cargo test)
cargo test --all

# Run only property tests
cargo test proptest
```

### Fuzz Testing

```bash
cd fuzz

# Install cargo-fuzz
cargo install cargo-fuzz

# List available targets
cargo fuzz list

# Run a fuzz target
cargo +nightly fuzz run fuzz_username_validation

# Run with timeout
cargo +nightly fuzz run fuzz_symmetric_decrypt -- -max_total_time=300
```

### Code Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --all --out Html

# Open report
open tarpaulin-report.html
```

### Benchmarks

```bash
# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench -p veritas-crypto
```

## Code Style

### Formatting

```bash
# Format all code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check
```

### Linting

```bash
# Run clippy
cargo clippy --all-targets

# Run with all warnings as errors
cargo clippy --all-targets -- -D warnings

# Allow specific lints
cargo clippy --all-targets -- -A clippy::too_many_arguments
```

### Documentation

```bash
# Generate docs
cargo doc --no-deps

# Generate and open docs
cargo doc --no-deps --open

# Check doc examples compile
cargo test --doc
```

### Coding Guidelines

1. **Error Handling**
   - Use `thiserror` for error types
   - Provide context in error messages
   - Never panic in library code

2. **Security**
   - Use `Zeroize` for all secrets
   - Use `subtle` for constant-time comparisons
   - Never log sensitive data
   - Validate all inputs at boundaries

3. **Async Code**
   - Use `tokio` for async runtime
   - Prefer async/await over raw futures
   - Use channels for cross-task communication

4. **Testing**
   - Write unit tests for all public functions
   - Use property tests for input validation
   - Mock external dependencies

## Contributing

### Workflow

1. **Fork** the repository
2. **Create branch**: `git checkout -b feat/my-feature`
3. **Make changes** and commit
4. **Run tests**: `cargo test --all`
5. **Run lints**: `cargo clippy --all-targets`
6. **Push** and create PR

### Commit Messages

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security fix
- `refactor`: Code restructuring
- `docs`: Documentation
- `test`: Tests
- `chore`: Maintenance

Examples:
```
feat(crypto): implement ML-KEM key encapsulation

- Add MlKemKeyPair struct
- Integrate ml-kem crate v0.1
- Add zeroize on private key drop

Task-ID: 004
```

### Pull Request Checklist

- [ ] Tests pass (`cargo test --all`)
- [ ] Lints pass (`cargo clippy --all-targets`)
- [ ] Formatted (`cargo fmt --all`)
- [ ] Documentation updated
- [ ] TASKS.md updated (if applicable)
- [ ] VERSION_HISTORY.md updated

## Debugging

### Logging

```rust
use tracing::{debug, info, warn, error, instrument};

#[instrument(skip(password))]
pub async fn unlock(&self, password: &[u8]) -> Result<()> {
    info!("Unlocking client");
    debug!(state = ?self.state, "Current state");

    // ...

    if let Err(e) = result {
        error!(error = %e, "Failed to unlock");
    }

    Ok(())
}
```

Enable debug logging:
```bash
RUST_LOG=debug cargo run --bin veritas-node
RUST_LOG=veritas_core=trace cargo run --bin veritas-node
```

### LLDB/GDB

```bash
# Build with debug symbols
cargo build

# Debug with LLDB
lldb target/debug/veritas-node

# Debug with GDB
gdb target/debug/veritas-node
```

### Memory Profiling

```bash
# Install heaptrack
sudo apt install heaptrack

# Profile memory
heaptrack target/release/veritas-node
heaptrack --analyze heaptrack.veritas-node.*.gz
```

### Performance Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bin veritas-node

# Open flamegraph
open flamegraph.svg
```

## Release Process

### Version Bumping

1. Update version in `Cargo.toml` (workspace)
2. Update `VERSION_HISTORY.md`
3. Update `TASKS.md` if needed

### Pre-Release Checklist

```bash
# 1. Run full test suite
cargo test --all
cargo test --all -- --ignored

# 2. Run lints
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check

# 3. Security audit
cargo audit

# 4. Check documentation
cargo doc --no-deps

# 5. Build release binaries
cargo build --release
```

### Creating a Release

```bash
# Tag the release
git tag -a v0.3.0-beta -m "Release v0.3.0-beta"
git push origin v0.3.0-beta

# Build release artifacts
cargo build --release
```

### Publishing to crates.io

```bash
# Dry run first
cargo publish -p veritas-crypto --dry-run

# Publish in dependency order
cargo publish -p veritas-crypto
cargo publish -p veritas-identity
cargo publish -p veritas-protocol
# ... etc
```

## Development Tools

### Recommended IDE Extensions

**VS Code:**
- rust-analyzer
- Even Better TOML
- CodeLLDB

**IntelliJ/CLion:**
- Rust plugin

### Useful Commands

```bash
# Watch and rebuild
cargo watch -x build

# Watch and test
cargo watch -x test

# Check without building
cargo check --all

# Update dependencies
cargo update

# Show dependency tree
cargo tree

# Find unused dependencies
cargo +nightly udeps
```

## Next Steps

- [API Examples](API_EXAMPLES.md) - Code examples
- [Architecture](../docs/ARCHITECTURE.md) - System design
- [Security](../docs/SECURITY.md) - Security guidelines
