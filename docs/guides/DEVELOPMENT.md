# VERITAS Development Guide

Guide for developers contributing to the VERITAS Protocol.

**Version**: 0.4.0-beta
**Edition**: Rust 2024
**MSRV**: 1.85

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Rust 2024 Edition Guide](#rust-2024-edition-guide)
- [Contributing](#contributing)
- [Debugging](#debugging)
- [Release Process](#release-process)

## Development Setup

### Prerequisites

```bash
# Install Rust (1.85 or later required)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify Rust version (must be 1.85+)
rustc --version
# rustc 1.85.0 (... 2026-xx-xx)

# Update to latest stable if needed
rustup update stable

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

### Minimum Supported Rust Version (MSRV)

| Version | MSRV | Edition |
|---------|------|---------|
| 0.3.0-beta | **1.85** | **2024** |
| 0.2.x | 1.75 | 2021 |
| 0.1.x | 1.75 | 2021 |

**Important**: The Rust 2024 edition requires Rust 1.85 or later. Older toolchains will not compile this project.

### Clone and Build

```bash
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Build all crates
cargo build

# Run tests
cargo test --all

# Check for issues (stricter in Rust 2024)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit
```

## Project Structure

```
veritas/
├── Cargo.toml              # Workspace configuration (edition = "2024")
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
│   ├── veritas-ffi/        # C bindings (uses unsafe FFI)
│   ├── veritas-wasm/       # WASM bindings
│   └── veritas-py/         # Python bindings (PyO3 0.23)
│
├── docs/                   # Documentation
│   ├── getting-started/    # Installation, configuration
│   ├── guides/             # Deployment, CLI, development
│   └── reference/          # API, architecture, security
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
# Run clippy (with Rust 2024 stricter lints)
cargo clippy --all-targets

# Run with all warnings as errors (CI requirement)
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

---

## Rust 2024 Edition Guide

VERITAS Protocol v0.3.0-beta has completed migration to Rust 2024 edition. This section documents the changes, patterns, and guidelines for contributors.

### Migration Summary

| Aspect | Before | After |
|--------|--------|-------|
| Edition | 2021 | **2024** |
| MSRV | 1.75 | **1.85** |
| Crates Migrated | - | **11 of 11** |
| API Breaking Changes | - | **None** |

### Key Changes by Crate Type

#### Core Crates (No FFI)

Most core crates required minimal changes:
- `veritas-crypto`, `veritas-identity`, `veritas-reputation`, `veritas-protocol`, `veritas-chain`, `veritas-store`, `veritas-core`, `veritas-wasm`

These crates use `#![deny(unsafe_code)]` and required only:
- Updating `Cargo.toml` with `edition = "2024"` and `rust-version = "1.85"`
- Minor clippy fixes (see [New Clippy Lints](#new-clippy-lints-rust-2024))

#### FFI Crate (veritas-ffi)

The C FFI crate required significant changes for Rust 2024 unsafe attribute syntax:

```rust
// Rust 2021 (OLD - no longer compiles)
#[no_mangle]
pub extern "C" fn veritas_init() -> i32 { 0 }

// Rust 2024 (REQUIRED)
#[unsafe(no_mangle)]
pub extern "C" fn veritas_init() -> i32 { 0 }
```

**Changes made:**
- All 12 `#[no_mangle]` attributes converted to `#[unsafe(no_mangle)]`
- cbindgen upgraded from 0.26 to **0.29** for Rust 2024 syntax support
- C header generation verified working

#### Python Bindings (veritas-py)

PyO3 was upgraded for Rust 2024 compatibility:

```rust
// PyO3 0.20 (OLD)
#[pymodule]
fn veritas(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<VeritasClient>()?;
    Ok(())
}

// PyO3 0.23 (NEW)
#[pymodule]
fn veritas(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VeritasClient>()?;
    Ok(())
}
```

**Changes made:**
- PyO3 upgraded from 0.20 to **0.23**
- Module signature updated: `&PyModule` to `&Bound<'_, PyModule>`
- Error registration signature updated for new API

### Writing Edition-Compatible Unsafe Code

#### Rule 1: `#[no_mangle]` Requires `#[unsafe(...)]`

```rust
// WRONG - compile error in Rust 2024
#[no_mangle]
pub extern "C" fn my_function() -> i32 { 0 }

// CORRECT
#[unsafe(no_mangle)]
pub extern "C" fn my_function() -> i32 { 0 }
```

#### Rule 2: `#[export_name]` Requires `#[unsafe(...)]`

```rust
// WRONG - compile error in Rust 2024
#[export_name = "custom_name"]
pub extern "C" fn my_function() -> i32 { 0 }

// CORRECT
#[unsafe(export_name = "custom_name")]
pub extern "C" fn my_function() -> i32 { 0 }
```

#### Rule 3: Explicit `unsafe` Inside Unsafe Functions

```rust
// Rust 2021 - implicit unsafe operations allowed
unsafe fn process_ptr(ptr: *const u8) -> u8 {
    *ptr  // No unsafe block needed
}

// Rust 2024 - explicit unsafe REQUIRED
unsafe fn process_ptr(ptr: *const u8) -> u8 {
    unsafe { *ptr }  // Must wrap unsafe operations
}
```

#### Rule 4: `extern` Blocks Require `unsafe`

```rust
// Rust 2021 (OLD)
extern "C" {
    fn external_function();
}

// Rust 2024 (NEW)
unsafe extern "C" {
    fn external_function();

    // NEW: Can mark safe items explicitly
    pub safe fn sqrt(x: f64) -> f64;
}
```

#### Rule 5: No Mutable References to `static mut`

```rust
// WRONG - error in Rust 2024
static mut COUNTER: u64 = 0;
let r = unsafe { &mut COUNTER };  // ERROR!

// CORRECT - use raw pointers
static mut COUNTER: u64 = 0;
let ptr = unsafe { &raw mut COUNTER };
unsafe { *ptr += 1; }

// BEST - use atomics instead
use std::sync::atomic::{AtomicU64, Ordering};
static COUNTER: AtomicU64 = AtomicU64::new(0);
COUNTER.fetch_add(1, Ordering::SeqCst);
```

### Lock Scoping Changes (IMPORTANT)

Rust 2024 changes when `MutexGuard` and `RwLockGuard` are dropped in certain patterns. This affects code using `if let` and tail expressions with locks.

#### Pattern 1: `if let` with Lock Guards

```rust
// This pattern behaves DIFFERENTLY in Rust 2024
if let Some(data) = mutex.lock().unwrap().get(&key) {
    // Rust 2021: lock is held here
    // Rust 2024: lock may already be dropped!
    process(data);  // May fail if `data` borrows from guard
}
```

**Solution**: If you need the lock held, use explicit binding:

```rust
// Explicit scoping - works in both editions
let guard = mutex.lock().unwrap();
if let Some(data) = guard.get(&key) {
    process(data);  // Lock guaranteed held
}
// Guard drops here
```

#### Pattern 2: Tail Expression Temporaries

```rust
// Behavior may change in Rust 2024
fn get_value(map: &Mutex<HashMap<K, V>>, key: &K) -> Option<V> {
    map.lock().unwrap().get(key).cloned()
    // Rust 2021: MutexGuard dropped after this line
    // Rust 2024: MutexGuard may drop before return
}
```

**Solution**: Use explicit `drop()` when timing matters:

```rust
fn get_value(map: &Mutex<HashMap<K, V>>, key: &K) -> Option<V> {
    let guard = map.lock().unwrap();
    let result = guard.get(key).cloned();
    drop(guard);  // Explicit: lock released here
    result
}
```

#### VERITAS Lock Audit Results

All 33 lock operations in `veritas-net` were audited and verified safe:

| File | Lock Operations | Status |
|------|-----------------|--------|
| `gossip.rs` | 8 | Safe - no borrowed data escapes |
| `dht.rs` | 6 | Safe - all values cloned |
| `transport_manager.rs` | 19 | Safe - explicit drops used |

### New Clippy Lints (Rust 2024)

Rust 2024 enables stricter clippy lints by default. The following patterns were fixed during migration:

#### 1. `repeat().take()` to `repeat_n()`

```rust
// OLD - triggers clippy warning
let padding: Vec<u8> = std::iter::repeat(0u8).take(n).collect();

// NEW - cleaner
let padding: Vec<u8> = std::iter::repeat_n(0u8, n).collect();
```

#### 2. Manual `RangeInclusive::contains`

```rust
// OLD - triggers clippy warning
if value >= min && value <= max { ... }

// NEW - use contains()
if (min..=max).contains(&value) { ... }
```

#### 3. `map_or` to `is_none_or`

```rust
// OLD - triggers clippy warning in some cases
option.map_or(true, |v| v > 0)

// NEW - clearer intent
option.is_none_or(|v| v > 0)
```

#### 4. Duplicated `#![cfg(test)]` Attributes

```rust
// OLD - duplicated attribute warning
#![cfg(test)]
mod tests {
    #![cfg(test)]  // ERROR: duplicate
    // ...
}

// NEW - single attribute
#![cfg(test)]
mod tests {
    // ...
}
```

#### 5. Assertions on Constants

```rust
// OLD - may trigger lint
assert!(SOME_CONST > 0);

// NEW - use const block for compile-time check
const { assert!(SOME_CONST > 0) };
```

### Testing FFI Changes

When modifying FFI code, follow this verification process:

```bash
# 1. Build the FFI crate
cargo build -p veritas-ffi --release

# 2. Run FFI tests
cargo test -p veritas-ffi

# 3. Regenerate C header (if cbindgen.toml exists)
cbindgen --config cbindgen.toml --crate veritas-ffi --output include/veritas.h

# 4. Verify header compiles with C compiler
gcc -c -x c include/veritas.h -o /dev/null

# 5. Run clippy with warnings as errors
cargo clippy -p veritas-ffi -- -D warnings
```

### Async Closures (Future Refactoring)

Rust 2024 introduces native async closures. This is optional refactoring, not required:

```rust
// Rust 2021 - verbose pattern
let futures: Vec<_> = peers.iter()
    .map(|peer| {
        let peer = peer.clone();  // Must clone for async move
        async move {
            send_to_peer(&peer).await
        }
    })
    .collect();

// Rust 2024 - native async closures (OPTIONAL)
let futures: Vec<_> = peers.iter()
    .map(async |peer| {  // Direct capture, no clone needed!
        send_to_peer(peer).await
    })
    .collect();
```

This refactoring is tracked in TASKS.md as TASK-170 (P3 priority).

### Migration Checklist for New Crates

If adding a new crate to the workspace:

```bash
# 1. Create crate with edition 2024
cargo new crates/veritas-newcrate --lib

# 2. Update Cargo.toml
# [package]
# edition = "2024"
# rust-version = "1.85"

# 3. If using unsafe code, follow Rust 2024 patterns
# - #[unsafe(no_mangle)] not #[no_mangle]
# - unsafe extern "C" { } not extern "C" { }
# - Explicit unsafe blocks inside unsafe fns

# 4. Run checks
cargo test -p veritas-newcrate
cargo clippy -p veritas-newcrate -- -D warnings
```

---

## Contributing

### Workflow

1. **Fork** the repository
2. **Create branch**: `git checkout -b feat/my-feature`
3. **Make changes** and commit
4. **Run tests**: `cargo test --all`
5. **Run lints**: `cargo clippy --all-targets -- -D warnings`
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
- [ ] Lints pass (`cargo clippy --all-targets -- -D warnings`)
- [ ] Formatted (`cargo fmt --all`)
- [ ] Documentation updated
- [ ] TASKS.md updated (if applicable)
- [ ] VERSION_HISTORY.md updated
- [ ] **Rust 2024 patterns followed** (if adding unsafe/FFI code)

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

# 2. Run lints (strict mode - required for Rust 2024)
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

## Dependency Versions

Key dependencies updated for v0.3.0-beta:

| Dependency | Version | Notes |
|------------|---------|-------|
| PyO3 | 0.23 | Updated from 0.20 for Rust 2024 |
| cbindgen | 0.29 | Updated from 0.26 for Rust 2024 syntax |

## Next Steps

- [API Examples](API_EXAMPLES.md) - Code examples
- [Architecture](../reference/ARCHITECTURE.md) - System design
- [Security](../reference/SECURITY.md) - Security guidelines
