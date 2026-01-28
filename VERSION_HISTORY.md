# VERITAS Version History

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2024

### Added

- **Task 001**: Project scaffolding
  - Created workspace with 11 crates
  - Set up workspace dependencies
  - Added MIT + Apache-2.0 licenses
  - Created error types for all crates
  - Added protocol limits module

- **Task 002**: BLAKE3 hashing primitives
  - `Hash256` type with 32-byte output
  - Single input hashing
  - Multi-input hashing with domain separation
  - Keyed hashing (MAC)
  - Key derivation
  - Hex encoding/decoding
  - Constant-time comparison via `subtle`
  - `Zeroize` support
  - Unit tests

### Crates

| Crate | Version | Status |
|-------|---------|--------|
| veritas-crypto | 0.1.0-alpha.1 | Scaffolded |
| veritas-identity | 0.1.0-alpha.1 | Scaffolded |
| veritas-protocol | 0.1.0-alpha.1 | Scaffolded |
| veritas-chain | 0.1.0-alpha.1 | Scaffolded |
| veritas-net | 0.1.0-alpha.1 | Scaffolded |
| veritas-store | 0.1.0-alpha.1 | Scaffolded |
| veritas-reputation | 0.1.0-alpha.1 | Scaffolded |
| veritas-core | 0.1.0-alpha.1 | Scaffolded |
| veritas-ffi | 0.1.0-alpha.1 | Scaffolded |
| veritas-wasm | 0.1.0-alpha.1 | Scaffolded |
| veritas-py | 0.1.0-alpha.1 | Scaffolded |
