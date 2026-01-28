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

- **Task 003**: ChaCha20-Poly1305 symmetric encryption
  - `SymmetricKey` type with Zeroize
  - XChaCha20-Poly1305 AEAD encryption/decryption
  - 192-bit random nonce generation
  - Additional authenticated data (AAD) support
  - `EncryptedData` serialization
  - 15 unit tests

- **Task 004**: ML-KEM key encapsulation (PLACEHOLDER)
  - API design for `MlKemKeyPair`, `MlKemPublicKey`, `MlKemPrivateKey`
  - `encapsulate()` and `decapsulate()` function signatures
  - Waiting for ml-kem crate to stabilize (currently 0.3.0-pre.5)
  - Size constants defined (PUBLIC_KEY_SIZE, CIPHERTEXT_SIZE, etc.)

- **Task 005**: ML-DSA digital signatures (PLACEHOLDER)
  - API design for `MlDsaKeyPair`, `MlDsaPublicKey`, `MlDsaPrivateKey`
  - `sign()` and `verify()` method signatures
  - Waiting for ml-dsa crate to stabilize (currently 0.1.0-rc.4)
  - Size constants defined (PUBLIC_KEY_SIZE, SIGNATURE_SIZE, etc.)

- **Task 006**: X25519 key exchange
  - `X25519StaticPrivateKey` for long-term keys
  - `X25519EphemeralKeyPair` for per-message keys
  - `X25519PublicKey` with serialization
  - `SharedSecret` with Zeroize and key derivation
  - Diffie-Hellman key agreement
  - 12 unit tests

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
