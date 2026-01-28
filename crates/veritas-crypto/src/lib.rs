//! # veritas-crypto
//!
//! Cryptographic primitives for the VERITAS protocol.
//!
//! This crate provides post-quantum secure cryptographic operations:
//!
//! - **Hashing**: BLAKE3 for fast, secure hashing
//! - **Symmetric Encryption**: ChaCha20-Poly1305 AEAD
//! - **Key Encapsulation**: ML-KEM (post-quantum) + X25519 (hybrid)
//! - **Digital Signatures**: ML-DSA (post-quantum)
//! - **Key Derivation**: Argon2id for password-based key derivation
//!
//! ## Security
//!
//! All secret data implements `Zeroize` for secure memory cleanup.
//! Constant-time comparisons are used for all security-sensitive operations.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod hash;

pub use error::{CryptoError, Result};
pub use hash::Hash256;
