//! # veritas-crypto
//!
//! Cryptographic primitives for the VERITAS Protocol.
//!
//! This crate provides post-quantum secure cryptography using:
//! - **ML-KEM** (FIPS 203) for key encapsulation
//! - **ML-DSA** (FIPS 204) for digital signatures
//! - **ChaCha20-Poly1305** for symmetric encryption
//! - **BLAKE3** for hashing
//! - **X25519** for hybrid key exchange (optional fallback)
//!
//! ## Security
//!
//! All secret data uses `zeroize` for secure memory cleanup.
//! All comparisons of secrets use constant-time operations via `subtle`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{CryptoError, Result};
