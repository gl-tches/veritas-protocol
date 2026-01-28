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
//!
//! ## Post-Quantum Status
//!
//! The ML-KEM and ML-DSA modules are currently placeholder implementations
//! pending stabilization of the underlying crates. The X25519 module provides
//! classical key exchange that will be combined with ML-KEM in hybrid mode.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod hash;
pub mod mldsa;
pub mod mlkem;
pub mod symmetric;
pub mod x25519;

pub use error::{CryptoError, Result};
pub use hash::Hash256;
pub use mldsa::{MlDsaKeyPair, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature};
pub use mlkem::{MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey};
pub use symmetric::{decrypt, encrypt, EncryptedData, Nonce, SymmetricKey};
pub use x25519::{SharedSecret, X25519EphemeralKeyPair, X25519PublicKey, X25519StaticPrivateKey};
