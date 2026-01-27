//! # veritas-identity
//!
//! Identity and DID system for the VERITAS Protocol.
//!
//! This crate provides:
//! - **IdentityHash**: BLAKE3 hash of public key as unique identifier
//! - **Identity**: Complete keypair with ML-KEM and ML-DSA keys
//! - **Username**: Optional human-readable alias system
//! - **Key Lifecycle**: Expiry, rotation, and revocation support
//! - **Identity Limits**: Max 3 identities per device origin

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{IdentityError, Result};
