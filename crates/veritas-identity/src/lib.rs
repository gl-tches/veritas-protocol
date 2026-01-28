//! # veritas-identity
//!
//! Decentralized identity system for the VERITAS protocol.
//!
//! Provides:
//! - Identity hash generation from public keys
//! - Identity keypair management
//! - Username registration and linking
//! - Key lifecycle (rotation, revocation, expiry)

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{IdentityError, Result};
