//! # veritas-store
//!
//! Encrypted local storage for the VERITAS Protocol.
//!
//! This crate provides:
//! - **EncryptedDb**: sled wrapper with ChaCha20-Poly1305 encryption
//! - **MessageQueue**: Inbox/outbox for message delivery
//! - **Keyring**: Secure identity key storage
//!
//! ## Security
//!
//! - All data encrypted at rest with ChaCha20-Poly1305
//! - Keys derived from password using Argon2id
//! - Automatic cleanup of expired messages

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{StoreError, Result};
