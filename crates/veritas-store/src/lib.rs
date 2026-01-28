//! # veritas-store
//!
//! Encrypted local storage for VERITAS protocol.
//!
//! Provides:
//! - Encrypted database using sled + ChaCha20
//! - Message queue (inbox/outbox)
//! - Identity keyring
//! - Block cache

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{Result, StoreError};
