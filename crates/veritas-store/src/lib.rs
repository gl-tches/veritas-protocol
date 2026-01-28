//! # veritas-store
//!
//! Encrypted local storage for VERITAS protocol.
//!
//! Provides:
//! - Encrypted database using sled + ChaCha20-Poly1305
//! - Message queue (inbox/outbox)
//! - Identity keyring
//! - Block cache
//!
//! ## Encrypted Database
//!
//! The core storage component is [`EncryptedDb`], which provides encrypted
//! key-value storage backed by sled. All values are encrypted at rest using
//! ChaCha20-Poly1305 with keys derived from a password via Argon2id.
//!
//! ```no_run
//! use veritas_store::EncryptedDb;
//! use std::path::Path;
//!
//! // Open or create an encrypted database
//! let db = EncryptedDb::open(Path::new("/tmp/veritas-db"), b"password").unwrap();
//!
//! // Store encrypted data
//! db.put(b"user:alice", b"encrypted profile data").unwrap();
//!
//! // Retrieve and decrypt
//! let data = db.get(b"user:alice").unwrap();
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod encrypted_db;
pub mod error;
pub mod keyring;
pub mod message_queue;

pub use encrypted_db::{DbKey, EncryptedDb, EncryptedTree};
pub use error::{Result, StoreError};
pub use keyring::{ExportedIdentity, Keyring, KeyringEntry, KeyringMetadata};
pub use message_queue::{
    InboxMessage, InboxStats, MessageId, MessageQueue, MessageStatus, OutboxStats, QueuedMessage,
};
