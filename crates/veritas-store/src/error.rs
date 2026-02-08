//! Error types for storage operations.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Error, Debug)]
pub enum StoreError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),

    /// Identity error.
    #[error("Identity error: {0}")]
    Identity(#[from] veritas_identity::IdentityError),

    /// Key not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid password.
    #[error("Invalid password")]
    InvalidPassword,

    /// Storage is locked.
    #[error("Storage is locked")]
    Locked,

    /// Corruption detected.
    #[error("Data corruption detected: {0}")]
    Corruption(String),

    /// Storage capacity exceeded.
    #[error("Storage full: {0}")]
    StoreFull(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for storage operations.
pub type Result<T> = std::result::Result<T, StoreError>;
