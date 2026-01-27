//! Error types for storage operations.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Error, Debug)]
pub enum StoreError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Key not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error.
    #[error("Decryption error: data corrupted or wrong password")]
    Decryption,

    /// Invalid password.
    #[error("Invalid password")]
    InvalidPassword,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Message queue full.
    #[error("Message queue full")]
    QueueFull,

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),
}

/// Result type for storage operations.
pub type Result<T> = std::result::Result<T, StoreError>;
