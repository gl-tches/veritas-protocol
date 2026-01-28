//! Error types for protocol operations.

use thiserror::Error;

/// Errors that can occur during protocol operations.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Identity error.
    #[error("Identity error: {0}")]
    Identity(#[from] veritas_identity::IdentityError),

    /// Message too long.
    #[error("Message too long: max {max} characters, got {actual}")]
    MessageTooLong {
        /// Maximum allowed characters.
        max: usize,
        /// Actual character count.
        actual: usize,
    },

    /// Too many chunks.
    #[error("Too many chunks: max {max}, got {actual}")]
    TooManyChunks {
        /// Maximum allowed chunks.
        max: usize,
        /// Actual chunk count.
        actual: usize,
    },

    /// Invalid envelope format.
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Invalid signature.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Message expired.
    #[error("Message has expired")]
    MessageExpired,

    /// Duplicate nonce detected.
    #[error("Duplicate nonce detected")]
    DuplicateNonce,

    /// Decryption failed.
    #[error("Failed to decrypt message")]
    DecryptionFailed,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid recipient.
    #[error("Invalid recipient")]
    InvalidRecipient,
}

/// Result type for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;
