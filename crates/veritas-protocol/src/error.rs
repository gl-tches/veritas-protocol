//! Error types for protocol operations.

use thiserror::Error;

/// Errors that can occur during protocol operations.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Message content too long.
    #[error("Message too long: max {max} characters, got {actual}")]
    MessageTooLong {
        /// Maximum allowed characters.
        max: usize,
        /// Actual character count.
        actual: usize,
    },

    /// Too many message chunks.
    #[error("Too many chunks: max {max}, got {actual}")]
    TooManyChunks {
        /// Maximum allowed chunks.
        max: usize,
        /// Actual chunk count.
        actual: usize,
    },

    /// Message has expired.
    #[error("Message has expired (TTL exceeded)")]
    MessageExpired,

    /// Invalid message format.
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Chunk reassembly failed.
    #[error("Chunk reassembly failed: {0}")]
    ChunkReassembly(String),

    /// Invalid receipt.
    #[error("Invalid receipt: {0}")]
    InvalidReceipt(String),

    /// Group error.
    #[error("Group error: {0}")]
    Group(String),

    /// Group size exceeded.
    #[error("Group size exceeded: max {max}, got {actual}")]
    GroupSizeExceeded {
        /// Maximum allowed members.
        max: usize,
        /// Actual member count.
        actual: usize,
    },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Identity error.
    #[error("Identity error: {0}")]
    Identity(#[from] veritas_identity::IdentityError),
}

/// Result type for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;
