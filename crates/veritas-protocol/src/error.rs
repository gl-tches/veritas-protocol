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

    /// Invalid chunk index.
    #[error("Invalid chunk index: {index} >= total {total}")]
    InvalidChunkIndex {
        /// The invalid index.
        index: u8,
        /// Total number of chunks.
        total: u8,
    },

    /// Chunk hash mismatch during verification.
    #[error("Chunk hash mismatch for chunk {chunk_index}")]
    ChunkHashMismatch {
        /// Index of the corrupted chunk.
        chunk_index: u8,
    },

    /// Reassembled message hash doesn't match expected hash.
    #[error("Reassembled message hash does not match expected hash")]
    MessageHashMismatch,

    /// Incomplete message (not all chunks received).
    #[error("Incomplete message: received {received} of {expected} chunks")]
    IncompleteMessage {
        /// Number of chunks received.
        received: usize,
        /// Total chunks expected.
        expected: usize,
    },

    /// Too many pending reassembly sessions (DoS prevention).
    #[error("Too many pending reassembly sessions: {current} exceeds maximum {max}")]
    TooManyPendingSessions {
        /// Current number of pending sessions.
        current: usize,
        /// Maximum allowed sessions.
        max: usize,
    },

    /// Reassembly buffer size exceeded (DoS prevention).
    #[error("Reassembly buffer size exceeded: {size} bytes exceeds maximum {max} bytes")]
    ReassemblyBufferExceeded {
        /// Current buffer size in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
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

    // === Group Errors ===
    /// Group is full.
    #[error("Group is full: max {max} members")]
    GroupFull {
        /// Maximum allowed members.
        max: usize,
    },

    /// Member already in group.
    #[error("Member already in group")]
    MemberAlreadyInGroup,

    /// Member not in group.
    #[error("Member not in group")]
    MemberNotInGroup,

    /// Not authorized to perform group operation.
    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    /// Cannot remove the last admin from a group.
    #[error("Cannot remove the last admin from group")]
    CannotRemoveLastAdmin,

    /// Invalid group key generation.
    #[error("Invalid key generation: expected {expected}, got {actual}")]
    InvalidKeyGeneration {
        /// Expected generation.
        expected: u32,
        /// Actual generation.
        actual: u32,
    },

    /// Group not found.
    #[error("Group not found")]
    GroupNotFound,
}

/// Result type for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;
