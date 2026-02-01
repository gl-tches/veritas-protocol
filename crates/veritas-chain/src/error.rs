//! Error types for blockchain operations.

use thiserror::Error;

/// Errors that can occur during blockchain operations.
#[derive(Error, Debug)]
pub enum ChainError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),

    /// Block not found.
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    /// Invalid block.
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    /// Invalid block signature.
    ///
    /// SECURITY: This error indicates that a block's cryptographic signature
    /// could not be verified. This could be a forged block attack.
    /// See VERITAS-2026-0002.
    #[error("Invalid block signature: {0}")]
    InvalidSignature(String),

    /// Validator public key mismatch.
    ///
    /// SECURITY: The validator's public key does not derive to the claimed
    /// validator identity. This could indicate a validator impersonation attack.
    /// See VERITAS-2026-0002.
    #[error("Validator key mismatch: claimed {claimed}, derived {derived}")]
    ValidatorKeyMismatch {
        /// The claimed validator identity hash.
        claimed: String,
        /// The identity hash derived from the public key.
        derived: String,
    },

    /// Missing block signature.
    ///
    /// SECURITY: A block that requires a signature was submitted without one.
    /// Non-genesis blocks MUST be signed by an authorized validator.
    /// See VERITAS-2026-0002.
    #[error("Missing block signature: non-genesis blocks must be signed")]
    MissingSignature,

    /// Invalid proof.
    #[error("Invalid merkle proof")]
    InvalidProof,

    /// Empty tree.
    #[error("Cannot create merkle tree from empty leaves")]
    EmptyTree,

    /// Invalid leaf index.
    #[error("Leaf index {index} out of bounds (tree has {size} leaves)")]
    InvalidLeafIndex {
        /// The requested index.
        index: usize,
        /// The size of the tree.
        size: usize,
    },

    /// Chain is behind.
    #[error("Chain is behind by {blocks} blocks")]
    ChainBehind {
        /// Number of blocks behind.
        blocks: u64,
    },

    /// Fork detected.
    #[error("Fork detected at height {height}")]
    ForkDetected {
        /// Height where fork was detected.
        height: u64,
    },

    /// Validator error.
    #[error("Validator error: {0}")]
    Validator(String),

    /// Insufficient stake.
    #[error("Insufficient stake: required {required}, have {actual}")]
    InsufficientStake {
        /// Required stake.
        required: u32,
        /// Actual stake.
        actual: u32,
    },

    /// SLA violation.
    #[error("SLA violation: {0}")]
    SlaViolation(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Username already registered to a different identity.
    ///
    /// SECURITY (VERITAS-2026-0090): This error indicates that a username
    /// registration was rejected because another identity already owns
    /// this username. This prevents username impersonation attacks.
    #[error("Username already registered: {username} (owned by {owner})")]
    UsernameTaken {
        /// The username that was attempted to be registered.
        username: String,
        /// The hex-encoded identity hash of the current owner.
        owner: String,
    },

    /// Invalid username format or reserved username.
    ///
    /// SECURITY (VERITAS-2026-0090): This error indicates that a username
    /// failed validation (format, length, reserved name, etc.).
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
}

/// Result type for blockchain operations.
pub type Result<T> = std::result::Result<T, ChainError>;
