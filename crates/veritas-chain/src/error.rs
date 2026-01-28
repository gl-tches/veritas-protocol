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
}

/// Result type for blockchain operations.
pub type Result<T> = std::result::Result<T, ChainError>;
