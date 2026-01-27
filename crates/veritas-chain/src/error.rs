//! Error types for blockchain operations.

use thiserror::Error;

/// Errors that can occur during blockchain operations.
#[derive(Error, Debug)]
pub enum ChainError {
    /// Block validation failed.
    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    /// Invalid block hash.
    #[error("Invalid block hash")]
    InvalidBlockHash,

    /// Invalid previous block reference.
    #[error("Invalid previous block reference")]
    InvalidPreviousBlock,

    /// Invalid Merkle proof.
    #[error("Invalid Merkle proof")]
    InvalidMerkleProof,

    /// Block not found.
    #[error("Block not found at height {height}")]
    BlockNotFound {
        /// Requested block height.
        height: u64,
    },

    /// Chain sync failed.
    #[error("Chain sync failed: {0}")]
    SyncFailed(String),

    /// Validator not found.
    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),

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

    /// Double signing detected.
    #[error("Double signing detected")]
    DoubleSigning,

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),
}

/// Result type for blockchain operations.
pub type Result<T> = std::result::Result<T, ChainError>;
