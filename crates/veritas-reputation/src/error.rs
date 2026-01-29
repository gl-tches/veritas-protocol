//! Error types for reputation operations.

use thiserror::Error;

/// Errors that can occur during reputation operations.
#[derive(Error, Debug)]
pub enum ReputationError {
    /// Identity not found.
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Insufficient reputation.
    #[error("Insufficient reputation: required {required}, have {actual}")]
    InsufficientReputation {
        /// Required reputation.
        required: u32,
        /// Actual reputation.
        actual: u32,
    },

    /// Identity is quarantined.
    #[error("Identity is quarantined")]
    Quarantined,

    /// Identity is blacklisted.
    #[error("Identity is blacklisted")]
    Blacklisted,

    /// Invalid report.
    #[error("Invalid report: {0}")]
    InvalidReport(String),

    // === VERITAS-2026-0010: New error types for interaction proof authentication ===

    /// Self-interaction is not allowed.
    ///
    /// Reputation cannot be gained from interactions with oneself.
    #[error("Self-interaction is not allowed")]
    SelfInteractionNotAllowed,

    /// Invalid signature in interaction proof.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Counter-signature required but not provided.
    ///
    /// Some interaction types require both parties to sign the proof.
    #[error("Counter-signature required but not provided")]
    MissingCounterSignature,

    /// Nonce has already been used (replay attack detected).
    #[error("Nonce has already been used")]
    NonceAlreadyUsed,

    /// Invalid interaction proof.
    #[error("Invalid interaction proof: {0}")]
    InvalidProof(String),

    /// Proof identity mismatch.
    ///
    /// The identities in the proof don't match the expected parties.
    #[error("Proof identity mismatch: expected {expected}, got {actual}")]
    ProofIdentityMismatch {
        /// Expected identity (hex).
        expected: String,
        /// Actual identity in proof (hex).
        actual: String,
    },
}

/// Result type for reputation operations.
pub type Result<T> = std::result::Result<T, ReputationError>;
