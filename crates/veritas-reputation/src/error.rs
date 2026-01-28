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
}

/// Result type for reputation operations.
pub type Result<T> = std::result::Result<T, ReputationError>;
