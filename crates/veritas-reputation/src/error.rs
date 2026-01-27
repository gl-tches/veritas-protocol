//! Error types for reputation operations.

use thiserror::Error;

/// Errors that can occur during reputation operations.
#[derive(Error, Debug)]
pub enum ReputationError {
    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {0}")]
    RateLimited(String),

    /// Insufficient reputation.
    #[error("Insufficient reputation: required {required}, have {actual}")]
    InsufficientReputation {
        /// Required reputation.
        required: u32,
        /// Actual reputation.
        actual: u32,
    },

    /// Identity quarantined.
    #[error("Identity quarantined due to low reputation")]
    Quarantined,

    /// Identity blacklisted.
    #[error("Identity blacklisted")]
    Blacklisted,

    /// Report rejected.
    #[error("Report rejected: {0}")]
    ReportRejected(String),

    /// Collusion detected.
    #[error("Collusion detected in cluster")]
    CollusionDetected,
}

/// Result type for reputation operations.
pub type Result<T> = std::result::Result<T, ReputationError>;
