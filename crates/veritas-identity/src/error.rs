//! Error types for identity operations.

use thiserror::Error;

/// Errors that can occur during identity operations.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Identity not found.
    #[error("Identity not found: {0}")]
    NotFound(String),

    /// Identity already exists.
    #[error("Identity already exists")]
    AlreadyExists,

    /// Invalid username format.
    #[error("Invalid username: {reason}")]
    InvalidUsername {
        /// Reason for invalidity.
        reason: String,
    },

    /// Username already taken.
    #[error("Username already taken: {0}")]
    UsernameTaken(String),

    /// Identity expired.
    #[error("Identity has expired")]
    Expired,

    /// Identity revoked.
    #[error("Identity has been revoked")]
    Revoked,

    /// Maximum identities per origin reached.
    #[error("Maximum identities ({max}) per origin reached")]
    MaxIdentitiesReached {
        /// Maximum allowed identities.
        max: u32,
    },

    /// Invalid key state transition.
    #[error("Invalid key state transition: {from} -> {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Attempted state.
        to: String,
    },

    /// Hardware attestation verification failed.
    #[error("Hardware attestation failed: {reason}")]
    HardwareAttestationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// No supported hardware available for attestation.
    #[error("Hardware not available: {reason}")]
    HardwareNotAvailable {
        /// Reason hardware is unavailable.
        reason: String,
    },

    /// Origin fingerprint requires hardware attestation.
    #[error("Origin fingerprint requires hardware attestation in production")]
    HardwareAttestationRequired,
}

/// Result type for identity operations.
pub type Result<T> = std::result::Result<T, IdentityError>;
