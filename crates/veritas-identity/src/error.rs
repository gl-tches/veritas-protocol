//! Error types for identity operations.

use thiserror::Error;

/// Errors that can occur during identity operations.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// Identity creation failed.
    #[error("Identity creation failed: {0}")]
    Creation(String),

    /// Identity not found.
    #[error("Identity not found: {0}")]
    NotFound(String),

    /// Identity has expired.
    #[error("Identity has expired")]
    Expired,

    /// Identity has been revoked.
    #[error("Identity has been revoked")]
    Revoked,

    /// Invalid username format.
    #[error("Invalid username: {0}")]
    InvalidUsername(String),

    /// Username already taken.
    #[error("Username already taken: {0}")]
    UsernameTaken(String),

    /// Maximum identities per origin reached.
    #[error("Maximum identities ({max}) per origin reached")]
    MaxIdentitiesReached {
        /// Maximum allowed identities.
        max: u32,
    },

    /// Key rotation failed.
    #[error("Key rotation failed: {0}")]
    RotationFailed(String),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),
}

/// Result type for identity operations.
pub type Result<T> = std::result::Result<T, IdentityError>;
