//! Error types for high-level API operations.

use thiserror::Error;

/// Errors that can occur during high-level API operations.
#[derive(Error, Debug)]
pub enum CoreError {
    /// Client not initialized.
    #[error("Client not initialized")]
    NotInitialized,

    /// No identity loaded.
    #[error("No identity loaded")]
    NoIdentity,

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Recipient not found.
    #[error("Recipient not found")]
    RecipientNotFound,

    /// Message verification failed.
    #[error("Message verification failed")]
    VerificationFailed,

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] veritas_crypto::CryptoError),

    /// Identity error.
    #[error("Identity error: {0}")]
    Identity(#[from] veritas_identity::IdentityError),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),

    /// Chain error.
    #[error("Chain error: {0}")]
    Chain(#[from] veritas_chain::ChainError),

    /// Network error.
    #[error("Network error: {0}")]
    Net(#[from] veritas_net::NetError),

    /// Storage error.
    #[error("Storage error: {0}")]
    Store(#[from] veritas_store::StoreError),

    /// Reputation error.
    #[error("Reputation error: {0}")]
    Reputation(#[from] veritas_reputation::ReputationError),
}

/// Result type for high-level API operations.
pub type Result<T> = std::result::Result<T, CoreError>;
