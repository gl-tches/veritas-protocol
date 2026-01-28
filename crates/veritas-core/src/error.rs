//! Error types for core operations.

use thiserror::Error;

/// Errors that can occur during core operations.
#[derive(Error, Debug)]
pub enum CoreError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
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

    /// Not initialized.
    #[error("Client not initialized")]
    NotInitialized,

    /// Already initialized.
    #[error("Client already initialized")]
    AlreadyInitialized,

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
