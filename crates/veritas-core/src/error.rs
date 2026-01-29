//! Error types for core operations.

use thiserror::Error;

use crate::time::TimeError;

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

    /// Time validation error.
    #[error("Time error: {0}")]
    Time(#[from] TimeError),

    /// Not initialized.
    #[error("Client not initialized")]
    NotInitialized,

    /// Already initialized.
    #[error("Client already initialized")]
    AlreadyInitialized,

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Client is locked.
    #[error("Client is locked - call unlock() first")]
    Locked,

    /// Client is shutting down.
    #[error("Client is shutting down")]
    ShuttingDown,

    /// Invalid client state for operation.
    #[error("Invalid state for operation: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// No primary identity set.
    #[error("No primary identity set - create or set an identity first")]
    NoPrimaryIdentity,

    /// Identity not found.
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    /// Authentication failed.
    #[error("Authentication failed: incorrect password")]
    AuthenticationFailed,

    /// Feature not implemented.
    #[error("Feature not yet implemented: {0}")]
    NotImplemented(String),
}

/// Result type for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
