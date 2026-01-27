//! Error types for networking operations.

use thiserror::Error;

/// Errors that can occur during networking operations.
#[derive(Error, Debug)]
pub enum NetError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    Connection(String),

    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// No transport available.
    #[error("No transport available")]
    NoTransport,

    /// DHT operation failed.
    #[error("DHT operation failed: {0}")]
    Dht(String),

    /// Gossip operation failed.
    #[error("Gossip operation failed: {0}")]
    Gossip(String),

    /// mDNS discovery failed.
    #[error("mDNS discovery failed: {0}")]
    Mdns(String),

    /// Bluetooth error.
    #[error("Bluetooth error: {0}")]
    Bluetooth(String),

    /// Message relay failed.
    #[error("Message relay failed: {0}")]
    Relay(String),

    /// Timeout.
    #[error("Operation timed out")]
    Timeout,

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),

    /// Reputation error.
    #[error("Reputation error: {0}")]
    Reputation(#[from] veritas_reputation::ReputationError),
}

/// Result type for networking operations.
pub type Result<T> = std::result::Result<T, NetError>;
