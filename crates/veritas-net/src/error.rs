//! Error types for networking operations.

use thiserror::Error;

/// Errors that can occur during networking operations.
#[derive(Error, Debug)]
pub enum NetError {
    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] veritas_protocol::ProtocolError),

    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// No transport available.
    #[error("No transport available")]
    NoTransport,

    /// Transport error.
    #[error("Transport error: {0}")]
    Transport(String),

    /// DHT operation failed.
    #[error("DHT error: {0}")]
    Dht(String),

    /// Gossip error.
    #[error("Gossip error: {0}")]
    Gossip(String),

    /// Message delivery failed.
    #[error("Message delivery failed: {0}")]
    DeliveryFailed(String),

    /// Timeout.
    #[error("Operation timed out")]
    Timeout,

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for networking operations.
pub type Result<T> = std::result::Result<T, NetError>;
