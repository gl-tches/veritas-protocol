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

    /// Node not started.
    #[error("Node not started")]
    NodeNotStarted,

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Subscription error.
    #[error("Subscription error: {0}")]
    Subscription(String),

    /// Relay error.
    #[error("Relay error: {0}")]
    Relay(String),

    /// Message too large.
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Hop limit exceeded.
    #[error("Hop limit exceeded: {hops} (max: {max})")]
    HopLimitExceeded {
        /// Current hop count.
        hops: u8,
        /// Maximum allowed hops.
        max: u8,
    },

    /// Discovery error.
    #[error("Discovery error: {0}")]
    Discovery(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Channel closed.
    #[error("Channel closed")]
    ChannelClosed,

    /// Swarm error.
    #[error("Swarm error: {0}")]
    Swarm(String),

    /// Dial error.
    #[error("Dial error: {0}")]
    Dial(String),

    /// Listen error.
    #[error("Listen error: {0}")]
    Listen(String),

    /// Peer is banned.
    #[error("Peer is banned: {0}")]
    PeerBanned(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
}

/// Result type for networking operations.
pub type Result<T> = std::result::Result<T, NetError>;
