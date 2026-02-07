//! # veritas-net
//!
//! P2P networking layer for VERITAS protocol.
//!
//! Provides:
//! - Network-first transport selection
//! - libp2p integration (DHT, Gossipsub)
//! - Local network discovery (mDNS)
//! - Bluetooth relay transport
//! - Store-and-forward for offline peers
//!
//! ## Transport Selection
//!
//! The transport manager implements a strict priority order:
//!
//! 1. **Internet first**: Always prefer direct internet connectivity
//! 2. **Local WiFi relay**: Fall back to mDNS-discovered local peers
//! 3. **Bluetooth relay**: BLE as pure relay (no PIN, no pairing)
//! 4. **Queue locally**: Store messages for later delivery
//!
//! ## Gossip Protocol
//!
//! The gossip module provides privacy-preserving message announcements:
//!
//! - Messages are announced via derived mailbox keys, not recipient identities
//! - Timestamps use hourly buckets to hide exact send times
//! - Message sizes use fixed padding buckets (1024/2048/4096/8192)
//!
//! See [`gossip::GossipManager`] for the main interface.
//!
//! ## Security Model
//!
//! All transports are treated as untrusted relays. Security comes from
//! end-to-end encryption, not transport-layer security. Bluetooth
//! specifically requires NO PIN or pairing - it's a pure relay.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod bluetooth;
pub mod dht;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod node;
pub mod rate_limiter;
pub mod relay;
pub mod subnet_limiter;
pub mod transport;
pub mod transport_manager;

pub use bluetooth::{BlePeer, BluetoothConfig, BluetoothRelay, BluetoothStats};
pub use dht::{
    DEFAULT_MAX_RECORD_SIZE, DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_REPLICATION_FACTOR, DhtConfig,
    DhtKey, DhtRecord, DhtRecordSet, DhtStorage, DhtStorageStats, DhtStorageStatsSnapshot,
    MessageId, compute_message_id, derive_dht_key,
};
pub use discovery::{DiscoveredPeer, DiscoveryConfig, DiscoveryEvent, LocalDiscovery};
pub use error::{NetError, Result};
pub use gossip::{
    BlockAnnouncement, GossipAnnouncement, GossipConfig, GossipManager, MessageAnnouncement,
    ReceiptAnnouncement, TOPIC_BLOCKS, TOPIC_MESSAGES, TOPIC_RECEIPTS,
};
pub use node::{
    NodeBehaviour, NodeConfig, NodeEvent, VERITAS_GOSSIPSUB_PREFIX, VERITAS_KAD_PROTOCOL,
    VeritasNode, peer_id_from_multiaddr,
};
pub use rate_limiter::{
    DEFAULT_BAN_DURATION_SECS, DEFAULT_BURST_MULTIPLIER, DEFAULT_GLOBAL_RATE,
    DEFAULT_PER_PEER_RATE, DEFAULT_VIOLATIONS_BEFORE_BAN, RateLimitConfig, RateLimitResult,
    RateLimiter,
};
pub use relay::{RelayConfig, RelayManager, RelayStats, RelayedMessage};
pub use subnet_limiter::{
    MAX_PEERS_PER_SUBNET, PeerAcceptResult, SUBNET_MASK_V4, SUBNET_MASK_V6, SubnetKey,
    SubnetLimiter, SubnetLimiterConfig, SubnetLimiterStats, SubnetLimiterStatsSnapshot,
};
pub use transport::{
    NetworkAddress, PeerInfo, SelectionReason, Transport, TransportCapabilities, TransportConfig,
    TransportSelection, TransportSelector, TransportState,
};
pub use transport_manager::{
    BluetoothTransport, BoxFuture, InternetTransport, LocalTransport, TransportManager,
    TransportManagerConfig, TransportStats, TransportStatus, TransportType,
};

// Re-export common libp2p types for convenience
pub use libp2p::{Multiaddr, PeerId};
