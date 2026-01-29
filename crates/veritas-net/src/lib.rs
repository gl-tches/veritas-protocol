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
//! - Message sizes use fixed padding buckets (256/512/1024)
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
pub mod transport;
pub mod transport_manager;

pub use bluetooth::{BlePeer, BluetoothConfig, BluetoothRelay, BluetoothStats};
pub use dht::{
    compute_message_id, derive_dht_key, DhtConfig, DhtKey, DhtRecord, DhtRecordSet, DhtStorage,
    DhtStorageStats, DhtStorageStatsSnapshot, MessageId, DEFAULT_MAX_RECORD_SIZE,
    DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_REPLICATION_FACTOR,
};
pub use discovery::{DiscoveredPeer, DiscoveryConfig, DiscoveryEvent, LocalDiscovery};
pub use error::{NetError, Result};
pub use gossip::{
    BlockAnnouncement, GossipAnnouncement, GossipConfig, GossipManager, MessageAnnouncement,
    ReceiptAnnouncement, TOPIC_BLOCKS, TOPIC_MESSAGES, TOPIC_RECEIPTS,
};
pub use rate_limiter::{
    RateLimitConfig, RateLimitResult, RateLimiter, DEFAULT_BAN_DURATION_SECS,
    DEFAULT_BURST_MULTIPLIER, DEFAULT_GLOBAL_RATE, DEFAULT_PER_PEER_RATE,
    DEFAULT_VIOLATIONS_BEFORE_BAN,
};
pub use node::{
    peer_id_from_multiaddr, NodeBehaviour, NodeConfig, NodeEvent, VeritasNode,
    VERITAS_GOSSIPSUB_PREFIX, VERITAS_KAD_PROTOCOL,
};
pub use relay::{RelayConfig, RelayManager, RelayStats, RelayedMessage};
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
