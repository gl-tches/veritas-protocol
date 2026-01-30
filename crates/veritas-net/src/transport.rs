//! Transport abstraction layer for VERITAS networking.
//!
//! This module provides the core transport abstractions that enable network-first
//! transport selection with automatic fallback through the transport priority chain:
//!
//! 1. **Internet** - Direct libp2p connections (TCP, WebSocket, QUIC)
//! 2. **LocalNetwork** - Local WiFi/LAN via mDNS discovery
//! 3. **Bluetooth** - BLE relay for offline scenarios (pure relay, no security boundary)
//! 4. **Queued** - Local storage when no connectivity available
//!
//! # Design Principles
//!
//! - **Network-first**: Always attempt Internet connectivity before falling back
//! - **Bluetooth is relay only**: BLE provides no security guarantees; all security
//!   comes from end-to-end encryption at the protocol layer
//! - **No PIN/pairing for BLE**: Any VERITAS node can relay messages
//! - **Minimal metadata leakage**: Transport layer sees only mailbox keys, not identities
//!
//! # Example
//!
//! ```ignore
//! use veritas_net::transport::{TransportSelector, TransportType};
//!
//! let selector = TransportSelector::new(config).await?;
//! let transport = selector.select_transport().await;
//!
//! match transport {
//!     TransportType::Internet => { /* Use libp2p directly */ }
//!     TransportType::LocalNetwork => { /* Use mDNS peers */ }
//!     TransportType::Bluetooth => { /* Use BLE relay */ }
//!     TransportType::Queued => { /* Store locally for later */ }
//! }
//! ```

use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};

// Re-export libp2p's core types that we wrap
pub use libp2p::Multiaddr;

/// Wrapper around libp2p's PeerId providing VERITAS-specific functionality.
///
/// This type wraps the underlying libp2p peer identifier to provide a stable
/// interface and additional serialization support needed by VERITAS.
///
/// # Security Note
///
/// `PeerId` identifies transport-layer peers, NOT VERITAS identities. A single
/// VERITAS identity may connect from multiple `PeerId`s, and a single device
/// may host multiple VERITAS identities. Never use `PeerId` for identity verification.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerId(libp2p::PeerId);

impl PeerId {
    /// Creates a new `PeerId` from the underlying libp2p type.
    #[inline]
    pub fn new(inner: libp2p::PeerId) -> Self {
        Self(inner)
    }

    /// Returns a reference to the underlying libp2p `PeerId`.
    #[inline]
    pub fn inner(&self) -> &libp2p::PeerId {
        &self.0
    }

    /// Consumes self and returns the underlying libp2p `PeerId`.
    #[inline]
    pub fn into_inner(self) -> libp2p::PeerId {
        self.0
    }

    /// Converts the peer ID to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Attempts to create a `PeerId` from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid peer ID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        libp2p::PeerId::from_bytes(bytes)
            .map(Self)
            .map_err(|e| NetError::Transport(format!("Invalid peer ID bytes: {}", e)))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<libp2p::PeerId> for PeerId {
    fn from(inner: libp2p::PeerId) -> Self {
        Self(inner)
    }
}

impl From<PeerId> for libp2p::PeerId {
    fn from(peer_id: PeerId) -> Self {
        peer_id.0
    }
}

impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_base58())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<libp2p::PeerId>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Network address representation supporting multiple address formats.
///
/// Wraps libp2p's `Multiaddr` to provide a unified address type for all
/// transport types (Internet, local network, Bluetooth).
///
/// # Supported Formats
///
/// - `/ip4/1.2.3.4/tcp/4001` - IPv4 TCP
/// - `/ip6/::1/tcp/4001` - IPv6 TCP
/// - `/dns4/example.com/tcp/443/wss` - DNS WebSocket Secure
/// - `/ip4/192.168.1.1/udp/4001/quic-v1` - QUIC
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NetworkAddress(Multiaddr);

impl NetworkAddress {
    /// Creates a new `NetworkAddress` from a `Multiaddr`.
    #[inline]
    pub fn new(addr: Multiaddr) -> Self {
        Self(addr)
    }

    /// Parses a network address from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid multiaddress.
    pub fn parse(s: &str) -> Result<Self> {
        s.parse::<Multiaddr>()
            .map(Self)
            .map_err(|e| NetError::Transport(format!("Invalid address: {}", e)))
    }

    /// Returns a reference to the underlying `Multiaddr`.
    #[inline]
    pub fn inner(&self) -> &Multiaddr {
        &self.0
    }

    /// Consumes self and returns the underlying `Multiaddr`.
    #[inline]
    pub fn into_inner(self) -> Multiaddr {
        self.0
    }

    /// Checks if this is a loopback address.
    pub fn is_loopback(&self) -> bool {
        self.0.iter().any(|p| {
            matches!(p, libp2p::multiaddr::Protocol::Ip4(ip) if ip.is_loopback())
                || matches!(p, libp2p::multiaddr::Protocol::Ip6(ip) if ip.is_loopback())
        })
    }

    /// Checks if this is a private/local network address.
    ///
    /// For IPv4, checks RFC 1918 private ranges.
    /// For IPv6, checks loopback and link-local addresses.
    pub fn is_private(&self) -> bool {
        self.0.iter().any(|p| {
            match p {
                libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_private(),
                libp2p::multiaddr::Protocol::Ip6(ip) => {
                    // Check common non-global IPv6 addresses
                    // Loopback (::1) or link-local (fe80::/10)
                    ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80
                }
                _ => false,
            }
        })
    }

    /// Appends a peer ID to this address, creating a full peer address.
    pub fn with_peer_id(self, peer_id: &PeerId) -> Self {
        Self(
            self.0
                .with(libp2p::multiaddr::Protocol::P2p(*peer_id.inner())),
        )
    }
}

impl fmt::Debug for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkAddress({})", self.0)
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Multiaddr> for NetworkAddress {
    fn from(addr: Multiaddr) -> Self {
        Self(addr)
    }
}

impl From<NetworkAddress> for Multiaddr {
    fn from(addr: NetworkAddress) -> Self {
        addr.0
    }
}

impl Serialize for NetworkAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Multiaddr>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Transport type indicating the communication channel to use.
///
/// Transport selection follows a strict priority order (network-first):
///
/// 1. `Internet` - Always preferred when available
/// 2. `LocalNetwork` - WiFi/LAN fallback
/// 3. `Bluetooth` - BLE relay when no IP connectivity
/// 4. `Queued` - Local storage when completely offline
///
/// # Security Model
///
/// All transports are treated as untrusted channels. Security is provided by
/// end-to-end encryption at the protocol layer, NOT by transport security:
///
/// - **Internet**: Noise protocol encryption (libp2p) + VERITAS E2E
/// - **LocalNetwork**: Same as Internet
/// - **Bluetooth**: NO transport security - pure relay, VERITAS E2E only
/// - **Queued**: Local encryption at rest
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    /// Internet connectivity via libp2p (TCP, WebSocket, QUIC).
    ///
    /// This is the preferred transport when available. Uses libp2p's Noise
    /// protocol for transport encryption on top of VERITAS E2E encryption.
    Internet,

    /// Local network connectivity via mDNS discovery.
    ///
    /// Used when Internet is unavailable but local network peers exist.
    /// Peers on the same WiFi/LAN can discover each other and relay messages.
    LocalNetwork,

    /// Bluetooth Low Energy relay transport.
    ///
    /// # Security Warning
    ///
    /// BLE is a **pure relay** transport with NO security guarantees:
    /// - No PIN verification required
    /// - No pairing required
    /// - Any VERITAS node can relay messages
    /// - All security comes from VERITAS E2E encryption
    ///
    /// BLE is NOT a security boundary - it merely extends network reach.
    Bluetooth,

    /// Message queued locally for later delivery.
    ///
    /// Used when no network connectivity is available. Messages are stored
    /// locally and transmitted when connectivity is restored.
    Queued,
}

impl TransportType {
    /// Returns the priority of this transport (lower = higher priority).
    ///
    /// Used for transport selection ordering.
    #[inline]
    pub const fn priority(&self) -> u8 {
        match self {
            TransportType::Internet => 0,
            TransportType::LocalNetwork => 1,
            TransportType::Bluetooth => 2,
            TransportType::Queued => 3,
        }
    }

    /// Returns whether this transport provides real-time delivery.
    ///
    /// `Queued` transport does not provide real-time delivery.
    #[inline]
    pub const fn is_realtime(&self) -> bool {
        !matches!(self, TransportType::Queued)
    }

    /// Returns whether this transport can reach external (non-local) peers.
    #[inline]
    pub const fn can_reach_external(&self) -> bool {
        matches!(self, TransportType::Internet)
    }

    /// Returns the capabilities of this transport type.
    pub const fn capabilities(&self) -> TransportCapabilities {
        match self {
            TransportType::Internet => TransportCapabilities::INTERNET,
            TransportType::LocalNetwork => TransportCapabilities::LOCAL_NETWORK,
            TransportType::Bluetooth => TransportCapabilities::BLUETOOTH,
            TransportType::Queued => TransportCapabilities::QUEUED,
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Internet => write!(f, "Internet"),
            TransportType::LocalNetwork => write!(f, "Local Network"),
            TransportType::Bluetooth => write!(f, "Bluetooth"),
            TransportType::Queued => write!(f, "Queued"),
        }
    }
}

/// Connection status for a transport.
///
/// Represents the current state of a transport's connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    /// Transport is not initialized or available on this platform.
    Unavailable,

    /// Transport is initialized but not connected.
    Disconnected,

    /// Transport is attempting to connect.
    Connecting,

    /// Transport is connected and ready for use.
    Connected,

    /// Transport is connected but experiencing issues.
    Degraded,

    /// Transport connection failed with an error.
    Error,
}

impl TransportStatus {
    /// Returns whether this status indicates the transport can send messages.
    #[inline]
    pub const fn can_send(&self) -> bool {
        matches!(self, TransportStatus::Connected | TransportStatus::Degraded)
    }

    /// Returns whether this status indicates the transport is attempting connection.
    #[inline]
    pub const fn is_connecting(&self) -> bool {
        matches!(self, TransportStatus::Connecting)
    }

    /// Returns whether this status indicates a problem.
    #[inline]
    pub const fn has_error(&self) -> bool {
        matches!(self, TransportStatus::Error | TransportStatus::Unavailable)
    }
}

impl fmt::Display for TransportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportStatus::Unavailable => write!(f, "Unavailable"),
            TransportStatus::Disconnected => write!(f, "Disconnected"),
            TransportStatus::Connecting => write!(f, "Connecting"),
            TransportStatus::Connected => write!(f, "Connected"),
            TransportStatus::Degraded => write!(f, "Degraded"),
            TransportStatus::Error => write!(f, "Error"),
        }
    }
}

/// Capabilities and constraints of a transport type.
///
/// Describes what each transport can and cannot do, used for transport
/// selection and routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCapabilities {
    /// Whether the transport supports real-time bidirectional communication.
    pub realtime: bool,

    /// Whether the transport can reach peers outside the local network.
    pub external_reach: bool,

    /// Whether the transport supports DHT operations.
    pub supports_dht: bool,

    /// Whether the transport supports gossip/pubsub.
    pub supports_gossip: bool,

    /// Whether the transport requires peer discovery.
    pub requires_discovery: bool,

    /// Maximum message size in bytes (0 = unlimited).
    pub max_message_size: usize,

    /// Typical latency in milliseconds (0 = unknown/variable).
    pub typical_latency_ms: u32,

    /// Whether the transport provides any transport-layer encryption.
    ///
    /// Note: Even if `false`, VERITAS E2E encryption always applies.
    pub transport_encrypted: bool,

    /// Whether messages may be relayed through untrusted intermediaries.
    pub may_be_relayed: bool,

    /// Estimated battery impact (0-100, where 100 is highest impact).
    pub battery_impact: u8,
}

impl TransportCapabilities {
    /// Capabilities for Internet transport.
    pub const INTERNET: Self = Self {
        realtime: true,
        external_reach: true,
        supports_dht: true,
        supports_gossip: true,
        requires_discovery: false,
        max_message_size: 0, // Unlimited (chunked)
        typical_latency_ms: 100,
        transport_encrypted: true, // Noise protocol
        may_be_relayed: true,      // DHT routing
        battery_impact: 20,
    };

    /// Capabilities for local network transport.
    pub const LOCAL_NETWORK: Self = Self {
        realtime: true,
        external_reach: false,
        supports_dht: true,
        supports_gossip: true,
        requires_discovery: true, // mDNS required
        max_message_size: 0,
        typical_latency_ms: 10,
        transport_encrypted: true, // Noise protocol
        may_be_relayed: true,
        battery_impact: 15,
    };

    /// Capabilities for Bluetooth transport.
    ///
    /// # Security Note
    ///
    /// `transport_encrypted` is `false` because BLE is treated as a pure
    /// relay with no security guarantees. Security comes from VERITAS E2E only.
    pub const BLUETOOTH: Self = Self {
        realtime: true,
        external_reach: false,
        supports_dht: false,
        supports_gossip: false,
        requires_discovery: true, // BLE scanning required
        max_message_size: 512,    // BLE MTU constraints
        typical_latency_ms: 50,
        transport_encrypted: false, // NO transport security - relay only
        may_be_relayed: true,
        battery_impact: 40,
    };

    /// Capabilities for queued (offline) transport.
    pub const QUEUED: Self = Self {
        realtime: false,
        external_reach: false,
        supports_dht: false,
        supports_gossip: false,
        requires_discovery: false,
        max_message_size: 0,
        typical_latency_ms: 0, // Unknown - depends on reconnection
        transport_encrypted: false,
        may_be_relayed: false,
        battery_impact: 0,
    };
}

/// Information about a discovered or connected peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's identifier.
    pub peer_id: PeerId,

    /// Known addresses for this peer.
    pub addresses: Vec<NetworkAddress>,

    /// Transport types this peer is reachable via.
    pub transports: Vec<TransportType>,

    /// Current connection status with this peer.
    pub status: TransportStatus,

    /// When this peer was first discovered.
    pub discovered_at: u64,

    /// When we last successfully communicated with this peer.
    pub last_seen: Option<u64>,

    /// Observed round-trip latency in milliseconds.
    pub latency_ms: Option<u32>,

    /// Protocol version reported by this peer.
    pub protocol_version: Option<String>,
}

impl PeerInfo {
    /// Creates a new `PeerInfo` with minimal information.
    pub fn new(peer_id: PeerId, discovered_at: u64) -> Self {
        Self {
            peer_id,
            addresses: Vec::new(),
            transports: Vec::new(),
            status: TransportStatus::Disconnected,
            discovered_at,
            last_seen: None,
            latency_ms: None,
            protocol_version: None,
        }
    }

    /// Returns the best transport to use for this peer.
    ///
    /// Selects based on transport priority (Internet > LocalNetwork > Bluetooth).
    pub fn best_transport(&self) -> Option<TransportType> {
        self.transports.iter().min_by_key(|t| t.priority()).copied()
    }

    /// Returns whether this peer is currently reachable.
    pub fn is_reachable(&self) -> bool {
        self.status.can_send() && !self.transports.is_empty()
    }
}

/// Configuration for transport behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Timeout for connection attempts.
    pub connect_timeout: Duration,

    /// Timeout for individual send operations.
    pub send_timeout: Duration,

    /// Maximum number of connection retry attempts.
    pub max_retries: u32,

    /// Base delay between retry attempts (exponential backoff applied).
    pub retry_base_delay: Duration,

    /// Whether to enable Internet transport.
    pub enable_internet: bool,

    /// Whether to enable local network (mDNS) transport.
    pub enable_local_network: bool,

    /// Whether to enable Bluetooth transport.
    pub enable_bluetooth: bool,

    /// Whether to enable message queueing when offline.
    pub enable_queue: bool,

    /// Maximum size of the offline message queue.
    pub max_queue_size: usize,

    /// How long to keep queued messages before expiring.
    pub queue_ttl: Duration,

    /// Bootstrap nodes for initial network connection.
    pub bootstrap_nodes: Vec<NetworkAddress>,

    /// Listen addresses for incoming connections.
    pub listen_addresses: Vec<NetworkAddress>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            send_timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_base_delay: Duration::from_millis(500),
            enable_internet: true,
            enable_local_network: true,
            enable_bluetooth: true,
            enable_queue: true,
            max_queue_size: 1000,
            queue_ttl: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            bootstrap_nodes: Vec::new(),
            listen_addresses: Vec::new(),
        }
    }
}

/// Result of a transport selection decision.
#[derive(Debug, Clone)]
pub struct TransportSelection {
    /// The selected transport type.
    pub transport: TransportType,

    /// Why this transport was selected.
    pub reason: SelectionReason,

    /// Alternative transports that could be used.
    pub alternatives: Vec<TransportType>,
}

/// Reason for transport selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionReason {
    /// Transport selected because it has highest priority and is available.
    HighestPriorityAvailable,

    /// Higher priority transports are not available.
    FallbackFromHigherPriority,

    /// Specifically requested by the caller.
    ExplicitRequest,

    /// Required for the operation (e.g., DHT requires Internet).
    RequiredForOperation,

    /// Only available option.
    OnlyOption,
}

/// Trait for transport implementations.
///
/// Each transport type (Internet, LocalNetwork, Bluetooth, Queue) implements
/// this trait to provide a unified interface for the transport selector.
///
/// # Implementors
///
/// - `InternetTransport` - libp2p-based Internet connectivity
/// - `LocalNetworkTransport` - mDNS-based local discovery
/// - `BluetoothTransport` - BLE relay (platform-specific)
/// - `QueueTransport` - Local message queue
///
/// # Object Safety
///
/// This trait uses async methods and is NOT object-safe by default. For dynamic
/// dispatch, implementors should use the `async_trait` crate or use the
/// state-based `TransportSelector` which tracks transport availability via
/// `TransportState`.
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    /// Returns the transport type.
    fn transport_type(&self) -> TransportType;

    /// Returns the current status of this transport.
    async fn status(&self) -> TransportStatus;

    /// Checks if this transport is currently connected and can send messages.
    async fn is_connected(&self) -> bool {
        self.status().await.can_send()
    }

    /// Checks if any peers are available via this transport.
    async fn has_peers(&self) -> bool;

    /// Returns the list of currently connected peers.
    async fn connected_peers(&self) -> Vec<PeerInfo>;

    /// Returns the number of connected peers.
    async fn peer_count(&self) -> usize {
        self.connected_peers().await.len()
    }

    /// Attempts to establish connectivity.
    ///
    /// For Internet transport, this means connecting to bootstrap nodes.
    /// For LocalNetwork, this starts mDNS discovery.
    /// For Bluetooth, this starts BLE scanning.
    /// For Queue, this is a no-op.
    async fn connect(&self) -> Result<()>;

    /// Disconnects from all peers and stops the transport.
    async fn disconnect(&self) -> Result<()>;

    /// Returns the capabilities of this transport.
    fn capabilities(&self) -> TransportCapabilities {
        self.transport_type().capabilities()
    }
}

/// State of individual transport availability.
///
/// Used by `TransportSelector` to track which transports are available
/// without requiring dynamic dispatch on the `Transport` trait.
#[derive(Debug, Clone, Default)]
pub struct TransportState {
    /// Whether Internet transport is available/connected.
    pub internet_connected: bool,

    /// Number of Internet peers.
    pub internet_peer_count: usize,

    /// Whether local network has available peers.
    pub local_has_peers: bool,

    /// Number of local network peers.
    pub local_peer_count: usize,

    /// Whether Bluetooth has available peers.
    pub bluetooth_has_peers: bool,

    /// Number of Bluetooth peers.
    pub bluetooth_peer_count: usize,
}

impl TransportState {
    /// Creates a new transport state with all transports unavailable.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates Internet transport state.
    pub fn set_internet(&mut self, connected: bool, peer_count: usize) {
        self.internet_connected = connected;
        self.internet_peer_count = peer_count;
    }

    /// Updates local network transport state.
    pub fn set_local(&mut self, has_peers: bool, peer_count: usize) {
        self.local_has_peers = has_peers;
        self.local_peer_count = peer_count;
    }

    /// Updates Bluetooth transport state.
    pub fn set_bluetooth(&mut self, has_peers: bool, peer_count: usize) {
        self.bluetooth_has_peers = has_peers;
        self.bluetooth_peer_count = peer_count;
    }

    /// Returns total peer count across all transports.
    pub fn total_peers(&self) -> usize {
        self.internet_peer_count + self.local_peer_count + self.bluetooth_peer_count
    }

    /// Returns whether any real-time transport is available.
    pub fn any_available(&self) -> bool {
        self.internet_connected || self.local_has_peers || self.bluetooth_has_peers
    }
}

/// Selector for choosing the best available transport.
///
/// Implements the network-first transport selection strategy defined in CLAUDE.md:
///
/// 1. Always try Internet first
/// 2. Fall back to local WiFi relay
/// 3. Fall back to Bluetooth relay
/// 4. Queue locally if nothing else available
///
/// # Design
///
/// This selector uses a state-based approach rather than dynamic dispatch
/// on transport trait objects. Transport backends update the `TransportState`
/// through message passing, and the selector reads this state to make decisions.
///
/// # Example
///
/// ```ignore
/// use veritas_net::transport::{TransportSelector, TransportConfig, TransportState};
///
/// let config = TransportConfig::default();
/// let selector = TransportSelector::new(config);
///
/// // Update state from transport backends
/// selector.update_state(|state| {
///     state.set_internet(true, 5);
/// }).await;
///
/// // Select best transport
/// let selection = selector.select_transport().await;
/// println!("Using {} because {:?}", selection.transport, selection.reason);
/// ```
pub struct TransportSelector {
    /// Current state of all transports.
    state: Arc<tokio::sync::RwLock<TransportState>>,

    /// Configuration for transport selection.
    config: TransportConfig,
}

impl TransportSelector {
    /// Creates a new transport selector with the given config.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            state: Arc::new(tokio::sync::RwLock::new(TransportState::new())),
            config,
        }
    }

    /// Updates the transport state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// selector.update_state(|state| {
    ///     state.set_internet(true, 3);
    ///     state.set_local(false, 0);
    /// }).await;
    /// ```
    pub async fn update_state<F>(&self, f: F)
    where
        F: FnOnce(&mut TransportState),
    {
        let mut state = self.state.write().await;
        f(&mut state);
    }

    /// Returns a snapshot of the current transport state.
    pub async fn state(&self) -> TransportState {
        self.state.read().await.clone()
    }

    /// Selects the best available transport following the priority chain.
    ///
    /// # Transport Priority (CRITICAL: Network-first)
    ///
    /// 1. Internet - if connected
    /// 2. LocalNetwork - if peers available
    /// 3. Bluetooth - if peers available
    /// 4. Queued - always available as fallback
    pub async fn select_transport(&self) -> TransportSelection {
        let state = self.state.read().await;

        // 1. ALWAYS try Internet first
        if self.config.enable_internet && state.internet_connected {
            return TransportSelection {
                transport: TransportType::Internet,
                reason: SelectionReason::HighestPriorityAvailable,
                alternatives: self.compute_alternatives(&state, TransportType::Internet),
            };
        }

        // 2. Try local WiFi relay
        if self.config.enable_local_network && state.local_has_peers {
            return TransportSelection {
                transport: TransportType::LocalNetwork,
                reason: SelectionReason::FallbackFromHigherPriority,
                alternatives: self.compute_alternatives(&state, TransportType::LocalNetwork),
            };
        }

        // 3. Fall back to Bluetooth relay
        if self.config.enable_bluetooth && state.bluetooth_has_peers {
            return TransportSelection {
                transport: TransportType::Bluetooth,
                reason: SelectionReason::FallbackFromHigherPriority,
                alternatives: self.compute_alternatives(&state, TransportType::Bluetooth),
            };
        }

        // 4. No connectivity - queue locally
        TransportSelection {
            transport: TransportType::Queued,
            reason: SelectionReason::OnlyOption,
            alternatives: Vec::new(),
        }
    }

    /// Selects a specific transport type if available.
    ///
    /// Returns `None` if the requested transport is not available or not enabled.
    pub async fn select_specific(
        &self,
        transport_type: TransportType,
    ) -> Option<TransportSelection> {
        let state = self.state.read().await;

        let is_available = match transport_type {
            TransportType::Internet => self.config.enable_internet && state.internet_connected,
            TransportType::LocalNetwork => {
                self.config.enable_local_network && state.local_has_peers
            }
            TransportType::Bluetooth => self.config.enable_bluetooth && state.bluetooth_has_peers,
            TransportType::Queued => self.config.enable_queue,
        };

        if is_available {
            Some(TransportSelection {
                transport: transport_type,
                reason: SelectionReason::ExplicitRequest,
                alternatives: self.compute_alternatives(&state, transport_type),
            })
        } else {
            None
        }
    }

    /// Returns the status of all transports.
    pub async fn all_statuses(&self) -> Vec<(TransportType, TransportStatus)> {
        let state = self.state.read().await;

        vec![
            (
                TransportType::Internet,
                if state.internet_connected {
                    TransportStatus::Connected
                } else {
                    TransportStatus::Disconnected
                },
            ),
            (
                TransportType::LocalNetwork,
                if state.local_has_peers {
                    TransportStatus::Connected
                } else {
                    TransportStatus::Disconnected
                },
            ),
            (
                TransportType::Bluetooth,
                if state.bluetooth_has_peers {
                    TransportStatus::Connected
                } else {
                    TransportStatus::Disconnected
                },
            ),
            (TransportType::Queued, TransportStatus::Connected), // Always available
        ]
    }

    /// Computes available alternatives to the selected transport.
    fn compute_alternatives(
        &self,
        state: &TransportState,
        selected: TransportType,
    ) -> Vec<TransportType> {
        let mut alternatives = Vec::new();

        if selected != TransportType::Internet
            && self.config.enable_internet
            && state.internet_connected
        {
            alternatives.push(TransportType::Internet);
        }

        if selected != TransportType::LocalNetwork
            && self.config.enable_local_network
            && state.local_has_peers
        {
            alternatives.push(TransportType::LocalNetwork);
        }

        if selected != TransportType::Bluetooth
            && self.config.enable_bluetooth
            && state.bluetooth_has_peers
        {
            alternatives.push(TransportType::Bluetooth);
        }

        if selected != TransportType::Queued && self.config.enable_queue {
            alternatives.push(TransportType::Queued);
        }

        alternatives.sort_by_key(|t| t.priority());
        alternatives
    }

    /// Returns a reference to the transport configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Returns whether any real-time transport is currently available.
    pub async fn is_any_available(&self) -> bool {
        let state = self.state.read().await;
        state.any_available()
    }
}

/// Statistics for transport usage and performance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Total messages sent via this transport.
    pub messages_sent: u64,

    /// Total messages received via this transport.
    pub messages_received: u64,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// Number of successful connections.
    pub connections_succeeded: u64,

    /// Number of failed connection attempts.
    pub connections_failed: u64,

    /// Average round-trip latency in milliseconds.
    pub avg_latency_ms: f64,

    /// Total time connected in seconds.
    pub total_connected_secs: u64,
}

impl TransportStats {
    /// Creates new empty statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a sent message.
    pub fn record_send(&mut self, bytes: u64) {
        self.messages_sent += 1;
        self.bytes_sent += bytes;
    }

    /// Records a received message.
    pub fn record_receive(&mut self, bytes: u64) {
        self.messages_received += 1;
        self.bytes_received += bytes;
    }

    /// Updates the average latency with a new sample.
    pub fn update_latency(&mut self, latency_ms: u64) {
        // Exponential moving average
        const ALPHA: f64 = 0.1;
        self.avg_latency_ms = (1.0 - ALPHA) * self.avg_latency_ms + ALPHA * (latency_ms as f64);
    }
}
