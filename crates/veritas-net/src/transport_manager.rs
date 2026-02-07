//! Transport manager for network-first transport selection.
//!
//! The transport manager handles selection between different transport backends
//! following VERITAS's network-first design principle:
//!
//! 1. **Internet first**: Always try internet connectivity first
//! 2. **Local WiFi relay**: Fall back to local network discovery
//! 3. **Bluetooth relay**: BLE as pure relay (no PIN, no pairing)
//! 4. **Queue locally**: If no transport available, queue for later
//!
//! ## Security Model
//!
//! Transport selection does NOT affect security - all messages are end-to-end
//! encrypted before reaching any transport. Bluetooth is used as a pure relay
//! mechanism without PIN verification or pairing requirements.
//!
//! ## Usage
//!
//! ```ignore
//! use veritas_net::transport::{TransportManager, TransportManagerConfig};
//! use std::time::Duration;
//!
//! let config = TransportManagerConfig::default();
//! let manager = TransportManager::new(config);
//!
//! // Select best available transport
//! let transport = manager.select_transport().await;
//!
//! // Send via best available transport
//! manager.send_via_best_transport(&data, &mailbox_key).await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, instrument, warn};
use veritas_protocol::MailboxKey;

use crate::error::{NetError, Result};

/// A boxed future that is Send.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Default timeout for internet connectivity check.
const DEFAULT_INTERNET_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Default interval for local network discovery.
const DEFAULT_LOCAL_DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);

/// Default interval for Bluetooth discovery.
const DEFAULT_BLUETOOTH_DISCOVERY_INTERVAL: Duration = Duration::from_secs(15);

/// Channel buffer size for transport status updates.
const STATUS_CHANNEL_BUFFER: usize = 32;

/// Types of available transports.
///
/// Transports are listed in priority order - internet is always preferred
/// when available, followed by local network, then Bluetooth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    /// Internet connectivity (libp2p over TCP/QUIC).
    ///
    /// Highest priority - always try this first.
    Internet,

    /// Local network discovery (mDNS on WiFi).
    ///
    /// Used when internet is unavailable but local peers exist.
    LocalNetwork,

    /// Bluetooth Low Energy relay.
    ///
    /// Pure relay - no PIN, no pairing. Security from E2E encryption.
    Bluetooth,

    /// No connectivity - message queued locally.
    ///
    /// Messages are stored and sent when connectivity returns.
    Queued,
}

impl TransportType {
    /// Get the priority of this transport (lower is higher priority).
    pub fn priority(&self) -> u8 {
        match self {
            TransportType::Internet => 0,
            TransportType::LocalNetwork => 1,
            TransportType::Bluetooth => 2,
            TransportType::Queued => 3,
        }
    }

    /// Check if this transport provides direct connectivity.
    pub fn is_connected(&self) -> bool {
        !matches!(self, TransportType::Queued)
    }

    /// Human-readable name for the transport.
    pub fn name(&self) -> &'static str {
        match self {
            TransportType::Internet => "Internet",
            TransportType::LocalNetwork => "Local Network",
            TransportType::Bluetooth => "Bluetooth",
            TransportType::Queued => "Queued",
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Status update from a transport backend.
#[derive(Debug, Clone)]
pub struct TransportStatus {
    /// The transport type this status is for.
    pub transport: TransportType,
    /// Whether the transport is currently available.
    pub available: bool,
    /// Number of connected peers (if applicable).
    pub peer_count: usize,
    /// Optional error message if transport is unavailable.
    pub error: Option<String>,
}

impl TransportStatus {
    /// Create a new transport status.
    pub fn new(transport: TransportType, available: bool) -> Self {
        Self {
            transport,
            available,
            peer_count: 0,
            error: None,
        }
    }

    /// Create an available status with peer count.
    pub fn available_with_peers(transport: TransportType, peer_count: usize) -> Self {
        Self {
            transport,
            available: peer_count > 0 || matches!(transport, TransportType::Internet),
            peer_count,
            error: None,
        }
    }

    /// Create an unavailable status with error.
    pub fn unavailable(transport: TransportType, error: impl Into<String>) -> Self {
        Self {
            transport,
            available: false,
            peer_count: 0,
            error: Some(error.into()),
        }
    }
}

/// Configuration for the transport manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportManagerConfig {
    /// Enable internet transport (libp2p).
    pub enable_internet: bool,

    /// Enable local network discovery (mDNS).
    pub enable_local: bool,

    /// Enable Bluetooth relay transport.
    pub enable_bluetooth: bool,

    /// Timeout for internet connectivity checks.
    #[serde(with = "humantime_serde")]
    pub internet_check_timeout: Duration,

    /// Interval for local network peer discovery.
    #[serde(with = "humantime_serde")]
    pub local_discovery_interval: Duration,

    /// Interval for Bluetooth peer discovery.
    #[serde(with = "humantime_serde")]
    pub bluetooth_discovery_interval: Duration,

    /// Whether to automatically queue messages when no transport is available.
    pub auto_queue: bool,

    /// Maximum messages to queue when offline.
    pub max_queued_messages: usize,
}

impl Default for TransportManagerConfig {
    fn default() -> Self {
        Self {
            enable_internet: true,
            enable_local: true,
            enable_bluetooth: true,
            internet_check_timeout: DEFAULT_INTERNET_CHECK_TIMEOUT,
            local_discovery_interval: DEFAULT_LOCAL_DISCOVERY_INTERVAL,
            bluetooth_discovery_interval: DEFAULT_BLUETOOTH_DISCOVERY_INTERVAL,
            auto_queue: true,
            max_queued_messages: 1000,
        }
    }
}

impl TransportManagerConfig {
    /// Create a config with only internet transport enabled.
    pub fn internet_only() -> Self {
        Self {
            enable_internet: true,
            enable_local: false,
            enable_bluetooth: false,
            ..Default::default()
        }
    }

    /// Create a config with all transports disabled (offline mode).
    pub fn offline() -> Self {
        Self {
            enable_internet: false,
            enable_local: false,
            enable_bluetooth: false,
            ..Default::default()
        }
    }
}

/// Trait for internet transport backend.
///
/// Implementations should provide libp2p-based connectivity.
///
/// This trait uses boxed futures instead of async fn to enable
/// dynamic dispatch (dyn-compatibility).
pub trait InternetTransport: Send + Sync {
    /// Check if internet connectivity is available.
    fn is_connected(&self) -> BoxFuture<'_, bool>;

    /// Send data to a mailbox.
    fn send(&self, data: &[u8], mailbox: &MailboxKey) -> BoxFuture<'_, Result<()>>;

    /// Get the number of connected peers.
    fn peer_count(&self) -> BoxFuture<'_, usize>;
}

/// Trait for local network transport backend.
///
/// Implementations should provide mDNS-based local discovery.
///
/// This trait uses boxed futures instead of async fn to enable
/// dynamic dispatch (dyn-compatibility).
pub trait LocalTransport: Send + Sync {
    /// Check if local peers are available.
    fn has_peers(&self) -> BoxFuture<'_, bool>;

    /// Send data to a mailbox via local network.
    fn send(&self, data: &[u8], mailbox: &MailboxKey) -> BoxFuture<'_, Result<()>>;

    /// Get the number of discovered local peers.
    fn peer_count(&self) -> BoxFuture<'_, usize>;
}

/// Trait for Bluetooth transport backend.
///
/// Implementations should provide BLE relay functionality.
/// Note: No PIN verification or pairing required - BLE is pure relay.
///
/// This trait uses boxed futures instead of async fn to enable
/// dynamic dispatch (dyn-compatibility).
pub trait BluetoothTransport: Send + Sync {
    /// Check if Bluetooth peers are available.
    fn has_peers(&self) -> BoxFuture<'_, bool>;

    /// Send data to a mailbox via Bluetooth relay.
    fn send(&self, data: &[u8], mailbox: &MailboxKey) -> BoxFuture<'_, Result<()>>;

    /// Get the number of discovered Bluetooth peers.
    fn peer_count(&self) -> BoxFuture<'_, usize>;
}

/// Internal state of transport availability.
#[derive(Debug, Default)]
struct TransportState {
    internet_available: bool,
    internet_peer_count: usize,
    local_available: bool,
    local_peer_count: usize,
    bluetooth_available: bool,
    bluetooth_peer_count: usize,
}

/// Manager for selecting and using transports.
///
/// The transport manager implements the network-first selection policy
/// required by VERITAS:
///
/// 1. Always try internet first
/// 2. Fall back to local WiFi relay
/// 3. Fall back to Bluetooth relay
/// 4. Queue locally if no transport available
pub struct TransportManager {
    /// Configuration.
    config: TransportManagerConfig,

    /// Internet transport backend.
    internet: Option<Arc<dyn InternetTransport>>,

    /// Local network transport backend.
    local: Option<Arc<dyn LocalTransport>>,

    /// Bluetooth transport backend.
    bluetooth: Option<Arc<dyn BluetoothTransport>>,

    /// Current transport state.
    state: Arc<RwLock<TransportState>>,

    /// Channel for receiving status updates.
    status_rx: Option<mpsc::Receiver<TransportStatus>>,

    /// Channel for sending status updates (kept for cloning).
    status_tx: mpsc::Sender<TransportStatus>,
}

impl TransportManager {
    /// Create a new transport manager with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for enabled transports and timeouts
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = TransportManagerConfig::default();
    /// let manager = TransportManager::new(config);
    /// ```
    pub fn new(config: TransportManagerConfig) -> Self {
        let (status_tx, status_rx) = mpsc::channel(STATUS_CHANNEL_BUFFER);

        Self {
            config,
            internet: None,
            local: None,
            bluetooth: None,
            state: Arc::new(RwLock::new(TransportState::default())),
            status_rx: Some(status_rx),
            status_tx,
        }
    }

    /// Set the internet transport backend.
    pub fn with_internet_transport(mut self, transport: Arc<dyn InternetTransport>) -> Self {
        if self.config.enable_internet {
            self.internet = Some(transport);
        }
        self
    }

    /// Set the local network transport backend.
    pub fn with_local_transport(mut self, transport: Arc<dyn LocalTransport>) -> Self {
        if self.config.enable_local {
            self.local = Some(transport);
        }
        self
    }

    /// Set the Bluetooth transport backend.
    pub fn with_bluetooth_transport(mut self, transport: Arc<dyn BluetoothTransport>) -> Self {
        if self.config.enable_bluetooth {
            self.bluetooth = Some(transport);
        }
        self
    }

    /// Get a sender for transport status updates.
    ///
    /// Use this to notify the manager of transport availability changes.
    pub fn status_sender(&self) -> mpsc::Sender<TransportStatus> {
        self.status_tx.clone()
    }

    /// Take the status receiver for processing updates.
    ///
    /// Can only be called once - returns None on subsequent calls.
    pub fn take_status_receiver(&mut self) -> Option<mpsc::Receiver<TransportStatus>> {
        self.status_rx.take()
    }

    /// Process a status update from a transport backend.
    pub async fn handle_status_update(&self, status: TransportStatus) {
        let mut state = self.state.write().await;

        match status.transport {
            TransportType::Internet => {
                state.internet_available = status.available;
                state.internet_peer_count = status.peer_count;
            }
            TransportType::LocalNetwork => {
                state.local_available = status.available;
                state.local_peer_count = status.peer_count;
            }
            TransportType::Bluetooth => {
                state.bluetooth_available = status.available;
                state.bluetooth_peer_count = status.peer_count;
            }
            TransportType::Queued => {
                // Queued is not a real transport, ignore
            }
        }

        if let Some(ref error) = status.error {
            warn!(
                transport = %status.transport,
                error = %error,
                "Transport reported error"
            );
        } else {
            debug!(
                transport = %status.transport,
                available = status.available,
                peers = status.peer_count,
                "Transport status updated"
            );
        }
    }

    /// Select the best available transport.
    ///
    /// Implements the network-first selection policy:
    /// 1. ALWAYS try internet first
    /// 2. Try local WiFi relay
    /// 3. Fall back to Bluetooth relay
    /// 4. No connectivity - queue locally
    ///
    /// # Returns
    ///
    /// The best available transport type.
    #[instrument(skip(self))]
    pub async fn select_transport(&self) -> TransportType {
        // 1. ALWAYS try internet first
        if self.config.enable_internet {
            if let Some(ref internet) = self.internet {
                if internet.is_connected().await {
                    debug!("Selected Internet transport");
                    return TransportType::Internet;
                }
            } else {
                // Check cached state if no backend
                let state = self.state.read().await;
                if state.internet_available {
                    debug!("Selected Internet transport (from cached state)");
                    return TransportType::Internet;
                }
            }
        }

        // 2. Try local WiFi relay
        if self.config.enable_local {
            if let Some(ref local) = self.local {
                if local.has_peers().await {
                    debug!("Selected LocalNetwork transport");
                    return TransportType::LocalNetwork;
                }
            } else {
                // Check cached state if no backend
                let state = self.state.read().await;
                if state.local_available {
                    debug!("Selected LocalNetwork transport (from cached state)");
                    return TransportType::LocalNetwork;
                }
            }
        }

        // 3. Fall back to Bluetooth relay
        if self.config.enable_bluetooth {
            if let Some(ref bluetooth) = self.bluetooth {
                if bluetooth.has_peers().await {
                    debug!("Selected Bluetooth transport");
                    return TransportType::Bluetooth;
                }
            } else {
                // Check cached state if no backend
                let state = self.state.read().await;
                if state.bluetooth_available {
                    debug!("Selected Bluetooth transport (from cached state)");
                    return TransportType::Bluetooth;
                }
            }
        }

        // 4. No connectivity - queue locally
        debug!("No transport available, queuing message");
        TransportType::Queued
    }

    /// Check if any transport is available.
    ///
    /// # Returns
    ///
    /// `true` if at least one transport can send messages immediately.
    #[instrument(skip(self))]
    pub async fn is_any_available(&self) -> bool {
        let transport = self.select_transport().await;
        transport.is_connected()
    }

    /// Get a list of all currently available transports.
    ///
    /// Returns transports in priority order (highest priority first).
    ///
    /// # Returns
    ///
    /// A vector of available transport types.
    #[instrument(skip(self))]
    pub async fn get_available_transports(&self) -> Vec<TransportType> {
        let mut available = Vec::new();

        // Check internet
        if self.config.enable_internet {
            let is_available = if let Some(ref internet) = self.internet {
                internet.is_connected().await
            } else {
                self.state.read().await.internet_available
            };
            if is_available {
                available.push(TransportType::Internet);
            }
        }

        // Check local network
        if self.config.enable_local {
            let is_available = if let Some(ref local) = self.local {
                local.has_peers().await
            } else {
                self.state.read().await.local_available
            };
            if is_available {
                available.push(TransportType::LocalNetwork);
            }
        }

        // Check Bluetooth
        if self.config.enable_bluetooth {
            let is_available = if let Some(ref bluetooth) = self.bluetooth {
                bluetooth.has_peers().await
            } else {
                self.state.read().await.bluetooth_available
            };
            if is_available {
                available.push(TransportType::Bluetooth);
            }
        }

        available
    }

    /// Send data via the best available transport.
    ///
    /// Follows the network-first selection policy to choose the transport,
    /// then sends the data. If no transport is available and auto_queue
    /// is enabled, returns `Ok(())` after queuing (caller should handle
    /// queued messages separately).
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted envelope data to send
    /// * `mailbox` - The mailbox key for routing
    ///
    /// # Errors
    ///
    /// Returns `NetError::NoTransport` if no transport is available and
    /// auto_queue is disabled.
    ///
    /// Returns `NetError::Transport` if the transport fails to send.
    #[instrument(skip(self, data, mailbox))]
    pub async fn send_via_best_transport(&self, data: &[u8], mailbox: &MailboxKey) -> Result<()> {
        let transport = self.select_transport().await;

        match transport {
            TransportType::Internet => {
                if let Some(ref internet) = self.internet {
                    info!("Sending via Internet transport");
                    internet.send(data, mailbox).await
                } else {
                    Err(NetError::Transport(
                        "Internet transport not configured".to_string(),
                    ))
                }
            }
            TransportType::LocalNetwork => {
                if let Some(ref local) = self.local {
                    info!("Sending via LocalNetwork transport");
                    local.send(data, mailbox).await
                } else {
                    Err(NetError::Transport(
                        "Local transport not configured".to_string(),
                    ))
                }
            }
            TransportType::Bluetooth => {
                if let Some(ref bluetooth) = self.bluetooth {
                    info!("Sending via Bluetooth transport");
                    bluetooth.send(data, mailbox).await
                } else {
                    Err(NetError::Transport(
                        "Bluetooth transport not configured".to_string(),
                    ))
                }
            }
            TransportType::Queued => {
                if self.config.auto_queue {
                    info!(
                        data_len = data.len(),
                        "No transport available, message queued"
                    );
                    // Caller is responsible for actually queuing the message
                    // We just indicate that queuing should happen
                    Ok(())
                } else {
                    Err(NetError::NoTransport)
                }
            }
        }
    }

    /// Get transport statistics.
    pub async fn stats(&self) -> TransportStats {
        let state = self.state.read().await;

        TransportStats {
            internet_available: self.config.enable_internet && state.internet_available,
            internet_peer_count: state.internet_peer_count,
            local_available: self.config.enable_local && state.local_available,
            local_peer_count: state.local_peer_count,
            bluetooth_available: self.config.enable_bluetooth && state.bluetooth_available,
            bluetooth_peer_count: state.bluetooth_peer_count,
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &TransportManagerConfig {
        &self.config
    }
}

/// Statistics about transport availability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Whether internet transport is available.
    pub internet_available: bool,
    /// Number of internet peers.
    pub internet_peer_count: usize,
    /// Whether local network transport is available.
    pub local_available: bool,
    /// Number of local network peers.
    pub local_peer_count: usize,
    /// Whether Bluetooth transport is available.
    pub bluetooth_available: bool,
    /// Number of Bluetooth peers.
    pub bluetooth_peer_count: usize,
}

impl TransportStats {
    /// Get the total number of connected peers across all transports.
    pub fn total_peers(&self) -> usize {
        self.internet_peer_count + self.local_peer_count + self.bluetooth_peer_count
    }

    /// Check if any transport is available.
    pub fn any_available(&self) -> bool {
        self.internet_available || self.local_available || self.bluetooth_available
    }
}

/// Serde support for Duration using humantime format.
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
