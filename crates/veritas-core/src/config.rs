//! Configuration for VERITAS client.
//!
//! Provides comprehensive configuration options for the VERITAS client,
//! including storage, network, reputation, and feature settings.
//!
//! # Example
//!
//! ```
//! use veritas_core::config::{ClientConfig, ClientConfigBuilder};
//! use std::time::Duration;
//!
//! // Use defaults
//! let config = ClientConfig::default();
//!
//! // Or use builder for customization
//! let config = ClientConfigBuilder::new()
//!     .with_in_memory_storage()
//!     .with_connection_timeout(Duration::from_secs(60))
//!     .with_bootstrap_peer("peer1.veritas.network:4001".into())
//!     .disable_bluetooth()
//!     .build();
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Default connection timeout in seconds.
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Default maximum queued messages.
const DEFAULT_MAX_QUEUED_MESSAGES: usize = 1000;

/// Default reputation decay rate as a percentage.
const DEFAULT_DECAY_RATE_PERCENT: f32 = 1.0;

/// Main client configuration.
///
/// Contains all configuration options for the VERITAS client,
/// organized into logical groups.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Storage configuration.
    pub storage: StorageConfig,

    /// Network configuration.
    pub network: NetworkConfig,

    /// Reputation system configuration.
    pub reputation: ReputationConfig,

    /// Feature flags and settings.
    pub features: FeatureConfig,
}

impl ClientConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration builder.
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::new()
    }

    /// Create a configuration for in-memory operation (useful for testing).
    pub fn in_memory() -> Self {
        ClientConfigBuilder::new().with_in_memory_storage().build()
    }

    /// Validate the configuration.
    ///
    /// Returns an error if any configuration values are invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate storage
        if !self.storage.in_memory && self.storage.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "storage.data_dir".into(),
                reason: "data directory cannot be empty when not using in-memory storage".into(),
            });
        }

        // Validate network
        if self.network.connection_timeout.as_secs() == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.connection_timeout".into(),
                reason: "connection timeout must be greater than zero".into(),
            });
        }

        // Validate reputation
        if self.reputation.decay_rate_percent < 0.0 || self.reputation.decay_rate_percent > 100.0 {
            return Err(ConfigError::InvalidValue {
                field: "reputation.decay_rate_percent".into(),
                reason: "decay rate must be between 0.0 and 100.0".into(),
            });
        }

        // Validate features
        if self.features.max_queued_messages == 0 {
            return Err(ConfigError::InvalidValue {
                field: "features.max_queued_messages".into(),
                reason: "max queued messages must be greater than zero".into(),
            });
        }

        Ok(())
    }
}

/// Storage configuration.
///
/// Controls where and how data is stored locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Directory for storing data.
    ///
    /// Defaults to the platform-specific data directory:
    /// - Linux: `~/.local/share/veritas`
    /// - macOS: `~/Library/Application Support/veritas`
    /// - Windows: `C:\Users\<User>\AppData\Roaming\veritas`
    pub data_dir: PathBuf,

    /// Use in-memory storage instead of disk.
    ///
    /// Useful for testing or ephemeral sessions.
    /// Data will be lost when the client is dropped.
    pub in_memory: bool,

    /// Encrypt the local database.
    ///
    /// When enabled, all stored data is encrypted with a key
    /// derived from the identity's secret key.
    pub encrypt_database: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            in_memory: false,
            encrypt_database: true,
        }
    }
}

/// Network configuration.
///
/// Controls network connectivity and peer discovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable internet connectivity.
    ///
    /// When enabled, the client can connect to peers over the internet.
    /// This is the primary transport and should usually be enabled.
    pub enable_internet: bool,

    /// Enable local network discovery.
    ///
    /// When enabled, the client will discover peers on the local network
    /// using mDNS and can relay messages through them.
    pub enable_local_discovery: bool,

    /// Enable Bluetooth transport.
    ///
    /// When enabled, the client can relay messages through Bluetooth LE
    /// when internet connectivity is unavailable.
    ///
    /// Note: Bluetooth is a relay-only transport. Security comes from
    /// end-to-end encryption, not from the transport layer.
    pub enable_bluetooth: bool,

    /// Bootstrap peers for initial network connection.
    ///
    /// These are well-known peers used to join the network.
    /// Format: multiaddr strings like `/dns4/peer1.veritas.network/tcp/4001`
    pub bootstrap_peers: Vec<String>,

    /// Addresses to listen on for incoming connections.
    ///
    /// Format: multiaddr strings like `/ip4/0.0.0.0/tcp/4001`
    pub listen_addresses: Vec<String>,

    /// Connection timeout duration.
    ///
    /// How long to wait when establishing connections to peers.
    #[serde(with = "duration_serde")]
    pub connection_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_internet: true,
            enable_local_discovery: true,
            enable_bluetooth: true,
            bootstrap_peers: Vec::new(),
            listen_addresses: Vec::new(),
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
        }
    }
}

/// Reputation system configuration.
///
/// Controls how the reputation system operates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Enable the reputation system.
    ///
    /// When disabled, all reputation checks are skipped.
    pub enabled: bool,

    /// Enable collusion detection.
    ///
    /// Uses graph analysis to detect clusters of users
    /// who may be gaming the reputation system.
    pub enable_collusion_detection: bool,

    /// Reputation decay rate as a percentage (0.0 - 100.0).
    ///
    /// Controls how quickly reputation decays over time.
    /// A value of 1.0 means 1% decay per decay period.
    pub decay_rate_percent: f32,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_collusion_detection: true,
            decay_rate_percent: DEFAULT_DECAY_RATE_PERCENT,
        }
    }
}

/// Feature flags and settings.
///
/// Controls optional features and their behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Add random timing jitter to message sends.
    ///
    /// Helps prevent timing analysis attacks by adding
    /// a random delay (0-3 seconds) before sending messages.
    pub timing_jitter: bool,

    /// Automatically queue messages when offline.
    ///
    /// When enabled, messages are stored locally and sent
    /// automatically when connectivity is restored.
    pub auto_queue_offline: bool,

    /// Maximum number of queued messages.
    ///
    /// Limits how many messages can be queued for offline delivery.
    pub max_queued_messages: usize,

    /// Enable delivery receipts.
    ///
    /// When enabled, senders receive confirmation when their
    /// message is delivered to the recipient's device.
    pub delivery_receipts: bool,

    /// Enable read receipts.
    ///
    /// When enabled, senders receive confirmation when the
    /// recipient reads their message.
    ///
    /// Note: This can leak activity information and is
    /// disabled by default for privacy.
    pub read_receipts: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            timing_jitter: true,
            auto_queue_offline: true,
            max_queued_messages: DEFAULT_MAX_QUEUED_MESSAGES,
            delivery_receipts: true,
            read_receipts: false,
        }
    }
}

/// Builder for constructing `ClientConfig` with custom values.
///
/// Provides a fluent interface for building configuration.
#[derive(Clone, Debug, Default)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ClientConfig::default(),
        }
    }

    /// Build the final configuration.
    pub fn build(self) -> ClientConfig {
        self.config
    }

    /// Build and validate the configuration.
    ///
    /// Returns an error if validation fails.
    pub fn build_validated(self) -> Result<ClientConfig, ConfigError> {
        let config = self.build();
        config.validate()?;
        Ok(config)
    }

    // ===== Storage Configuration =====

    /// Set the data directory.
    pub fn with_data_dir(mut self, path: PathBuf) -> Self {
        self.config.storage.data_dir = path;
        self
    }

    /// Use in-memory storage.
    pub fn with_in_memory_storage(mut self) -> Self {
        self.config.storage.in_memory = true;
        self
    }

    /// Use disk storage (default).
    pub fn with_disk_storage(mut self) -> Self {
        self.config.storage.in_memory = false;
        self
    }

    /// Enable database encryption (default).
    pub fn with_encrypted_database(mut self) -> Self {
        self.config.storage.encrypt_database = true;
        self
    }

    /// Disable database encryption.
    pub fn with_unencrypted_database(mut self) -> Self {
        self.config.storage.encrypt_database = false;
        self
    }

    // ===== Network Configuration =====

    /// Enable internet connectivity (default).
    pub fn enable_internet(mut self) -> Self {
        self.config.network.enable_internet = true;
        self
    }

    /// Disable internet connectivity.
    pub fn disable_internet(mut self) -> Self {
        self.config.network.enable_internet = false;
        self
    }

    /// Enable local network discovery (default).
    pub fn enable_local_discovery(mut self) -> Self {
        self.config.network.enable_local_discovery = true;
        self
    }

    /// Disable local network discovery.
    pub fn disable_local_discovery(mut self) -> Self {
        self.config.network.enable_local_discovery = false;
        self
    }

    /// Enable Bluetooth transport (default).
    pub fn enable_bluetooth(mut self) -> Self {
        self.config.network.enable_bluetooth = true;
        self
    }

    /// Disable Bluetooth transport.
    pub fn disable_bluetooth(mut self) -> Self {
        self.config.network.enable_bluetooth = false;
        self
    }

    /// Add a bootstrap peer.
    pub fn with_bootstrap_peer(mut self, peer: String) -> Self {
        self.config.network.bootstrap_peers.push(peer);
        self
    }

    /// Set all bootstrap peers, replacing any existing.
    pub fn with_bootstrap_peers(mut self, peers: Vec<String>) -> Self {
        self.config.network.bootstrap_peers = peers;
        self
    }

    /// Add a listen address.
    pub fn with_listen_address(mut self, addr: String) -> Self {
        self.config.network.listen_addresses.push(addr);
        self
    }

    /// Set all listen addresses, replacing any existing.
    pub fn with_listen_addresses(mut self, addrs: Vec<String>) -> Self {
        self.config.network.listen_addresses = addrs;
        self
    }

    /// Set the connection timeout.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.network.connection_timeout = timeout;
        self
    }

    // ===== Reputation Configuration =====

    /// Enable the reputation system (default).
    pub fn enable_reputation(mut self) -> Self {
        self.config.reputation.enabled = true;
        self
    }

    /// Disable the reputation system.
    pub fn disable_reputation(mut self) -> Self {
        self.config.reputation.enabled = false;
        self
    }

    /// Enable collusion detection (default).
    pub fn enable_collusion_detection(mut self) -> Self {
        self.config.reputation.enable_collusion_detection = true;
        self
    }

    /// Disable collusion detection.
    pub fn disable_collusion_detection(mut self) -> Self {
        self.config.reputation.enable_collusion_detection = false;
        self
    }

    /// Set the reputation decay rate.
    pub fn with_decay_rate(mut self, rate_percent: f32) -> Self {
        self.config.reputation.decay_rate_percent = rate_percent;
        self
    }

    // ===== Feature Configuration =====

    /// Enable timing jitter (default).
    pub fn enable_timing_jitter(mut self) -> Self {
        self.config.features.timing_jitter = true;
        self
    }

    /// Disable timing jitter.
    pub fn disable_timing_jitter(mut self) -> Self {
        self.config.features.timing_jitter = false;
        self
    }

    /// Enable automatic offline queuing (default).
    pub fn enable_auto_queue(mut self) -> Self {
        self.config.features.auto_queue_offline = true;
        self
    }

    /// Disable automatic offline queuing.
    pub fn disable_auto_queue(mut self) -> Self {
        self.config.features.auto_queue_offline = false;
        self
    }

    /// Set the maximum number of queued messages.
    pub fn with_max_queued_messages(mut self, max: usize) -> Self {
        self.config.features.max_queued_messages = max;
        self
    }

    /// Enable delivery receipts (default).
    pub fn enable_delivery_receipts(mut self) -> Self {
        self.config.features.delivery_receipts = true;
        self
    }

    /// Disable delivery receipts.
    pub fn disable_delivery_receipts(mut self) -> Self {
        self.config.features.delivery_receipts = false;
        self
    }

    /// Enable read receipts.
    pub fn enable_read_receipts(mut self) -> Self {
        self.config.features.read_receipts = true;
        self
    }

    /// Disable read receipts (default).
    pub fn disable_read_receipts(mut self) -> Self {
        self.config.features.read_receipts = false;
        self
    }
}

/// Configuration error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    /// Invalid configuration value.
    #[error("Invalid configuration value for '{field}': {reason}")]
    InvalidValue {
        /// The field name.
        field: String,
        /// The reason it's invalid.
        reason: String,
    },

    /// Missing required configuration.
    #[error("Missing required configuration: {0}")]
    Missing(String),
}

/// Get the default data directory for the current platform.
fn default_data_dir() -> PathBuf {
    // Try platform-specific data directory
    if let Some(data_dir) = dirs::data_dir() {
        return data_dir.join("veritas");
    }

    // Fall back to home directory
    if let Some(home_dir) = dirs::home_dir() {
        return home_dir.join(".veritas");
    }

    // Last resort: current directory
    PathBuf::from(".veritas")
}

/// Serde support for Duration serialization.
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    /// Serializable representation of Duration.
    #[derive(Serialize, Deserialize)]
    struct DurationRepr {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let repr = DurationRepr {
            secs: duration.as_secs(),
            nanos: duration.subsec_nanos(),
        };
        repr.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DurationRepr::deserialize(deserializer)?;
        Ok(Duration::new(repr.secs, repr.nanos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();

        // Storage defaults
        assert!(!config.storage.in_memory);
        assert!(config.storage.encrypt_database);

        // Network defaults
        assert!(config.network.enable_internet);
        assert!(config.network.enable_local_discovery);
        assert!(config.network.enable_bluetooth);
        assert!(config.network.bootstrap_peers.is_empty());
        assert!(config.network.listen_addresses.is_empty());
        assert_eq!(
            config.network.connection_timeout,
            Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS)
        );

        // Reputation defaults
        assert!(config.reputation.enabled);
        assert!(config.reputation.enable_collusion_detection);
        assert!(
            (config.reputation.decay_rate_percent - DEFAULT_DECAY_RATE_PERCENT).abs()
                < f32::EPSILON
        );

        // Feature defaults
        assert!(config.features.timing_jitter);
        assert!(config.features.auto_queue_offline);
        assert_eq!(
            config.features.max_queued_messages,
            DEFAULT_MAX_QUEUED_MESSAGES
        );
        assert!(config.features.delivery_receipts);
        assert!(!config.features.read_receipts);
    }

    #[test]
    fn test_in_memory_config() {
        let config = ClientConfig::in_memory();
        assert!(config.storage.in_memory);
    }

    #[test]
    fn test_builder_storage() {
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .with_unencrypted_database()
            .build();

        assert!(config.storage.in_memory);
        assert!(!config.storage.encrypt_database);
    }

    #[test]
    fn test_builder_network() {
        let config = ClientConfigBuilder::new()
            .disable_bluetooth()
            .disable_local_discovery()
            .with_bootstrap_peer("/dns4/peer1.example.com/tcp/4001".into())
            .with_bootstrap_peer("/dns4/peer2.example.com/tcp/4001".into())
            .with_listen_address("/ip4/0.0.0.0/tcp/4001".into())
            .with_connection_timeout(Duration::from_secs(60))
            .build();

        assert!(config.network.enable_internet);
        assert!(!config.network.enable_local_discovery);
        assert!(!config.network.enable_bluetooth);
        assert_eq!(config.network.bootstrap_peers.len(), 2);
        assert_eq!(config.network.listen_addresses.len(), 1);
        assert_eq!(config.network.connection_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_builder_reputation() {
        let config = ClientConfigBuilder::new()
            .disable_collusion_detection()
            .with_decay_rate(2.5)
            .build();

        assert!(config.reputation.enabled);
        assert!(!config.reputation.enable_collusion_detection);
        assert!((config.reputation.decay_rate_percent - 2.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_builder_features() {
        let config = ClientConfigBuilder::new()
            .disable_timing_jitter()
            .with_max_queued_messages(500)
            .disable_delivery_receipts()
            .enable_read_receipts()
            .build();

        assert!(!config.features.timing_jitter);
        assert!(config.features.auto_queue_offline);
        assert_eq!(config.features.max_queued_messages, 500);
        assert!(!config.features.delivery_receipts);
        assert!(config.features.read_receipts);
    }

    #[test]
    fn test_validation_valid_config() {
        let config = ClientConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_in_memory_with_empty_path() {
        // In-memory storage with empty path should be valid
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .with_data_dir(PathBuf::new())
            .build();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_invalid_decay_rate() {
        let mut config = ClientConfig::default();
        config.reputation.decay_rate_percent = -1.0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidValue { field, .. }) if field == "reputation.decay_rate_percent"
        ));

        config.reputation.decay_rate_percent = 101.0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidValue { field, .. }) if field == "reputation.decay_rate_percent"
        ));
    }

    #[test]
    fn test_validation_zero_timeout() {
        let mut config = ClientConfig::default();
        config.network.connection_timeout = Duration::from_secs(0);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidValue { field, .. }) if field == "network.connection_timeout"
        ));
    }

    #[test]
    fn test_validation_zero_queued_messages() {
        let mut config = ClientConfig::default();
        config.features.max_queued_messages = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidValue { field, .. }) if field == "features.max_queued_messages"
        ));
    }

    #[test]
    fn test_build_validated() {
        let result = ClientConfigBuilder::new()
            .with_decay_rate(-5.0)
            .build_validated();
        assert!(result.is_err());

        let result = ClientConfigBuilder::new().build_validated();
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .disable_bluetooth()
            .with_bootstrap_peer("/dns4/example.com/tcp/4001".into())
            .with_decay_rate(1.5)
            .with_max_queued_messages(2000)
            .build();

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ClientConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(original.storage.in_memory, deserialized.storage.in_memory);
        assert_eq!(
            original.network.enable_bluetooth,
            deserialized.network.enable_bluetooth
        );
        assert_eq!(
            original.network.bootstrap_peers,
            deserialized.network.bootstrap_peers
        );
        assert!(
            (original.reputation.decay_rate_percent - deserialized.reputation.decay_rate_percent)
                .abs()
                < f32::EPSILON
        );
        assert_eq!(
            original.features.max_queued_messages,
            deserialized.features.max_queued_messages
        );
    }

    #[test]
    fn test_default_data_dir() {
        let path = default_data_dir();
        // Should end with "veritas" or ".veritas"
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name == "veritas" || name == ".veritas");
    }

    #[test]
    fn test_builder_replace_peers() {
        let config = ClientConfigBuilder::new()
            .with_bootstrap_peer("peer1".into())
            .with_bootstrap_peer("peer2".into())
            .with_bootstrap_peers(vec!["peer3".into()])
            .build();

        assert_eq!(config.network.bootstrap_peers, vec!["peer3"]);
    }

    #[test]
    fn test_builder_replace_addresses() {
        let config = ClientConfigBuilder::new()
            .with_listen_address("addr1".into())
            .with_listen_address("addr2".into())
            .with_listen_addresses(vec!["addr3".into()])
            .build();

        assert_eq!(config.network.listen_addresses, vec!["addr3"]);
    }
}
