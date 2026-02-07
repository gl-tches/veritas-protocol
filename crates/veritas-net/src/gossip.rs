//! Gossipsub protocol implementation for VERITAS.
//!
//! Provides a privacy-preserving gossip layer for announcing messages and blocks
//! without revealing content. Uses libp2p's Gossipsub protocol with metadata-minimizing
//! announcements.
//!
//! ## Privacy Properties
//!
//! - **Mailbox Keys**: Announcements use derived mailbox keys, not recipient identities
//! - **Timestamp Buckets**: Hourly buckets instead of exact timestamps
//! - **Size Buckets**: Fixed padding bucket sizes (1024/2048/4096/8192) hide true message size
//! - **No Content**: Only hashes and routing info are announced
//!
//! ## Topics
//!
//! - `veritas/messages/v1` - New message announcements
//! - `veritas/blocks/v1` - New block announcements
//! - `veritas/receipts/v1` - Delivery receipt announcements

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::gossipsub::{
    self, Behaviour as GossipsubBehaviour, ConfigBuilder as GossipsubConfigBuilder, IdentTopic,
    Message as GossipsubMessage, MessageAuthenticity, MessageId, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use veritas_crypto::Hash256;
use veritas_protocol::{MailboxKey, PADDING_BUCKETS};

use crate::error::{NetError, Result};
use crate::rate_limiter::{RateLimitConfig, RateLimitResult, RateLimiter};

// ============================================================================
// Topic Constants
// ============================================================================

/// Topic for new message announcements.
pub const TOPIC_MESSAGES: &str = "veritas/messages/v1";

/// Topic for new block announcements.
pub const TOPIC_BLOCKS: &str = "veritas/blocks/v1";

/// Topic for delivery receipt announcements.
pub const TOPIC_RECEIPTS: &str = "veritas/receipts/v1";

/// Duration of timestamp buckets (1 hour in seconds).
const TIMESTAMP_BUCKET_SECS: u64 = 60 * 60;

/// Maximum size of a serialized `MessageAnnouncement` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
pub const MAX_MESSAGE_ANNOUNCEMENT_SIZE: usize = 8192;

/// Maximum size of a serialized `BlockAnnouncement` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
pub const MAX_BLOCK_ANNOUNCEMENT_SIZE: usize = 8192;

/// Maximum size of a serialized `ReceiptAnnouncement` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
pub const MAX_RECEIPT_ANNOUNCEMENT_SIZE: usize = 4096;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the gossip protocol.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Interval between heartbeats for mesh maintenance.
    /// Default: 1 second.
    pub heartbeat_interval: Duration,

    /// Maximum size of a gossip message in bytes.
    /// Default: 65536 (64 KiB).
    pub max_transmit_size: usize,

    /// Target number of peers in the mesh for each topic.
    /// Default: 6.
    pub mesh_n: usize,

    /// Minimum number of peers in the mesh before triggering grafting.
    /// Default: 4.
    pub mesh_n_low: usize,

    /// Maximum number of peers in the mesh before triggering pruning.
    /// Default: 12.
    pub mesh_n_high: usize,

    /// Number of peers to gossip to (lazy push).
    /// Default: 6.
    pub gossip_lazy: usize,

    /// Number of heartbeats to keep message history.
    /// Default: 5.
    pub history_length: usize,

    /// Number of heartbeats to include in gossip.
    /// Default: 3.
    pub history_gossip: usize,

    /// Rate limiting configuration for incoming announcements.
    /// Addresses VERITAS-2026-0007.
    pub rate_limit: RateLimitConfig,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(1),
            max_transmit_size: 65536,
            mesh_n: 6,
            mesh_n_low: 4,
            mesh_n_high: 12,
            gossip_lazy: 6,
            history_length: 5,
            history_gossip: 3,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl GossipConfig {
    /// Create a new gossip configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the heartbeat interval.
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Set the maximum transmit size.
    pub fn with_max_transmit_size(mut self, size: usize) -> Self {
        self.max_transmit_size = size;
        self
    }

    /// Set the target mesh size.
    pub fn with_mesh_n(mut self, n: usize) -> Self {
        self.mesh_n = n;
        self
    }

    /// Set the minimum mesh size.
    pub fn with_mesh_n_low(mut self, n: usize) -> Self {
        self.mesh_n_low = n;
        self
    }

    /// Set the maximum mesh size.
    pub fn with_mesh_n_high(mut self, n: usize) -> Self {
        self.mesh_n_high = n;
        self
    }

    /// Set the gossip lazy parameter.
    pub fn with_gossip_lazy(mut self, n: usize) -> Self {
        self.gossip_lazy = n;
        self
    }

    /// Set the history length.
    pub fn with_history_length(mut self, n: usize) -> Self {
        self.history_length = n;
        self
    }

    /// Set the history gossip parameter.
    pub fn with_history_gossip(mut self, n: usize) -> Self {
        self.history_gossip = n;
        self
    }

    /// Set the rate limiting configuration.
    ///
    /// # Security
    ///
    /// Rate limiting is essential to prevent VERITAS-2026-0007 (gossip flooding).
    /// The default configuration provides reasonable protection.
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = config;
        self
    }

    /// Build a libp2p gossipsub configuration from this config.
    fn to_gossipsub_config(
        &self,
    ) -> std::result::Result<gossipsub::Config, gossipsub::ConfigBuilderError> {
        GossipsubConfigBuilder::default()
            .heartbeat_interval(self.heartbeat_interval)
            .max_transmit_size(self.max_transmit_size)
            .mesh_n(self.mesh_n)
            .mesh_n_low(self.mesh_n_low)
            .mesh_n_high(self.mesh_n_high)
            .gossip_lazy(self.gossip_lazy)
            .history_length(self.history_length)
            .history_gossip(self.history_gossip)
            .validation_mode(ValidationMode::Strict)
            .build()
    }
}

// ============================================================================
// Announcement Types
// ============================================================================

/// A message announcement with minimal metadata.
///
/// This announcement is visible to relays but reveals minimal information:
/// - Uses derived mailbox key instead of recipient identity
/// - Uses hourly timestamp buckets instead of exact time
/// - Uses padded size buckets instead of true message size
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageAnnouncement {
    /// Derived mailbox key for routing (NOT the recipient's identity hash).
    /// Changes with each epoch and salt, making messages unlinkable.
    pub mailbox_key: MailboxKey,

    /// Hash of the encrypted message for deduplication and retrieval.
    pub message_hash: Hash256,

    /// Timestamp bucket (hourly granularity).
    /// Computed as `unix_timestamp / 3600` to hide exact send time.
    pub timestamp_bucket: u64,

    /// Size bucket indicating padded message size.
    /// One of: 1024, 2048, 4096, or 8192 bytes.
    pub size_bucket: u16,
}

impl MessageAnnouncement {
    /// Create a new message announcement.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The derived mailbox key for the recipient
    /// * `message_hash` - Hash of the encrypted message
    /// * `timestamp_secs` - Unix timestamp in seconds (will be bucketed)
    /// * `padded_size` - Size of the padded message (will be validated)
    ///
    /// # Returns
    ///
    /// A new `MessageAnnouncement` or an error if the size bucket is invalid.
    pub fn new(
        mailbox_key: MailboxKey,
        message_hash: Hash256,
        timestamp_secs: u64,
        padded_size: usize,
    ) -> Result<Self> {
        // Validate and convert size to bucket
        let size_bucket = validate_size_bucket(padded_size)?;

        // Convert timestamp to hourly bucket
        let timestamp_bucket = timestamp_secs / TIMESTAMP_BUCKET_SECS;

        Ok(Self {
            mailbox_key,
            message_hash,
            timestamp_bucket,
            size_bucket,
        })
    }

    /// Create a message announcement for the current time.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The derived mailbox key for the recipient
    /// * `message_hash` - Hash of the encrypted message
    /// * `padded_size` - Size of the padded message
    pub fn new_now(
        mailbox_key: MailboxKey,
        message_hash: Hash256,
        padded_size: usize,
    ) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        Self::new(mailbox_key, message_hash, now, padded_size)
    }

    /// Serialize the announcement to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetError::Gossip(format!("serialization failed: {}", e)))
    }

    /// Deserialize an announcement from bytes.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_MESSAGE_ANNOUNCEMENT_SIZE {
            return Err(NetError::Gossip(format!(
                "MessageAnnouncement too large: {} bytes (max: {})",
                bytes.len(),
                MAX_MESSAGE_ANNOUNCEMENT_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Gossip(format!("deserialization failed: {}", e)))
    }
}

/// A block announcement for the blockchain layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockAnnouncement {
    /// Hash of the block.
    pub block_hash: Hash256,

    /// Height of the block in the chain.
    pub height: u64,

    /// Timestamp bucket (hourly granularity).
    pub timestamp_bucket: u64,
}

impl BlockAnnouncement {
    /// Create a new block announcement.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the block
    /// * `height` - Block height
    /// * `timestamp_secs` - Unix timestamp in seconds (will be bucketed)
    pub fn new(block_hash: Hash256, height: u64, timestamp_secs: u64) -> Self {
        let timestamp_bucket = timestamp_secs / TIMESTAMP_BUCKET_SECS;

        Self {
            block_hash,
            height,
            timestamp_bucket,
        }
    }

    /// Create a block announcement for the current time.
    pub fn new_now(block_hash: Hash256, height: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        Self::new(block_hash, height, now)
    }

    /// Serialize the announcement to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetError::Gossip(format!("serialization failed: {}", e)))
    }

    /// Deserialize an announcement from bytes.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_BLOCK_ANNOUNCEMENT_SIZE {
            return Err(NetError::Gossip(format!(
                "BlockAnnouncement too large: {} bytes (max: {})",
                bytes.len(),
                MAX_BLOCK_ANNOUNCEMENT_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Gossip(format!("deserialization failed: {}", e)))
    }
}

/// A delivery receipt announcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAnnouncement {
    /// Hash of the original message this receipt is for.
    pub message_hash: Hash256,

    /// Hash of the receipt itself.
    pub receipt_hash: Hash256,

    /// Timestamp bucket (hourly granularity).
    pub timestamp_bucket: u64,
}

impl ReceiptAnnouncement {
    /// Create a new receipt announcement.
    pub fn new(message_hash: Hash256, receipt_hash: Hash256, timestamp_secs: u64) -> Self {
        let timestamp_bucket = timestamp_secs / TIMESTAMP_BUCKET_SECS;

        Self {
            message_hash,
            receipt_hash,
            timestamp_bucket,
        }
    }

    /// Create a receipt announcement for the current time.
    pub fn new_now(message_hash: Hash256, receipt_hash: Hash256) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        Self::new(message_hash, receipt_hash, now)
    }

    /// Serialize the announcement to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetError::Gossip(format!("serialization failed: {}", e)))
    }

    /// Deserialize an announcement from bytes.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_RECEIPT_ANNOUNCEMENT_SIZE {
            return Err(NetError::Gossip(format!(
                "ReceiptAnnouncement too large: {} bytes (max: {})",
                bytes.len(),
                MAX_RECEIPT_ANNOUNCEMENT_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Gossip(format!("deserialization failed: {}", e)))
    }
}

// ============================================================================
// Gossip Manager
// ============================================================================

/// Maximum number of seen message IDs to track for deduplication.
///
/// SECURITY: When this limit is reached, the oldest entries are evicted
/// one-by-one (FIFO) instead of clearing the entire set. This prevents
/// a replay window where all previously seen messages could be replayed
/// after a bulk clear. See VERITAS-2026-0014.
const MAX_SEEN_MESSAGES: usize = 10000;

/// LRU-style deduplication tracker for seen gossip messages.
///
/// Uses a `VecDeque` for FIFO ordering and a `HashSet` for O(1) lookups.
/// When the maximum size is reached, the oldest entry is evicted rather
/// than clearing the entire set, which would create a replay window.
///
/// # Security
///
/// This addresses the gossip replay vulnerability where clearing the
/// entire `seen_messages` set allowed all previously seen messages to
/// be replayed.
struct SeenMessages {
    /// FIFO order of message IDs (oldest at front).
    order: VecDeque<MessageId>,
    /// Set of message IDs for O(1) lookup.
    set: HashSet<MessageId>,
    /// Maximum number of entries before eviction.
    max_size: usize,
}

impl SeenMessages {
    /// Create a new SeenMessages tracker with the given capacity.
    fn new(max_size: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(max_size),
            set: HashSet::with_capacity(max_size),
            max_size,
        }
    }

    /// Check if a message ID has been seen.
    fn contains(&self, id: &MessageId) -> bool {
        self.set.contains(id)
    }

    /// Insert a message ID. If at capacity, evict the oldest entry.
    fn insert(&mut self, id: MessageId) {
        if self.set.contains(&id) {
            return;
        }

        // Evict oldest entries if at capacity
        while self.set.len() >= self.max_size {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            } else {
                break;
            }
        }

        self.set.insert(id.clone());
        self.order.push_back(id);
    }

    /// Get the number of tracked message IDs.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }
}

/// Internal state for the gossip manager.
struct GossipState {
    /// Set of subscribed topics.
    subscribed_topics: HashSet<String>,

    /// Mesh peers per topic.
    mesh_peers: HashMap<String, HashSet<PeerId>>,

    /// Recently seen message IDs for deduplication (LRU-style eviction).
    seen_messages: SeenMessages,
}

impl GossipState {
    fn new() -> Self {
        Self {
            subscribed_topics: HashSet::new(),
            mesh_peers: HashMap::new(),
            seen_messages: SeenMessages::new(MAX_SEEN_MESSAGES),
        }
    }
}

/// Simple rate limiter for local (outgoing) announcements.
///
/// Prevents this node from flooding the network with its own announcements.
/// Uses a simple sliding window approach for simplicity.
#[derive(Debug)]
struct LocalRateLimiter {
    /// Maximum announcements per second.
    max_per_second: u32,

    /// Timestamps of recent announcements.
    recent_timestamps: Vec<Instant>,
}

impl LocalRateLimiter {
    fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            recent_timestamps: Vec::with_capacity(max_per_second as usize * 2),
        }
    }

    /// Check if a local announcement is allowed.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        let one_second_ago = now - Duration::from_secs(1);

        // Remove timestamps older than 1 second
        self.recent_timestamps.retain(|t| *t > one_second_ago);

        // Check if we're under the limit
        if self.recent_timestamps.len() < self.max_per_second as usize {
            self.recent_timestamps.push(now);
            true
        } else {
            false
        }
    }
}

/// Manager for gossip protocol operations.
///
/// Handles topic subscriptions, message publishing, and peer mesh tracking.
/// Provides a high-level interface over libp2p's Gossipsub.
///
/// # Security
///
/// This manager includes rate limiting to prevent VERITAS-2026-0007 (gossip flooding).
/// All incoming announcements should be processed through `handle_announcement()`
/// which enforces per-peer and global rate limits.
pub struct GossipManager {
    /// Configuration for the gossip protocol.
    config: GossipConfig,

    /// The underlying gossipsub behaviour (when connected to swarm).
    /// This is set via `set_behaviour` after the swarm is created.
    behaviour: Option<Arc<RwLock<GossipsubBehaviour>>>,

    /// Internal state.
    state: Arc<RwLock<GossipState>>,

    /// Local peer ID.
    local_peer_id: Option<PeerId>,

    /// Rate limiter for incoming announcements.
    /// SECURITY: Addresses VERITAS-2026-0007 - gossip flooding prevention.
    rate_limiter: Arc<Mutex<RateLimiter>>,

    /// Local rate limiter for outgoing announcements (self rate limiting).
    /// Prevents this node from accidentally flooding the network.
    local_rate_limiter: Arc<Mutex<LocalRateLimiter>>,
}

impl GossipManager {
    /// Create a new gossip manager with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the gossip protocol
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::gossip::{GossipConfig, GossipManager};
    ///
    /// let config = GossipConfig::default();
    /// let manager = GossipManager::new(config);
    /// ```
    pub fn new(config: GossipConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit.clone());
        let local_rate_limiter = LocalRateLimiter::new(config.rate_limit.per_peer_rate);

        Self {
            config,
            behaviour: None,
            state: Arc::new(RwLock::new(GossipState::new())),
            local_peer_id: None,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            local_rate_limiter: Arc::new(Mutex::new(local_rate_limiter)),
        }
    }

    /// Create a gossip manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(GossipConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Create a libp2p gossipsub behaviour from this manager's configuration.
    ///
    /// This should be called when setting up the libp2p swarm.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The local node's keypair for message signing
    ///
    /// # Returns
    ///
    /// A configured `GossipsubBehaviour` or an error.
    pub fn create_behaviour(&self, keypair: &Keypair) -> Result<GossipsubBehaviour> {
        let gossipsub_config = self
            .config
            .to_gossipsub_config()
            .map_err(|e| NetError::Gossip(format!("invalid config: {}", e)))?;

        // Use signed messages for authenticity
        let message_authenticity = MessageAuthenticity::Signed(keypair.clone());

        GossipsubBehaviour::new(message_authenticity, gossipsub_config)
            .map_err(|e| NetError::Gossip(format!("failed to create behaviour: {}", e)))
    }

    /// Set the gossipsub behaviour reference.
    ///
    /// Called after the swarm is created to enable publishing.
    pub fn set_behaviour(
        &mut self,
        behaviour: Arc<RwLock<GossipsubBehaviour>>,
        local_peer_id: PeerId,
    ) {
        self.behaviour = Some(behaviour);
        self.local_peer_id = Some(local_peer_id);
    }

    /// Subscribe to a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic name to subscribe to
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, or an error if the subscription failed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::gossip::{GossipManager, TOPIC_MESSAGES};
    ///
    /// let mut manager = GossipManager::with_defaults();
    /// manager.subscribe(TOPIC_MESSAGES)?;
    /// ```
    pub async fn subscribe(&mut self, topic: &str) -> Result<()> {
        let ident_topic = IdentTopic::new(topic);

        // Subscribe in the behaviour if available
        if let Some(behaviour) = &self.behaviour {
            let mut behaviour = behaviour.write().await;
            behaviour
                .subscribe(&ident_topic)
                .map_err(|e| NetError::Gossip(format!("subscribe failed: {}", e)))?;
        }

        // Track subscription in state
        let mut state = self.state.write().await;
        state.subscribed_topics.insert(topic.to_string());
        state.mesh_peers.entry(topic.to_string()).or_default();

        info!(topic = %topic, "Subscribed to gossip topic");
        Ok(())
    }

    /// Unsubscribe from a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic name to unsubscribe from
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, or an error if not subscribed.
    pub async fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        let ident_topic = IdentTopic::new(topic);

        // Unsubscribe in the behaviour if available
        if let Some(behaviour) = &self.behaviour {
            let mut behaviour = behaviour.write().await;
            behaviour
                .unsubscribe(&ident_topic)
                .map_err(|e| NetError::Gossip(format!("unsubscribe failed: {}", e)))?;
        }

        // Update state
        let mut state = self.state.write().await;
        if !state.subscribed_topics.remove(topic) {
            return Err(NetError::Gossip(format!(
                "not subscribed to topic: {}",
                topic
            )));
        }
        state.mesh_peers.remove(topic);

        info!(topic = %topic, "Unsubscribed from gossip topic");
        Ok(())
    }

    /// Check if subscribed to a topic.
    pub async fn is_subscribed(&self, topic: &str) -> bool {
        let state = self.state.read().await;
        state.subscribed_topics.contains(topic)
    }

    /// Get the list of subscribed topics.
    pub async fn subscribed_topics(&self) -> Vec<String> {
        let state = self.state.read().await;
        state.subscribed_topics.iter().cloned().collect()
    }

    /// Announce a new message to the network.
    ///
    /// Publishes a message announcement to the messages topic.
    /// The announcement contains minimal metadata for privacy.
    ///
    /// # Arguments
    ///
    /// * `announcement` - The message announcement to publish
    ///
    /// # Returns
    ///
    /// `Ok(())` if the announcement was published successfully.
    ///
    /// # Errors
    ///
    /// Returns `NetError::RateLimitExceeded` if the local rate limit is exceeded.
    ///
    /// # Security
    ///
    /// This method includes local rate limiting to prevent this node from
    /// accidentally flooding the network. See VERITAS-2026-0007.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::gossip::{GossipManager, MessageAnnouncement};
    /// use veritas_protocol::MailboxKey;
    /// use veritas_crypto::Hash256;
    ///
    /// let manager = GossipManager::with_defaults();
    /// let mailbox_key = MailboxKey::from_bytes([0u8; 32]);
    /// let message_hash = Hash256::hash(b"message content");
    ///
    /// let announcement = MessageAnnouncement::new_now(
    ///     mailbox_key,
    ///     message_hash,
    ///     256, // padded size
    /// )?;
    ///
    /// manager.announce_message(announcement).await?;
    /// ```
    pub async fn announce_message(&self, announcement: MessageAnnouncement) -> Result<()> {
        // SECURITY: Check local rate limit BEFORE publishing (VERITAS-2026-0007)
        {
            let mut local_limiter = self.local_rate_limiter.lock().await;
            if !local_limiter.check() {
                warn!("Local rate limit exceeded for message announcements");
                return Err(NetError::RateLimitExceeded(
                    "local announcement rate limit exceeded".to_string(),
                ));
            }
        }

        let data = announcement.to_bytes()?;
        self.publish(TOPIC_MESSAGES, data).await?;

        debug!(
            message_hash = %announcement.message_hash,
            size_bucket = announcement.size_bucket,
            "Announced message"
        );

        Ok(())
    }

    /// Announce a new block to the network.
    ///
    /// Publishes a block announcement to the blocks topic.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the block
    /// * `height` - Height of the block in the chain
    ///
    /// # Returns
    ///
    /// `Ok(())` if the announcement was published successfully.
    pub async fn announce_block(&self, block_hash: &Hash256, height: u64) -> Result<()> {
        let announcement = BlockAnnouncement::new_now(block_hash.clone(), height);
        let data = announcement.to_bytes()?;
        self.publish(TOPIC_BLOCKS, data).await?;

        debug!(
            block_hash = %block_hash,
            height = height,
            "Announced block"
        );

        Ok(())
    }

    /// Announce a delivery receipt to the network.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - Hash of the original message
    /// * `receipt_hash` - Hash of the receipt
    pub async fn announce_receipt(
        &self,
        message_hash: &Hash256,
        receipt_hash: &Hash256,
    ) -> Result<()> {
        let announcement = ReceiptAnnouncement::new_now(message_hash.clone(), receipt_hash.clone());
        let data = announcement.to_bytes()?;
        self.publish(TOPIC_RECEIPTS, data).await?;

        debug!(
            message_hash = %message_hash,
            receipt_hash = %receipt_hash,
            "Announced receipt"
        );

        Ok(())
    }

    /// Publish data to a topic.
    async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        let behaviour = self
            .behaviour
            .as_ref()
            .ok_or_else(|| NetError::Gossip("behaviour not set".to_string()))?;

        let ident_topic = IdentTopic::new(topic);
        let mut behaviour = behaviour.write().await;

        behaviour
            .publish(ident_topic, data)
            .map_err(|e| NetError::Gossip(format!("publish failed: {}", e)))?;

        Ok(())
    }

    /// Handle an incoming gossip message (without rate limiting).
    ///
    /// Called by the swarm event handler when a gossip message is received.
    /// **Note**: For rate-limited handling, use `handle_announcement()` instead.
    ///
    /// # Arguments
    ///
    /// * `message` - The received gossipsub message
    ///
    /// # Returns
    ///
    /// The parsed announcement type if successful.
    pub async fn handle_message(&self, message: &GossipsubMessage) -> Result<GossipAnnouncement> {
        let topic = message.topic.as_str();

        // Check for duplicate using LRU-style deduplication
        {
            let mut state = self.state.write().await;
            let message_id = compute_message_id(message);
            if state.seen_messages.contains(&message_id) {
                return Err(NetError::Gossip("duplicate message".to_string()));
            }
            // SECURITY: Insert with FIFO eviction instead of clearing the entire set.
            // This prevents a replay window where all previously seen messages
            // could be replayed after a bulk clear.
            state.seen_messages.insert(message_id);
        }

        // Parse based on topic
        match topic {
            TOPIC_MESSAGES => {
                let announcement = MessageAnnouncement::from_bytes(&message.data)?;
                Ok(GossipAnnouncement::Message(announcement))
            }
            TOPIC_BLOCKS => {
                let announcement = BlockAnnouncement::from_bytes(&message.data)?;
                Ok(GossipAnnouncement::Block(announcement))
            }
            TOPIC_RECEIPTS => {
                let announcement = ReceiptAnnouncement::from_bytes(&message.data)?;
                Ok(GossipAnnouncement::Receipt(announcement))
            }
            _ => Err(NetError::Gossip(format!("unknown topic: {}", topic))),
        }
    }

    /// Handle an incoming announcement from a peer with rate limiting.
    ///
    /// This is the **primary entry point** for processing incoming gossip
    /// announcements. It enforces rate limits BEFORE processing.
    ///
    /// # Security
    ///
    /// This method addresses VERITAS-2026-0007 (gossip flooding):
    /// - Checks if peer is banned before processing
    /// - Applies per-peer and global rate limits
    /// - Records violations and bans repeat offenders
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer that sent the announcement
    /// * `message` - The received gossipsub message
    ///
    /// # Returns
    ///
    /// The parsed announcement if rate limits pass and parsing succeeds.
    ///
    /// # Errors
    ///
    /// - `NetError::PeerBanned` - The peer is banned
    /// - `NetError::RateLimitExceeded` - Rate limit exceeded
    /// - `NetError::Gossip` - Parsing or validation error
    pub async fn handle_announcement(
        &self,
        peer_id: &PeerId,
        message: &GossipsubMessage,
    ) -> Result<GossipAnnouncement> {
        // SECURITY: Check rate limit BEFORE any processing (VERITAS-2026-0007)
        let rate_limit_result = {
            let mut limiter = self.rate_limiter.lock().await;
            limiter.check_detailed(peer_id)
        };

        match rate_limit_result {
            RateLimitResult::Allowed => {
                // Proceed with normal message handling
                self.handle_message(message).await
            }
            RateLimitResult::Banned => {
                warn!(
                    peer = %peer_id,
                    "Rejected announcement from banned peer"
                );
                Err(NetError::PeerBanned(peer_id.to_string()))
            }
            RateLimitResult::PeerLimitExceeded => {
                // Record violation and potentially ban
                let banned = {
                    let mut limiter = self.rate_limiter.lock().await;
                    limiter.record_violation(peer_id)
                };

                if banned {
                    warn!(
                        peer = %peer_id,
                        "Peer banned for repeated rate limit violations"
                    );
                } else {
                    debug!(
                        peer = %peer_id,
                        "Rate limit exceeded for peer"
                    );
                }

                Err(NetError::RateLimitExceeded(format!(
                    "per-peer rate limit exceeded for {}",
                    peer_id
                )))
            }
            RateLimitResult::GlobalLimitExceeded => {
                debug!("Global rate limit exceeded");
                Err(NetError::RateLimitExceeded(
                    "global rate limit exceeded".to_string(),
                ))
            }
        }
    }

    /// Check if a peer is currently banned.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer to check
    ///
    /// # Returns
    ///
    /// `true` if the peer is banned, `false` otherwise.
    pub async fn is_peer_banned(&self, peer_id: &PeerId) -> bool {
        let mut limiter = self.rate_limiter.lock().await;
        limiter.is_banned(peer_id)
    }

    /// Manually ban a peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer to ban
    pub async fn ban_peer(&self, peer_id: &PeerId) {
        let mut limiter = self.rate_limiter.lock().await;
        limiter.ban_peer(peer_id);
        warn!(peer = %peer_id, "Peer manually banned");
    }

    /// Manually unban a peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer to unban
    pub async fn unban_peer(&self, peer_id: &PeerId) {
        let mut limiter = self.rate_limiter.lock().await;
        limiter.unban_peer(peer_id);
        info!(peer = %peer_id, "Peer manually unbanned");
    }

    /// Get the list of currently banned peers.
    pub async fn banned_peers(&self) -> Vec<PeerId> {
        let limiter = self.rate_limiter.lock().await;
        limiter.banned_peers()
    }

    /// Get the violation count for a peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer to check
    pub async fn peer_violation_count(&self, peer_id: &PeerId) -> u32 {
        let limiter = self.rate_limiter.lock().await;
        limiter.violation_count(peer_id)
    }

    /// Add a peer to the mesh for a topic.
    ///
    /// Called when the gossipsub protocol adds a peer to the mesh.
    pub async fn add_mesh_peer(&self, topic: &str, peer_id: PeerId) {
        let mut state = self.state.write().await;
        if let Some(peers) = state.mesh_peers.get_mut(topic) {
            peers.insert(peer_id);
            debug!(topic = %topic, peer = %peer_id, "Added peer to mesh");
        }
    }

    /// Remove a peer from the mesh for a topic.
    ///
    /// Called when the gossipsub protocol removes a peer from the mesh.
    pub async fn remove_mesh_peer(&self, topic: &str, peer_id: &PeerId) {
        let mut state = self.state.write().await;
        if let Some(peers) = state.mesh_peers.get_mut(topic) {
            peers.remove(peer_id);
            debug!(topic = %topic, peer = %peer_id, "Removed peer from mesh");
        }
    }

    /// Get the number of mesh peers for a topic.
    pub async fn mesh_peer_count(&self, topic: &str) -> usize {
        let state = self.state.read().await;
        state
            .mesh_peers
            .get(topic)
            .map(|peers| peers.len())
            .unwrap_or(0)
    }

    /// Get all mesh peers for a topic.
    pub async fn mesh_peers(&self, topic: &str) -> Vec<PeerId> {
        let state = self.state.read().await;
        state
            .mesh_peers
            .get(topic)
            .map(|peers| peers.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if the mesh is healthy (has enough peers).
    pub async fn is_mesh_healthy(&self, topic: &str) -> bool {
        self.mesh_peer_count(topic).await >= self.config.mesh_n_low
    }
}

/// Parsed gossip announcement.
#[derive(Debug, Clone)]
pub enum GossipAnnouncement {
    /// A message announcement.
    Message(MessageAnnouncement),
    /// A block announcement.
    Block(BlockAnnouncement),
    /// A receipt announcement.
    Receipt(ReceiptAnnouncement),
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate that a size is a valid padding bucket.
fn validate_size_bucket(size: usize) -> Result<u16> {
    if PADDING_BUCKETS.contains(&size) {
        Ok(size as u16)
    } else {
        Err(NetError::Gossip(format!(
            "invalid size bucket: {} (expected one of {:?})",
            size, PADDING_BUCKETS
        )))
    }
}

/// Compute a message ID for deduplication.
fn compute_message_id(message: &GossipsubMessage) -> MessageId {
    // Use the hash of the message data as the ID
    let hash = Hash256::hash(&message.data);
    MessageId::from(hash.to_bytes().to_vec())
}

/// Get the current timestamp bucket.
pub fn current_timestamp_bucket() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();

    now / TIMESTAMP_BUCKET_SECS
}

/// Convert a timestamp to its bucket.
pub fn timestamp_to_bucket(timestamp_secs: u64) -> u64 {
    timestamp_secs / TIMESTAMP_BUCKET_SECS
}

/// Get the start of a timestamp bucket (for range queries).
pub fn bucket_start_timestamp(bucket: u64) -> u64 {
    bucket * TIMESTAMP_BUCKET_SECS
}

/// Get the end of a timestamp bucket (exclusive).
pub fn bucket_end_timestamp(bucket: u64) -> u64 {
    (bucket + 1) * TIMESTAMP_BUCKET_SECS
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Rate Limiting Tests (VERITAS-2026-0007)
    // ========================================================================

    #[tokio::test]
    async fn test_rate_limit_config_in_gossip_config() {
        let rate_config = RateLimitConfig::default()
            .with_per_peer_rate(5)
            .with_global_rate(100);

        let gossip_config = GossipConfig::default().with_rate_limit(rate_config);

        assert_eq!(gossip_config.rate_limit.per_peer_rate, 5);
        assert_eq!(gossip_config.rate_limit.global_rate, 100);
    }

    #[tokio::test]
    async fn test_gossip_manager_has_rate_limiter() {
        let manager = GossipManager::with_defaults();

        // Verify rate limiter is initialized
        let peer = PeerId::random();
        assert!(!manager.is_peer_banned(&peer).await);
        assert_eq!(manager.peer_violation_count(&peer).await, 0);
    }

    #[tokio::test]
    async fn test_manual_peer_ban_unban() {
        let manager = GossipManager::with_defaults();
        let peer = PeerId::random();

        // Initially not banned
        assert!(!manager.is_peer_banned(&peer).await);

        // Ban the peer
        manager.ban_peer(&peer).await;
        assert!(manager.is_peer_banned(&peer).await);

        // Verify in banned list
        let banned = manager.banned_peers().await;
        assert!(banned.contains(&peer));

        // Unban the peer
        manager.unban_peer(&peer).await;
        assert!(!manager.is_peer_banned(&peer).await);
    }

    #[tokio::test]
    async fn test_local_rate_limiter_basic() {
        let mut limiter = LocalRateLimiter::new(3);

        // Should allow first 3 requests
        assert!(limiter.check());
        assert!(limiter.check());
        assert!(limiter.check());

        // 4th should fail
        assert!(!limiter.check());
    }

    #[tokio::test]
    async fn test_local_rate_limiter_recovery() {
        use std::time::Duration;
        use tokio::time::sleep;

        let mut limiter = LocalRateLimiter::new(10);

        // Exhaust the limit
        for _ in 0..10 {
            assert!(limiter.check());
        }
        assert!(!limiter.check());

        // Wait for tokens to recover
        sleep(Duration::from_millis(1100)).await;

        // Should allow requests again
        assert!(limiter.check());
    }

    // ========================================================================
    // Announcement Tests
    // ========================================================================

    #[test]
    fn test_message_announcement_creation() {
        let mailbox_key = MailboxKey::from_bytes([1u8; 32]);
        let message_hash = Hash256::hash(b"test message");

        let announcement =
            MessageAnnouncement::new(mailbox_key.clone(), message_hash.clone(), 1704067200, 1024)
                .unwrap();

        assert_eq!(announcement.mailbox_key, mailbox_key);
        assert_eq!(announcement.message_hash, message_hash);
        assert_eq!(announcement.size_bucket, 1024);
        // 1704067200 / 3600 = 473352
        assert_eq!(announcement.timestamp_bucket, 473352);
    }

    #[test]
    fn test_message_announcement_invalid_size_bucket() {
        let mailbox_key = MailboxKey::from_bytes([1u8; 32]);
        let message_hash = Hash256::hash(b"test message");

        // 100 is not a valid padding bucket (should be 1024, 2048, 4096, or 8192)
        let result = MessageAnnouncement::new(mailbox_key, message_hash, 1704067200, 100);

        assert!(result.is_err());
    }

    #[test]
    fn test_message_announcement_serialization_roundtrip() {
        let mailbox_key = MailboxKey::from_bytes([2u8; 32]);
        let message_hash = Hash256::hash(b"test");

        let original = MessageAnnouncement::new(mailbox_key, message_hash, 1704067200, 2048).unwrap();

        let bytes = original.to_bytes().unwrap();
        let deserialized = MessageAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_block_announcement_creation() {
        let block_hash = Hash256::hash(b"block data");
        let announcement = BlockAnnouncement::new(block_hash.clone(), 42, 1704067200);

        assert_eq!(announcement.block_hash, block_hash);
        assert_eq!(announcement.height, 42);
    }

    #[test]
    fn test_receipt_announcement_creation() {
        let message_hash = Hash256::hash(b"message");
        let receipt_hash = Hash256::hash(b"receipt");

        let announcement =
            ReceiptAnnouncement::new(message_hash.clone(), receipt_hash.clone(), 1704067200);

        assert_eq!(announcement.message_hash, message_hash);
        assert_eq!(announcement.receipt_hash, receipt_hash);
    }

    // ========================================================================
    // Timestamp Bucket Tests
    // ========================================================================

    #[test]
    fn test_timestamp_to_bucket() {
        // 1704067200 = 2024-01-01 00:00:00 UTC
        // 1704067200 / 3600 = 473352
        assert_eq!(timestamp_to_bucket(1704067200), 473352);

        // Same hour should be same bucket
        assert_eq!(timestamp_to_bucket(1704067200 + 1800), 473352);

        // Next hour should be next bucket
        assert_eq!(timestamp_to_bucket(1704067200 + 3600), 473353);
    }

    #[test]
    fn test_bucket_start_timestamp() {
        let bucket = 473352_u64;
        assert_eq!(bucket_start_timestamp(bucket), bucket * 3600);
    }

    #[test]
    fn test_bucket_end_timestamp() {
        let bucket = 473352_u64;
        assert_eq!(bucket_end_timestamp(bucket), (bucket + 1) * 3600);
    }

    // ========================================================================
    // Size Bucket Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_size_bucket_valid() {
        assert!(validate_size_bucket(1024).is_ok());
        assert!(validate_size_bucket(2048).is_ok());
        assert!(validate_size_bucket(4096).is_ok());
        assert!(validate_size_bucket(8192).is_ok());
    }

    #[test]
    fn test_validate_size_bucket_invalid() {
        assert!(validate_size_bucket(0).is_err());
        assert!(validate_size_bucket(256).is_err());
        assert!(validate_size_bucket(512).is_err());
        assert!(validate_size_bucket(300).is_err());
    }

    // ========================================================================
    // GossipConfig Builder Tests
    // ========================================================================

    #[test]
    fn test_gossip_config_default() {
        let config = GossipConfig::default();

        assert_eq!(config.heartbeat_interval, Duration::from_secs(1));
        assert_eq!(config.max_transmit_size, 65536);
        assert_eq!(config.mesh_n, 6);
        assert_eq!(config.mesh_n_low, 4);
        assert_eq!(config.mesh_n_high, 12);
    }

    #[test]
    fn test_gossip_config_builder() {
        let config = GossipConfig::new()
            .with_heartbeat_interval(Duration::from_secs(2))
            .with_max_transmit_size(32768)
            .with_mesh_n(8)
            .with_mesh_n_low(5)
            .with_mesh_n_high(15)
            .with_gossip_lazy(8)
            .with_history_length(10)
            .with_history_gossip(5);

        assert_eq!(config.heartbeat_interval, Duration::from_secs(2));
        assert_eq!(config.max_transmit_size, 32768);
        assert_eq!(config.mesh_n, 8);
        assert_eq!(config.mesh_n_low, 5);
        assert_eq!(config.mesh_n_high, 15);
        assert_eq!(config.gossip_lazy, 8);
        assert_eq!(config.history_length, 10);
        assert_eq!(config.history_gossip, 5);
    }

    // ========================================================================
    // Security Tests (VERITAS-2026-0007)
    // ========================================================================

    /// Test that rate limiting configuration is properly propagated.
    #[test]
    fn test_security_rate_limit_config_propagation() {
        let rate_config = RateLimitConfig::default()
            .with_per_peer_rate(10)
            .with_global_rate(1000)
            .with_violations_before_ban(5)
            .with_ban_duration_secs(300);

        let gossip_config = GossipConfig::default().with_rate_limit(rate_config);

        assert_eq!(gossip_config.rate_limit.per_peer_rate, 10);
        assert_eq!(gossip_config.rate_limit.global_rate, 1000);
        assert_eq!(gossip_config.rate_limit.violations_before_ban, 5);
        assert_eq!(gossip_config.rate_limit.ban_duration_secs, 300);
    }

    /// Test that the GossipManager properly initializes with rate limiting.
    #[tokio::test]
    async fn test_security_gossip_manager_rate_limiter_initialized() {
        let config = GossipConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_peer_rate(5)
                .with_violations_before_ban(3),
        );

        let manager = GossipManager::new(config);

        // Verify the rate limiter is working
        let peer = PeerId::random();

        // Initially no violations
        assert_eq!(manager.peer_violation_count(&peer).await, 0);
        assert!(!manager.is_peer_banned(&peer).await);
    }

    /// Test that banned peers are properly tracked.
    #[tokio::test]
    async fn test_security_banned_peers_tracking() {
        let manager = GossipManager::with_defaults();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        // Ban multiple peers
        manager.ban_peer(&peer1).await;
        manager.ban_peer(&peer2).await;

        let banned = manager.banned_peers().await;
        assert_eq!(banned.len(), 2);
        assert!(banned.contains(&peer1));
        assert!(banned.contains(&peer2));
        assert!(!banned.contains(&peer3));

        // Unban one
        manager.unban_peer(&peer1).await;

        let banned = manager.banned_peers().await;
        assert_eq!(banned.len(), 1);
        assert!(!banned.contains(&peer1));
        assert!(banned.contains(&peer2));
    }

    // ========================================================================
    // SeenMessages Tests (VERITAS-2026-0014 - Replay Window Fix)
    // ========================================================================

    #[test]
    fn test_seen_messages_basic_insert_and_contains() {
        let mut seen = SeenMessages::new(100);

        let id1 = MessageId::from(vec![1u8; 32]);
        let id2 = MessageId::from(vec![2u8; 32]);

        assert!(!seen.contains(&id1));
        seen.insert(id1.clone());
        assert!(seen.contains(&id1));
        assert!(!seen.contains(&id2));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn test_seen_messages_duplicate_insert_ignored() {
        let mut seen = SeenMessages::new(100);

        let id1 = MessageId::from(vec![1u8; 32]);
        seen.insert(id1.clone());
        seen.insert(id1.clone());

        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn test_seen_messages_fifo_eviction() {
        let mut seen = SeenMessages::new(3);

        let id1 = MessageId::from(vec![1u8; 32]);
        let id2 = MessageId::from(vec![2u8; 32]);
        let id3 = MessageId::from(vec![3u8; 32]);
        let id4 = MessageId::from(vec![4u8; 32]);

        seen.insert(id1.clone());
        seen.insert(id2.clone());
        seen.insert(id3.clone());
        assert_eq!(seen.len(), 3);

        // Insert a 4th -- oldest (id1) should be evicted
        seen.insert(id4.clone());
        assert_eq!(seen.len(), 3);

        // id1 should no longer be present (evicted)
        assert!(!seen.contains(&id1));
        // id2, id3, id4 should still be present
        assert!(seen.contains(&id2));
        assert!(seen.contains(&id3));
        assert!(seen.contains(&id4));
    }

    #[test]
    fn test_seen_messages_no_complete_clear() {
        // This is the key security test: after eviction, previously seen
        // messages (except the evicted one) should NOT be replayable.
        let mut seen = SeenMessages::new(5);

        // Fill with 5 messages
        let ids: Vec<MessageId> = (0..5)
            .map(|i| MessageId::from(vec![i as u8; 32]))
            .collect();
        for id in &ids {
            seen.insert(id.clone());
        }
        assert_eq!(seen.len(), 5);

        // Insert one more -- only the oldest (ids[0]) should be evicted
        let new_id = MessageId::from(vec![99u8; 32]);
        seen.insert(new_id.clone());
        assert_eq!(seen.len(), 5);

        // ids[0] was evicted
        assert!(!seen.contains(&ids[0]));

        // ids[1..4] should still be tracked (NOT cleared)
        for id in &ids[1..] {
            assert!(seen.contains(id), "Previously seen message should still be tracked after FIFO eviction");
        }

        // New ID should be tracked
        assert!(seen.contains(&new_id));
    }

    #[test]
    fn test_seen_messages_sequential_eviction() {
        let mut seen = SeenMessages::new(3);

        // Insert messages 1-5 sequentially
        for i in 1u8..=5 {
            seen.insert(MessageId::from(vec![i; 32]));
        }

        // Only last 3 should remain (3, 4, 5)
        assert_eq!(seen.len(), 3);
        assert!(!seen.contains(&MessageId::from(vec![1u8; 32])));
        assert!(!seen.contains(&MessageId::from(vec![2u8; 32])));
        assert!(seen.contains(&MessageId::from(vec![3u8; 32])));
        assert!(seen.contains(&MessageId::from(vec![4u8; 32])));
        assert!(seen.contains(&MessageId::from(vec![5u8; 32])));
    }

    // ========================================================================
    // Pre-deserialization size check tests (VERITAS-2026-0003)
    // ========================================================================

    #[test]
    fn test_message_announcement_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_MESSAGE_ANNOUNCEMENT_SIZE + 1];
        let result = MessageAnnouncement::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_message_announcement_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_MESSAGE_ANNOUNCEMENT_SIZE];
        let result = MessageAnnouncement::from_bytes(&at_limit);
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_message_announcement_roundtrip_within_limit() {
        let mailbox_key = MailboxKey::from_bytes([1u8; 32]);
        let message_hash = Hash256::hash(b"test message");
        let announcement =
            MessageAnnouncement::new(mailbox_key, message_hash, 1704067200, 1024).unwrap();

        let bytes = announcement.to_bytes().unwrap();
        assert!(
            bytes.len() <= MAX_MESSAGE_ANNOUNCEMENT_SIZE,
            "Serialized MessageAnnouncement ({} bytes) exceeds limit ({})",
            bytes.len(),
            MAX_MESSAGE_ANNOUNCEMENT_SIZE
        );

        let restored = MessageAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(announcement, restored);
    }

    #[test]
    fn test_block_announcement_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_BLOCK_ANNOUNCEMENT_SIZE + 1];
        let result = BlockAnnouncement::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_block_announcement_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_BLOCK_ANNOUNCEMENT_SIZE];
        let result = BlockAnnouncement::from_bytes(&at_limit);
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_block_announcement_roundtrip_within_limit() {
        let block_hash = Hash256::hash(b"block data");
        let announcement = BlockAnnouncement::new(block_hash, 42, 1704067200);

        let bytes = announcement.to_bytes().unwrap();
        assert!(
            bytes.len() <= MAX_BLOCK_ANNOUNCEMENT_SIZE,
            "Serialized BlockAnnouncement ({} bytes) exceeds limit ({})",
            bytes.len(),
            MAX_BLOCK_ANNOUNCEMENT_SIZE
        );

        let restored = BlockAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(announcement, restored);
    }

    #[test]
    fn test_receipt_announcement_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_RECEIPT_ANNOUNCEMENT_SIZE + 1];
        let result = ReceiptAnnouncement::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_receipt_announcement_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_RECEIPT_ANNOUNCEMENT_SIZE];
        let result = ReceiptAnnouncement::from_bytes(&at_limit);
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_receipt_announcement_roundtrip_within_limit() {
        let message_hash = Hash256::hash(b"message");
        let receipt_hash = Hash256::hash(b"receipt");
        let announcement = ReceiptAnnouncement::new(message_hash, receipt_hash, 1704067200);

        let bytes = announcement.to_bytes().unwrap();
        assert!(
            bytes.len() <= MAX_RECEIPT_ANNOUNCEMENT_SIZE,
            "Serialized ReceiptAnnouncement ({} bytes) exceeds limit ({})",
            bytes.len(),
            MAX_RECEIPT_ANNOUNCEMENT_SIZE
        );

        let restored = ReceiptAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(announcement, restored);
    }
}
