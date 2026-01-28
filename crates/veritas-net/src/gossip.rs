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
//! - **Size Buckets**: Fixed padding bucket sizes (256/512/1024) hide true message size
//! - **No Content**: Only hashes and routing info are announced
//!
//! ## Topics
//!
//! - `veritas/messages/v1` - New message announcements
//! - `veritas/blocks/v1` - New block announcements
//! - `veritas/receipts/v1` - Delivery receipt announcements

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use libp2p::gossipsub::{
    self, Behaviour as GossipsubBehaviour, ConfigBuilder as GossipsubConfigBuilder, IdentTopic,
    Message as GossipsubMessage, MessageAuthenticity, MessageId, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use veritas_crypto::Hash256;
use veritas_protocol::{MailboxKey, PADDING_BUCKETS};

use crate::error::{NetError, Result};

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
    /// One of: 256, 512, or 1024 bytes.
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Gossip(format!("deserialization failed: {}", e)))
    }
}

// ============================================================================
// Gossip Manager
// ============================================================================

/// Internal state for the gossip manager.
struct GossipState {
    /// Set of subscribed topics.
    subscribed_topics: HashSet<String>,

    /// Mesh peers per topic.
    mesh_peers: HashMap<String, HashSet<PeerId>>,

    /// Recently seen message IDs for deduplication.
    seen_messages: HashSet<MessageId>,
}

impl GossipState {
    fn new() -> Self {
        Self {
            subscribed_topics: HashSet::new(),
            mesh_peers: HashMap::new(),
            seen_messages: HashSet::new(),
        }
    }
}

/// Manager for gossip protocol operations.
///
/// Handles topic subscriptions, message publishing, and peer mesh tracking.
/// Provides a high-level interface over libp2p's Gossipsub.
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
        Self {
            config,
            behaviour: None,
            state: Arc::new(RwLock::new(GossipState::new())),
            local_peer_id: None,
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

    /// Handle an incoming gossip message.
    ///
    /// Called by the swarm event handler when a gossip message is received.
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

        // Check for duplicate
        {
            let mut state = self.state.write().await;
            let message_id = compute_message_id(message);
            if state.seen_messages.contains(&message_id) {
                return Err(NetError::Gossip("duplicate message".to_string()));
            }
            state.seen_messages.insert(message_id);

            // Prune old message IDs to prevent unbounded growth
            // Keep last 10000 messages
            if state.seen_messages.len() > 10000 {
                state.seen_messages.clear();
            }
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
