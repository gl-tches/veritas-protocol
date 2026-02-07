//! Store-and-forward relay for offline peer message delivery.
//!
//! This module implements message relaying for peers that are temporarily
//! offline. Messages are held by relay nodes and delivered when the
//! recipient reconnects to the network.
//!
//! ## Architecture
//!
//! ```text
//! Sender → Relay Node → (stores message) → Recipient comes online → Delivery
//! ```
//!
//! ## Security Properties
//!
//! - **Hop Counting**: Messages expire after max hops to prevent infinite loops
//! - **TTL Enforcement**: Messages expire after 7 days (configurable)
//! - **Forward Delay**: Random jitter prevents traffic analysis
//! - **No Metadata Leakage**: Relay only sees mailbox keys, not identities
//!
//! ## Usage
//!
//! ```ignore
//! use veritas_net::relay::{RelayConfig, RelayManager};
//! use veritas_protocol::{MinimalEnvelope, MailboxKey};
//!
//! let config = RelayConfig::default();
//! let mut relay = RelayManager::new(config);
//!
//! // Store a message for offline peer
//! relay.store_for_relay(&mailbox_key, envelope)?;
//!
//! // Later, when peer comes online
//! let messages = relay.get_pending(&mailbox_key);
//! for msg in messages {
//!     // Deliver message
//!     relay.mark_delivered(&mailbox_key, &msg_hash)?;
//! }
//!
//! // Periodically prune expired messages
//! let pruned = relay.prune_expired();
//! ```

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_protocol::{MESSAGE_TTL_SECS, MailboxKey, MinimalEnvelope};

use crate::error::{NetError, Result};

/// Default maximum hop count before message is dropped.
const DEFAULT_MAX_HOP_COUNT: u8 = 3;

/// Default maximum number of stored messages per relay.
const DEFAULT_MAX_STORED_MESSAGES: usize = 100_000;

/// Default maximum message size in bytes.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 8192;

/// Default forward delay range for traffic analysis resistance (0-500ms).
const DEFAULT_FORWARD_DELAY_MS: u64 = 500;

/// Configuration for the relay manager.
///
/// Controls message storage limits, TTL, and forwarding behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum number of hops a message can traverse.
    ///
    /// After this many hops, the message is dropped to prevent
    /// infinite relay loops. Default: 3
    pub max_hop_count: u8,

    /// Time-to-live for stored messages.
    ///
    /// Messages older than this are pruned. Default: 7 days
    pub message_ttl: Duration,

    /// Maximum number of messages the relay will store.
    ///
    /// When exceeded, oldest messages are dropped first.
    /// Default: 100,000
    pub max_stored_messages: usize,

    /// Maximum size of a single message in bytes.
    ///
    /// Messages larger than this are rejected. Default: 8192
    pub max_message_size: usize,

    /// Random delay added before forwarding for traffic analysis resistance.
    ///
    /// The actual delay is uniformly distributed from 0 to this value.
    /// Default: 500ms
    pub forward_delay: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_hop_count: DEFAULT_MAX_HOP_COUNT,
            message_ttl: Duration::from_secs(MESSAGE_TTL_SECS),
            max_stored_messages: DEFAULT_MAX_STORED_MESSAGES,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            forward_delay: Duration::from_millis(DEFAULT_FORWARD_DELAY_MS),
        }
    }
}

impl RelayConfig {
    /// Create a new relay configuration with custom values.
    pub fn new(
        max_hop_count: u8,
        message_ttl: Duration,
        max_stored_messages: usize,
        max_message_size: usize,
        forward_delay: Duration,
    ) -> Self {
        Self {
            max_hop_count,
            message_ttl,
            max_stored_messages,
            max_message_size,
            forward_delay,
        }
    }

    /// Create a configuration optimized for low-resource environments.
    pub fn low_resource() -> Self {
        Self {
            max_hop_count: 2,
            message_ttl: Duration::from_secs(24 * 60 * 60), // 1 day
            max_stored_messages: 10_000,
            max_message_size: 1024,
            forward_delay: Duration::from_millis(200),
        }
    }

    /// Create a configuration optimized for high-throughput relays.
    pub fn high_throughput() -> Self {
        Self {
            max_hop_count: 5,
            message_ttl: Duration::from_secs(MESSAGE_TTL_SECS),
            max_stored_messages: 1_000_000,
            max_message_size: 8192,
            forward_delay: Duration::from_millis(100),
        }
    }

    /// Validate the configuration.
    ///
    /// Returns an error if any values are invalid.
    pub fn validate(&self) -> Result<()> {
        if self.max_hop_count == 0 {
            return Err(NetError::Transport(
                "max_hop_count must be at least 1".to_string(),
            ));
        }

        if self.message_ttl.is_zero() {
            return Err(NetError::Transport(
                "message_ttl must be greater than zero".to_string(),
            ));
        }

        if self.max_stored_messages == 0 {
            return Err(NetError::Transport(
                "max_stored_messages must be at least 1".to_string(),
            ));
        }

        if self.max_message_size < 1024 {
            return Err(NetError::Transport(
                "max_message_size must be at least 1024 bytes".to_string(),
            ));
        }

        Ok(())
    }
}

/// A message being held for relay delivery.
///
/// Contains the encrypted envelope plus relay metadata like hop count
/// and delivery attempts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayedMessage {
    /// The minimal metadata envelope containing the encrypted message.
    envelope: MinimalEnvelope,

    /// Number of hops this message has traversed.
    ///
    /// Incremented each time the message is forwarded.
    /// Message is dropped when this reaches max_hop_count.
    hop_count: u8,

    /// Unix timestamp when this relay received the message.
    received_at: u64,

    /// Number of times we've attempted to forward this message.
    ///
    /// Used for retry logic and failure tracking.
    forward_attempts: u8,

    /// Hash of the envelope for deduplication and tracking.
    message_hash: Hash256,
}

impl RelayedMessage {
    /// Create a new relayed message from an envelope.
    fn new(envelope: MinimalEnvelope, hop_count: u8) -> Self {
        let message_hash = envelope.envelope_hash();
        let received_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        Self {
            envelope,
            hop_count,
            received_at,
            forward_attempts: 0,
            message_hash,
        }
    }

    /// Get the envelope.
    pub fn envelope(&self) -> &MinimalEnvelope {
        &self.envelope
    }

    /// Get the current hop count.
    pub fn hop_count(&self) -> u8 {
        self.hop_count
    }

    /// Get the timestamp when this message was received.
    pub fn received_at(&self) -> u64 {
        self.received_at
    }

    /// Get the number of forward attempts.
    pub fn forward_attempts(&self) -> u8 {
        self.forward_attempts
    }

    /// Get the message hash.
    pub fn message_hash(&self) -> &Hash256 {
        &self.message_hash
    }

    /// Get the size of this message in bytes.
    pub fn size(&self) -> usize {
        self.envelope.size()
    }

    /// Check if the message has expired based on TTL.
    fn is_expired(&self, ttl_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        now.saturating_sub(self.received_at) > ttl_secs
    }

    /// Increment the hop count.
    fn increment_hop(&mut self) -> u8 {
        self.hop_count = self.hop_count.saturating_add(1);
        self.hop_count
    }

    /// Increment the forward attempt counter.
    fn increment_forward_attempts(&mut self) {
        self.forward_attempts = self.forward_attempts.saturating_add(1);
    }
}

/// Statistics about relay operations.
///
/// Used for monitoring and debugging relay health.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayStats {
    /// Number of messages currently stored.
    pub messages_stored: usize,

    /// Total messages successfully forwarded (lifetime counter).
    pub messages_forwarded: u64,

    /// Total messages that expired and were pruned (lifetime counter).
    pub messages_expired: u64,

    /// Total bytes currently stored across all messages.
    pub bytes_stored: usize,

    /// Number of unique mailboxes with pending messages.
    pub active_mailboxes: usize,

    /// Total messages rejected due to hop limit exceeded.
    pub hop_limit_exceeded: u64,

    /// Total messages rejected due to size limit.
    pub size_limit_exceeded: u64,

    /// Total messages rejected due to storage full.
    pub storage_full_rejections: u64,
}

impl RelayStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Manager for store-and-forward relay operations.
///
/// Holds messages for offline peers and tracks delivery status.
/// Messages are stored in memory and indexed by mailbox key for
/// efficient retrieval when peers come online.
///
/// ## Thread Safety
///
/// This type is NOT thread-safe. For concurrent access, wrap in
/// appropriate synchronization primitives (e.g., `Mutex` or `RwLock`).
pub struct RelayManager {
    /// Configuration for this relay.
    config: RelayConfig,

    /// Messages indexed by mailbox key.
    ///
    /// Each mailbox can have multiple pending messages.
    messages: HashMap<[u8; 32], Vec<RelayedMessage>>,

    /// Set of message hashes for deduplication.
    ///
    /// Prevents storing the same message multiple times.
    seen_hashes: HashMap<Hash256, ()>,

    /// Relay statistics.
    stats: RelayStats,
}

impl RelayManager {
    /// Create a new relay manager with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Relay configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::relay::{RelayConfig, RelayManager};
    ///
    /// let config = RelayConfig::default();
    /// let relay = RelayManager::new(config);
    /// ```
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            messages: HashMap::new(),
            seen_hashes: HashMap::new(),
            stats: RelayStats::new(),
        }
    }

    /// Create a new relay manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RelayConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Store a message for relay to an offline peer.
    ///
    /// The message will be held until the recipient's mailbox key
    /// requests pending messages, or until the message expires.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The recipient's derived mailbox key
    /// * `envelope` - The encrypted message envelope
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message size exceeds the configured limit
    /// - Storage is full
    /// - Message is a duplicate (same hash already stored)
    ///
    /// # Example
    ///
    /// ```ignore
    /// relay.store_for_relay(&mailbox_key, envelope)?;
    /// ```
    pub fn store_for_relay(
        &mut self,
        mailbox_key: &MailboxKey,
        envelope: MinimalEnvelope,
    ) -> Result<()> {
        self.store_for_relay_with_hop(mailbox_key, envelope, 0)
    }

    /// Store a message with an existing hop count.
    ///
    /// Used when receiving a relayed message from another node.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The recipient's derived mailbox key
    /// * `envelope` - The encrypted message envelope
    /// * `hop_count` - Current hop count from previous relays
    pub fn store_for_relay_with_hop(
        &mut self,
        mailbox_key: &MailboxKey,
        envelope: MinimalEnvelope,
        hop_count: u8,
    ) -> Result<()> {
        // Check hop count limit
        if hop_count >= self.config.max_hop_count {
            self.stats.hop_limit_exceeded += 1;
            return Err(NetError::DeliveryFailed(format!(
                "message exceeded maximum hop count of {}",
                self.config.max_hop_count
            )));
        }

        // Check message size
        let msg_size = envelope.size();
        if msg_size > self.config.max_message_size {
            self.stats.size_limit_exceeded += 1;
            return Err(NetError::DeliveryFailed(format!(
                "message size {} exceeds limit of {}",
                msg_size, self.config.max_message_size
            )));
        }

        // Check storage capacity
        if self.stats.messages_stored >= self.config.max_stored_messages {
            self.stats.storage_full_rejections += 1;
            return Err(NetError::DeliveryFailed("relay storage full".to_string()));
        }

        // NET-FIX-7: Bound the seen_hashes set to prevent unbounded memory growth.
        // If it exceeds twice the max stored messages, prune old entries.
        let max_seen = self.config.max_stored_messages.saturating_mul(2);
        if self.seen_hashes.len() > max_seen {
            self.seen_hashes.clear();
        }

        // Check for duplicates
        let message_hash = envelope.envelope_hash();
        if self.seen_hashes.contains_key(&message_hash) {
            return Err(NetError::DeliveryFailed(
                "duplicate message already stored".to_string(),
            ));
        }

        // Validate envelope structure
        envelope.validate().map_err(NetError::Protocol)?;

        // Create relayed message
        let relayed = RelayedMessage::new(envelope, hop_count);

        // Store message
        let key = *mailbox_key.as_bytes();
        self.messages.entry(key).or_default().push(relayed);
        self.seen_hashes.insert(message_hash, ());

        // Update stats
        self.stats.messages_stored += 1;
        self.stats.bytes_stored += msg_size;
        self.stats.active_mailboxes = self.messages.len();

        Ok(())
    }

    /// Get all pending messages for a mailbox key.
    ///
    /// Returns references to messages waiting for delivery.
    /// Call `mark_delivered` after successfully delivering each message.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The recipient's derived mailbox key
    ///
    /// # Returns
    ///
    /// A vector of references to pending messages, or empty if none.
    pub fn get_pending(&self, mailbox_key: &MailboxKey) -> Vec<&RelayedMessage> {
        let key = *mailbox_key.as_bytes();
        self.messages
            .get(&key)
            .map(|msgs| msgs.iter().collect())
            .unwrap_or_default()
    }

    /// Get mutable references to pending messages for a mailbox key.
    ///
    /// Allows modifying message state (e.g., incrementing forward attempts).
    pub fn get_pending_mut(&mut self, mailbox_key: &MailboxKey) -> Vec<&mut RelayedMessage> {
        let key = *mailbox_key.as_bytes();
        self.messages
            .get_mut(&key)
            .map(|msgs| msgs.iter_mut().collect())
            .unwrap_or_default()
    }

    /// Check if there are any pending messages for a mailbox key.
    pub fn has_pending(&self, mailbox_key: &MailboxKey) -> bool {
        let key = *mailbox_key.as_bytes();
        self.messages
            .get(&key)
            .map(|msgs| !msgs.is_empty())
            .unwrap_or(false)
    }

    /// Count pending messages for a mailbox key.
    pub fn pending_count(&self, mailbox_key: &MailboxKey) -> usize {
        let key = *mailbox_key.as_bytes();
        self.messages.get(&key).map(|msgs| msgs.len()).unwrap_or(0)
    }

    /// Mark a message as delivered and remove it from storage.
    ///
    /// Call this after successfully delivering a message to the recipient.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The recipient's derived mailbox key
    /// * `message_hash` - Hash of the delivered message
    ///
    /// # Errors
    ///
    /// Returns an error if the message was not found.
    pub fn mark_delivered(
        &mut self,
        mailbox_key: &MailboxKey,
        message_hash: &Hash256,
    ) -> Result<()> {
        let key = *mailbox_key.as_bytes();

        let messages = self
            .messages
            .get_mut(&key)
            .ok_or_else(|| NetError::DeliveryFailed("no messages for mailbox key".to_string()))?;

        // Find and remove the message
        let original_len = messages.len();
        let mut removed_size = 0;

        messages.retain(|msg| {
            if msg.message_hash() == message_hash {
                removed_size = msg.size();
                false
            } else {
                true
            }
        });

        if messages.len() == original_len {
            return Err(NetError::DeliveryFailed("message not found".to_string()));
        }

        // Remove from seen hashes
        self.seen_hashes.remove(message_hash);

        // Update stats
        self.stats.messages_stored = self.stats.messages_stored.saturating_sub(1);
        self.stats.bytes_stored = self.stats.bytes_stored.saturating_sub(removed_size);
        self.stats.messages_forwarded += 1;

        // Clean up empty mailbox entries
        if messages.is_empty() {
            self.messages.remove(&key);
            self.stats.active_mailboxes = self.messages.len();
        }

        Ok(())
    }

    /// Check if a message should be forwarded.
    ///
    /// Returns true if the message has not exceeded the hop limit
    /// and has not expired.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to check
    pub fn should_forward(&self, message: &RelayedMessage) -> bool {
        // Check hop count
        if message.hop_count() >= self.config.max_hop_count {
            return false;
        }

        // Check expiration
        if message.is_expired(self.config.message_ttl.as_secs()) {
            return false;
        }

        true
    }

    /// Increment the hop count for a message.
    ///
    /// Call this before forwarding a message to another relay.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - Hash of the message to update
    ///
    /// # Returns
    ///
    /// The new hop count after incrementing.
    ///
    /// # Errors
    ///
    /// Returns an error if the message was not found.
    pub fn increment_hop(&mut self, message_hash: &Hash256) -> Result<u8> {
        // Find the message across all mailboxes
        for messages in self.messages.values_mut() {
            for msg in messages.iter_mut() {
                if msg.message_hash() == message_hash {
                    return Ok(msg.increment_hop());
                }
            }
        }

        Err(NetError::DeliveryFailed("message not found".to_string()))
    }

    /// Record a forward attempt for a message.
    ///
    /// Call this when attempting to forward a message, regardless of success.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - Hash of the message to update
    ///
    /// # Errors
    ///
    /// Returns an error if the message was not found.
    pub fn record_forward_attempt(&mut self, message_hash: &Hash256) -> Result<()> {
        // Find the message across all mailboxes
        for messages in self.messages.values_mut() {
            for msg in messages.iter_mut() {
                if msg.message_hash() == message_hash {
                    msg.increment_forward_attempts();
                    return Ok(());
                }
            }
        }

        Err(NetError::DeliveryFailed("message not found".to_string()))
    }

    /// Prune expired messages from storage.
    ///
    /// Should be called periodically to clean up old messages.
    /// Messages that have exceeded the TTL are removed.
    ///
    /// # Returns
    ///
    /// The number of messages that were pruned.
    pub fn prune_expired(&mut self) -> usize {
        let ttl_secs = self.config.message_ttl.as_secs();
        let mut pruned_count = 0;
        let mut pruned_bytes = 0;

        // Collect expired message hashes first
        let mut expired_hashes = Vec::new();

        for messages in self.messages.values() {
            for msg in messages {
                if msg.is_expired(ttl_secs) {
                    expired_hashes.push(msg.message_hash().clone());
                }
            }
        }

        // Remove expired messages
        for (_, messages) in self.messages.iter_mut() {
            let original_len = messages.len();
            messages.retain(|msg| {
                if msg.is_expired(ttl_secs) {
                    pruned_bytes += msg.size();
                    false
                } else {
                    true
                }
            });
            pruned_count += original_len - messages.len();
        }

        // Remove empty mailbox entries
        self.messages.retain(|_, messages| !messages.is_empty());

        // Remove from seen hashes
        for hash in expired_hashes {
            self.seen_hashes.remove(&hash);
        }

        // Update stats
        self.stats.messages_stored = self.stats.messages_stored.saturating_sub(pruned_count);
        self.stats.bytes_stored = self.stats.bytes_stored.saturating_sub(pruned_bytes);
        self.stats.messages_expired += pruned_count as u64;
        self.stats.active_mailboxes = self.messages.len();

        pruned_count
    }

    /// Get current relay statistics.
    pub fn stats(&self) -> RelayStats {
        self.stats.clone()
    }

    /// Get the number of messages currently stored.
    pub fn message_count(&self) -> usize {
        self.stats.messages_stored
    }

    /// Get the total bytes currently stored.
    pub fn bytes_stored(&self) -> usize {
        self.stats.bytes_stored
    }

    /// Check if the relay has reached storage capacity.
    pub fn is_full(&self) -> bool {
        self.stats.messages_stored >= self.config.max_stored_messages
    }

    /// Get the configured forward delay for traffic analysis resistance.
    ///
    /// Returns a random duration between 0 and the configured max delay.
    pub fn get_forward_delay(&self) -> Duration {
        use rand::Rng;
        let max_ms = self.config.forward_delay.as_millis() as u64;
        if max_ms == 0 {
            return Duration::ZERO;
        }
        let delay_ms = rand::thread_rng().gen_range(0..=max_ms);
        Duration::from_millis(delay_ms)
    }

    /// Clear all stored messages.
    ///
    /// Use with caution - this drops all pending messages.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.seen_hashes.clear();
        self.stats.messages_stored = 0;
        self.stats.bytes_stored = 0;
        self.stats.active_mailboxes = 0;
    }

    /// Get all mailbox keys with pending messages.
    ///
    /// Useful for iterating over all pending deliveries.
    pub fn pending_mailboxes(&self) -> Vec<MailboxKey> {
        self.messages
            .keys()
            .map(|key| MailboxKey::from_bytes(*key))
            .collect()
    }

    /// Remove all messages for a specific mailbox key.
    ///
    /// # Returns
    ///
    /// The number of messages removed.
    pub fn remove_mailbox(&mut self, mailbox_key: &MailboxKey) -> usize {
        let key = *mailbox_key.as_bytes();

        if let Some(messages) = self.messages.remove(&key) {
            let count = messages.len();
            let bytes: usize = messages.iter().map(|m| m.size()).sum();

            // Remove from seen hashes
            for msg in &messages {
                self.seen_hashes.remove(msg.message_hash());
            }

            // Update stats
            self.stats.messages_stored = self.stats.messages_stored.saturating_sub(count);
            self.stats.bytes_stored = self.stats.bytes_stored.saturating_sub(bytes);
            self.stats.active_mailboxes = self.messages.len();

            count
        } else {
            0
        }
    }
}

impl std::fmt::Debug for RelayManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayManager")
            .field("config", &self.config)
            .field("messages_stored", &self.stats.messages_stored)
            .field("bytes_stored", &self.stats.bytes_stored)
            .field("active_mailboxes", &self.stats.active_mailboxes)
            .finish()
    }
}
