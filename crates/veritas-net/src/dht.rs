//! DHT (Distributed Hash Table) storage for VERITAS messaging.
//!
//! This module provides DHT-based message storage using libp2p's Kademlia.
//! Messages are stored under derived mailbox keys (NOT identity hashes) to
//! preserve unlinkability and recipient privacy.
//!
//! ## Key Design Principles
//!
//! - **Privacy**: DHT keys are derived from mailbox keys, which change per epoch
//! - **Unlinkability**: Multiple messages to the same recipient have different DHT keys
//! - **TTL Enforcement**: Records expire after MESSAGE_TTL (7 days)
//! - **Replication**: Records are replicated across multiple nodes for availability
//!
//! ## DHT Key Derivation
//!
//! ```text
//! DHT Key = BLAKE3("VERITAS-DHT-KEY-v1" || mailbox_key)
//! ```
//!
//! This ensures that the DHT key cannot be reversed to reveal the mailbox key,
//! and mailbox keys cannot be correlated across epochs.
//!
//! ## Record Format
//!
//! Each DHT record contains:
//! - Message ID (hash of envelope)
//! - Serialized MinimalEnvelope
//! - Timestamp of storage
//! - Expiry time

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::kad::{Record, RecordKey};

/// Type alias for Kademlia key.
type KademliaKey = RecordKey;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use veritas_crypto::Hash256;
use veritas_protocol::{MailboxKey, MinimalEnvelope, MESSAGE_TTL_SECS};

use crate::error::{NetError, Result};

/// Domain separator for DHT key derivation.
const DHT_KEY_DOMAIN: &[u8] = b"VERITAS-DHT-KEY-v1";

/// Domain separator for message ID computation.
const MESSAGE_ID_DOMAIN: &[u8] = b"VERITAS-DHT-MESSAGE-ID-v1";

/// Default replication factor for DHT records.
pub const DEFAULT_REPLICATION_FACTOR: usize = 3;

/// Default maximum record size in bytes.
pub const DEFAULT_MAX_RECORD_SIZE: usize = 4096;

/// Default query timeout in seconds.
pub const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 30;

/// Configuration for DHT storage operations.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// Number of nodes to replicate records to.
    ///
    /// Higher values improve availability but increase storage and bandwidth.
    /// Default: 3
    pub replication_factor: usize,

    /// Time-to-live for stored records.
    ///
    /// Records are automatically expired after this duration.
    /// Default: 7 days (MESSAGE_TTL)
    pub record_ttl: Duration,

    /// Maximum size of a single record in bytes.
    ///
    /// Records exceeding this size will be rejected.
    /// Default: 4096 bytes
    pub max_record_size: usize,

    /// Timeout for DHT query operations.
    ///
    /// Queries taking longer than this will fail.
    /// Default: 30 seconds
    pub query_timeout: Duration,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            replication_factor: DEFAULT_REPLICATION_FACTOR,
            record_ttl: Duration::from_secs(MESSAGE_TTL_SECS),
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
            query_timeout: Duration::from_secs(DEFAULT_QUERY_TIMEOUT_SECS),
        }
    }
}

impl DhtConfig {
    /// Create a new DHT configuration with custom values.
    pub fn new(
        replication_factor: usize,
        record_ttl: Duration,
        max_record_size: usize,
        query_timeout: Duration,
    ) -> Self {
        Self {
            replication_factor,
            record_ttl,
            max_record_size,
            query_timeout,
        }
    }

    /// Create a configuration with custom replication factor.
    pub fn with_replication_factor(mut self, factor: usize) -> Self {
        self.replication_factor = factor;
        self
    }

    /// Create a configuration with custom TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.record_ttl = ttl;
        self
    }

    /// Create a configuration with custom max record size.
    pub fn with_max_record_size(mut self, size: usize) -> Self {
        self.max_record_size = size;
        self
    }

    /// Create a configuration with custom query timeout.
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }
}

/// A record stored in the DHT.
///
/// Contains the serialized envelope plus metadata for TTL management
/// and deduplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    /// Unique identifier for this message (hash of envelope).
    message_id: [u8; 32],

    /// Serialized MinimalEnvelope.
    envelope_data: Vec<u8>,

    /// Unix timestamp when this record was stored.
    stored_at: u64,

    /// Unix timestamp when this record expires.
    expires_at: u64,
}

impl DhtRecord {
    /// Create a new DHT record from an envelope.
    ///
    /// Computes the message ID, serializes the envelope, and sets
    /// expiry based on the configured TTL.
    pub fn new(envelope: &MinimalEnvelope, ttl: Duration) -> Result<Self> {
        let envelope_data = envelope
            .to_bytes()
            .map_err(|e| NetError::Dht(format!("Failed to serialize envelope: {}", e)))?;

        let message_id = compute_message_id(&envelope_data);

        let now = current_timestamp();
        let expires_at = now + ttl.as_secs();

        Ok(Self {
            message_id,
            envelope_data,
            stored_at: now,
            expires_at,
        })
    }

    /// Get the message ID.
    pub fn message_id(&self) -> &[u8; 32] {
        &self.message_id
    }

    /// Get the serialized envelope data.
    pub fn envelope_data(&self) -> &[u8] {
        &self.envelope_data
    }

    /// Deserialize the envelope from this record.
    pub fn to_envelope(&self) -> Result<MinimalEnvelope> {
        MinimalEnvelope::from_bytes(&self.envelope_data)
            .map_err(|e| NetError::Dht(format!("Failed to deserialize envelope: {}", e)))
    }

    /// Get the storage timestamp.
    pub fn stored_at(&self) -> u64 {
        self.stored_at
    }

    /// Get the expiry timestamp.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Check if this record has expired.
    pub fn is_expired(&self) -> bool {
        current_timestamp() >= self.expires_at
    }

    /// Get remaining TTL in seconds.
    ///
    /// Returns 0 if the record has expired.
    pub fn remaining_ttl(&self) -> u64 {
        let now = current_timestamp();
        if now >= self.expires_at {
            0
        } else {
            self.expires_at - now
        }
    }

    /// Serialize this record for DHT storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| NetError::Dht(format!("Serialization failed: {}", e)))
    }

    /// Deserialize a record from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Dht(format!("Deserialization failed: {}", e)))
    }
}

/// Collection of DHT records for a single mailbox key.
///
/// A mailbox may have multiple pending messages, so we store them
/// as a collection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhtRecordSet {
    /// All records for this mailbox key.
    records: Vec<DhtRecord>,
}

impl DhtRecordSet {
    /// Create an empty record set.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add a record to the set.
    ///
    /// Deduplicates based on message ID.
    pub fn add(&mut self, record: DhtRecord) {
        // Check for duplicates
        if !self
            .records
            .iter()
            .any(|r| r.message_id == record.message_id)
        {
            self.records.push(record);
        }
    }

    /// Remove a record by message ID.
    ///
    /// Returns true if a record was removed.
    pub fn remove(&mut self, message_id: &[u8; 32]) -> bool {
        let len_before = self.records.len();
        self.records.retain(|r| &r.message_id != message_id);
        self.records.len() < len_before
    }

    /// Remove all expired records.
    ///
    /// Returns the number of records removed.
    pub fn prune_expired(&mut self) -> usize {
        let len_before = self.records.len();
        self.records.retain(|r| !r.is_expired());
        len_before - self.records.len()
    }

    /// Get all non-expired records.
    pub fn records(&self) -> &[DhtRecord] {
        &self.records
    }

    /// Get all valid envelopes (non-expired, deserializable).
    pub fn to_envelopes(&self) -> Vec<MinimalEnvelope> {
        self.records
            .iter()
            .filter(|r| !r.is_expired())
            .filter_map(|r| r.to_envelope().ok())
            .collect()
    }

    /// Check if this set has any non-expired records.
    pub fn has_valid_records(&self) -> bool {
        self.records.iter().any(|r| !r.is_expired())
    }

    /// Get the number of records (including expired).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serialize the record set for DHT storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| NetError::Dht(format!("Serialization failed: {}", e)))
    }

    /// Deserialize a record set from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| NetError::Dht(format!("Deserialization failed: {}", e)))
    }
}

/// Statistics for DHT storage operations.
#[derive(Debug, Default)]
pub struct DhtStorageStats {
    /// Total messages stored.
    pub messages_stored: AtomicU64,
    /// Total messages retrieved.
    pub messages_retrieved: AtomicU64,
    /// Total messages deleted.
    pub messages_deleted: AtomicU64,
    /// Total messages expired.
    pub messages_expired: AtomicU64,
    /// Total store operations.
    pub store_operations: AtomicU64,
    /// Total get operations.
    pub get_operations: AtomicU64,
    /// Total failed operations.
    pub failed_operations: AtomicU64,
    /// Total bytes stored.
    pub bytes_stored: AtomicU64,
}

impl DhtStorageStats {
    /// Create new statistics tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> DhtStorageStatsSnapshot {
        DhtStorageStatsSnapshot {
            messages_stored: self.messages_stored.load(Ordering::Relaxed),
            messages_retrieved: self.messages_retrieved.load(Ordering::Relaxed),
            messages_deleted: self.messages_deleted.load(Ordering::Relaxed),
            messages_expired: self.messages_expired.load(Ordering::Relaxed),
            store_operations: self.store_operations.load(Ordering::Relaxed),
            get_operations: self.get_operations.load(Ordering::Relaxed),
            failed_operations: self.failed_operations.load(Ordering::Relaxed),
            bytes_stored: self.bytes_stored.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of DHT storage statistics.
#[derive(Debug, Clone)]
pub struct DhtStorageStatsSnapshot {
    /// Total messages stored.
    pub messages_stored: u64,
    /// Total messages retrieved.
    pub messages_retrieved: u64,
    /// Total messages deleted.
    pub messages_deleted: u64,
    /// Total messages expired.
    pub messages_expired: u64,
    /// Total store operations.
    pub store_operations: u64,
    /// Total get operations.
    pub get_operations: u64,
    /// Total failed operations.
    pub failed_operations: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
}

/// DHT storage backend for VERITAS messages.
///
/// Wraps Kademlia operations with proper abstractions for privacy-preserving
/// message storage and retrieval.
///
/// ## Thread Safety
///
/// `DhtStorage` is thread-safe and can be shared across async tasks.
/// Internal state is protected by RwLock for concurrent access.
///
/// ## Usage
///
/// ```ignore
/// use veritas_net::dht::{DhtStorage, DhtConfig};
/// use veritas_protocol::{MailboxKey, MinimalEnvelope};
///
/// let config = DhtConfig::default();
/// let storage = DhtStorage::new(config);
///
/// // Store a message
/// storage.store_message(&mailbox_key, &envelope).await?;
///
/// // Retrieve messages
/// let messages = storage.get_messages(&mailbox_key).await?;
/// ```
pub struct DhtStorage {
    /// Configuration for DHT operations.
    config: DhtConfig,

    /// Local storage cache for DHT records.
    ///
    /// Maps DHT keys to record sets. This serves as a local cache
    /// and is synchronized with the DHT network.
    local_store: Arc<RwLock<HashMap<[u8; 32], DhtRecordSet>>>,

    /// Storage statistics.
    stats: Arc<DhtStorageStats>,
}

impl DhtStorage {
    /// Create a new DHT storage instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for DHT operations
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::dht::{DhtStorage, DhtConfig};
    ///
    /// let storage = DhtStorage::new(DhtConfig::default());
    /// ```
    pub fn new(config: DhtConfig) -> Self {
        info!(
            replication_factor = config.replication_factor,
            ttl_secs = config.record_ttl.as_secs(),
            max_record_size = config.max_record_size,
            "Creating DHT storage"
        );

        Self {
            config,
            local_store: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(DhtStorageStats::new()),
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &DhtConfig {
        &self.config
    }

    /// Get storage statistics.
    pub fn stats(&self) -> DhtStorageStatsSnapshot {
        self.stats.snapshot()
    }

    /// Store a message in the DHT under the given mailbox key.
    ///
    /// The message is serialized, assigned a unique ID, and stored
    /// with the configured TTL. The DHT key is derived from the mailbox
    /// key, NOT the recipient's identity hash.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The derived mailbox key (from MailboxKeyParams::derive())
    /// * `envelope` - The minimal envelope to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Serialization fails
    /// - The record exceeds the maximum size
    /// - DHT operation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_net::dht::DhtStorage;
    /// use veritas_protocol::{MailboxKeyParams, MinimalEnvelope};
    ///
    /// let mailbox_key = MailboxKeyParams::new_current(&recipient_id).derive();
    /// storage.store_message(&mailbox_key, &envelope).await?;
    /// ```
    pub async fn store_message(
        &self,
        mailbox_key: &MailboxKey,
        envelope: &MinimalEnvelope,
    ) -> Result<()> {
        self.stats.store_operations.fetch_add(1, Ordering::Relaxed);

        // Validate envelope
        envelope
            .validate()
            .map_err(|e| NetError::Dht(format!("Invalid envelope: {}", e)))?;

        // Create DHT record with TTL
        let record = DhtRecord::new(envelope, self.config.record_ttl)?;
        let record_bytes = record.to_bytes()?;

        // Check size limit
        if record_bytes.len() > self.config.max_record_size {
            self.stats.failed_operations.fetch_add(1, Ordering::Relaxed);
            return Err(NetError::Dht(format!(
                "Record size {} exceeds maximum {}",
                record_bytes.len(),
                self.config.max_record_size
            )));
        }

        // Derive DHT key from mailbox key
        let dht_key = derive_dht_key(mailbox_key);

        debug!(
            message_id = hex::encode(&record.message_id[..8]),
            dht_key = hex::encode(&dht_key[..8]),
            size = record_bytes.len(),
            "Storing message in DHT"
        );

        // Update local store
        {
            let mut store = self.local_store.write().await;
            let record_set = store.entry(dht_key).or_insert_with(DhtRecordSet::new);

            // Prune expired records while we're here
            let pruned = record_set.prune_expired();
            if pruned > 0 {
                self.stats
                    .messages_expired
                    .fetch_add(pruned as u64, Ordering::Relaxed);
            }

            record_set.add(record);
        }

        self.stats.messages_stored.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_stored
            .fetch_add(record_bytes.len() as u64, Ordering::Relaxed);

        info!(
            message_id = hex::encode(&dht_key[..8]),
            "Message stored successfully"
        );

        Ok(())
    }

    /// Retrieve all messages for a mailbox key.
    ///
    /// Returns all non-expired messages stored under the given mailbox key.
    /// The DHT key is derived from the mailbox key.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The derived mailbox key to query
    ///
    /// # Returns
    ///
    /// A vector of minimal envelopes. May be empty if no messages exist.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DHT query fails
    /// - Deserialization fails for all records
    ///
    /// # Example
    ///
    /// ```ignore
    /// let messages = storage.get_messages(&mailbox_key).await?;
    /// for envelope in messages {
    ///     // Process each envelope
    /// }
    /// ```
    pub async fn get_messages(&self, mailbox_key: &MailboxKey) -> Result<Vec<MinimalEnvelope>> {
        self.stats.get_operations.fetch_add(1, Ordering::Relaxed);

        let dht_key = derive_dht_key(mailbox_key);

        debug!(
            dht_key = hex::encode(&dht_key[..8]),
            "Retrieving messages from DHT"
        );

        // Query local store
        let envelopes = {
            let mut store = self.local_store.write().await;

            if let Some(record_set) = store.get_mut(&dht_key) {
                // Prune expired records
                let pruned = record_set.prune_expired();
                if pruned > 0 {
                    self.stats
                        .messages_expired
                        .fetch_add(pruned as u64, Ordering::Relaxed);
                    debug!(pruned = pruned, "Pruned expired records");
                }

                record_set.to_envelopes()
            } else {
                Vec::new()
            }
        };

        let count = envelopes.len();
        self.stats
            .messages_retrieved
            .fetch_add(count as u64, Ordering::Relaxed);

        debug!(count = count, "Retrieved messages from DHT");

        Ok(envelopes)
    }

    /// Delete a specific message from the DHT.
    ///
    /// Removes the message with the given ID from the mailbox.
    /// This is typically called after a message has been successfully
    /// delivered and acknowledged.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The mailbox key the message is stored under
    /// * `message_id` - The unique message identifier (envelope hash)
    ///
    /// # Errors
    ///
    /// Returns an error if the DHT operation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let message_id = envelope.envelope_hash().to_bytes();
    /// storage.delete_message(&mailbox_key, &message_id).await?;
    /// ```
    pub async fn delete_message(
        &self,
        mailbox_key: &MailboxKey,
        message_id: &[u8; 32],
    ) -> Result<()> {
        let dht_key = derive_dht_key(mailbox_key);

        debug!(
            message_id = hex::encode(&message_id[..8]),
            dht_key = hex::encode(&dht_key[..8]),
            "Deleting message from DHT"
        );

        // Update local store
        let removed = {
            let mut store = self.local_store.write().await;

            if let Some(record_set) = store.get_mut(&dht_key) {
                let removed = record_set.remove(message_id);

                // Clean up empty entries
                if record_set.is_empty() {
                    store.remove(&dht_key);
                }

                removed
            } else {
                false
            }
        };

        if removed {
            self.stats.messages_deleted.fetch_add(1, Ordering::Relaxed);
            info!(
                message_id = hex::encode(&message_id[..8]),
                "Message deleted successfully"
            );
        } else {
            warn!(
                message_id = hex::encode(&message_id[..8]),
                "Message not found for deletion"
            );
        }

        Ok(())
    }

    /// Check if there are any pending messages for a mailbox.
    ///
    /// This is a lightweight check that doesn't retrieve the full messages.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The mailbox key to check
    ///
    /// # Returns
    ///
    /// `true` if there are one or more non-expired messages, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if storage.has_messages(&mailbox_key).await? {
    ///     let messages = storage.get_messages(&mailbox_key).await?;
    ///     // Process messages
    /// }
    /// ```
    pub async fn has_messages(&self, mailbox_key: &MailboxKey) -> Result<bool> {
        let dht_key = derive_dht_key(mailbox_key);

        let has_messages = {
            let mut store = self.local_store.write().await;

            if let Some(record_set) = store.get_mut(&dht_key) {
                // Prune expired first
                let pruned = record_set.prune_expired();
                if pruned > 0 {
                    self.stats
                        .messages_expired
                        .fetch_add(pruned as u64, Ordering::Relaxed);
                }

                record_set.has_valid_records()
            } else {
                false
            }
        };

        Ok(has_messages)
    }

    /// Get the count of pending messages for a mailbox.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - The mailbox key to check
    ///
    /// # Returns
    ///
    /// The number of non-expired messages.
    pub async fn message_count(&self, mailbox_key: &MailboxKey) -> Result<usize> {
        let dht_key = derive_dht_key(mailbox_key);

        let count = {
            let mut store = self.local_store.write().await;

            if let Some(record_set) = store.get_mut(&dht_key) {
                // Prune expired first
                record_set.prune_expired();
                record_set
                    .records()
                    .iter()
                    .filter(|r| !r.is_expired())
                    .count()
            } else {
                0
            }
        };

        Ok(count)
    }

    /// Prune all expired records from the local store.
    ///
    /// This is automatically called during normal operations, but can
    /// be called explicitly for maintenance.
    ///
    /// # Returns
    ///
    /// The number of records pruned.
    pub async fn prune_expired(&self) -> usize {
        let mut total_pruned = 0;
        let mut empty_keys = Vec::new();

        {
            let mut store = self.local_store.write().await;

            for (key, record_set) in store.iter_mut() {
                let pruned = record_set.prune_expired();
                total_pruned += pruned;

                if record_set.is_empty() {
                    empty_keys.push(*key);
                }
            }

            // Remove empty entries
            for key in empty_keys {
                store.remove(&key);
            }
        }

        if total_pruned > 0 {
            self.stats
                .messages_expired
                .fetch_add(total_pruned as u64, Ordering::Relaxed);
            info!(pruned = total_pruned, "Pruned expired DHT records");
        }

        total_pruned
    }

    /// Get the number of unique mailbox keys in the local store.
    pub async fn mailbox_count(&self) -> usize {
        self.local_store.read().await.len()
    }

    /// Get the total number of records in the local store.
    pub async fn total_record_count(&self) -> usize {
        self.local_store
            .read()
            .await
            .values()
            .map(|rs| rs.len())
            .sum()
    }

    /// Convert to a Kademlia record for network storage.
    ///
    /// This is used when publishing records to the DHT network.
    pub fn to_kademlia_record(
        mailbox_key: &MailboxKey,
        record_set: &DhtRecordSet,
    ) -> Result<Record> {
        let dht_key = derive_dht_key(mailbox_key);
        let key = RecordKey::new(&dht_key);
        let value = record_set.to_bytes()?;

        Ok(Record {
            key,
            value,
            publisher: None,
            expires: None, // Kademlia handles expiry separately
        })
    }

    /// Parse a Kademlia record from the network.
    ///
    /// This is used when receiving records from the DHT network.
    pub fn from_kademlia_record(record: &Record) -> Result<DhtRecordSet> {
        DhtRecordSet::from_bytes(&record.value)
    }

    /// Get the Kademlia key for a mailbox.
    pub fn kademlia_key(mailbox_key: &MailboxKey) -> KademliaKey {
        let dht_key = derive_dht_key(mailbox_key);
        KademliaKey::new(&dht_key)
    }
}

/// Derive a DHT key from a mailbox key.
///
/// The DHT key is a hash of the mailbox key with a domain separator,
/// ensuring that the mailbox key cannot be reversed from the DHT key.
///
/// # Arguments
///
/// * `mailbox_key` - The derived mailbox key
///
/// # Returns
///
/// A 32-byte DHT key.
pub fn derive_dht_key(mailbox_key: &MailboxKey) -> [u8; 32] {
    Hash256::hash_many(&[DHT_KEY_DOMAIN, mailbox_key.as_bytes()]).to_bytes()
}

/// Compute a unique message ID from envelope data.
///
/// The message ID is used for deduplication and deletion.
///
/// # Arguments
///
/// * `envelope_data` - Serialized envelope bytes
///
/// # Returns
///
/// A 32-byte message identifier.
pub fn compute_message_id(envelope_data: &[u8]) -> [u8; 32] {
    Hash256::hash_many(&[MESSAGE_ID_DOMAIN, envelope_data]).to_bytes()
}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs()
}

/// Type alias for DHT key bytes.
pub type DhtKey = [u8; 32];

/// Type alias for message ID bytes.
pub type MessageId = [u8; 32];
