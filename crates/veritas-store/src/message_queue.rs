//! Message queue with inbox and outbox support.
//!
//! Provides persistent storage for:
//! - Outgoing messages (queued for sending, with retry logic)
//! - Incoming messages (received, pending read)
//!
//! ## Retry Logic
//!
//! Failed sends use exponential backoff:
//! - First retry: 30 seconds
//! - Subsequent: 60s, 120s, 240s, 480s (capped at 8 minutes)
//! - Max 5 retries before permanent failure

use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError};
use veritas_protocol::limits::MESSAGE_TTL_SECS;

/// Initial retry delay in seconds.
const INITIAL_RETRY_DELAY_SECS: i64 = 30;

/// Maximum retry delay in seconds (8 minutes).
const MAX_RETRY_DELAY_SECS: i64 = 480;

/// Maximum number of retries before permanent failure.
const MAX_RETRIES: u32 = 5;

/// Tree name for outbox messages.
const OUTBOX_TREE: &str = "message_outbox";

/// Tree name for inbox messages.
const INBOX_TREE: &str = "message_inbox";

/// Unique identifier for a message.
///
/// Generated using cryptographically secure random bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

impl MessageId {
    /// Generate a new random message ID using OS randomness.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a MessageId from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(StoreError::Serialization(format!(
                "Invalid MessageId length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of this ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to owned byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Format as hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MessageId({}...)", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Status of a queued outgoing message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Waiting to be sent.
    Pending,
    /// Currently being sent (in-flight).
    Sending,
    /// Successfully sent to network.
    Sent,
    /// Delivery confirmed by recipient.
    Delivered,
    /// Send failed after all retries.
    Failed,
    /// Read by recipient (acknowledged).
    Read,
}

impl MessageStatus {
    /// Check if this status represents a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::Read)
    }

    /// Check if this message is still waiting to be sent.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// A message queued for outgoing delivery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique message identifier.
    pub id: MessageId,
    /// Recipient identity hash (32 bytes).
    pub recipient: [u8; 32],
    /// Already-encrypted message payload.
    pub encrypted_payload: Vec<u8>,
    /// Current delivery status.
    pub status: MessageStatus,
    /// Unix timestamp when message was created.
    pub created_at: i64,
    /// Unix timestamp when message was last updated.
    pub updated_at: i64,
    /// Number of send attempts.
    pub retry_count: u32,
    /// Unix timestamp for next retry attempt (if applicable).
    pub next_retry_at: Option<i64>,
}

impl QueuedMessage {
    /// Create a new pending message for the outbox.
    fn new(recipient: [u8; 32], encrypted_payload: Vec<u8>) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: MessageId::generate(),
            recipient,
            encrypted_payload,
            status: MessageStatus::Pending,
            created_at: now,
            updated_at: now,
            retry_count: 0,
            next_retry_at: None,
        }
    }

    /// Calculate the next retry time based on retry count.
    fn calculate_next_retry(&self) -> i64 {
        let now = Utc::now().timestamp();
        let delay = std::cmp::min(
            INITIAL_RETRY_DELAY_SECS * (1 << self.retry_count.min(4)),
            MAX_RETRY_DELAY_SECS,
        );
        now + delay
    }

    /// Check if this message has exceeded the maximum retry count.
    fn is_max_retries(&self) -> bool {
        self.retry_count >= MAX_RETRIES
    }

    /// Check if this message is ready for retry now.
    fn is_ready_for_retry(&self, now: i64) -> bool {
        matches!(self.status, MessageStatus::Pending)
            && self.next_retry_at.map_or(true, |t| now >= t)
    }

    /// Check if this message has expired (older than MESSAGE_TTL_SECS).
    fn is_expired(&self, now: i64) -> bool {
        now - self.created_at > MESSAGE_TTL_SECS as i64
    }
}

/// A received message in the inbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxMessage {
    /// Unique message identifier.
    pub id: MessageId,
    /// Sender identity hash (32 bytes), populated after decryption.
    pub sender: Option<[u8; 32]>,
    /// Encrypted message payload.
    pub encrypted_payload: Vec<u8>,
    /// Unix timestamp when message was received.
    pub received_at: i64,
    /// Whether the message has been read.
    pub read: bool,
}

impl InboxMessage {
    /// Create a new inbox message from encrypted payload.
    fn new(encrypted_payload: Vec<u8>) -> Self {
        Self {
            id: MessageId::generate(),
            sender: None,
            encrypted_payload,
            received_at: Utc::now().timestamp(),
            read: false,
        }
    }

    /// Check if this message has expired (older than MESSAGE_TTL_SECS).
    fn is_expired(&self, now: i64) -> bool {
        now - self.received_at > MESSAGE_TTL_SECS as i64
    }
}

/// Message queue providing inbox and outbox storage.
///
/// Uses sled for persistent storage of messages awaiting delivery
/// and received messages pending read.
pub struct MessageQueue {
    outbox: sled::Tree,
    inbox: sled::Tree,
}

impl MessageQueue {
    /// Create a message queue using the given database.
    ///
    /// Opens (or creates) the required trees for inbox and outbox storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the database trees cannot be opened.
    pub fn new(db: &sled::Db) -> Result<Self> {
        let outbox = db
            .open_tree(OUTBOX_TREE)
            .map_err(|e| StoreError::Database(format!("Failed to open outbox tree: {}", e)))?;

        let inbox = db
            .open_tree(INBOX_TREE)
            .map_err(|e| StoreError::Database(format!("Failed to open inbox tree: {}", e)))?;

        Ok(Self { outbox, inbox })
    }

    // =======================================================================
    // Outbox Operations
    // =======================================================================

    /// Queue a message for sending.
    ///
    /// Creates a new pending message in the outbox. The message will be picked up
    /// by the sending system and delivered to the recipient.
    ///
    /// # Arguments
    ///
    /// * `recipient` - The 32-byte identity hash of the recipient
    /// * `encrypted` - The already-encrypted message payload
    ///
    /// # Returns
    ///
    /// The unique MessageId assigned to this message.
    pub fn queue_outgoing(&self, recipient: &[u8; 32], encrypted: Vec<u8>) -> Result<MessageId> {
        let message = QueuedMessage::new(*recipient, encrypted);
        let id = message.id.clone();

        let serialized = bincode::serialize(&message).map_err(|e| {
            StoreError::Serialization(format!("Failed to serialize message: {}", e))
        })?;

        self.outbox
            .insert(id.as_bytes(), serialized)
            .map_err(|e| StoreError::Database(format!("Failed to insert message: {}", e)))?;

        Ok(id)
    }

    /// Get all pending messages in the outbox.
    ///
    /// Returns messages that are in the `Pending` status and have not been
    /// permanently failed.
    pub fn get_pending(&self) -> Result<Vec<QueuedMessage>> {
        let mut messages = Vec::new();

        for result in self.outbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate outbox: {}", e)))?;

            let message: QueuedMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if message.status.is_pending() {
                messages.push(message);
            }
        }

        // Sort by created_at (oldest first)
        messages.sort_by_key(|m| m.created_at);
        Ok(messages)
    }

    /// Get messages that are ready for retry.
    ///
    /// Returns pending messages whose next_retry_at time has passed.
    pub fn get_ready_for_retry(&self) -> Result<Vec<QueuedMessage>> {
        let now = Utc::now().timestamp();
        let mut messages = Vec::new();

        for result in self.outbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate outbox: {}", e)))?;

            let message: QueuedMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if message.is_ready_for_retry(now) {
                messages.push(message);
            }
        }

        // Sort by next_retry_at (soonest first)
        messages.sort_by_key(|m| m.next_retry_at.unwrap_or(0));
        Ok(messages)
    }

    /// Update the status of an outbox message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is not found or the update fails.
    pub fn update_status(&self, id: &MessageId, status: MessageStatus) -> Result<()> {
        let key = id.as_bytes();

        let value = self
            .outbox
            .get(key)
            .map_err(|e| StoreError::Database(format!("Failed to get message: {}", e)))?
            .ok_or_else(|| StoreError::KeyNotFound(format!("Message not found: {}", id)))?;

        let mut message: QueuedMessage = bincode::deserialize(&value)
            .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

        message.status = status;
        message.updated_at = Utc::now().timestamp();

        let serialized = bincode::serialize(&message)
            .map_err(|e| StoreError::Serialization(format!("Failed to serialize: {}", e)))?;

        self.outbox
            .insert(key, serialized)
            .map_err(|e| StoreError::Database(format!("Failed to update message: {}", e)))?;

        Ok(())
    }

    /// Mark a message as sent.
    ///
    /// Updates the status to `Sent` and records the current timestamp.
    pub fn mark_sent(&self, id: &MessageId) -> Result<()> {
        self.update_status(id, MessageStatus::Sent)
    }

    /// Mark a message as delivered.
    ///
    /// Updates the status to `Delivered` to indicate the recipient has received it.
    pub fn mark_delivered(&self, id: &MessageId) -> Result<()> {
        self.update_status(id, MessageStatus::Delivered)
    }

    /// Mark a message as failed and schedule retry.
    ///
    /// Increments the retry counter and calculates the next retry time using
    /// exponential backoff. If max retries exceeded, marks as permanently failed.
    pub fn mark_failed(&self, id: &MessageId) -> Result<()> {
        let key = id.as_bytes();

        let value = self
            .outbox
            .get(key)
            .map_err(|e| StoreError::Database(format!("Failed to get message: {}", e)))?
            .ok_or_else(|| StoreError::KeyNotFound(format!("Message not found: {}", id)))?;

        let mut message: QueuedMessage = bincode::deserialize(&value)
            .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

        message.retry_count += 1;
        message.updated_at = Utc::now().timestamp();

        if message.is_max_retries() {
            // Permanent failure after max retries
            message.status = MessageStatus::Failed;
            message.next_retry_at = None;
        } else {
            // Schedule next retry with exponential backoff
            message.status = MessageStatus::Pending;
            message.next_retry_at = Some(message.calculate_next_retry());
        }

        let serialized = bincode::serialize(&message)
            .map_err(|e| StoreError::Serialization(format!("Failed to serialize: {}", e)))?;

        self.outbox
            .insert(key, serialized)
            .map_err(|e| StoreError::Database(format!("Failed to update message: {}", e)))?;

        Ok(())
    }

    /// Get an outbox message by ID.
    ///
    /// # Returns
    ///
    /// `Some(QueuedMessage)` if found, `None` if not found.
    pub fn get_outbox_message(&self, id: &MessageId) -> Result<Option<QueuedMessage>> {
        let key = id.as_bytes();

        match self.outbox.get(key) {
            Ok(Some(value)) => {
                let message: QueuedMessage = bincode::deserialize(&value).map_err(|e| {
                    StoreError::Serialization(format!("Failed to deserialize: {}", e))
                })?;
                Ok(Some(message))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!(
                "Failed to get message: {}",
                e
            ))),
        }
    }

    // =======================================================================
    // Inbox Operations
    // =======================================================================

    /// Store a received message in the inbox.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted message payload as received from the network
    ///
    /// # Returns
    ///
    /// The unique MessageId assigned to this message.
    pub fn store_incoming(&self, encrypted: Vec<u8>) -> Result<MessageId> {
        let message = InboxMessage::new(encrypted);
        let id = message.id.clone();

        let serialized = bincode::serialize(&message).map_err(|e| {
            StoreError::Serialization(format!("Failed to serialize message: {}", e))
        })?;

        self.inbox
            .insert(id.as_bytes(), serialized)
            .map_err(|e| StoreError::Database(format!("Failed to insert message: {}", e)))?;

        Ok(id)
    }

    /// Get all unread messages in the inbox.
    ///
    /// Returns messages that have not been marked as read, sorted by
    /// received time (oldest first).
    pub fn get_unread(&self) -> Result<Vec<InboxMessage>> {
        let mut messages = Vec::new();

        for result in self.inbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate inbox: {}", e)))?;

            let message: InboxMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if !message.read {
                messages.push(message);
            }
        }

        // Sort by received_at (oldest first)
        messages.sort_by_key(|m| m.received_at);
        Ok(messages)
    }

    /// Get inbox messages with pagination.
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of messages to return
    /// * `offset` - Number of messages to skip
    ///
    /// # Returns
    ///
    /// Messages sorted by received time (newest first).
    pub fn get_inbox(&self, limit: usize, offset: usize) -> Result<Vec<InboxMessage>> {
        let mut messages = Vec::new();

        for result in self.inbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate inbox: {}", e)))?;

            let message: InboxMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            messages.push(message);
        }

        // Sort by received_at (newest first for inbox view)
        messages.sort_by_key(|m| std::cmp::Reverse(m.received_at));

        // Apply pagination
        let paginated: Vec<InboxMessage> = messages.into_iter().skip(offset).take(limit).collect();

        Ok(paginated)
    }

    /// Mark an inbox message as read.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is not found.
    pub fn mark_read(&self, id: &MessageId) -> Result<()> {
        let key = id.as_bytes();

        let value = self
            .inbox
            .get(key)
            .map_err(|e| StoreError::Database(format!("Failed to get message: {}", e)))?
            .ok_or_else(|| StoreError::KeyNotFound(format!("Message not found: {}", id)))?;

        let mut message: InboxMessage = bincode::deserialize(&value)
            .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

        message.read = true;

        let serialized = bincode::serialize(&message)
            .map_err(|e| StoreError::Serialization(format!("Failed to serialize: {}", e)))?;

        self.inbox
            .insert(key, serialized)
            .map_err(|e| StoreError::Database(format!("Failed to update message: {}", e)))?;

        Ok(())
    }

    /// Get an inbox message by ID.
    ///
    /// # Returns
    ///
    /// `Some(InboxMessage)` if found, `None` if not found.
    pub fn get_inbox_message(&self, id: &MessageId) -> Result<Option<InboxMessage>> {
        let key = id.as_bytes();

        match self.inbox.get(key) {
            Ok(Some(value)) => {
                let message: InboxMessage = bincode::deserialize(&value).map_err(|e| {
                    StoreError::Serialization(format!("Failed to deserialize: {}", e))
                })?;
                Ok(Some(message))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!(
                "Failed to get message: {}",
                e
            ))),
        }
    }

    /// Delete an inbox message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is not found.
    pub fn delete_inbox_message(&self, id: &MessageId) -> Result<()> {
        let key = id.as_bytes();

        let existed = self
            .inbox
            .remove(key)
            .map_err(|e| StoreError::Database(format!("Failed to delete message: {}", e)))?
            .is_some();

        if !existed {
            return Err(StoreError::KeyNotFound(format!(
                "Message not found: {}",
                id
            )));
        }

        Ok(())
    }

    // =======================================================================
    // Cleanup Operations
    // =======================================================================

    /// Remove expired messages from both inbox and outbox.
    ///
    /// Messages older than MESSAGE_TTL_SECS (7 days) are removed.
    ///
    /// # Returns
    ///
    /// The total number of messages removed.
    pub fn cleanup_expired(&self) -> Result<usize> {
        let now = Utc::now().timestamp();
        let mut removed = 0;

        // Clean up outbox
        let mut outbox_to_remove = Vec::new();
        for result in self.outbox.iter() {
            let (key, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate outbox: {}", e)))?;

            let message: QueuedMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if message.is_expired(now) {
                outbox_to_remove.push(key.to_vec());
            }
        }

        for key in outbox_to_remove {
            self.outbox
                .remove(&key)
                .map_err(|e| StoreError::Database(format!("Failed to remove message: {}", e)))?;
            removed += 1;
        }

        // Clean up inbox
        let mut inbox_to_remove = Vec::new();
        for result in self.inbox.iter() {
            let (key, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate inbox: {}", e)))?;

            let message: InboxMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if message.is_expired(now) {
                inbox_to_remove.push(key.to_vec());
            }
        }

        for key in inbox_to_remove {
            self.inbox
                .remove(&key)
                .map_err(|e| StoreError::Database(format!("Failed to remove message: {}", e)))?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Remove sent messages older than the given age.
    ///
    /// This can be used to clean up successfully sent messages that no longer
    /// need to be tracked.
    ///
    /// # Arguments
    ///
    /// * `age_secs` - Remove sent messages older than this many seconds
    ///
    /// # Returns
    ///
    /// The number of messages removed.
    pub fn cleanup_sent_older_than(&self, age_secs: i64) -> Result<usize> {
        let now = Utc::now().timestamp();
        let cutoff = now - age_secs;
        let mut removed = 0;

        let mut to_remove = Vec::new();
        for result in self.outbox.iter() {
            let (key, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate outbox: {}", e)))?;

            let message: QueuedMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            // Only remove sent/delivered/read messages that are old enough
            if matches!(
                message.status,
                MessageStatus::Sent | MessageStatus::Delivered | MessageStatus::Read
            ) && message.updated_at < cutoff
            {
                to_remove.push(key.to_vec());
            }
        }

        for key in to_remove {
            self.outbox
                .remove(&key)
                .map_err(|e| StoreError::Database(format!("Failed to remove message: {}", e)))?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Get the count of messages in the outbox by status.
    pub fn outbox_count(&self) -> Result<OutboxStats> {
        let mut stats = OutboxStats::default();

        for result in self.outbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate outbox: {}", e)))?;

            let message: QueuedMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            match message.status {
                MessageStatus::Pending => stats.pending += 1,
                MessageStatus::Sending => stats.sending += 1,
                MessageStatus::Sent => stats.sent += 1,
                MessageStatus::Delivered => stats.delivered += 1,
                MessageStatus::Failed => stats.failed += 1,
                MessageStatus::Read => stats.read += 1,
            }
            stats.total += 1;
        }

        Ok(stats)
    }

    /// Get the count of messages in the inbox.
    pub fn inbox_count(&self) -> Result<InboxStats> {
        let mut stats = InboxStats::default();

        for result in self.inbox.iter() {
            let (_, value) = result
                .map_err(|e| StoreError::Database(format!("Failed to iterate inbox: {}", e)))?;

            let message: InboxMessage = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(format!("Failed to deserialize: {}", e)))?;

            if message.read {
                stats.read += 1;
            } else {
                stats.unread += 1;
            }
            stats.total += 1;
        }

        Ok(stats)
    }
}

/// Statistics for the outbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboxStats {
    /// Total messages in outbox.
    pub total: usize,
    /// Messages pending send.
    pub pending: usize,
    /// Messages currently being sent.
    pub sending: usize,
    /// Messages successfully sent.
    pub sent: usize,
    /// Messages confirmed delivered.
    pub delivered: usize,
    /// Messages that permanently failed.
    pub failed: usize,
    /// Messages confirmed read by recipient.
    pub read: usize,
}

/// Statistics for the inbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InboxStats {
    /// Total messages in inbox.
    pub total: usize,
    /// Unread messages.
    pub unread: usize,
    /// Read messages.
    pub read: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db() -> (TempDir, sled::Db) {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let db = sled::open(dir.path()).expect("Failed to open test db");
        (dir, db)
    }

    fn create_test_queue() -> (TempDir, MessageQueue) {
        let (dir, db) = create_test_db();
        let queue = MessageQueue::new(&db).expect("Failed to create queue");
        (dir, queue)
    }

    #[test]
    fn test_message_id_generation() {
        let id1 = MessageId::generate();
        let id2 = MessageId::generate();

        // Should be unique
        assert_ne!(id1, id2);

        // Should be 32 bytes
        assert_eq!(id1.as_bytes().len(), 32);
        assert_eq!(id2.as_bytes().len(), 32);
    }

    #[test]
    fn test_message_id_from_bytes() {
        let bytes = [42u8; 32];
        let id = MessageId::from_bytes(&bytes).unwrap();
        assert_eq!(id.as_bytes(), &bytes);

        // Invalid length should fail
        let short = [0u8; 16];
        assert!(MessageId::from_bytes(&short).is_err());
    }

    #[test]
    fn test_message_id_hex_format() {
        let bytes = [0xab; 32];
        let id = MessageId::from_bytes(&bytes).unwrap();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_queue_outgoing_message() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let payload = b"encrypted message".to_vec();

        let id = queue.queue_outgoing(&recipient, payload.clone()).unwrap();

        // Should be retrievable
        let message = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(message.id, id);
        assert_eq!(message.recipient, recipient);
        assert_eq!(message.encrypted_payload, payload);
        assert_eq!(message.status, MessageStatus::Pending);
        assert_eq!(message.retry_count, 0);
        assert!(message.next_retry_at.is_none());
    }

    #[test]
    fn test_get_pending_messages() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];

        // Queue multiple messages
        let id1 = queue.queue_outgoing(&recipient, b"msg1".to_vec()).unwrap();
        let id2 = queue.queue_outgoing(&recipient, b"msg2".to_vec()).unwrap();

        // Mark one as sent
        queue.mark_sent(&id1).unwrap();

        // Only id2 should be pending
        let pending = queue.get_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id2);
    }

    #[test]
    fn test_status_transitions() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // Pending -> Sending
        queue.update_status(&id, MessageStatus::Sending).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Sending);

        // Sending -> Sent
        queue.mark_sent(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Sent);

        // Sent -> Delivered
        queue.mark_delivered(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);
        assert!(msg.status.is_terminal());
    }

    #[test]
    fn test_retry_scheduling() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // First failure
        queue.mark_failed(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Pending);
        assert_eq!(msg.retry_count, 1);
        assert!(msg.next_retry_at.is_some());

        // Check exponential backoff
        let first_retry = msg.next_retry_at.unwrap();

        queue.mark_failed(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.retry_count, 2);
        let second_retry = msg.next_retry_at.unwrap();

        // Second retry should be later than first (exponential backoff)
        // Note: This depends on timing, so we just check it's set
        assert!(second_retry >= first_retry);
    }

    #[test]
    fn test_max_retries() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // Fail MAX_RETRIES times
        for _ in 0..MAX_RETRIES {
            queue.mark_failed(&id).unwrap();
        }

        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Failed);
        assert!(msg.status.is_terminal());
        assert!(msg.next_retry_at.is_none());
    }

    #[test]
    fn test_ready_for_retry() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // New message should be ready for retry (no delay yet)
        let ready = queue.get_ready_for_retry().unwrap();
        assert_eq!(ready.len(), 1);

        // After failure, should not be immediately ready
        queue.mark_failed(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();

        // next_retry_at is in the future
        let now = Utc::now().timestamp();
        if let Some(retry_at) = msg.next_retry_at {
            // If retry time is in the future, shouldn't be ready
            if retry_at > now {
                assert!(!msg.is_ready_for_retry(now));
            }
        }
    }

    #[test]
    fn test_store_incoming_message() {
        let (_dir, queue) = create_test_queue();

        let payload = b"encrypted incoming".to_vec();
        let id = queue.store_incoming(payload.clone()).unwrap();

        let message = queue.get_inbox_message(&id).unwrap().unwrap();
        assert_eq!(message.id, id);
        assert_eq!(message.encrypted_payload, payload);
        assert!(!message.read);
        assert!(message.sender.is_none());
    }

    #[test]
    fn test_get_unread_messages() {
        let (_dir, queue) = create_test_queue();

        // Store multiple messages
        let id1 = queue.store_incoming(b"msg1".to_vec()).unwrap();
        let id2 = queue.store_incoming(b"msg2".to_vec()).unwrap();

        // Mark one as read
        queue.mark_read(&id1).unwrap();

        // Only id2 should be unread
        let unread = queue.get_unread().unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].id, id2);
    }

    #[test]
    fn test_inbox_pagination() {
        let (_dir, queue) = create_test_queue();

        // Store several messages
        for i in 0..5 {
            queue
                .store_incoming(format!("msg{}", i).into_bytes())
                .unwrap();
        }

        // Get first page
        let page1 = queue.get_inbox(2, 0).unwrap();
        assert_eq!(page1.len(), 2);

        // Get second page
        let page2 = queue.get_inbox(2, 2).unwrap();
        assert_eq!(page2.len(), 2);

        // Get remaining
        let page3 = queue.get_inbox(2, 4).unwrap();
        assert_eq!(page3.len(), 1);

        // Beyond end
        let empty = queue.get_inbox(2, 10).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_delete_inbox_message() {
        let (_dir, queue) = create_test_queue();

        let id = queue.store_incoming(b"msg".to_vec()).unwrap();

        // Should exist
        assert!(queue.get_inbox_message(&id).unwrap().is_some());

        // Delete it
        queue.delete_inbox_message(&id).unwrap();

        // Should not exist
        assert!(queue.get_inbox_message(&id).unwrap().is_none());

        // Double delete should fail
        assert!(queue.delete_inbox_message(&id).is_err());
    }

    #[test]
    fn test_cleanup_expired_messages() {
        let (_dir, db) = create_test_db();
        let queue = MessageQueue::new(&db).unwrap();

        // Queue a message
        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // Manually set created_at to very old (more than 7 days)
        let mut msg = queue.get_outbox_message(&id).unwrap().unwrap();
        msg.created_at = Utc::now().timestamp() - (MESSAGE_TTL_SECS as i64 + 1);

        let serialized = bincode::serialize(&msg).unwrap();
        queue.outbox.insert(id.as_bytes(), serialized).unwrap();

        // Cleanup should remove it
        let removed = queue.cleanup_expired().unwrap();
        assert_eq!(removed, 1);

        // Should be gone
        assert!(queue.get_outbox_message(&id).unwrap().is_none());
    }

    #[test]
    fn test_cleanup_sent_older_than() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];

        // Queue and mark as sent
        let id1 = queue.queue_outgoing(&recipient, b"msg1".to_vec()).unwrap();
        queue.mark_sent(&id1).unwrap();

        // Manually set updated_at to old
        let mut msg = queue.get_outbox_message(&id1).unwrap().unwrap();
        msg.updated_at = Utc::now().timestamp() - 3600; // 1 hour ago
        let serialized = bincode::serialize(&msg).unwrap();
        queue.outbox.insert(id1.as_bytes(), serialized).unwrap();

        // Queue another that stays pending
        let id2 = queue.queue_outgoing(&recipient, b"msg2".to_vec()).unwrap();

        // Cleanup sent messages older than 1800 seconds (30 min)
        let removed = queue.cleanup_sent_older_than(1800).unwrap();
        assert_eq!(removed, 1);

        // id1 should be gone, id2 should remain
        assert!(queue.get_outbox_message(&id1).unwrap().is_none());
        assert!(queue.get_outbox_message(&id2).unwrap().is_some());
    }

    #[test]
    fn test_outbox_stats() {
        let (_dir, queue) = create_test_queue();

        let recipient = [1u8; 32];

        // Queue some messages
        let id1 = queue.queue_outgoing(&recipient, b"msg1".to_vec()).unwrap();
        let id2 = queue.queue_outgoing(&recipient, b"msg2".to_vec()).unwrap();
        let _id3 = queue.queue_outgoing(&recipient, b"msg3".to_vec()).unwrap();

        // Mark id1 as sent
        queue.mark_sent(&id1).unwrap();

        // Mark id2 as delivered
        queue.mark_sent(&id2).unwrap();
        queue.mark_delivered(&id2).unwrap();

        let stats = queue.outbox_count().unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.delivered, 1);
    }

    #[test]
    fn test_inbox_stats() {
        let (_dir, queue) = create_test_queue();

        // Store messages
        let id1 = queue.store_incoming(b"msg1".to_vec()).unwrap();
        let _id2 = queue.store_incoming(b"msg2".to_vec()).unwrap();
        let _id3 = queue.store_incoming(b"msg3".to_vec()).unwrap();

        // Mark one as read
        queue.mark_read(&id1).unwrap();

        let stats = queue.inbox_count().unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.read, 1);
        assert_eq!(stats.unread, 2);
    }

    #[test]
    fn test_message_status_is_terminal() {
        assert!(!MessageStatus::Pending.is_terminal());
        assert!(!MessageStatus::Sending.is_terminal());
        assert!(!MessageStatus::Sent.is_terminal());
        assert!(MessageStatus::Delivered.is_terminal());
        assert!(MessageStatus::Failed.is_terminal());
        assert!(MessageStatus::Read.is_terminal());
    }

    #[test]
    fn test_message_not_found_errors() {
        let (_dir, queue) = create_test_queue();

        let fake_id = MessageId::generate();

        // Outbox operations
        assert!(queue.update_status(&fake_id, MessageStatus::Sent).is_err());
        assert!(queue.mark_sent(&fake_id).is_err());
        assert!(queue.mark_delivered(&fake_id).is_err());
        assert!(queue.mark_failed(&fake_id).is_err());

        // Inbox operations
        assert!(queue.mark_read(&fake_id).is_err());
        assert!(queue.delete_inbox_message(&fake_id).is_err());
    }

    #[test]
    fn test_exponential_backoff_values() {
        // Verify backoff calculation
        let mut msg = QueuedMessage::new([0u8; 32], vec![]);

        // retry 0: 30s
        msg.retry_count = 0;
        let delay0 = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay0 >= 29 && delay0 <= 31);

        // retry 1: 60s
        msg.retry_count = 1;
        let delay1 = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay1 >= 59 && delay1 <= 61);

        // retry 2: 120s
        msg.retry_count = 2;
        let delay2 = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay2 >= 119 && delay2 <= 121);

        // retry 3: 240s
        msg.retry_count = 3;
        let delay3 = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay3 >= 239 && delay3 <= 241);

        // retry 4: 480s (capped)
        msg.retry_count = 4;
        let delay4 = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay4 >= 479 && delay4 <= 481);

        // retry 5+: still 480s (capped at MAX_RETRY_DELAY_SECS)
        msg.retry_count = 10;
        let delay_max = msg.calculate_next_retry() - Utc::now().timestamp();
        assert!(delay_max >= 479 && delay_max <= 481);
    }
}
