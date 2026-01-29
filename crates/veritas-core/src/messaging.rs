//! Messaging types for the VERITAS protocol high-level API.
//!
//! This module provides user-friendly types for working with messages
//! in the VERITAS protocol. These types wrap the lower-level protocol
//! and storage types to provide a cleaner API.
//!
//! ## Core Types
//!
//! - [`MessageHash`]: A unique identifier for tracking messages
//! - [`ReceivedMessage`]: A fully decrypted and verified incoming message
//! - [`MessageStatus`]: The delivery status of an outgoing message
//! - [`SendOptions`]: Configuration options for sending messages
//!
//! ## Example
//!
//! ```ignore
//! use veritas_core::messaging::{ReceivedMessage, SendOptions, MessageStatus};
//!
//! // Send with delivery receipt request
//! let options = SendOptions::default().with_receipt();
//! let hash = client.send_message(&recipient, "Hello!", options).await?;
//!
//! // Check message status
//! let status = client.message_status(&hash).await?;
//! if status == MessageStatus::Delivered {
//!     println!("Message delivered!");
//! }
//!
//! // Receive and process messages
//! let messages = client.receive_messages().await?;
//! for msg in messages {
//!     if let Some(text) = msg.text() {
//!         println!("From {}: {}", msg.sender, text);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};

use veritas_crypto::Hash256;
use veritas_identity::{IdentityHash, IdentityPublicKeys};
use veritas_protocol::{DeliveryReceiptData, MessageContent};
use veritas_store::{MessageId, MessageStatus as QueueStatus};

/// A hash uniquely identifying a message.
///
/// This is used for tracking messages through the system, referencing
/// messages in replies, and correlating delivery receipts.
///
/// The message hash is derived from the message content, sender, timestamp,
/// and other metadata to ensure uniqueness.
pub type MessageHash = Hash256;

/// A received message that has been decrypted and verified.
///
/// This type represents a message after it has been:
/// 1. Retrieved from storage
/// 2. Decrypted using the recipient's private key
/// 3. Optionally verified against the sender's public key
///
/// ## Fields
///
/// - `id`: Local storage identifier for this message
/// - `message_hash`: Unique hash for tracking and referencing
/// - `sender`: Identity hash of the message sender
/// - `content`: The decrypted message content
/// - `timestamp`: Unix timestamp when the message was created (by sender)
/// - `received_at`: Unix timestamp when the message was received locally
/// - `reply_to`: Hash of the message this is a reply to (if any)
/// - `read`: Whether the message has been marked as read
/// - `sender_public_keys`: Sender's public keys (if available for verification)
/// - `signature_verified`: Whether the sender's signature was verified
///
/// ## Security Notes
///
/// The `signature_verified` field indicates whether cryptographic verification
/// succeeded. Messages with unverified signatures should be treated with caution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Local storage identifier for this message.
    ///
    /// This ID is unique within the local message store and is used
    /// for operations like marking as read or deleting.
    pub id: MessageId,

    /// Unique hash identifying this message.
    ///
    /// This hash is derived from the message content and metadata,
    /// and can be used to reference the message in replies or receipts.
    pub message_hash: MessageHash,

    /// Identity hash of the message sender.
    ///
    /// This is extracted from the encrypted inner payload after decryption.
    pub sender: IdentityHash,

    /// The decrypted message content.
    ///
    /// Can be text, a delivery receipt, or a group message.
    pub content: MessageContent,

    /// Unix timestamp when the message was created (by the sender).
    ///
    /// This is the timestamp embedded in the encrypted payload, not
    /// when it was received.
    pub timestamp: u64,

    /// Unix timestamp when the message was received locally.
    ///
    /// This is when the message arrived at the recipient's device.
    pub received_at: i64,

    /// Hash of the message this is a reply to (if any).
    ///
    /// Used for threading conversations.
    pub reply_to: Option<MessageHash>,

    /// Whether the message has been marked as read.
    ///
    /// This is a local state that persists across sessions.
    pub read: bool,

    /// Sender's public keys if available.
    ///
    /// These keys can be used to verify the message signature or
    /// to encrypt replies without needing to look up the sender.
    pub sender_public_keys: Option<IdentityPublicKeys>,

    /// Whether the sender's signature was successfully verified.
    ///
    /// If `true`, the message content is cryptographically proven
    /// to be from the claimed sender. If `false`, either verification
    /// failed or couldn't be performed (e.g., sender keys unavailable).
    pub signature_verified: bool,
}

impl ReceivedMessage {
    /// Get the text content if this is a text message.
    ///
    /// Returns `None` if this is a receipt or group message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(text) = message.text() {
    ///     println!("Message: {}", text);
    /// }
    /// ```
    pub fn text(&self) -> Option<&str> {
        self.content.as_text()
    }

    /// Check if this message is a delivery receipt.
    ///
    /// Delivery receipts are sent automatically by recipients to
    /// confirm message delivery or read status.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if message.is_receipt() {
    ///     let receipt = message.receipt().unwrap();
    ///     println!("Receipt for message: {}", receipt.message_id);
    /// }
    /// ```
    pub fn is_receipt(&self) -> bool {
        self.content.is_receipt()
    }

    /// Get the delivery receipt data if this is a receipt message.
    ///
    /// Returns `None` if this is not a receipt.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(receipt) = message.receipt() {
    ///     match receipt.receipt_type {
    ///         ReceiptType::Delivered => println!("Message delivered"),
    ///         ReceiptType::Read => println!("Message read"),
    ///         ReceiptType::Error => println!("Delivery failed"),
    ///     }
    /// }
    /// ```
    pub fn receipt(&self) -> Option<&DeliveryReceiptData> {
        self.content.as_receipt()
    }

    /// Check if this is a group message.
    ///
    /// Group messages are encrypted for multiple recipients and
    /// contain additional group metadata.
    pub fn is_group_message(&self) -> bool {
        self.content.is_group_message()
    }

    /// Check if the message signature was verified.
    ///
    /// A verified signature provides cryptographic proof that the
    /// message came from the claimed sender and hasn't been modified.
    pub fn is_verified(&self) -> bool {
        self.signature_verified
    }

    /// Check if sender's public keys are available.
    ///
    /// If available, these can be used for verification or to send
    /// encrypted replies.
    pub fn has_sender_keys(&self) -> bool {
        self.sender_public_keys.is_some()
    }
}

impl PartialEq for ReceivedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.message_hash == other.message_hash
    }
}

impl Eq for ReceivedMessage {}

impl std::hash::Hash for ReceivedMessage {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.message_hash.as_bytes().hash(state);
    }
}

/// Delivery status of an outgoing message.
///
/// This tracks the lifecycle of a sent message from creation
/// through delivery and acknowledgment.
///
/// ## Status Flow
///
/// ```text
/// Pending -> Sending -> Sent -> Delivered -> Read
///                  \-> Failed (on error)
/// ```
///
/// ## Terminal States
///
/// - `Delivered`: Message reached the recipient
/// - `Read`: Recipient opened the message
/// - `Failed`: Delivery failed after all retries
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Message is queued and waiting to be sent.
    ///
    /// The message is stored locally and will be sent when
    /// network connectivity is available.
    Pending,

    /// Message is currently being transmitted.
    ///
    /// The network layer is actively attempting to deliver
    /// the message to the recipient's mailbox.
    Sending,

    /// Message was successfully sent to the network.
    ///
    /// The message has been accepted by the network but
    /// delivery to the recipient is not yet confirmed.
    Sent,

    /// Message was confirmed delivered to recipient.
    ///
    /// A delivery receipt was received indicating the
    /// message reached the recipient's device.
    Delivered,

    /// Message was opened/read by recipient.
    ///
    /// A read receipt was received indicating the
    /// recipient viewed the message content.
    Read,

    /// Message delivery failed after all retries.
    ///
    /// The message could not be delivered and will not
    /// be retried automatically. Check error details
    /// for the failure reason.
    Failed,
}

impl MessageStatus {
    /// Check if this is a terminal state.
    ///
    /// Terminal states indicate the message lifecycle is complete
    /// and no further status changes are expected.
    ///
    /// Terminal states: `Delivered`, `Read`, `Failed`
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Delivered | Self::Read | Self::Failed)
    }

    /// Check if the message is still pending delivery.
    ///
    /// Returns `true` for `Pending` and `Sending` states.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending | Self::Sending)
    }

    /// Check if the message was successfully delivered.
    ///
    /// Returns `true` for `Delivered` and `Read` states.
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered | Self::Read)
    }

    /// Check if the message failed to deliver.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Get a human-readable description of the status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "Waiting to send",
            Self::Sending => "Sending",
            Self::Sent => "Sent to network",
            Self::Delivered => "Delivered",
            Self::Read => "Read by recipient",
            Self::Failed => "Delivery failed",
        }
    }
}

impl From<QueueStatus> for MessageStatus {
    fn from(status: QueueStatus) -> Self {
        match status {
            QueueStatus::Pending => Self::Pending,
            QueueStatus::Sending => Self::Sending,
            QueueStatus::Sent => Self::Sent,
            QueueStatus::Delivered => Self::Delivered,
            QueueStatus::Read => Self::Read,
            QueueStatus::Failed => Self::Failed,
        }
    }
}

impl std::fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Options for sending a message.
///
/// Provides configuration for message sending behavior including
/// delivery receipts, reply threading, and timing.
///
/// ## Default Behavior
///
/// By default, messages:
/// - Do not request delivery receipts
/// - Are not replies to other messages
/// - Include random timing jitter for privacy
///
/// ## Example
///
/// ```ignore
/// // Simple send
/// let options = SendOptions::default();
///
/// // With delivery receipt
/// let options = SendOptions::default().with_receipt();
///
/// // As a reply with receipt
/// let options = SendOptions::default()
///     .reply_to(original_message_hash)
///     .with_receipt();
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SendOptions {
    /// Request a delivery receipt from the recipient.
    ///
    /// If `true`, the recipient's client will automatically send
    /// back a delivery receipt when the message is received.
    ///
    /// Note: Recipients can disable receipt generation in their settings.
    pub request_delivery_receipt: bool,

    /// Hash of the message being replied to.
    ///
    /// When set, this message will be linked to the original message
    /// for threading in the conversation view.
    pub reply_to: Option<MessageHash>,

    /// Skip the random timing jitter before sending.
    ///
    /// By default, a random delay (0-3 seconds) is added before sending
    /// to prevent timing analysis attacks. Set to `true` to send immediately.
    ///
    /// **Warning**: Disabling jitter may reduce privacy by making message
    /// timing more predictable.
    pub skip_jitter: bool,
}

impl SendOptions {
    /// Create new send options with default values.
    ///
    /// Default: no receipt, no reply, jitter enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a delivery receipt from the recipient.
    ///
    /// Returns a modified copy with `request_delivery_receipt` set to `true`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let options = SendOptions::default().with_receipt();
    /// assert!(options.request_delivery_receipt);
    /// ```
    pub fn with_receipt(mut self) -> Self {
        self.request_delivery_receipt = true;
        self
    }

    /// Set this message as a reply to another message.
    ///
    /// Returns a modified copy with `reply_to` set to the given hash.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - Hash of the message being replied to
    ///
    /// # Example
    ///
    /// ```ignore
    /// let options = SendOptions::default().reply_to(original_hash);
    /// assert_eq!(options.reply_to, Some(original_hash));
    /// ```
    pub fn reply_to(mut self, message_hash: MessageHash) -> Self {
        self.reply_to = Some(message_hash);
        self
    }

    /// Skip the timing jitter before sending.
    ///
    /// Returns a modified copy with `skip_jitter` set to `true`.
    ///
    /// **Warning**: This may reduce privacy by making message timing
    /// more predictable to observers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let options = SendOptions::default().without_jitter();
    /// assert!(options.skip_jitter);
    /// ```
    pub fn without_jitter(mut self) -> Self {
        self.skip_jitter = true;
        self
    }

    /// Check if this message is a reply.
    pub fn is_reply(&self) -> bool {
        self.reply_to.is_some()
    }

    /// Check if timing jitter is enabled.
    pub fn has_jitter(&self) -> bool {
        !self.skip_jitter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_status_from_queue_status() {
        assert_eq!(
            MessageStatus::from(QueueStatus::Pending),
            MessageStatus::Pending
        );
        assert_eq!(
            MessageStatus::from(QueueStatus::Sending),
            MessageStatus::Sending
        );
        assert_eq!(MessageStatus::from(QueueStatus::Sent), MessageStatus::Sent);
        assert_eq!(
            MessageStatus::from(QueueStatus::Delivered),
            MessageStatus::Delivered
        );
        assert_eq!(MessageStatus::from(QueueStatus::Read), MessageStatus::Read);
        assert_eq!(
            MessageStatus::from(QueueStatus::Failed),
            MessageStatus::Failed
        );
    }

    #[test]
    fn test_message_status_is_terminal() {
        assert!(!MessageStatus::Pending.is_terminal());
        assert!(!MessageStatus::Sending.is_terminal());
        assert!(!MessageStatus::Sent.is_terminal());
        assert!(MessageStatus::Delivered.is_terminal());
        assert!(MessageStatus::Read.is_terminal());
        assert!(MessageStatus::Failed.is_terminal());
    }

    #[test]
    fn test_message_status_is_pending() {
        assert!(MessageStatus::Pending.is_pending());
        assert!(MessageStatus::Sending.is_pending());
        assert!(!MessageStatus::Sent.is_pending());
        assert!(!MessageStatus::Delivered.is_pending());
        assert!(!MessageStatus::Read.is_pending());
        assert!(!MessageStatus::Failed.is_pending());
    }

    #[test]
    fn test_message_status_is_delivered() {
        assert!(!MessageStatus::Pending.is_delivered());
        assert!(!MessageStatus::Sending.is_delivered());
        assert!(!MessageStatus::Sent.is_delivered());
        assert!(MessageStatus::Delivered.is_delivered());
        assert!(MessageStatus::Read.is_delivered());
        assert!(!MessageStatus::Failed.is_delivered());
    }

    #[test]
    fn test_message_status_is_failed() {
        assert!(!MessageStatus::Pending.is_failed());
        assert!(!MessageStatus::Sending.is_failed());
        assert!(!MessageStatus::Sent.is_failed());
        assert!(!MessageStatus::Delivered.is_failed());
        assert!(!MessageStatus::Read.is_failed());
        assert!(MessageStatus::Failed.is_failed());
    }

    #[test]
    fn test_message_status_display() {
        assert_eq!(format!("{}", MessageStatus::Pending), "Waiting to send");
        assert_eq!(format!("{}", MessageStatus::Sending), "Sending");
        assert_eq!(format!("{}", MessageStatus::Sent), "Sent to network");
        assert_eq!(format!("{}", MessageStatus::Delivered), "Delivered");
        assert_eq!(format!("{}", MessageStatus::Read), "Read by recipient");
        assert_eq!(format!("{}", MessageStatus::Failed), "Delivery failed");
    }

    #[test]
    fn test_send_options_default() {
        let options = SendOptions::default();
        assert!(!options.request_delivery_receipt);
        assert!(options.reply_to.is_none());
        assert!(!options.skip_jitter);
    }

    #[test]
    fn test_send_options_with_receipt() {
        let options = SendOptions::default().with_receipt();
        assert!(options.request_delivery_receipt);
        assert!(options.reply_to.is_none());
        assert!(!options.skip_jitter);
    }

    #[test]
    fn test_send_options_reply_to() {
        let hash = Hash256::hash(b"test message");
        let options = SendOptions::default().reply_to(hash.clone());
        assert!(!options.request_delivery_receipt);
        assert_eq!(options.reply_to, Some(hash));
        assert!(!options.skip_jitter);
    }

    #[test]
    fn test_send_options_without_jitter() {
        let options = SendOptions::default().without_jitter();
        assert!(!options.request_delivery_receipt);
        assert!(options.reply_to.is_none());
        assert!(options.skip_jitter);
    }

    #[test]
    fn test_send_options_chaining() {
        let hash = Hash256::hash(b"original message");
        let options = SendOptions::default()
            .with_receipt()
            .reply_to(hash.clone())
            .without_jitter();

        assert!(options.request_delivery_receipt);
        assert_eq!(options.reply_to, Some(hash));
        assert!(options.skip_jitter);
    }

    #[test]
    fn test_send_options_is_reply() {
        let options = SendOptions::default();
        assert!(!options.is_reply());

        let hash = Hash256::hash(b"test");
        let options = SendOptions::default().reply_to(hash);
        assert!(options.is_reply());
    }

    #[test]
    fn test_send_options_has_jitter() {
        let options = SendOptions::default();
        assert!(options.has_jitter());

        let options = SendOptions::default().without_jitter();
        assert!(!options.has_jitter());
    }

    #[test]
    fn test_received_message_equality() {
        let hash1 = Hash256::hash(b"message 1");
        let hash2 = Hash256::hash(b"message 2");
        let sender = veritas_identity::IdentityHash::from_public_key(b"sender");
        let content = MessageContent::text("Hello").unwrap();

        let msg1 = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: hash1.clone(),
            sender: sender.clone(),
            content: content.clone(),
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        let msg2 = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: hash1.clone(),
            sender: sender.clone(),
            content: content.clone(),
            timestamp: 2000, // Different timestamp
            received_at: 2001,
            reply_to: None,
            read: true, // Different read status
            sender_public_keys: None,
            signature_verified: false, // Different verification
        };

        let msg3 = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: hash2,
            sender,
            content,
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        // Same message_hash = equal
        assert_eq!(msg1, msg2);

        // Different message_hash = not equal
        assert_ne!(msg1, msg3);
    }

    #[test]
    fn test_received_message_text() {
        let sender = veritas_identity::IdentityHash::from_public_key(b"sender");
        let content = MessageContent::text("Hello, world!").unwrap();

        let msg = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test"),
            sender,
            content,
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        assert_eq!(msg.text(), Some("Hello, world!"));
        assert!(!msg.is_receipt());
        assert!(msg.receipt().is_none());
    }

    #[test]
    fn test_received_message_receipt() {
        use veritas_protocol::receipts::ReceiptType;

        let sender = veritas_identity::IdentityHash::from_public_key(b"sender");
        let receipt_data =
            DeliveryReceiptData::new(Hash256::hash(b"original message"), ReceiptType::Delivered);
        let content = MessageContent::receipt(receipt_data);

        let msg = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test"),
            sender,
            content,
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        assert!(msg.text().is_none());
        assert!(msg.is_receipt());
        assert!(msg.receipt().is_some());
        assert_eq!(msg.receipt().unwrap().receipt_type, ReceiptType::Delivered);
    }

    #[test]
    fn test_received_message_verification_status() {
        let sender = veritas_identity::IdentityHash::from_public_key(b"sender");
        let content = MessageContent::text("Test").unwrap();

        let verified_msg = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test"),
            sender: sender.clone(),
            content: content.clone(),
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        let unverified_msg = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test2"),
            sender,
            content,
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: false,
        };

        assert!(verified_msg.is_verified());
        assert!(!unverified_msg.is_verified());
    }

    #[test]
    fn test_received_message_has_sender_keys() {
        let keypair = veritas_identity::IdentityKeyPair::generate();
        let sender = keypair.identity_hash().clone();
        let public_keys = keypair.public_keys().clone();
        let content = MessageContent::text("Test").unwrap();

        let msg_without_keys = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test"),
            sender: sender.clone(),
            content: content.clone(),
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: None,
            signature_verified: true,
        };

        let msg_with_keys = ReceivedMessage {
            id: veritas_store::MessageId::generate(),
            message_hash: Hash256::hash(b"test2"),
            sender,
            content,
            timestamp: 1000,
            received_at: 1001,
            reply_to: None,
            read: false,
            sender_public_keys: Some(public_keys),
            signature_verified: true,
        };

        assert!(!msg_without_keys.has_sender_keys());
        assert!(msg_with_keys.has_sender_keys());
    }
}
