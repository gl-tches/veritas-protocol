//! Inner payload structures for encrypted message content.
//!
//! The inner payload contains all sensitive metadata that must be
//! hidden from relays. This includes:
//!
//! - Sender identity
//! - Timestamp
//! - Message content
//! - Digital signature
//! - Message references (reply_to)
//!
//! ## Security Properties
//!
//! - All metadata is encrypted end-to-end
//! - Relays only see the envelope, never the inner payload
//! - Message integrity is protected by the signature
//! - TTL enforcement prevents stale message replay

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::groups::GroupMessageData;
use crate::limits::MESSAGE_TTL_SECS;
use crate::receipts::DeliveryReceiptData;
use crate::signing::MessageSignature;
use crate::ProtocolError;

/// Content types that can be carried in a message.
///
/// Each variant represents a different type of communication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageContent {
    /// A text message (max 300 chars per chunk).
    Text(String),

    /// A delivery receipt acknowledging message receipt.
    Receipt(DeliveryReceiptData),

    /// A message sent to a group.
    GroupMessage(Box<GroupMessageData>),
}

impl PartialEq for MessageContent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Text(a), Self::Text(b)) => a == b,
            (Self::Receipt(a), Self::Receipt(b)) => a == b,
            (Self::GroupMessage(a), Self::GroupMessage(b)) => {
                // Compare by hash since GroupMessageData doesn't implement PartialEq
                a.hash() == b.hash()
            }
            _ => false,
        }
    }
}

impl Eq for MessageContent {}

impl MessageContent {
    /// Create a text message content.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::MessageTooLong` if the text exceeds
    /// the maximum allowed length.
    pub fn text(content: &str) -> Result<Self, ProtocolError> {
        let char_count = content.chars().count();
        if char_count > crate::limits::MAX_MESSAGE_CHARS {
            return Err(ProtocolError::MessageTooLong {
                max: crate::limits::MAX_MESSAGE_CHARS,
                actual: char_count,
            });
        }
        Ok(Self::Text(content.to_string()))
    }

    /// Create a delivery receipt content.
    pub fn receipt(data: DeliveryReceiptData) -> Self {
        Self::Receipt(data)
    }

    /// Create a group message content.
    pub fn group_message(data: GroupMessageData) -> Self {
        Self::GroupMessage(Box::new(data))
    }

    /// Check if this is a text message.
    pub fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Check if this is a delivery receipt.
    pub fn is_receipt(&self) -> bool {
        matches!(self, Self::Receipt(_))
    }

    /// Check if this is a group message.
    pub fn is_group_message(&self) -> bool {
        matches!(self, Self::GroupMessage(_))
    }

    /// Get the text content if this is a text message.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// Get the receipt data if this is a delivery receipt.
    pub fn as_receipt(&self) -> Option<&DeliveryReceiptData> {
        match self {
            Self::Receipt(data) => Some(data),
            _ => None,
        }
    }

    /// Get the group message data if this is a group message.
    pub fn as_group_message(&self) -> Option<&GroupMessageData> {
        match self {
            Self::GroupMessage(data) => Some(data),
            _ => None,
        }
    }
}

/// The inner payload of a message, encrypted within the envelope.
///
/// This structure contains all the sensitive information that must
/// be hidden from relays and intermediaries. Only the intended
/// recipient can decrypt and read this payload.
///
/// ## Fields
///
/// - `sender_id`: Identity hash of the sender (HIDDEN from relays)
/// - `timestamp`: Unix timestamp when message was created (HIDDEN)
/// - `content`: The actual message content
/// - `signature`: Sender's signature over the content
/// - `message_id`: Unique identifier for this message
/// - `reply_to`: Optional reference to a previous message
///
/// ## Security
///
/// The signature is computed over a hash of the content, timestamp,
/// and message_id to provide integrity and authenticity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerPayload {
    /// Sender's identity hash (HIDDEN from relays).
    sender_id: IdentityHash,

    /// Unix timestamp in seconds (HIDDEN from relays).
    timestamp: u64,

    /// Message content.
    content: MessageContent,

    /// Sender's signature over the content hash.
    signature: MessageSignature,

    /// Unique message identifier.
    message_id: Hash256,

    /// Reference to a previous message (for replies/threads).
    reply_to: Option<Hash256>,
}

impl InnerPayload {
    /// Create a new inner payload.
    ///
    /// Generates a unique message ID and sets the current timestamp.
    /// The signature is initially a placeholder and should be set
    /// using `set_signature()` after signing.
    ///
    /// # Arguments
    ///
    /// * `sender_id` - The sender's identity hash
    /// * `content` - The message content
    /// * `reply_to` - Optional hash of message being replied to
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_protocol::envelope::inner::{InnerPayload, MessageContent};
    /// use veritas_identity::IdentityHash;
    ///
    /// let sender = IdentityHash::from_public_key(b"sender-pubkey");
    /// let content = MessageContent::text("Hello!").unwrap();
    ///
    /// let payload = InnerPayload::new(sender, content, None);
    /// ```
    pub fn new(
        sender_id: IdentityHash,
        content: MessageContent,
        reply_to: Option<Hash256>,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        // Generate unique message ID from sender, timestamp, and content hash
        let content_bytes = bincode::serialize(&content).unwrap_or_default();
        let message_id = Hash256::hash_many(&[
            b"VERITAS-MESSAGE-ID-v1",
            sender_id.as_bytes(),
            &timestamp.to_be_bytes(),
            &content_bytes,
        ]);

        Self {
            sender_id,
            timestamp,
            content,
            signature: MessageSignature::placeholder(),
            message_id,
            reply_to,
        }
    }

    /// Create a payload with explicit values (for testing/deserialization).
    pub fn new_with_values(
        sender_id: IdentityHash,
        timestamp: u64,
        content: MessageContent,
        signature: MessageSignature,
        message_id: Hash256,
        reply_to: Option<Hash256>,
    ) -> Self {
        Self {
            sender_id,
            timestamp,
            content,
            signature,
            message_id,
            reply_to,
        }
    }

    /// Get the sender's identity hash.
    pub fn sender_id(&self) -> &IdentityHash {
        &self.sender_id
    }

    /// Get the message timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the message content.
    pub fn content(&self) -> &MessageContent {
        &self.content
    }

    /// Get the message signature.
    pub fn signature(&self) -> &MessageSignature {
        &self.signature
    }

    /// Get the message ID.
    pub fn message_id(&self) -> &Hash256 {
        &self.message_id
    }

    /// Get the reply-to reference if present.
    pub fn reply_to(&self) -> Option<&Hash256> {
        self.reply_to.as_ref()
    }

    /// Set the signature on this payload.
    ///
    /// Call this after computing the signature over `content_hash()`.
    pub fn set_signature(&mut self, signature: MessageSignature) {
        self.signature = signature;
    }

    /// Compute the content hash for signing/verification.
    ///
    /// The hash is computed over:
    /// - Sender ID
    /// - Timestamp
    /// - Message ID
    /// - Content
    /// - Reply-to (if present)
    ///
    /// This hash should be signed by the sender.
    pub fn content_hash(&self) -> Hash256 {
        let content_bytes = bincode::serialize(&self.content).unwrap_or_default();
        let reply_bytes = self
            .reply_to
            .as_ref()
            .map(|h| h.to_bytes().to_vec())
            .unwrap_or_default();

        Hash256::hash_many(&[
            b"VERITAS-CONTENT-HASH-v1",
            self.sender_id.as_bytes(),
            &self.timestamp.to_be_bytes(),
            self.message_id.as_bytes(),
            &content_bytes,
            &reply_bytes,
        ])
    }

    /// Check if the message has expired.
    ///
    /// Messages older than MESSAGE_TTL_SECS are considered expired
    /// and should be rejected.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        now.saturating_sub(self.timestamp) > MESSAGE_TTL_SECS
    }

    /// Check if the message has expired at a specific time.
    ///
    /// # Arguments
    ///
    /// * `now_secs` - Current Unix timestamp in seconds
    pub fn is_expired_at(&self, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.timestamp) > MESSAGE_TTL_SECS
    }

    /// Serialize the payload to bytes.
    ///
    /// Uses bincode for efficient binary serialization.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Serialization` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        bincode::serialize(self).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Deserialize a payload from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Serialization` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        bincode::deserialize(bytes).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Validate the payload.
    ///
    /// Checks:
    /// - Message is not expired
    /// - Content is valid
    /// - Message ID is not zero
    ///
    /// # Errors
    ///
    /// Returns appropriate `ProtocolError` if validation fails.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.is_expired() {
            return Err(ProtocolError::MessageExpired);
        }

        // Validate text content length if applicable
        if let MessageContent::Text(text) = &self.content {
            let char_count = text.chars().count();
            if char_count > crate::limits::MAX_MESSAGE_CHARS {
                return Err(ProtocolError::MessageTooLong {
                    max: crate::limits::MAX_MESSAGE_CHARS,
                    actual: char_count,
                });
            }
        }

        if self.message_id.is_zero() {
            return Err(ProtocolError::InvalidEnvelope(
                "message_id cannot be zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::ReceiptType;

    fn test_sender() -> IdentityHash {
        IdentityHash::from_public_key(b"test-sender-public-key")
    }

    #[test]
    fn test_message_content_text() {
        let content = MessageContent::text("Hello, VERITAS!").unwrap();
        assert!(content.is_text());
        assert!(!content.is_receipt());
        assert!(!content.is_group_message());
        assert_eq!(content.as_text(), Some("Hello, VERITAS!"));
    }

    #[test]
    fn test_message_content_text_too_long() {
        let long_text = "a".repeat(301);
        let result = MessageContent::text(&long_text);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooLong {
                max: 300,
                actual: 301
            })
        ));
    }

    #[test]
    fn test_message_content_receipt() {
        let hash = Hash256::hash(b"message");
        let data = DeliveryReceiptData::new(hash.clone(), ReceiptType::Delivered);
        let content = MessageContent::receipt(data.clone());

        assert!(content.is_receipt());
        let receipt = content.as_receipt().unwrap();
        assert_eq!(receipt.message_id, hash);
        assert_eq!(receipt.receipt_type, ReceiptType::Delivered);
    }

    #[test]
    fn test_inner_payload_new() {
        let sender = test_sender();
        let content = MessageContent::text("Test message").unwrap();

        let payload = InnerPayload::new(sender.clone(), content.clone(), None);

        assert_eq!(payload.sender_id(), &sender);
        assert!(payload.timestamp() > 0);
        assert_eq!(payload.content(), &content);
        assert!(payload.signature().is_placeholder());
        assert!(!payload.message_id().is_zero());
        assert!(payload.reply_to().is_none());
    }

    #[test]
    fn test_inner_payload_with_reply() {
        let sender = test_sender();
        let content = MessageContent::text("Reply message").unwrap();
        let reply_to = Hash256::hash(b"original-message");

        let payload = InnerPayload::new(sender, content, Some(reply_to.clone()));

        assert_eq!(payload.reply_to(), Some(&reply_to));
    }

    #[test]
    fn test_inner_payload_serialization() {
        let sender = test_sender();
        let content = MessageContent::text("Serialize me").unwrap();
        let payload = InnerPayload::new(sender, content, None);

        let bytes = payload.to_bytes().unwrap();
        let restored = InnerPayload::from_bytes(&bytes).unwrap();

        assert_eq!(payload.sender_id(), restored.sender_id());
        assert_eq!(payload.timestamp(), restored.timestamp());
        assert_eq!(payload.content(), restored.content());
        assert_eq!(payload.message_id(), restored.message_id());
    }

    #[test]
    fn test_inner_payload_content_hash_deterministic() {
        let sender = test_sender();
        let content = MessageContent::text("Hash me").unwrap();
        let message_id = Hash256::hash(b"test-message-id");
        let timestamp = 1000000u64;

        // Create two payloads with same explicit values
        let payload1 = InnerPayload::new_with_values(
            sender.clone(),
            timestamp,
            content.clone(),
            MessageSignature::placeholder(),
            message_id.clone(),
            None,
        );

        let payload2 = InnerPayload::new_with_values(
            sender,
            timestamp,
            content,
            MessageSignature::placeholder(),
            message_id,
            None,
        );

        // Same inputs = same content hash
        assert_eq!(payload1.content_hash(), payload2.content_hash());
    }

    #[test]
    fn test_inner_payload_content_hash_different_inputs() {
        let sender = test_sender();
        let content = MessageContent::text("Hash me").unwrap();

        let payload1 = InnerPayload::new_with_values(
            sender.clone(),
            1000000,
            content.clone(),
            MessageSignature::placeholder(),
            Hash256::hash(b"msg-1"),
            None,
        );

        let payload2 = InnerPayload::new_with_values(
            sender,
            2000000, // Different timestamp
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"msg-2"), // Different message_id
            None,
        );

        // Different inputs = different content hash
        assert_ne!(payload1.content_hash(), payload2.content_hash());
    }

    #[test]
    fn test_inner_payload_is_expired() {
        let sender = test_sender();
        let content = MessageContent::text("Old message").unwrap();

        // Create payload with old timestamp
        let old_timestamp = 1000; // Way in the past
        let message_id = Hash256::hash(b"old-message");

        let payload = InnerPayload::new_with_values(
            sender,
            old_timestamp,
            content,
            MessageSignature::placeholder(),
            message_id,
            None,
        );

        assert!(payload.is_expired());
    }

    #[test]
    fn test_inner_payload_not_expired() {
        let sender = test_sender();
        let content = MessageContent::text("Fresh message").unwrap();

        let payload = InnerPayload::new(sender, content, None);

        assert!(!payload.is_expired());
    }

    #[test]
    fn test_inner_payload_is_expired_at() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let timestamp = 1000000;
        let message_id = Hash256::hash(b"test");

        let payload = InnerPayload::new_with_values(
            sender,
            timestamp,
            content,
            MessageSignature::placeholder(),
            message_id,
            None,
        );

        // Not expired at timestamp + TTL - 1
        assert!(!payload.is_expired_at(timestamp + MESSAGE_TTL_SECS - 1));

        // Not expired exactly at TTL
        assert!(!payload.is_expired_at(timestamp + MESSAGE_TTL_SECS));

        // Expired at timestamp + TTL + 1
        assert!(payload.is_expired_at(timestamp + MESSAGE_TTL_SECS + 1));
    }

    #[test]
    fn test_inner_payload_validate_expired() {
        let sender = test_sender();
        let content = MessageContent::text("Old").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            1, // Very old timestamp
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        assert!(matches!(
            payload.validate(),
            Err(ProtocolError::MessageExpired)
        ));
    }

    #[test]
    fn test_inner_payload_validate_zero_message_id() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload = InnerPayload::new_with_values(
            sender,
            now,
            content,
            MessageSignature::placeholder(),
            Hash256::default(), // Zero hash
            None,
        );

        assert!(matches!(
            payload.validate(),
            Err(ProtocolError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_inner_payload_validate_success() {
        let sender = test_sender();
        let content = MessageContent::text("Valid message").unwrap();
        let payload = InnerPayload::new(sender, content, None);

        assert!(payload.validate().is_ok());
    }

    #[test]
    fn test_set_signature() {
        let sender = test_sender();
        let content = MessageContent::text("Sign me").unwrap();
        let mut payload = InnerPayload::new(sender, content, None);

        assert!(payload.signature().is_placeholder());

        // Create a non-placeholder signature
        let sig = MessageSignature::from_bytes(
            &[0x42u8; 32],
            crate::signing::SignatureVersion::HmacBlake3,
        )
        .unwrap();
        payload.set_signature(sig);
        assert!(!payload.signature().is_placeholder());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn inner_payload_serialization_roundtrip(text in ".{0,300}") {
            let sender = IdentityHash::from_public_key(b"sender");
            let content = MessageContent::text(&text).unwrap();
            let payload = InnerPayload::new(sender, content, None);

            let bytes = payload.to_bytes().unwrap();
            let restored = InnerPayload::from_bytes(&bytes).unwrap();

            prop_assert_eq!(payload.sender_id(), restored.sender_id());
            prop_assert_eq!(payload.timestamp(), restored.timestamp());
            prop_assert_eq!(payload.message_id(), restored.message_id());
        }

        #[test]
        fn content_hash_deterministic(text in ".{0,300}") {
            let sender = IdentityHash::from_public_key(b"sender");
            let content = MessageContent::text(&text).unwrap();

            // Create with explicit values for reproducibility
            let now = 1000000u64;
            let msg_id = Hash256::hash(b"test");

            let payload1 = InnerPayload::new_with_values(
                sender.clone(),
                now,
                content.clone(),
                MessageSignature::placeholder(),
                msg_id.clone(),
                None,
            );

            let payload2 = InnerPayload::new_with_values(
                sender,
                now,
                content,
                MessageSignature::placeholder(),
                msg_id,
                None,
            );

            prop_assert_eq!(payload1.content_hash(), payload2.content_hash());
        }
    }
}
