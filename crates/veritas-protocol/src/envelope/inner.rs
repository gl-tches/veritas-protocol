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
//!
//! ## Security: Time Validation (VERITAS-2026-0009)
//!
//! All timestamp-based operations validate time bounds:
//! - Future timestamps (beyond allowed clock skew) are rejected
//! - Ancient timestamps (before protocol inception) are rejected
//! - This prevents time manipulation attacks

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::groups::GroupMessageData;
use crate::limits::MESSAGE_TTL_SECS;
use crate::receipts::DeliveryReceiptData;
use crate::signing::MessageSignature;
use crate::ProtocolError;

// === Time Validation Constants (VERITAS-2026-0009) ===

/// Maximum allowed clock skew in seconds (5 minutes).
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC).
const MIN_VALID_TIMESTAMP: u64 = 1704067200;

/// Maximum valid timestamp (2100-01-01 00:00:00 UTC).
const MAX_VALID_TIMESTAMP: u64 = 4102444800;

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

    /// Cipher suite used for this message.
    /// 0 = ChaCha20-Poly1305 + X25519 + BLAKE3 (current)
    /// 1 = ChaCha20-Poly1305 + X25519 + ML-KEM + BLAKE3 (future hybrid)
    pub cipher_suite: u8,

    /// Protocol wire format version.
    pub protocol_version: u8,
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
            cipher_suite: 0,
            protocol_version: 2,
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
            cipher_suite: 0,
            protocol_version: 2,
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
            &[self.cipher_suite],
            &[self.protocol_version],
        ])
    }

    /// Check if the message has expired.
    ///
    /// Messages older than MESSAGE_TTL_SECS are considered expired
    /// and should be rejected.
    ///
    /// ## Security (VERITAS-2026-0009)
    ///
    /// This method validates timestamps:
    /// - Future timestamps (beyond allowed clock skew) are treated as expired
    /// - Ancient timestamps (before protocol inception) are treated as expired
    /// - Invalid timestamps indicate manipulation and are rejected
    ///
    /// # Returns
    ///
    /// `true` if the message is expired or has invalid timestamps, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        self.is_expired_at(now)
    }

    /// Check if the message has expired at a specific time.
    ///
    /// ## Security (VERITAS-2026-0009)
    ///
    /// This method validates both the message timestamp and the reference time:
    /// - Message timestamps in the future (beyond clock skew) are rejected
    /// - Ancient timestamps (before protocol inception) are rejected
    /// - Invalid reference times are rejected
    ///
    /// # Arguments
    ///
    /// * `now_secs` - Current Unix timestamp in seconds
    ///
    /// # Returns
    ///
    /// `true` if the message is expired or has invalid timestamps, `false` otherwise.
    pub fn is_expired_at(&self, now_secs: u64) -> bool {
        // SECURITY: Validate message timestamp is within valid bounds
        if !Self::is_valid_timestamp(self.timestamp) {
            return true; // Invalid timestamp = expired for safety
        }

        // SECURITY: Validate reference time is reasonable
        if !Self::is_valid_timestamp(now_secs) {
            return true; // Invalid reference time = expired for safety
        }

        // SECURITY: Reject future timestamps (beyond allowed clock skew)
        // This prevents attackers from creating messages with future timestamps
        // that would never expire
        if self.timestamp > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return true; // Future timestamp = expired for safety
        }

        // Standard TTL expiry check
        now_secs.saturating_sub(self.timestamp) > MESSAGE_TTL_SECS
    }

    /// Validate that a timestamp is within acceptable bounds.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The Unix timestamp to validate
    ///
    /// # Returns
    ///
    /// `true` if the timestamp is valid, `false` otherwise.
    fn is_valid_timestamp(timestamp: u64) -> bool {
        (MIN_VALID_TIMESTAMP..=MAX_VALID_TIMESTAMP).contains(&timestamp)
    }

    /// Validate the message timestamp.
    ///
    /// ## Security (VERITAS-2026-0009)
    ///
    /// Performs comprehensive timestamp validation:
    /// - Rejects timestamps before MIN_VALID_TIMESTAMP (ancient)
    /// - Rejects timestamps after MAX_VALID_TIMESTAMP (far future)
    /// - Rejects timestamps more than MAX_CLOCK_SKEW_SECS in the future
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::MessageExpired` for invalid timestamps.
    pub fn validate_timestamp(&self) -> Result<(), ProtocolError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        self.validate_timestamp_at(now)
    }

    /// Validate the message timestamp against a specific reference time.
    ///
    /// # Arguments
    ///
    /// * `now_secs` - The reference Unix timestamp in seconds
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::MessageExpired` for invalid timestamps.
    pub fn validate_timestamp_at(&self, now_secs: u64) -> Result<(), ProtocolError> {
        // Check for ancient timestamp
        if self.timestamp < MIN_VALID_TIMESTAMP {
            return Err(ProtocolError::MessageExpired);
        }

        // Check for far-future timestamp
        if self.timestamp > MAX_VALID_TIMESTAMP {
            return Err(ProtocolError::MessageExpired);
        }

        // Check for near-future timestamp (beyond clock skew)
        if self.timestamp > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(ProtocolError::InvalidEnvelope(
                "message timestamp is in the future".to_string(),
            ));
        }

        Ok(())
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
    /// # Security
    ///
    /// This function checks the input size BEFORE deserialization to prevent
    /// OOM attacks from malicious size fields (VERITAS-2026-0003).
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidEnvelope` if input exceeds `MAX_INNER_ENVELOPE_SIZE`,
    /// or `ProtocolError::Serialization` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        // SECURITY: Check size BEFORE deserialization to prevent OOM attacks
        // from malicious size fields in the serialized data (VERITAS-2026-0003)
        if bytes.len() > crate::limits::MAX_INNER_ENVELOPE_SIZE {
            return Err(ProtocolError::InvalidEnvelope(format!(
                "inner payload too large: {} bytes exceeds maximum {} bytes",
                bytes.len(),
                crate::limits::MAX_INNER_ENVELOPE_SIZE
            )));
        }

        bincode::deserialize(bytes).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Validate the payload.
    ///
    /// Checks:
    /// - Timestamp is valid (VERITAS-2026-0009)
    /// - Message is not expired
    /// - Content is valid
    /// - Message ID is not zero
    ///
    /// # Errors
    ///
    /// Returns appropriate `ProtocolError` if validation fails.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // SECURITY: Validate timestamp first (VERITAS-2026-0009)
        self.validate_timestamp()?;

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

        // Use a valid timestamp within MIN_VALID_TIMESTAMP and MAX_VALID_TIMESTAMP
        let timestamp = 1710000000u64; // March 2024
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

    // === Security Tests for VERITAS-2026-0003 ===

    #[test]
    fn test_oversized_inner_payload_rejected() {
        // SECURITY: Verify that oversized inner payloads are rejected BEFORE deserialization
        // This prevents OOM attacks from malicious size fields (VERITAS-2026-0003)
        let oversized = vec![0u8; crate::limits::MAX_INNER_ENVELOPE_SIZE + 1];
        let result = InnerPayload::from_bytes(&oversized);

        assert!(matches!(
            result,
            Err(ProtocolError::InvalidEnvelope(msg)) if msg.contains("too large")
        ));
    }

    #[test]
    fn test_exactly_max_size_inner_payload_allowed_to_deserialize() {
        // An inner payload at exactly MAX_INNER_ENVELOPE_SIZE should be allowed to attempt deserialization
        // (it will fail deserialization due to invalid content, but not due to size check)
        let at_limit = vec![0u8; crate::limits::MAX_INNER_ENVELOPE_SIZE];
        let result = InnerPayload::from_bytes(&at_limit);

        // Should fail, but NOT because it's "too large" - the size check should pass
        match result {
            Err(ProtocolError::InvalidEnvelope(msg)) => {
                // Should NOT be the "too large" error
                assert!(
                    !msg.contains("too large"),
                    "Size check should pass for data at exactly MAX_INNER_ENVELOPE_SIZE"
                );
            }
            Err(_) => {
                // Any other error is fine (serialization, validation, etc.)
            }
            Ok(_) => {
                // Unlikely to succeed with zero bytes, but if it does, that's fine
            }
        }
    }

    #[test]
    fn test_valid_inner_payload_within_size_limit() {
        // Verify that valid inner payloads within the size limit work correctly
        let sender = test_sender();
        let content = MessageContent::text("Valid message").unwrap();
        let payload = InnerPayload::new(sender, content, None);

        let bytes = payload.to_bytes().unwrap();

        // Ensure our test payload is within limits
        assert!(bytes.len() <= crate::limits::MAX_INNER_ENVELOPE_SIZE);

        // Should deserialize successfully
        let restored = InnerPayload::from_bytes(&bytes).unwrap();
        assert_eq!(payload.sender_id(), restored.sender_id());
        assert_eq!(payload.message_id(), restored.message_id());
    }

    // === Security Tests for VERITAS-2026-0009 ===

    // Use a valid base time (March 2024)
    const TEST_BASE_TIME: u64 = 1710000000;

    #[test]
    fn test_is_valid_timestamp() {
        // Valid timestamps
        assert!(InnerPayload::is_valid_timestamp(MIN_VALID_TIMESTAMP));
        assert!(InnerPayload::is_valid_timestamp(MAX_VALID_TIMESTAMP));
        assert!(InnerPayload::is_valid_timestamp(TEST_BASE_TIME));

        // Invalid timestamps - too old
        assert!(!InnerPayload::is_valid_timestamp(MIN_VALID_TIMESTAMP - 1));
        assert!(!InnerPayload::is_valid_timestamp(0));
        assert!(!InnerPayload::is_valid_timestamp(1000000000)); // 2001

        // Invalid timestamps - too large
        assert!(!InnerPayload::is_valid_timestamp(MAX_VALID_TIMESTAMP + 1));
        assert!(!InnerPayload::is_valid_timestamp(u64::MAX));
    }

    #[test]
    fn test_is_expired_at_rejects_ancient_timestamp() {
        // SECURITY: Messages with ancient timestamps should be treated as expired
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            1000000000, // 2001 - before MIN_VALID_TIMESTAMP
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        // Should be treated as expired due to ancient timestamp
        assert!(payload.is_expired_at(TEST_BASE_TIME));
    }

    #[test]
    fn test_is_expired_at_rejects_far_future_timestamp() {
        // SECURITY: Messages with far-future timestamps should be treated as expired
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            MAX_VALID_TIMESTAMP + 1, // Beyond maximum valid
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        assert!(payload.is_expired_at(TEST_BASE_TIME));
    }

    #[test]
    fn test_is_expired_at_rejects_future_timestamp_beyond_skew() {
        // SECURITY: Messages with timestamps beyond clock skew should be treated as expired
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            TEST_BASE_TIME + MAX_CLOCK_SKEW_SECS + 1000, // Beyond clock skew
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        assert!(payload.is_expired_at(TEST_BASE_TIME));
    }

    #[test]
    fn test_is_expired_at_allows_timestamp_within_skew() {
        // SECURITY: Messages with timestamps within clock skew should be allowed
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            TEST_BASE_TIME + MAX_CLOCK_SKEW_SECS - 10, // Within clock skew
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        // Should NOT be expired (within acceptable skew)
        assert!(!payload.is_expired_at(TEST_BASE_TIME));
    }

    #[test]
    fn test_is_expired_at_rejects_invalid_reference_time() {
        // SECURITY: Invalid reference time should cause message to be treated as expired
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            TEST_BASE_TIME,
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        // Ancient reference time should cause expiry
        assert!(payload.is_expired_at(1000000000)); // 2001

        // Far-future reference time should cause expiry
        assert!(payload.is_expired_at(MAX_VALID_TIMESTAMP + 1));
    }

    #[test]
    fn test_validate_timestamp_rejects_ancient() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            1000000000, // 2001
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        let result = payload.validate_timestamp_at(TEST_BASE_TIME);
        assert!(matches!(result, Err(ProtocolError::MessageExpired)));
    }

    #[test]
    fn test_validate_timestamp_rejects_far_future() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            MAX_VALID_TIMESTAMP + 1,
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        let result = payload.validate_timestamp_at(TEST_BASE_TIME);
        assert!(matches!(result, Err(ProtocolError::MessageExpired)));
    }

    #[test]
    fn test_validate_timestamp_rejects_near_future() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            TEST_BASE_TIME + MAX_CLOCK_SKEW_SECS + 1000, // Beyond clock skew but within valid range
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        let result = payload.validate_timestamp_at(TEST_BASE_TIME);
        assert!(matches!(result, Err(ProtocolError::InvalidEnvelope(_))));
    }

    #[test]
    fn test_validate_timestamp_accepts_valid() {
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            TEST_BASE_TIME,
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        let result = payload.validate_timestamp_at(TEST_BASE_TIME);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_future_timestamp() {
        // SECURITY: Full validation should reject future timestamps
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload = InnerPayload::new_with_values(
            sender,
            now + MAX_CLOCK_SKEW_SECS + 1000, // Future timestamp
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        let result = payload.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_time_constants_consistent() {
        // Verify time constants are correctly defined
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300); // 5 minutes
        assert_eq!(MIN_VALID_TIMESTAMP, 1704067200); // 2024-01-01
        assert_eq!(MAX_VALID_TIMESTAMP, 4102444800); // 2100-01-01

        // Verify ordering
        const { assert!(MIN_VALID_TIMESTAMP < MAX_VALID_TIMESTAMP) }
        const { assert!(MAX_CLOCK_SKEW_SECS < MESSAGE_TTL_SECS) }
    }

    #[test]
    fn test_is_expired_at_zero_timestamp() {
        // SECURITY: Zero timestamp should be rejected
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            0,
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        assert!(payload.is_expired_at(TEST_BASE_TIME));
    }

    #[test]
    fn test_is_expired_at_max_u64_timestamp() {
        // SECURITY: Max u64 timestamp should be rejected
        let sender = test_sender();
        let content = MessageContent::text("Test").unwrap();

        let payload = InnerPayload::new_with_values(
            sender,
            u64::MAX,
            content,
            MessageSignature::placeholder(),
            Hash256::hash(b"test"),
            None,
        );

        assert!(payload.is_expired_at(TEST_BASE_TIME));
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
