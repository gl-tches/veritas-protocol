//! Delivery receipt types and operations.
//!
//! Provides structures for acknowledging message delivery status in the VERITAS
//! protocol. Receipts can indicate successful delivery, message read status,
//! or various error conditions.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use veritas_crypto::Hash256;
use veritas_identity::{IdentityHash, IdentityKeyPair};

use crate::error::{ProtocolError, Result};

/// Domain separator for receipt signing.
///
/// This prefix ensures receipt hashes cannot be confused with other
/// types of hashes in the VERITAS protocol.
pub const RECEIPT_DOMAIN_SEPARATOR: &[u8] = b"VERITAS-RECEIPT-v1";

/// Type of delivery receipt.
///
/// Indicates the status of message delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReceiptType {
    /// Message has been delivered to the recipient's device.
    ///
    /// This indicates the message was successfully received and stored
    /// on the recipient's device, but may not have been read yet.
    Delivered = 1,

    /// Message has been opened/read by the recipient.
    ///
    /// This indicates the recipient has actively viewed the message content.
    /// Note: Read receipts are optional and may be disabled by the recipient.
    Read = 2,

    /// Message delivery failed with an error.
    ///
    /// The associated `DeliveryError` provides details about the failure.
    Error = 3,
}

impl ReceiptType {
    /// Get the numeric value of the receipt type.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Create a receipt type from a numeric value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid receipt type.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Delivered),
            2 => Ok(Self::Read),
            3 => Ok(Self::Error),
            _ => Err(ProtocolError::InvalidEnvelope(format!(
                "Invalid receipt type: {}",
                value
            ))),
        }
    }
}

impl std::fmt::Display for ReceiptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delivered => write!(f, "Delivered"),
            Self::Read => write!(f, "Read"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// Errors that can occur during message delivery.
///
/// Used when a delivery receipt indicates failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryError {
    /// The recipient identity was not found.
    ///
    /// This may occur if the recipient's mailbox key is invalid or
    /// the identity has expired.
    RecipientNotFound,

    /// The message has expired before delivery.
    ///
    /// Messages have a 7-day TTL. This error occurs if the message
    /// could not be delivered within that window.
    MessageExpired,

    /// The recipient rejected the message.
    ///
    /// This may occur if the sender is blocked or the recipient's
    /// device refused to accept the message.
    Rejected,

    /// The recipient's message quota has been exceeded.
    ///
    /// Recipients may have limits on pending messages. This error
    /// indicates the limit has been reached.
    QuotaExceeded,

    /// Other delivery error.
    ///
    /// Contains a description of the error condition.
    Other(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecipientNotFound => write!(f, "Recipient not found"),
            Self::MessageExpired => write!(f, "Message expired"),
            Self::Rejected => write!(f, "Message rejected"),
            Self::QuotaExceeded => write!(f, "Quota exceeded"),
            Self::Other(msg) => write!(f, "Delivery error: {}", msg),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl DeliveryError {
    /// Create an "other" error with the given message.
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    /// Get a code representing the error type.
    ///
    /// Useful for serialization and matching.
    pub fn code(&self) -> u8 {
        match self {
            Self::RecipientNotFound => 1,
            Self::MessageExpired => 2,
            Self::Rejected => 3,
            Self::QuotaExceeded => 4,
            Self::Other(_) => 255,
        }
    }
}

/// Data for embedding a delivery receipt in a message.
///
/// This is a minimal representation suitable for including inside
/// an encrypted message payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceiptData {
    /// Hash of the original message being acknowledged.
    pub message_id: Hash256,

    /// Type of receipt (delivered, read, or error).
    pub receipt_type: ReceiptType,

    /// Error details if this is an error receipt.
    pub error: Option<DeliveryError>,
}

impl DeliveryReceiptData {
    /// Create a new delivery receipt data.
    pub fn new(message_id: Hash256, receipt_type: ReceiptType) -> Self {
        Self {
            message_id,
            receipt_type,
            error: None,
        }
    }

    /// Create a new error receipt data.
    pub fn with_error(message_id: Hash256, error: DeliveryError) -> Self {
        Self {
            message_id,
            receipt_type: ReceiptType::Error,
            error: Some(error),
        }
    }

    /// Compute a hash of this receipt data.
    ///
    /// Uses domain separation to prevent cross-protocol attacks.
    pub fn hash(&self) -> Hash256 {
        let error_bytes = match &self.error {
            Some(e) => bincode::serialize(e).unwrap_or_default(),
            None => Vec::new(),
        };

        Hash256::hash_many(&[
            RECEIPT_DOMAIN_SEPARATOR,
            b"DATA",
            self.message_id.as_bytes(),
            &[self.receipt_type.as_u8()],
            &error_bytes,
        ])
    }
}

/// A signed delivery receipt.
///
/// Contains all information needed to verify that a specific message
/// was delivered to or read by the recipient.
///
/// ## Fields
///
/// - `message_id`: Hash of the original message being acknowledged
/// - `issuer_id`: Identity hash of the receipt issuer (usually recipient)
/// - `receipt_type`: Whether this is a delivery, read, or error receipt
/// - `error`: Error details if delivery failed
/// - `timestamp`: When the receipt was created (Unix timestamp)
/// - `signature`: Cryptographic signature over the receipt (placeholder)
///
/// ## Signature
///
/// The signature is computed over:
/// ```text
/// Hash256::hash_many([
///     RECEIPT_DOMAIN_SEPARATOR,
///     message_id,
///     issuer_id,
///     receipt_type,
///     timestamp,
///     error (if present)
/// ])
/// ```
///
/// Note: Full signature integration is pending the signing module.
/// Currently uses a hash-based placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// Hash of the original message being acknowledged.
    pub message_id: Hash256,

    /// Identity hash of the receipt issuer.
    ///
    /// For delivery/read receipts, this is the message recipient.
    /// For error receipts, this may be a relay node.
    pub issuer_id: IdentityHash,

    /// Type of receipt.
    pub receipt_type: ReceiptType,

    /// Error details if this is an error receipt.
    pub error: Option<DeliveryError>,

    /// Unix timestamp when the receipt was created.
    pub timestamp: u64,

    /// Signature over the receipt hash.
    ///
    /// Currently a placeholder hash until the signing module is integrated.
    /// Will be replaced with a proper ML-DSA signature.
    pub signature: Vec<u8>,
}

impl DeliveryReceipt {
    /// Create a delivery receipt.
    ///
    /// Indicates the message has been delivered to the recipient's device.
    ///
    /// # Arguments
    ///
    /// * `message_id` - Hash of the message being acknowledged
    /// * `issuer_keypair` - Keypair of the receipt issuer (for signing)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let receipt = DeliveryReceipt::delivered(&message_id, &identity)?;
    /// ```
    pub fn delivered(message_id: &Hash256, issuer_keypair: &IdentityKeyPair) -> Result<Self> {
        Self::create(message_id, issuer_keypair, ReceiptType::Delivered, None)
    }

    /// Create a read receipt.
    ///
    /// Indicates the message has been opened/read by the recipient.
    ///
    /// # Arguments
    ///
    /// * `message_id` - Hash of the message being acknowledged
    /// * `issuer_keypair` - Keypair of the receipt issuer (for signing)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let receipt = DeliveryReceipt::read(&message_id, &identity)?;
    /// ```
    pub fn read(message_id: &Hash256, issuer_keypair: &IdentityKeyPair) -> Result<Self> {
        Self::create(message_id, issuer_keypair, ReceiptType::Read, None)
    }

    /// Create an error receipt.
    ///
    /// Indicates message delivery failed.
    ///
    /// # Arguments
    ///
    /// * `message_id` - Hash of the message that failed to deliver
    /// * `issuer_keypair` - Keypair of the receipt issuer (for signing)
    /// * `error` - Details about the delivery failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// let receipt = DeliveryReceipt::error(
    ///     &message_id,
    ///     &identity,
    ///     DeliveryError::RecipientNotFound,
    /// )?;
    /// ```
    pub fn error(
        message_id: &Hash256,
        issuer_keypair: &IdentityKeyPair,
        error: DeliveryError,
    ) -> Result<Self> {
        Self::create(message_id, issuer_keypair, ReceiptType::Error, Some(error))
    }

    /// Create a receipt with the specified type.
    fn create(
        message_id: &Hash256,
        issuer_keypair: &IdentityKeyPair,
        receipt_type: ReceiptType,
        error: Option<DeliveryError>,
    ) -> Result<Self> {
        let timestamp = current_timestamp();
        let issuer_id = issuer_keypair.identity_hash().clone();

        let mut receipt = Self {
            message_id: message_id.clone(),
            issuer_id,
            receipt_type,
            error,
            timestamp,
            signature: Vec::new(),
        };

        // Generate placeholder signature (hash-based until signing module is ready)
        let receipt_hash = receipt.receipt_hash();
        receipt.signature = receipt_hash.as_bytes().to_vec();

        Ok(receipt)
    }

    /// Compute the hash for signing.
    ///
    /// Returns a hash of all receipt fields (except signature) with domain separation.
    pub fn receipt_hash(&self) -> Hash256 {
        let error_bytes = match &self.error {
            Some(e) => bincode::serialize(e).unwrap_or_default(),
            None => Vec::new(),
        };

        Hash256::hash_many(&[
            RECEIPT_DOMAIN_SEPARATOR,
            self.message_id.as_bytes(),
            self.issuer_id.as_bytes(),
            &[self.receipt_type.as_u8()],
            &self.timestamp.to_be_bytes(),
            &error_bytes,
        ])
    }

    /// Check if this receipt is for the specified message.
    ///
    /// # Arguments
    ///
    /// * `message_id` - The message hash to check against
    ///
    /// # Returns
    ///
    /// `true` if this receipt acknowledges the given message.
    pub fn is_for_message(&self, message_id: &Hash256) -> bool {
        self.message_id == *message_id
    }

    /// Check if this is a successful delivery receipt.
    pub fn is_delivered(&self) -> bool {
        self.receipt_type == ReceiptType::Delivered
    }

    /// Check if this is a read receipt.
    pub fn is_read(&self) -> bool {
        self.receipt_type == ReceiptType::Read
    }

    /// Check if this is an error receipt.
    pub fn is_error(&self) -> bool {
        self.receipt_type == ReceiptType::Error
    }

    /// Get the error details if this is an error receipt.
    pub fn delivery_error(&self) -> Option<&DeliveryError> {
        self.error.as_ref()
    }

    /// Convert to a minimal data representation.
    ///
    /// Useful for embedding in message content.
    pub fn to_data(&self) -> DeliveryReceiptData {
        DeliveryReceiptData {
            message_id: self.message_id.clone(),
            receipt_type: self.receipt_type,
            error: self.error.clone(),
        }
    }

    /// Verify the receipt signature.
    ///
    /// # Note
    ///
    /// Currently uses hash comparison as a placeholder until the
    /// signing module is integrated. Will be updated to verify
    /// ML-DSA signatures.
    pub fn verify_signature(&self) -> bool {
        let expected_hash = self.receipt_hash();
        self.signature == expected_hash.as_bytes()
    }

    /// Serialize the receipt to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            ProtocolError::Serialization(format!("Failed to serialize receipt: {}", e))
        })
    }

    /// Deserialize a receipt from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            ProtocolError::Serialization(format!("Failed to deserialize receipt: {}", e))
        })
    }
}

impl PartialEq for DeliveryReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.message_id == other.message_id
            && self.issuer_id == other.issuer_id
            && self.receipt_type == other.receipt_type
            && self.error == other.error
            && self.timestamp == other.timestamp
    }
}

impl Eq for DeliveryReceipt {}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keypair() -> IdentityKeyPair {
        IdentityKeyPair::generate()
    }

    fn create_test_message_id() -> Hash256 {
        Hash256::hash(b"test message content")
    }

    #[test]
    fn test_receipt_type_as_u8() {
        assert_eq!(ReceiptType::Delivered.as_u8(), 1);
        assert_eq!(ReceiptType::Read.as_u8(), 2);
        assert_eq!(ReceiptType::Error.as_u8(), 3);
    }

    #[test]
    fn test_receipt_type_from_u8() {
        assert_eq!(ReceiptType::from_u8(1).unwrap(), ReceiptType::Delivered);
        assert_eq!(ReceiptType::from_u8(2).unwrap(), ReceiptType::Read);
        assert_eq!(ReceiptType::from_u8(3).unwrap(), ReceiptType::Error);
        assert!(ReceiptType::from_u8(0).is_err());
        assert!(ReceiptType::from_u8(4).is_err());
    }

    #[test]
    fn test_receipt_type_display() {
        assert_eq!(format!("{}", ReceiptType::Delivered), "Delivered");
        assert_eq!(format!("{}", ReceiptType::Read), "Read");
        assert_eq!(format!("{}", ReceiptType::Error), "Error");
    }

    #[test]
    fn test_delivery_error_display() {
        assert_eq!(
            format!("{}", DeliveryError::RecipientNotFound),
            "Recipient not found"
        );
        assert_eq!(
            format!("{}", DeliveryError::MessageExpired),
            "Message expired"
        );
        assert_eq!(format!("{}", DeliveryError::Rejected), "Message rejected");
        assert_eq!(
            format!("{}", DeliveryError::QuotaExceeded),
            "Quota exceeded"
        );
        assert_eq!(
            format!("{}", DeliveryError::Other("test".into())),
            "Delivery error: test"
        );
    }

    #[test]
    fn test_delivery_error_code() {
        assert_eq!(DeliveryError::RecipientNotFound.code(), 1);
        assert_eq!(DeliveryError::MessageExpired.code(), 2);
        assert_eq!(DeliveryError::Rejected.code(), 3);
        assert_eq!(DeliveryError::QuotaExceeded.code(), 4);
        assert_eq!(DeliveryError::Other("test".into()).code(), 255);
    }

    #[test]
    fn test_delivery_error_other() {
        let error = DeliveryError::other("custom error");
        assert_eq!(error, DeliveryError::Other("custom error".into()));
    }

    #[test]
    fn test_delivery_receipt_data_new() {
        let message_id = create_test_message_id();
        let data = DeliveryReceiptData::new(message_id.clone(), ReceiptType::Delivered);

        assert_eq!(data.message_id, message_id);
        assert_eq!(data.receipt_type, ReceiptType::Delivered);
        assert!(data.error.is_none());
    }

    #[test]
    fn test_delivery_receipt_data_with_error() {
        let message_id = create_test_message_id();
        let data = DeliveryReceiptData::with_error(message_id.clone(), DeliveryError::Rejected);

        assert_eq!(data.message_id, message_id);
        assert_eq!(data.receipt_type, ReceiptType::Error);
        assert_eq!(data.error, Some(DeliveryError::Rejected));
    }

    #[test]
    fn test_delivery_receipt_data_hash_deterministic() {
        let message_id = create_test_message_id();
        let data = DeliveryReceiptData::new(message_id, ReceiptType::Delivered);

        let hash1 = data.hash();
        let hash2 = data.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_delivery_receipt_data_hash_different_types() {
        let message_id = create_test_message_id();
        let data1 = DeliveryReceiptData::new(message_id.clone(), ReceiptType::Delivered);
        let data2 = DeliveryReceiptData::new(message_id, ReceiptType::Read);

        assert_ne!(data1.hash(), data2.hash());
    }

    #[test]
    fn test_create_delivered_receipt() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();

        assert_eq!(receipt.message_id, message_id);
        assert_eq!(receipt.issuer_id, *keypair.identity_hash());
        assert_eq!(receipt.receipt_type, ReceiptType::Delivered);
        assert!(receipt.error.is_none());
        assert!(receipt.timestamp > 0);
        assert!(!receipt.signature.is_empty());
    }

    #[test]
    fn test_create_read_receipt() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt = DeliveryReceipt::read(&message_id, &keypair).unwrap();

        assert_eq!(receipt.message_id, message_id);
        assert_eq!(receipt.receipt_type, ReceiptType::Read);
        assert!(receipt.error.is_none());
    }

    #[test]
    fn test_create_error_receipt() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();
        let error = DeliveryError::RecipientNotFound;

        let receipt = DeliveryReceipt::error(&message_id, &keypair, error.clone()).unwrap();

        assert_eq!(receipt.message_id, message_id);
        assert_eq!(receipt.receipt_type, ReceiptType::Error);
        assert_eq!(receipt.error, Some(error));
    }

    #[test]
    fn test_receipt_is_for_message() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();
        let other_message_id = Hash256::hash(b"other message");

        let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();

        assert!(receipt.is_for_message(&message_id));
        assert!(!receipt.is_for_message(&other_message_id));
    }

    #[test]
    fn test_receipt_type_checks() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let delivered = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        assert!(delivered.is_delivered());
        assert!(!delivered.is_read());
        assert!(!delivered.is_error());

        let read = DeliveryReceipt::read(&message_id, &keypair).unwrap();
        assert!(!read.is_delivered());
        assert!(read.is_read());
        assert!(!read.is_error());

        let error = DeliveryReceipt::error(&message_id, &keypair, DeliveryError::Rejected).unwrap();
        assert!(!error.is_delivered());
        assert!(!error.is_read());
        assert!(error.is_error());
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        let hash1 = receipt.receipt_hash();
        let hash2 = receipt.receipt_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_receipt_hash_different_for_different_messages() {
        let keypair = create_test_keypair();
        let message_id1 = Hash256::hash(b"message 1");
        let message_id2 = Hash256::hash(b"message 2");

        let receipt1 = DeliveryReceipt::delivered(&message_id1, &keypair).unwrap();
        let receipt2 = DeliveryReceipt::delivered(&message_id2, &keypair).unwrap();

        assert_ne!(receipt1.receipt_hash(), receipt2.receipt_hash());
    }

    #[test]
    fn test_receipt_verify_signature() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        assert!(receipt.verify_signature());
    }

    #[test]
    fn test_receipt_verify_signature_fails_on_tampering() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let mut receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        // Tamper with the receipt
        receipt.timestamp += 1;

        assert!(!receipt.verify_signature());
    }

    #[test]
    fn test_receipt_to_data() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();
        let error = DeliveryError::MessageExpired;

        let receipt = DeliveryReceipt::error(&message_id, &keypair, error.clone()).unwrap();
        let data = receipt.to_data();

        assert_eq!(data.message_id, message_id);
        assert_eq!(data.receipt_type, ReceiptType::Error);
        assert_eq!(data.error, Some(error));
    }

    #[test]
    fn test_receipt_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        let bytes = receipt.to_bytes().unwrap();
        let restored = DeliveryReceipt::from_bytes(&bytes).unwrap();

        assert_eq!(receipt, restored);
    }

    #[test]
    fn test_receipt_serialization_with_error() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();
        let error = DeliveryError::Other("custom error message".into());

        let receipt = DeliveryReceipt::error(&message_id, &keypair, error).unwrap();
        let bytes = receipt.to_bytes().unwrap();
        let restored = DeliveryReceipt::from_bytes(&bytes).unwrap();

        assert_eq!(receipt, restored);
        assert_eq!(
            restored.error,
            Some(DeliveryError::Other("custom error message".into()))
        );
    }

    #[test]
    fn test_receipt_error_accessor() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let delivered = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
        assert!(delivered.delivery_error().is_none());

        let error_receipt =
            DeliveryReceipt::error(&message_id, &keypair, DeliveryError::QuotaExceeded).unwrap();
        assert_eq!(
            error_receipt.delivery_error(),
            Some(&DeliveryError::QuotaExceeded)
        );
    }

    #[test]
    fn test_receipt_equality() {
        let keypair = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt1 = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();

        // Create with same timestamp by cloning fields
        let receipt2 = DeliveryReceipt {
            message_id: receipt1.message_id.clone(),
            issuer_id: receipt1.issuer_id.clone(),
            receipt_type: receipt1.receipt_type,
            error: receipt1.error.clone(),
            timestamp: receipt1.timestamp,
            signature: receipt1.signature.clone(),
        };

        assert_eq!(receipt1, receipt2);
    }

    #[test]
    fn test_different_issuers_produce_different_receipts() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();
        let message_id = create_test_message_id();

        let receipt1 = DeliveryReceipt::delivered(&message_id, &keypair1).unwrap();
        let receipt2 = DeliveryReceipt::delivered(&message_id, &keypair2).unwrap();

        assert_ne!(receipt1.issuer_id, receipt2.issuer_id);
        assert_ne!(receipt1.receipt_hash(), receipt2.receipt_hash());
    }

    #[test]
    fn test_delivery_receipt_data_serialization() {
        let message_id = create_test_message_id();
        let data = DeliveryReceiptData::with_error(message_id, DeliveryError::Rejected);

        let bytes = bincode::serialize(&data).unwrap();
        let restored: DeliveryReceiptData = bincode::deserialize(&bytes).unwrap();

        assert_eq!(data, restored);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn receipt_hash_always_32_bytes(message_bytes: Vec<u8>) {
            let keypair = IdentityKeyPair::generate();
            let message_id = Hash256::hash(&message_bytes);

            let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
            let hash = receipt.receipt_hash();

            prop_assert_eq!(hash.as_bytes().len(), 32);
        }

        #[test]
        fn receipt_serialization_roundtrip(message_bytes: Vec<u8>) {
            let keypair = IdentityKeyPair::generate();
            let message_id = Hash256::hash(&message_bytes);

            let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();
            let bytes = receipt.to_bytes().unwrap();
            let restored = DeliveryReceipt::from_bytes(&bytes).unwrap();

            prop_assert_eq!(receipt, restored);
        }

        #[test]
        fn signature_verification_consistent(message_bytes: Vec<u8>) {
            let keypair = IdentityKeyPair::generate();
            let message_id = Hash256::hash(&message_bytes);

            let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();

            // Signature should always verify for untampered receipt
            prop_assert!(receipt.verify_signature());
        }

        #[test]
        fn is_for_message_correct(message_bytes: Vec<u8>, other_bytes: Vec<u8>) {
            prop_assume!(message_bytes != other_bytes);

            let keypair = IdentityKeyPair::generate();
            let message_id = Hash256::hash(&message_bytes);
            let other_id = Hash256::hash(&other_bytes);

            let receipt = DeliveryReceipt::delivered(&message_id, &keypair).unwrap();

            prop_assert!(receipt.is_for_message(&message_id));
            prop_assert!(!receipt.is_for_message(&other_id));
        }
    }
}
