//! Message-as-transaction model for the VERITAS blockchain.
//!
//! Every encrypted message is a transaction on-chain. The chain IS the message
//! delivery mechanism (AD-1). Blocks contain ordered batches of message
//! transactions plus identity registrations, key rotations, and reputation changes.
//!
//! ## Transaction Lifecycle
//!
//! During epoch (30 days): Full transaction on-chain (ML-DSA signature + encrypted body + header)
//! After epoch ends: Body + signature PRUNED → only header remains permanently

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

/// A message transaction — lives on-chain for one epoch (30 days).
///
/// After the epoch boundary, the body and signature are pruned,
/// leaving only the header as a permanent record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageTransaction {
    /// Permanent header — stays on-chain forever.
    pub header: MessageHeader,
    /// Encrypted body — PRUNED after epoch ends.
    pub body: Option<EncryptedBody>,
    /// ML-DSA-65 signature (3,309 bytes) — PRUNED after epoch ends.
    pub signature: Option<Vec<u8>>,
}

/// Permanent message header — survives epoch pruning.
///
/// After pruning, the header is verifiable via Merkle proof
/// against the signed block header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    /// Derived mailbox key (from sender+recipient DH). NOT the recipient ID.
    pub mailbox_key: [u8; 32],
    /// Coarse timestamp bucket for privacy (not exact time).
    pub timestamp_bucket: u64,
    /// BLAKE3 hash of the encrypted body (proves content existed).
    pub body_hash: Hash256,
    /// Block height where this transaction was included.
    pub block_height: u64,
    /// Transaction index within the block.
    pub tx_index: u32,
}

/// Encrypted message body — pruned after epoch ends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedBody {
    /// Single-use X25519 ephemeral public key (32 bytes).
    pub ephemeral_public: [u8; 32],
    /// Random nonce (24 bytes for XChaCha20).
    pub nonce: [u8; 24],
    /// Encrypted and padded ciphertext.
    pub ciphertext: Vec<u8>,
}

/// All on-chain transaction types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transaction {
    /// Encrypted message delivery (the primary use case).
    Message(MessageTransaction),
    /// New identity registration.
    IdentityRegistration {
        /// Hash of the identity being registered.
        identity_hash: IdentityHash,
        /// Serialized public keys.
        public_keys: Vec<u8>,
        /// Registration timestamp.
        timestamp: u64,
        /// Signature proving ownership.
        signature: Vec<u8>,
    },
    /// Username claim.
    UsernameRegistration {
        /// The username being registered.
        username: String,
        /// Identity hash claiming this username.
        identity_hash: IdentityHash,
        /// Signature proving identity ownership.
        signature: Vec<u8>,
        /// Registration timestamp.
        timestamp: u64,
    },
    /// Key rotation announcement.
    KeyRotation {
        /// The old identity being rotated.
        old_identity: IdentityHash,
        /// The new identity replacing it.
        new_identity: IdentityHash,
        /// Signature from the old identity proving authorization.
        old_signature: Vec<u8>,
        /// Signature from the new identity proving possession.
        new_signature: Vec<u8>,
        /// Rotation timestamp.
        timestamp: u64,
    },
    /// Key revocation (future).
    KeyRevocation {
        /// Identity hash of the key being revoked.
        identity_hash: IdentityHash,
        /// Hash of the revoked key.
        revoked_key_hash: Hash256,
        /// Signature proving authorization.
        signature: Vec<u8>,
        /// Revocation timestamp.
        timestamp: u64,
    },
    /// Reputation score adjustment.
    ReputationChange {
        /// Identity whose reputation is changing.
        identity_hash: IdentityHash,
        /// Amount of change (positive or negative).
        change_amount: i32,
        /// Reason for the change.
        reason: String,
        /// Proof or reference supporting the change.
        proof: Option<Vec<u8>>,
        /// Timestamp of the change.
        timestamp: u64,
    },
    /// P2P image transfer proof (only hash goes on-chain).
    ImageProof {
        /// BLAKE3 hash of the image.
        image_hash: Hash256,
        /// Delivery receipt from recipient.
        delivery_receipt: Vec<u8>,
        /// Timestamp of the proof.
        timestamp: u64,
    },
}

impl MessageTransaction {
    /// Create a new full (unpruned) message transaction.
    pub fn new(header: MessageHeader, body: EncryptedBody, signature: Vec<u8>) -> Self {
        Self {
            header,
            body: Some(body),
            signature: Some(signature),
        }
    }

    /// Check if this transaction has been pruned (body and signature removed).
    pub fn is_pruned(&self) -> bool {
        self.body.is_none() && self.signature.is_none()
    }

    /// Prune the body and signature, keeping only the header.
    ///
    /// This is called at epoch boundary for all transactions in that epoch.
    pub fn prune(&mut self) {
        self.body = None;
        self.signature = None;
    }

    /// Verify the body hash matches the header's body_hash.
    ///
    /// Returns `true` if the body is present and its hash matches,
    /// or if the body has been pruned (cannot verify).
    pub fn verify_body_hash(&self) -> bool {
        match &self.body {
            Some(body) => {
                let computed = Self::compute_body_hash(body);
                computed == self.header.body_hash
            }
            None => true, // Pruned, cannot verify body
        }
    }

    /// Compute the BLAKE3 hash of an encrypted body.
    pub fn compute_body_hash(body: &EncryptedBody) -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&body.ephemeral_public);
        data.extend_from_slice(&body.nonce);
        data.extend_from_slice(&body.ciphertext);
        Hash256::hash(&data)
    }
}

impl MessageHeader {
    /// Create a new message header.
    pub fn new(
        mailbox_key: [u8; 32],
        timestamp_bucket: u64,
        body_hash: Hash256,
        block_height: u64,
        tx_index: u32,
    ) -> Self {
        Self {
            mailbox_key,
            timestamp_bucket,
            body_hash,
            block_height,
            tx_index,
        }
    }

    /// Compute a hash of this header for Merkle tree inclusion.
    pub fn hash(&self) -> Hash256 {
        Hash256::hash_many(&[
            b"VERITAS-TX-HEADER-v1",
            &self.mailbox_key,
            &self.timestamp_bucket.to_be_bytes(),
            self.body_hash.as_bytes(),
            &self.block_height.to_be_bytes(),
            &self.tx_index.to_be_bytes(),
        ])
    }
}

impl Transaction {
    /// Get the timestamp of this transaction.
    pub fn timestamp(&self) -> u64 {
        match self {
            Transaction::Message(tx) => tx.header.timestamp_bucket,
            Transaction::IdentityRegistration { timestamp, .. } => *timestamp,
            Transaction::UsernameRegistration { timestamp, .. } => *timestamp,
            Transaction::KeyRotation { timestamp, .. } => *timestamp,
            Transaction::KeyRevocation { timestamp, .. } => *timestamp,
            Transaction::ReputationChange { timestamp, .. } => *timestamp,
            Transaction::ImageProof { timestamp, .. } => *timestamp,
        }
    }

    /// Compute the hash of this transaction for Merkle tree inclusion.
    pub fn hash(&self) -> Hash256 {
        let serialized = bincode::serialize(self).unwrap_or_default();
        Hash256::hash_many(&[b"VERITAS-TX-v1", &serialized])
    }

    /// Check if this is a message transaction.
    pub fn is_message(&self) -> bool {
        matches!(self, Transaction::Message(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_body() -> EncryptedBody {
        EncryptedBody {
            ephemeral_public: [0xAA; 32],
            nonce: [0xBB; 24],
            ciphertext: vec![0xCC; 1024],
        }
    }

    fn test_header(body: &EncryptedBody) -> MessageHeader {
        MessageHeader::new(
            [0x11; 32],
            1700000000,
            MessageTransaction::compute_body_hash(body),
            100,
            0,
        )
    }

    #[test]
    fn test_message_transaction_creation() {
        let body = test_body();
        let header = test_header(&body);
        let sig = vec![0xDD; 3309]; // ML-DSA-65 signature size
        let tx = MessageTransaction::new(header, body, sig);

        assert!(!tx.is_pruned());
        assert!(tx.body.is_some());
        assert!(tx.signature.is_some());
    }

    #[test]
    fn test_message_transaction_pruning() {
        let body = test_body();
        let header = test_header(&body);
        let sig = vec![0xDD; 3309];
        let mut tx = MessageTransaction::new(header.clone(), body, sig);

        assert!(!tx.is_pruned());

        tx.prune();

        assert!(tx.is_pruned());
        assert!(tx.body.is_none());
        assert!(tx.signature.is_none());
        // Header survives pruning
        assert_eq!(tx.header.mailbox_key, header.mailbox_key);
    }

    #[test]
    fn test_body_hash_verification() {
        let body = test_body();
        let header = test_header(&body);
        let sig = vec![0xDD; 3309];
        let tx = MessageTransaction::new(header, body, sig);

        assert!(tx.verify_body_hash());
    }

    #[test]
    fn test_body_hash_mismatch_detected() {
        let body = test_body();
        let mut header = test_header(&body);
        header.body_hash = Hash256::hash(b"wrong hash"); // Tampered
        let sig = vec![0xDD; 3309];
        let tx = MessageTransaction::new(header, body, sig);

        assert!(!tx.verify_body_hash());
    }

    #[test]
    fn test_pruned_transaction_body_hash() {
        let body = test_body();
        let header = test_header(&body);
        let sig = vec![0xDD; 3309];
        let mut tx = MessageTransaction::new(header, body, sig);
        tx.prune();

        // Cannot verify pruned body, returns true (acceptable)
        assert!(tx.verify_body_hash());
    }

    #[test]
    fn test_transaction_enum_timestamp() {
        let body = test_body();
        let header = test_header(&body);
        let tx = Transaction::Message(MessageTransaction::new(header, body, vec![0; 3309]));
        assert_eq!(tx.timestamp(), 1700000000);
    }

    #[test]
    fn test_transaction_is_message() {
        let body = test_body();
        let header = test_header(&body);
        let tx = Transaction::Message(MessageTransaction::new(header, body, vec![0; 3309]));
        assert!(tx.is_message());

        let tx2 = Transaction::ReputationChange {
            identity_hash: IdentityHash::from_bytes(&[0; 32]).unwrap(),
            change_amount: 10,
            reason: "test".to_string(),
            proof: None,
            timestamp: 1700000000,
        };
        assert!(!tx2.is_message());
    }

    #[test]
    fn test_header_hash_deterministic() {
        let body = test_body();
        let header = test_header(&body);
        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2);
    }
}
