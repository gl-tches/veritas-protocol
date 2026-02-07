//! Transaction types for the VERITAS blockchain.
//!
//! Messages are transactions. The blockchain IS the message delivery mechanism.
//! Every encrypted message is a transaction on-chain.
//!
//! ## Epoch Pruning
//!
//! After an epoch ends (30 days):
//! - Message bodies and ML-DSA signatures are pruned
//! - Only `MessageHeader` remains permanently
//! - Headers are verifiable via Merkle proof against signed block headers

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

/// Domain separator for transaction hashing.
const TX_HASH_DOMAIN: &[u8] = b"VERITAS-v1.transaction.0";

/// Domain separator for pruned transaction hashing.
const TX_PRUNED_HASH_DOMAIN: &[u8] = b"VERITAS-v1.transaction-pruned.0";

/// A message transaction — lives on-chain for one epoch (30 days).
///
/// After epoch ends, body and signature are pruned. Only header remains.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageTransaction {
    /// Permanent header — survives epoch pruning.
    pub header: MessageHeader,
    /// Encrypted message body — PRUNED after epoch.
    pub body: Option<EncryptedBody>,
    /// ML-DSA-65 signature (3,309 bytes) — PRUNED after epoch.
    pub signature: Option<Vec<u8>>,
}

/// Permanent message header — stays on-chain forever.
///
/// After epoch pruning, this is all that remains. Headers are NOT individually
/// signed (signature was pruned with body). Headers are verifiable via Merkle
/// proof against the ML-DSA signed block header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    /// Derived mailbox key from sender+recipient DH.
    pub mailbox_key: [u8; 32],
    /// Coarse timestamp bucket (privacy — not exact time).
    pub timestamp_bucket: u64,
    /// BLAKE3 hash of encrypted body (proves content existed).
    pub body_hash: Hash256,
    /// Block height that included this transaction.
    pub block_height: u64,
    /// Transaction index within the block.
    pub tx_index: u32,
}

/// Encrypted body — pruned after epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedBody {
    /// Single-use X25519 ephemeral public key per message.
    pub ephemeral_public: [u8; 32],
    /// Random nonce.
    pub nonce: [u8; 24],
    /// Encrypted + padded to bucket size ciphertext.
    pub ciphertext: Vec<u8>,
}

/// P2P image transfer proof — only proof goes on-chain, not the image.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageProofTransaction {
    /// BLAKE3 hash of the image data.
    pub image_hash: Hash256,
    /// Delivery receipt signature.
    pub delivery_receipt: Vec<u8>,
    /// Sender's identity hash (for accountability).
    pub sender_hash: IdentityHash,
    /// Timestamp of the transfer.
    pub timestamp: u64,
}

/// All on-chain transaction types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transaction {
    /// Encrypted message delivery.
    Message(MessageTransaction),
    /// New identity registration.
    IdentityRegistration {
        /// Identity hash of the new identity.
        identity_hash: IdentityHash,
        /// Serialized public keys.
        public_keys: Vec<u8>,
        /// Registration timestamp.
        timestamp: u64,
        /// ML-DSA signature over the registration.
        signature: Vec<u8>,
    },
    /// Username claim.
    UsernameRegistration {
        /// The username being claimed.
        username: String,
        /// Identity claiming the username.
        identity_hash: IdentityHash,
        /// ML-DSA signature.
        signature: Vec<u8>,
        /// Registration timestamp.
        timestamp: u64,
    },
    /// Key update announcement.
    KeyRotation {
        /// Old identity hash.
        old_identity: IdentityHash,
        /// New identity hash.
        new_identity: IdentityHash,
        /// Signature from old key.
        old_signature: Vec<u8>,
        /// Signature from new key.
        new_signature: Vec<u8>,
        /// Rotation timestamp.
        timestamp: u64,
    },
    /// Key revocation.
    KeyRevocation {
        /// Identity being revoked.
        identity_hash: IdentityHash,
        /// Revocation signature.
        revocation_signature: Vec<u8>,
        /// Revocation timestamp.
        timestamp: u64,
    },
    /// Reputation score adjustment.
    ReputationChange {
        /// Identity whose score is changing.
        identity_hash: IdentityHash,
        /// Score change amount (signed).
        change_amount: i32,
        /// Reason for the change.
        reason: String,
        /// Interaction proof.
        proof: Vec<u8>,
        /// Change timestamp.
        timestamp: u64,
    },
    /// P2P image transfer proof.
    ImageProof(ImageProofTransaction),
}

impl MessageTransaction {
    /// Create a new message transaction with body and signature.
    pub fn new(header: MessageHeader, body: EncryptedBody, signature: Vec<u8>) -> Self {
        Self {
            header,
            body: Some(body),
            signature: Some(signature),
        }
    }

    /// Check if this transaction has been pruned (body + signature removed).
    pub fn is_pruned(&self) -> bool {
        self.body.is_none() && self.signature.is_none()
    }

    /// Prune this transaction (remove body and signature, keep header).
    pub fn prune(&mut self) {
        self.body = None;
        self.signature = None;
    }

    /// Get the transaction hash for Merkle tree inclusion.
    pub fn hash(&self) -> Hash256 {
        let header_bytes = bincode::serialize(&self.header).unwrap_or_default();
        if let Some(ref body) = self.body {
            let body_bytes = bincode::serialize(body).unwrap_or_default();
            Hash256::hash_many(&[TX_HASH_DOMAIN, &header_bytes, &body_bytes])
        } else {
            Hash256::hash_many(&[TX_PRUNED_HASH_DOMAIN, &header_bytes])
        }
    }

    /// Estimated size in bytes.
    pub fn estimated_size(&self) -> usize {
        let header_size = 32 + 8 + 32 + 8 + 4; // mailbox + timestamp + hash + height + index
        let body_size = self
            .body
            .as_ref()
            .map(|b| 32 + 24 + b.ciphertext.len())
            .unwrap_or(0);
        let sig_size = self.signature.as_ref().map(|s| s.len()).unwrap_or(0);
        header_size + body_size + sig_size
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

    /// Compute the timestamp bucket from a precise timestamp.
    /// Rounds down to 5-minute intervals for privacy.
    pub fn bucket_from_timestamp(timestamp: u64) -> u64 {
        (timestamp / 300) * 300
    }
}

impl EncryptedBody {
    /// Compute the BLAKE3 hash of this body for the header.
    pub fn hash(&self) -> Hash256 {
        let bytes = bincode::serialize(self).unwrap_or_default();
        Hash256::hash(&bytes)
    }
}

impl Transaction {
    /// Get the hash of this transaction for Merkle tree inclusion.
    pub fn hash(&self) -> Hash256 {
        let bytes = bincode::serialize(self).unwrap_or_default();
        Hash256::hash_many(&[TX_HASH_DOMAIN, &bytes])
    }

    /// Check if this is a message transaction.
    pub fn is_message(&self) -> bool {
        matches!(self, Transaction::Message(_))
    }

    /// Get the message transaction if this is one.
    pub fn as_message(&self) -> Option<&MessageTransaction> {
        match self {
            Transaction::Message(tx) => Some(tx),
            _ => None,
        }
    }

    /// Get the message transaction mutably for pruning.
    pub fn as_message_mut(&mut self) -> Option<&mut MessageTransaction> {
        match self {
            Transaction::Message(tx) => Some(tx),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> MessageHeader {
        MessageHeader::new(
            [0xAA; 32],
            MessageHeader::bucket_from_timestamp(1700000000),
            Hash256::hash(b"test body"),
            100,
            0,
        )
    }

    fn test_body() -> EncryptedBody {
        EncryptedBody {
            ephemeral_public: [0xBB; 32],
            nonce: [0xCC; 24],
            ciphertext: vec![0xDD; 1024],
        }
    }

    fn test_signature() -> Vec<u8> {
        vec![0xEE; 3309]
    }

    #[test]
    fn test_message_transaction_new() {
        let tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        assert!(!tx.is_pruned());
        assert!(tx.body.is_some());
        assert!(tx.signature.is_some());
    }

    #[test]
    fn test_message_transaction_prune() {
        let mut tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        tx.prune();
        assert!(tx.is_pruned());
        assert!(tx.body.is_none());
        assert!(tx.signature.is_none());
        // Header survives
        assert_eq!(tx.header.block_height, 100);
    }

    #[test]
    fn test_message_transaction_hash_changes_after_prune() {
        let tx_full = MessageTransaction::new(test_header(), test_body(), test_signature());
        let hash_full = tx_full.hash();

        let mut tx_pruned = tx_full.clone();
        tx_pruned.prune();
        let hash_pruned = tx_pruned.hash();

        assert_ne!(hash_full, hash_pruned);
    }

    #[test]
    fn test_timestamp_bucketing() {
        let ts = 1700000123;
        let bucket = MessageHeader::bucket_from_timestamp(ts);
        assert_eq!(bucket, 1700000100); // 5-min = 300s boundaries
        assert_eq!(bucket % 300, 0);
    }

    #[test]
    fn test_timestamp_bucketing_exact_boundary() {
        let ts = 1700000100;
        let bucket = MessageHeader::bucket_from_timestamp(ts);
        assert_eq!(bucket, 1700000100);
    }

    #[test]
    fn test_encrypted_body_hash() {
        let body = test_body();
        let hash1 = body.hash();
        let hash2 = body.hash();
        assert_eq!(hash1, hash2); // Deterministic
        assert!(!hash1.is_zero());
    }

    #[test]
    fn test_transaction_enum_message() {
        let msg_tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        let tx = Transaction::Message(msg_tx);
        assert!(tx.is_message());
        assert!(tx.as_message().is_some());
    }

    #[test]
    fn test_transaction_enum_non_message() {
        let tx = Transaction::IdentityRegistration {
            identity_hash: IdentityHash::from_bytes(&[1u8; 32]).unwrap(),
            public_keys: vec![0; 100],
            timestamp: 1700000000,
            signature: vec![0; 3309],
        };
        assert!(!tx.is_message());
        assert!(tx.as_message().is_none());
    }

    #[test]
    fn test_transaction_mut_pruning() {
        let msg_tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        let mut tx = Transaction::Message(msg_tx);
        if let Some(msg) = tx.as_message_mut() {
            msg.prune();
        }
        assert!(tx.as_message().unwrap().is_pruned());
    }

    #[test]
    fn test_transaction_hash_deterministic() {
        let msg_tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        let tx = Transaction::Message(msg_tx);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_image_proof_transaction() {
        let tx = Transaction::ImageProof(ImageProofTransaction {
            image_hash: Hash256::hash(b"test image"),
            delivery_receipt: vec![1, 2, 3],
            sender_hash: IdentityHash::from_bytes(&[5u8; 32]).unwrap(),
            timestamp: 1700000000,
        });
        assert!(!tx.is_message());
    }

    #[test]
    fn test_estimated_size() {
        let tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        let size = tx.estimated_size();
        assert!(size > 1024 + 3309); // At least body + sig

        let mut pruned = tx.clone();
        pruned.prune();
        assert!(pruned.estimated_size() < size);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tx = MessageTransaction::new(test_header(), test_body(), test_signature());
        let bytes = bincode::serialize(&tx).unwrap();
        let restored: MessageTransaction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(tx, restored);
    }
}
