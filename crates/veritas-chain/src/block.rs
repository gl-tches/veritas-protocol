//! Block structure and chain entries for the VERITAS blockchain.
//!
//! This module provides the core data structures for the blockchain layer:
//!
//! - [`Block`]: A complete block containing header and body
//! - [`BlockHeader`]: Metadata about a block (hash, parent, height, etc.)
//! - [`BlockBody`]: Contains the entries stored in the block
//! - [`ChainEntry`]: Different types of entries that can be stored on-chain
//!
//! ## Block Structure
//!
//! ```text
//! Block
//! ├── BlockHeader
//! │   ├── hash (computed)
//! │   ├── parent_hash
//! │   ├── height
//! │   ├── timestamp
//! │   ├── merkle_root
//! │   └── validator
//! └── BlockBody
//!     └── entries: Vec<ChainEntry>
//! ```
//!
//! ## Domain Separation
//!
//! All hashing operations use domain separation to prevent cross-protocol attacks:
//! - Block hash: `VERITAS-BLOCK-v1`
//! - Entry hash: `VERITAS-CHAIN-ENTRY-v1`
//!
//! ## Genesis Block
//!
//! The genesis block (height 0) has special properties:
//! - Parent hash is all zeros
//! - No validator signature required
//! - Contains initial protocol state

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::{ChainError, Result};

// ============================================================================
// Domain Separators
// ============================================================================

/// Domain separator for block hash computation.
const BLOCK_HASH_DOMAIN: &[u8] = b"VERITAS-BLOCK-v1";

/// Domain separator for chain entry hash computation.
const ENTRY_HASH_DOMAIN: &[u8] = b"VERITAS-CHAIN-ENTRY-v1";

/// Domain separator for genesis block identification.
const GENESIS_DOMAIN: &[u8] = b"VERITAS-GENESIS-v1";

// ============================================================================
// Block Header
// ============================================================================

/// Block header containing metadata about the block.
///
/// The header is separate from the body to allow efficient header-only
/// synchronization and validation without downloading full block contents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// Hash of this block's contents (computed from header fields + body).
    ///
    /// This is computed as:
    /// `BLAKE3(VERITAS-BLOCK-v1 || parent_hash || height || timestamp || merkle_root || validator)`
    pub hash: Hash256,

    /// Hash of the parent block (all zeros for genesis).
    pub parent_hash: Hash256,

    /// Block height (0 for genesis, monotonically increasing).
    pub height: u64,

    /// Unix timestamp in seconds when the block was created.
    pub timestamp: u64,

    /// Merkle root of all entries in the block body.
    ///
    /// This allows verification of entry inclusion without the full block.
    pub merkle_root: Hash256,

    /// Identity hash of the validator who created this block.
    ///
    /// For genesis, this is a special null validator.
    pub validator: IdentityHash,
}

impl BlockHeader {
    /// Create a new block header with computed hash.
    ///
    /// # Arguments
    ///
    /// * `parent_hash` - Hash of the parent block
    /// * `height` - Block height
    /// * `timestamp` - Unix timestamp in seconds
    /// * `merkle_root` - Merkle root of entries
    /// * `validator` - Identity hash of the block producer
    ///
    /// # Example
    ///
    /// ```ignore
    /// let header = BlockHeader::new(
    ///     parent_hash,
    ///     1,
    ///     chrono::Utc::now().timestamp() as u64,
    ///     merkle_root,
    ///     validator_id,
    /// );
    /// ```
    pub fn new(
        parent_hash: Hash256,
        height: u64,
        timestamp: u64,
        merkle_root: Hash256,
        validator: IdentityHash,
    ) -> Self {
        let hash = Self::compute_hash(&parent_hash, height, timestamp, &merkle_root, &validator);
        Self {
            hash,
            parent_hash,
            height,
            timestamp,
            merkle_root,
            validator,
        }
    }

    /// Compute the block hash from header components.
    ///
    /// Uses domain-separated BLAKE3 hashing to prevent cross-protocol attacks.
    pub fn compute_hash(
        parent_hash: &Hash256,
        height: u64,
        timestamp: u64,
        merkle_root: &Hash256,
        validator: &IdentityHash,
    ) -> Hash256 {
        Hash256::hash_many(&[
            BLOCK_HASH_DOMAIN,
            parent_hash.as_bytes(),
            &height.to_be_bytes(),
            &timestamp.to_be_bytes(),
            merkle_root.as_bytes(),
            validator.as_bytes(),
        ])
    }

    /// Verify that the block hash is correctly computed.
    ///
    /// Returns `true` if the stored hash matches the computed hash.
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            &self.parent_hash,
            self.height,
            self.timestamp,
            &self.merkle_root,
            &self.validator,
        );
        self.hash == computed
    }

    /// Get the block creation time as a DateTime.
    pub fn datetime(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.timestamp as i64, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.parent_hash.is_zero()
    }
}

// ============================================================================
// Block Body
// ============================================================================

/// Block body containing chain entries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockBody {
    /// Entries stored in this block.
    pub entries: Vec<ChainEntry>,
}

impl BlockBody {
    /// Create a new block body with the given entries.
    pub fn new(entries: Vec<ChainEntry>) -> Self {
        Self { entries }
    }

    /// Create an empty block body.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the body is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the merkle root of entries.
    ///
    /// For now, uses a simple hash of all entry hashes.
    /// TODO: Replace with proper Merkle tree in Task 021.
    pub fn compute_merkle_root(&self) -> Hash256 {
        if self.entries.is_empty() {
            // Empty merkle root
            return Hash256::hash_many(&[ENTRY_HASH_DOMAIN, b"empty"]);
        }

        // Collect all entry hashes
        let entry_hashes: Vec<[u8; 32]> =
            self.entries.iter().map(|e| e.hash().to_bytes()).collect();

        // Simple concatenated hash (proper Merkle tree in Task 021)
        let mut inputs: Vec<&[u8]> = vec![ENTRY_HASH_DOMAIN];
        for hash in &entry_hashes {
            inputs.push(hash);
        }
        Hash256::hash_many(&inputs)
    }
}

// ============================================================================
// Complete Block
// ============================================================================

/// A complete block containing header and body.
///
/// Blocks are the fundamental unit of the VERITAS blockchain.
/// Each block contains entries that record protocol state changes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// Block header with metadata.
    pub header: BlockHeader,

    /// Block body with entries.
    pub body: BlockBody,
}

impl Block {
    /// Create a new block with the given parameters.
    ///
    /// The block hash and merkle root are computed automatically.
    ///
    /// # Arguments
    ///
    /// * `parent_hash` - Hash of the parent block
    /// * `height` - Block height
    /// * `timestamp` - Unix timestamp in seconds
    /// * `entries` - Chain entries to include
    /// * `validator` - Identity hash of the block producer
    pub fn new(
        parent_hash: Hash256,
        height: u64,
        timestamp: u64,
        entries: Vec<ChainEntry>,
        validator: IdentityHash,
    ) -> Self {
        let body = BlockBody::new(entries);
        let merkle_root = body.compute_merkle_root();
        let header = BlockHeader::new(parent_hash, height, timestamp, merkle_root, validator);
        Self { header, body }
    }

    /// Create the genesis block.
    ///
    /// The genesis block has:
    /// - Height 0
    /// - All-zero parent hash
    /// - Special genesis validator
    /// - Optional initial entries
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Creation timestamp (typically protocol launch time)
    /// * `entries` - Initial chain entries (e.g., initial validators)
    pub fn genesis(timestamp: u64, entries: Vec<ChainEntry>) -> Self {
        let parent_hash = Hash256::default(); // All zeros
        let genesis_validator = Self::genesis_validator();

        Self::new(parent_hash, 0, timestamp, entries, genesis_validator)
    }

    /// Get the identity hash used for the genesis block validator.
    ///
    /// This is a special value derived from the genesis domain separator.
    pub fn genesis_validator() -> IdentityHash {
        let hash = Hash256::hash_many(&[GENESIS_DOMAIN, b"validator"]);
        IdentityHash::from(hash)
    }

    /// Get the block hash.
    pub fn hash(&self) -> &Hash256 {
        &self.header.hash
    }

    /// Get the block height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the parent hash.
    pub fn parent_hash(&self) -> &Hash256 {
        &self.header.parent_hash
    }

    /// Get the block timestamp.
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Get the validator identity.
    pub fn validator(&self) -> &IdentityHash {
        &self.header.validator
    }

    /// Get the entries in this block.
    pub fn entries(&self) -> &[ChainEntry] {
        &self.body.entries
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
    }

    /// Verify block integrity.
    ///
    /// Checks that:
    /// 1. Block hash is correctly computed
    /// 2. Merkle root matches entry hashes
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidBlock` if verification fails.
    pub fn verify(&self) -> Result<()> {
        // Verify hash
        if !self.header.verify_hash() {
            return Err(ChainError::InvalidBlock("block hash mismatch".to_string()));
        }

        // Verify merkle root
        let computed_root = self.body.compute_merkle_root();
        if computed_root != self.header.merkle_root {
            return Err(ChainError::InvalidBlock("merkle root mismatch".to_string()));
        }

        Ok(())
    }

    /// Serialize block to bytes using bincode.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::Storage` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| ChainError::Storage(format!("block serialization failed: {}", e)))
    }

    /// Deserialize block from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::Storage` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| ChainError::Storage(format!("block deserialization failed: {}", e)))
    }
}

// ============================================================================
// Chain Entry Types
// ============================================================================

/// Reason for a reputation change.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReputationChangeReason {
    /// Positive interaction with another user.
    PositiveInteraction,
    /// Successful message delivery.
    MessageDelivery,
    /// Report filed against the identity.
    NegativeReport,
    /// Spam detection triggered.
    SpamDetected,
    /// Validator reward.
    ValidatorReward,
    /// Validator slashing penalty.
    ValidatorSlash,
    /// Weekly decay toward neutral.
    WeeklyDecay,
    /// Other reason with description.
    Other(String),
}

/// Geographic region for validator diversity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ValidatorRegion {
    /// North America.
    NorthAmerica,
    /// South America.
    SouthAmerica,
    /// Europe.
    Europe,
    /// Asia.
    Asia,
    /// Africa.
    Africa,
    /// Oceania.
    Oceania,
    /// Unknown region.
    Unknown,
}

/// Slashing reason for validator penalties.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashReason {
    /// Missed block production opportunity.
    MissedBlock,
    /// SLA violation (uptime, latency, etc.).
    SlaViolation,
    /// Produced an invalid block.
    InvalidBlock,
    /// Double-signed (signed conflicting blocks).
    DoubleSigning,
}

/// Entry types that can be stored on the blockchain.
///
/// Each entry represents a state change in the VERITAS protocol.
/// All entries are cryptographically signed and verified before inclusion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainEntry {
    /// Registration of a new identity.
    IdentityRegistration {
        /// Hash of the identity being registered.
        identity_hash: IdentityHash,
        /// Serialized public keys (exchange + signing).
        public_keys: Vec<u8>,
        /// Registration timestamp.
        timestamp: u64,
        /// Signature proving ownership.
        signature: Vec<u8>,
    },

    /// Registration of a username linked to an identity.
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

    /// Key rotation from old identity to new identity.
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

    /// Proof that a message was sent.
    MessageProof {
        /// Hash of the message.
        message_hash: Hash256,
        /// Hash of the sender identity.
        sender_hash: IdentityHash,
        /// Hash of the recipient identity.
        recipient_hash: IdentityHash,
        /// Message timestamp.
        timestamp: u64,
        /// Merkle proof for message inclusion (if applicable).
        merkle_proof: Option<Vec<Hash256>>,
    },

    /// Change to an identity's reputation score.
    ReputationChange {
        /// Identity whose reputation is changing.
        identity_hash: IdentityHash,
        /// Amount of change (positive or negative).
        change_amount: i32,
        /// Reason for the change.
        reason: ReputationChangeReason,
        /// Proof or reference supporting the change.
        proof: Option<Vec<u8>>,
        /// Timestamp of the change.
        timestamp: u64,
    },

    /// Registration of a new validator.
    ValidatorRegistration {
        /// Identity hash of the validator.
        identity_hash: IdentityHash,
        /// Staked reputation amount.
        stake: u32,
        /// Geographic region for diversity.
        region: ValidatorRegion,
        /// Registration timestamp.
        timestamp: u64,
        /// Signature proving identity ownership.
        signature: Vec<u8>,
    },

    /// Validator voluntarily exiting.
    ValidatorExit {
        /// Identity hash of the exiting validator.
        identity_hash: IdentityHash,
        /// Exit timestamp.
        timestamp: u64,
        /// Signature proving authorization.
        signature: Vec<u8>,
    },

    /// Validator slashing for misbehavior.
    ValidatorSlash {
        /// Identity hash of the slashed validator.
        identity_hash: IdentityHash,
        /// Amount slashed.
        slash_amount: u32,
        /// Reason for slashing.
        reason: SlashReason,
        /// Evidence of misbehavior.
        evidence: Vec<u8>,
        /// Timestamp of the slash.
        timestamp: u64,
    },
}

impl ChainEntry {
    /// Compute the hash of this entry.
    ///
    /// Uses domain-separated BLAKE3 hashing.
    pub fn hash(&self) -> Hash256 {
        let serialized = bincode::serialize(self).unwrap_or_default();
        Hash256::hash_many(&[ENTRY_HASH_DOMAIN, &serialized])
    }

    /// Get the timestamp of this entry.
    pub fn timestamp(&self) -> u64 {
        match self {
            ChainEntry::IdentityRegistration { timestamp, .. } => *timestamp,
            ChainEntry::UsernameRegistration { timestamp, .. } => *timestamp,
            ChainEntry::KeyRotation { timestamp, .. } => *timestamp,
            ChainEntry::MessageProof { timestamp, .. } => *timestamp,
            ChainEntry::ReputationChange { timestamp, .. } => *timestamp,
            ChainEntry::ValidatorRegistration { timestamp, .. } => *timestamp,
            ChainEntry::ValidatorExit { timestamp, .. } => *timestamp,
            ChainEntry::ValidatorSlash { timestamp, .. } => *timestamp,
        }
    }

    /// Get the primary identity associated with this entry.
    pub fn identity(&self) -> Option<&IdentityHash> {
        match self {
            ChainEntry::IdentityRegistration { identity_hash, .. } => Some(identity_hash),
            ChainEntry::UsernameRegistration { identity_hash, .. } => Some(identity_hash),
            ChainEntry::KeyRotation { old_identity, .. } => Some(old_identity),
            ChainEntry::MessageProof { sender_hash, .. } => Some(sender_hash),
            ChainEntry::ReputationChange { identity_hash, .. } => Some(identity_hash),
            ChainEntry::ValidatorRegistration { identity_hash, .. } => Some(identity_hash),
            ChainEntry::ValidatorExit { identity_hash, .. } => Some(identity_hash),
            ChainEntry::ValidatorSlash { identity_hash, .. } => Some(identity_hash),
        }
    }

    /// Check if this is an identity registration entry.
    pub fn is_identity_registration(&self) -> bool {
        matches!(self, ChainEntry::IdentityRegistration { .. })
    }

    /// Check if this is a username registration entry.
    pub fn is_username_registration(&self) -> bool {
        matches!(self, ChainEntry::UsernameRegistration { .. })
    }

    /// Check if this is a key rotation entry.
    pub fn is_key_rotation(&self) -> bool {
        matches!(self, ChainEntry::KeyRotation { .. })
    }

    /// Check if this is a message proof entry.
    pub fn is_message_proof(&self) -> bool {
        matches!(self, ChainEntry::MessageProof { .. })
    }

    /// Check if this is a reputation change entry.
    pub fn is_reputation_change(&self) -> bool {
        matches!(self, ChainEntry::ReputationChange { .. })
    }

    /// Check if this is a validator-related entry.
    pub fn is_validator_entry(&self) -> bool {
        matches!(
            self,
            ChainEntry::ValidatorRegistration { .. }
                | ChainEntry::ValidatorExit { .. }
                | ChainEntry::ValidatorSlash { .. }
        )
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test identity hash
    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    // Helper to create a test hash
    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    // ==================== BlockHeader Tests ====================

    #[test]
    fn test_block_header_creation() {
        let parent = test_hash(1);
        let validator = test_identity(2);
        let merkle_root = test_hash(3);
        let timestamp = 1700000000u64;

        let header = BlockHeader::new(
            parent.clone(),
            1,
            timestamp,
            merkle_root.clone(),
            validator.clone(),
        );

        assert_eq!(header.height, 1);
        assert_eq!(header.timestamp, timestamp);
        assert_eq!(header.parent_hash, parent);
        assert_eq!(header.merkle_root, merkle_root);
        assert_eq!(header.validator, validator);
        assert!(!header.hash.is_zero());
    }

    #[test]
    fn test_block_header_hash_verification() {
        let header = BlockHeader::new(test_hash(1), 1, 1700000000, test_hash(3), test_identity(2));

        assert!(header.verify_hash());
    }

    #[test]
    fn test_block_header_hash_deterministic() {
        let parent = test_hash(1);
        let validator = test_identity(2);
        let merkle_root = test_hash(3);
        let timestamp = 1700000000u64;

        let header1 = BlockHeader::new(
            parent.clone(),
            1,
            timestamp,
            merkle_root.clone(),
            validator.clone(),
        );
        let header2 = BlockHeader::new(parent, 1, timestamp, merkle_root, validator);

        assert_eq!(header1.hash, header2.hash);
    }

    #[test]
    fn test_block_header_hash_changes_with_height() {
        let parent = test_hash(1);
        let validator = test_identity(2);
        let merkle_root = test_hash(3);

        let header1 = BlockHeader::new(
            parent.clone(),
            1,
            1700000000,
            merkle_root.clone(),
            validator.clone(),
        );
        let header2 = BlockHeader::new(parent, 2, 1700000000, merkle_root, validator);

        assert_ne!(header1.hash, header2.hash);
    }

    #[test]
    fn test_block_header_datetime() {
        let header = BlockHeader::new(test_hash(1), 1, 1700000000, test_hash(3), test_identity(2));

        let dt = header.datetime();
        assert_eq!(dt.timestamp(), 1700000000);
    }

    #[test]
    fn test_block_header_is_genesis() {
        // Genesis header
        let genesis_header = BlockHeader::new(
            Hash256::default(), // All zeros
            0,
            1700000000,
            test_hash(3),
            test_identity(2),
        );
        assert!(genesis_header.is_genesis());

        // Non-genesis header
        let non_genesis =
            BlockHeader::new(test_hash(1), 1, 1700000000, test_hash(3), test_identity(2));
        assert!(!non_genesis.is_genesis());
    }

    // ==================== BlockBody Tests ====================

    #[test]
    fn test_block_body_empty() {
        let body = BlockBody::empty();
        assert!(body.is_empty());
        assert_eq!(body.len(), 0);
    }

    #[test]
    fn test_block_body_with_entries() {
        let entries = vec![ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        }];

        let body = BlockBody::new(entries);
        assert!(!body.is_empty());
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn test_block_body_merkle_root_deterministic() {
        let entries = vec![ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        }];

        let body1 = BlockBody::new(entries.clone());
        let body2 = BlockBody::new(entries);

        assert_eq!(body1.compute_merkle_root(), body2.compute_merkle_root());
    }

    #[test]
    fn test_block_body_merkle_root_different_entries() {
        let body1 = BlockBody::new(vec![ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        }]);

        let body2 = BlockBody::new(vec![ChainEntry::IdentityRegistration {
            identity_hash: test_identity(2), // Different identity
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        }]);

        assert_ne!(body1.compute_merkle_root(), body2.compute_merkle_root());
    }

    // ==================== Block Tests ====================

    #[test]
    fn test_block_creation() {
        let parent = test_hash(1);
        let validator = test_identity(2);
        let entries = vec![ChainEntry::IdentityRegistration {
            identity_hash: test_identity(3),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        }];

        let block = Block::new(parent.clone(), 1, 1700000000, entries, validator.clone());

        assert_eq!(block.height(), 1);
        assert_eq!(block.timestamp(), 1700000000);
        assert_eq!(block.parent_hash(), &parent);
        assert_eq!(block.validator(), &validator);
        assert_eq!(block.entries().len(), 1);
    }

    #[test]
    fn test_genesis_block() {
        let entries = vec![ChainEntry::ValidatorRegistration {
            identity_hash: test_identity(1),
            stake: 700,
            region: ValidatorRegion::NorthAmerica,
            timestamp: 1700000000,
            signature: vec![1, 2, 3],
        }];

        let genesis = Block::genesis(1700000000, entries);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), 0);
        assert!(genesis.parent_hash().is_zero());
        assert_eq!(genesis.validator(), &Block::genesis_validator());
    }

    #[test]
    fn test_block_verification_success() {
        let block = Block::new(test_hash(1), 1, 1700000000, vec![], test_identity(2));

        assert!(block.verify().is_ok());
    }

    #[test]
    fn test_block_serialization_roundtrip() {
        let block = Block::new(
            test_hash(1),
            1,
            1700000000,
            vec![ChainEntry::IdentityRegistration {
                identity_hash: test_identity(3),
                public_keys: vec![1, 2, 3],
                timestamp: 1700000000,
                signature: vec![4, 5, 6],
            }],
            test_identity(2),
        );

        let bytes = block.to_bytes().unwrap();
        let restored = Block::from_bytes(&bytes).unwrap();

        assert_eq!(block, restored);
    }

    #[test]
    fn test_genesis_block_serialization() {
        let genesis = Block::genesis(1700000000, vec![]);
        let bytes = genesis.to_bytes().unwrap();
        let restored = Block::from_bytes(&bytes).unwrap();

        assert_eq!(genesis, restored);
        assert!(restored.is_genesis());
    }

    // ==================== ChainEntry Tests ====================

    #[test]
    fn test_chain_entry_identity_registration() {
        let entry = ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3, 4],
            timestamp: 1700000000,
            signature: vec![5, 6, 7, 8],
        };

        assert!(entry.is_identity_registration());
        assert!(!entry.is_username_registration());
        assert_eq!(entry.timestamp(), 1700000000);
        assert_eq!(entry.identity(), Some(&test_identity(1)));
    }

    #[test]
    fn test_chain_entry_username_registration() {
        let entry = ChainEntry::UsernameRegistration {
            username: "alice".to_string(),
            identity_hash: test_identity(1),
            signature: vec![1, 2, 3],
            timestamp: 1700000000,
        };

        assert!(entry.is_username_registration());
        assert!(!entry.is_identity_registration());
    }

    #[test]
    fn test_chain_entry_key_rotation() {
        let entry = ChainEntry::KeyRotation {
            old_identity: test_identity(1),
            new_identity: test_identity(2),
            old_signature: vec![1, 2, 3],
            new_signature: vec![4, 5, 6],
            timestamp: 1700000000,
        };

        assert!(entry.is_key_rotation());
        assert_eq!(entry.identity(), Some(&test_identity(1)));
    }

    #[test]
    fn test_chain_entry_message_proof() {
        let entry = ChainEntry::MessageProof {
            message_hash: test_hash(1),
            sender_hash: test_identity(2),
            recipient_hash: test_identity(3),
            timestamp: 1700000000,
            merkle_proof: Some(vec![test_hash(4), test_hash(5)]),
        };

        assert!(entry.is_message_proof());
        assert_eq!(entry.identity(), Some(&test_identity(2)));
    }

    #[test]
    fn test_chain_entry_reputation_change() {
        let entry = ChainEntry::ReputationChange {
            identity_hash: test_identity(1),
            change_amount: -10,
            reason: ReputationChangeReason::NegativeReport,
            proof: None,
            timestamp: 1700000000,
        };

        assert!(entry.is_reputation_change());
        assert_eq!(entry.timestamp(), 1700000000);
    }

    #[test]
    fn test_chain_entry_validator_registration() {
        let entry = ChainEntry::ValidatorRegistration {
            identity_hash: test_identity(1),
            stake: 800,
            region: ValidatorRegion::Europe,
            timestamp: 1700000000,
            signature: vec![1, 2, 3],
        };

        assert!(entry.is_validator_entry());
        assert!(!entry.is_message_proof());
    }

    #[test]
    fn test_chain_entry_validator_exit() {
        let entry = ChainEntry::ValidatorExit {
            identity_hash: test_identity(1),
            timestamp: 1700000000,
            signature: vec![1, 2, 3],
        };

        assert!(entry.is_validator_entry());
    }

    #[test]
    fn test_chain_entry_validator_slash() {
        let entry = ChainEntry::ValidatorSlash {
            identity_hash: test_identity(1),
            slash_amount: 50,
            reason: SlashReason::DoubleSigning,
            evidence: vec![1, 2, 3, 4],
            timestamp: 1700000000,
        };

        assert!(entry.is_validator_entry());
        assert_eq!(entry.identity(), Some(&test_identity(1)));
    }

    #[test]
    fn test_chain_entry_hash_deterministic() {
        let entry1 = ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        };

        let entry2 = ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        };

        assert_eq!(entry1.hash(), entry2.hash());
    }

    #[test]
    fn test_chain_entry_hash_different_for_different_entries() {
        let entry1 = ChainEntry::IdentityRegistration {
            identity_hash: test_identity(1),
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        };

        let entry2 = ChainEntry::IdentityRegistration {
            identity_hash: test_identity(2), // Different identity
            public_keys: vec![1, 2, 3],
            timestamp: 1700000000,
            signature: vec![4, 5, 6],
        };

        assert_ne!(entry1.hash(), entry2.hash());
    }

    // ==================== Reputation Reason Tests ====================

    #[test]
    fn test_reputation_change_reasons() {
        let reasons = vec![
            ReputationChangeReason::PositiveInteraction,
            ReputationChangeReason::MessageDelivery,
            ReputationChangeReason::NegativeReport,
            ReputationChangeReason::SpamDetected,
            ReputationChangeReason::ValidatorReward,
            ReputationChangeReason::ValidatorSlash,
            ReputationChangeReason::WeeklyDecay,
            ReputationChangeReason::Other("custom".to_string()),
        ];

        // All reasons should serialize/deserialize correctly
        for reason in reasons {
            let entry = ChainEntry::ReputationChange {
                identity_hash: test_identity(1),
                change_amount: 5,
                reason: reason.clone(),
                proof: None,
                timestamp: 1700000000,
            };

            let bytes = bincode::serialize(&entry).unwrap();
            let restored: ChainEntry = bincode::deserialize(&bytes).unwrap();
            assert_eq!(entry, restored);
        }
    }

    // ==================== Slash Reason Tests ====================

    #[test]
    fn test_slash_reasons() {
        let reasons = vec![
            SlashReason::MissedBlock,
            SlashReason::SlaViolation,
            SlashReason::InvalidBlock,
            SlashReason::DoubleSigning,
        ];

        for reason in reasons {
            let entry = ChainEntry::ValidatorSlash {
                identity_hash: test_identity(1),
                slash_amount: 100,
                reason: reason.clone(),
                evidence: vec![],
                timestamp: 1700000000,
            };

            let bytes = bincode::serialize(&entry).unwrap();
            let restored: ChainEntry = bincode::deserialize(&bytes).unwrap();
            assert_eq!(entry, restored);
        }
    }

    // ==================== Validator Region Tests ====================

    #[test]
    fn test_validator_regions() {
        let regions = vec![
            ValidatorRegion::NorthAmerica,
            ValidatorRegion::SouthAmerica,
            ValidatorRegion::Europe,
            ValidatorRegion::Asia,
            ValidatorRegion::Africa,
            ValidatorRegion::Oceania,
            ValidatorRegion::Unknown,
        ];

        for region in regions {
            let entry = ChainEntry::ValidatorRegistration {
                identity_hash: test_identity(1),
                stake: 700,
                region: region.clone(),
                timestamp: 1700000000,
                signature: vec![],
            };

            let bytes = bincode::serialize(&entry).unwrap();
            let restored: ChainEntry = bincode::deserialize(&bytes).unwrap();
            assert_eq!(entry, restored);
        }
    }

    // ==================== Block Verification Failure Tests ====================

    #[test]
    fn test_block_verification_hash_mismatch() {
        let mut block = Block::new(test_hash(1), 1, 1700000000, vec![], test_identity(2));

        // Tamper with the hash
        block.header.hash = test_hash(99);

        let result = block.verify();
        assert!(result.is_err());
        match result {
            Err(ChainError::InvalidBlock(msg)) => {
                assert!(msg.contains("hash mismatch"));
            }
            _ => panic!("Expected InvalidBlock error"),
        }
    }

    #[test]
    fn test_block_verification_merkle_mismatch() {
        let mut block = Block::new(test_hash(1), 1, 1700000000, vec![], test_identity(2));

        // Add an entry without updating merkle root
        block.body.entries.push(ChainEntry::IdentityRegistration {
            identity_hash: test_identity(99),
            public_keys: vec![],
            timestamp: 0,
            signature: vec![],
        });

        let result = block.verify();
        assert!(result.is_err());
        match result {
            Err(ChainError::InvalidBlock(msg)) => {
                assert!(msg.contains("merkle root mismatch"));
            }
            _ => panic!("Expected InvalidBlock error"),
        }
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_block_hash_changes_with_any_field(
            height1 in any::<u64>(),
            height2 in any::<u64>(),
            timestamp in any::<u64>()
        ) {
            prop_assume!(height1 != height2);

            let header1 = BlockHeader::new(
                test_hash(1),
                height1,
                timestamp,
                test_hash(3),
                test_identity(2),
            );
            let header2 = BlockHeader::new(
                test_hash(1),
                height2,
                timestamp,
                test_hash(3),
                test_identity(2),
            );

            prop_assert_ne!(header1.hash, header2.hash);
        }

        #[test]
        fn prop_block_serialization_roundtrip(height in 0u64..1000000, timestamp in 0u64..2000000000) {
            let block = Block::new(
                test_hash(1),
                height,
                timestamp,
                vec![],
                test_identity(2),
            );

            let bytes = block.to_bytes().unwrap();
            let restored = Block::from_bytes(&bytes).unwrap();

            prop_assert_eq!(block, restored);
        }

        #[test]
        fn prop_chain_entry_hash_deterministic(seed in 0u8..255) {
            let entry = ChainEntry::IdentityRegistration {
                identity_hash: test_identity(seed),
                public_keys: vec![seed; 10],
                timestamp: seed as u64 * 1000000,
                signature: vec![seed; 64],
            };

            let hash1 = entry.hash();
            let hash2 = entry.hash();

            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_genesis_always_valid(timestamp in 0u64..2000000000) {
            let genesis = Block::genesis(timestamp, vec![]);
            prop_assert!(genesis.is_genesis());
            prop_assert!(genesis.verify().is_ok());
        }
    }
}
