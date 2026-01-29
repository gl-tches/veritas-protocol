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
use veritas_crypto::{Hash256, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature};
use veritas_identity::IdentityHash;

use crate::{ChainError, Result};

// ============================================================================
// Signature Constants (VERITAS-2026-0002)
// ============================================================================

/// Domain separator for block signature computation.
///
/// SECURITY: Using a domain separator prevents cross-protocol signature attacks
/// where a valid signature from another context could be reused.
const BLOCK_SIGNATURE_DOMAIN: &[u8] = b"VERITAS-BLOCK-SIGNATURE-v1";

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
///
/// ## Security (VERITAS-2026-0002)
///
/// Non-genesis blocks MUST include a valid ML-DSA signature from the validator.
/// The signature covers the block hash and prevents forged blocks from being
/// accepted even if an attacker knows a valid validator ID.
///
/// Signature verification is performed by calling [`verify_signature()`] before
/// trusting any data from the block.
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

    /// ML-DSA public key of the validator (serialized).
    ///
    /// SECURITY (VERITAS-2026-0002): This public key MUST be verified to derive
    /// to the claimed `validator` identity hash. Empty for genesis blocks.
    #[serde(default)]
    pub validator_pubkey: Vec<u8>,

    /// ML-DSA signature over the block signing payload (serialized).
    ///
    /// SECURITY (VERITAS-2026-0002): This signature MUST be verified before
    /// trusting any block data. Empty for genesis blocks.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl BlockHeader {
    /// Create a new UNSIGNED block header with computed hash.
    ///
    /// # Warning
    ///
    /// This creates an unsigned block header. For production use, you MUST use
    /// [`new_signed()`] instead to create properly signed blocks.
    ///
    /// Unsigned headers are only valid for:
    /// - Genesis blocks (which don't require signatures)
    /// - Testing purposes
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
    /// // For genesis blocks only:
    /// let header = BlockHeader::new(
    ///     Hash256::default(), // All zeros for genesis
    ///     0,
    ///     chrono::Utc::now().timestamp() as u64,
    ///     merkle_root,
    ///     genesis_validator_id,
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
            validator_pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Create a new SIGNED block header with computed hash and ML-DSA signature.
    ///
    /// SECURITY (VERITAS-2026-0002): This is the REQUIRED constructor for all
    /// non-genesis blocks. The block is signed using the validator's ML-DSA
    /// private key, which cryptographically binds the block to the validator's
    /// identity.
    ///
    /// # Arguments
    ///
    /// * `parent_hash` - Hash of the parent block
    /// * `height` - Block height (must be > 0)
    /// * `timestamp` - Unix timestamp in seconds
    /// * `merkle_root` - Merkle root of entries
    /// * `validator` - Identity hash of the block producer
    /// * `validator_private_key` - ML-DSA private key for signing
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Signing fails
    /// - Height is 0 (use `new()` for genesis blocks)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let header = BlockHeader::new_signed(
    ///     parent_hash,
    ///     1,
    ///     chrono::Utc::now().timestamp() as u64,
    ///     merkle_root,
    ///     validator_id,
    ///     &validator_private_key,
    /// )?;
    /// ```
    pub fn new_signed(
        parent_hash: Hash256,
        height: u64,
        timestamp: u64,
        merkle_root: Hash256,
        validator: IdentityHash,
        validator_private_key: &MlDsaPrivateKey,
    ) -> Result<Self> {
        // Genesis blocks should use new() instead
        if height == 0 {
            return Err(ChainError::InvalidBlock(
                "genesis blocks should use new(), not new_signed()".to_string(),
            ));
        }

        let hash = Self::compute_hash(&parent_hash, height, timestamp, &merkle_root, &validator);

        // Get the public key from the private key
        let public_key = validator_private_key.public_key();
        let validator_pubkey = public_key.as_bytes().to_vec();

        // Compute the signing payload
        let signing_payload = Self::compute_signing_payload_static(&hash);

        // Sign the payload
        let signature_obj = validator_private_key
            .sign(&signing_payload)
            .map_err(|e| ChainError::InvalidSignature(format!("signing failed: {}", e)))?;

        Ok(Self {
            hash,
            parent_hash,
            height,
            timestamp,
            merkle_root,
            validator,
            validator_pubkey,
            signature: signature_obj.as_bytes().to_vec(),
        })
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

    /// Compute the signing payload for this block.
    ///
    /// The signing payload includes a domain separator and the block hash,
    /// ensuring that signatures are bound to this specific block and cannot
    /// be reused in other contexts.
    ///
    /// # Returns
    ///
    /// A byte vector containing the data that should be signed.
    pub fn compute_signing_payload(&self) -> Vec<u8> {
        Self::compute_signing_payload_static(&self.hash)
    }

    /// Static helper to compute the signing payload from a hash.
    ///
    /// This is used internally by both `compute_signing_payload()` and
    /// `new_signed()` to ensure consistent payload computation.
    fn compute_signing_payload_static(hash: &Hash256) -> Vec<u8> {
        let mut payload = Vec::with_capacity(BLOCK_SIGNATURE_DOMAIN.len() + 32);
        payload.extend_from_slice(BLOCK_SIGNATURE_DOMAIN);
        payload.extend_from_slice(hash.as_bytes());
        payload
    }

    /// Verify the block's cryptographic signature.
    ///
    /// SECURITY (VERITAS-2026-0002): This method MUST be called before trusting
    /// any data from a non-genesis block. It verifies:
    ///
    /// 1. The signature is present (non-empty)
    /// 2. The public key is present (non-empty)
    /// 3. The public key derives to the claimed validator identity
    /// 4. The ML-DSA signature is valid over the block's signing payload
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the signature is valid
    /// - `Err(ChainError::MissingSignature)` if signature or pubkey is missing
    /// - `Err(ChainError::ValidatorKeyMismatch)` if pubkey doesn't match validator
    /// - `Err(ChainError::InvalidSignature)` if signature verification fails
    ///
    /// # Genesis Blocks
    ///
    /// Genesis blocks (height 0, parent_hash all zeros) are exempt from
    /// signature verification and will return `Ok(())` even without a signature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // ALWAYS verify signature before trusting block data
    /// block.header.verify_signature()?;
    /// // Now safe to use block data
    /// process_block(&block);
    /// ```
    pub fn verify_signature(&self) -> Result<()> {
        // Genesis blocks don't require signatures
        if self.is_genesis() {
            return Ok(());
        }

        // SECURITY: Non-genesis blocks MUST have a signature
        if self.signature.is_empty() {
            return Err(ChainError::MissingSignature);
        }

        // SECURITY: Non-genesis blocks MUST have a public key
        if self.validator_pubkey.is_empty() {
            return Err(ChainError::MissingSignature);
        }

        // Parse the public key
        let pubkey = MlDsaPublicKey::from_bytes(&self.validator_pubkey)
            .map_err(|e| ChainError::InvalidSignature(format!("invalid public key: {}", e)))?;

        // SECURITY: Verify the public key derives to the claimed validator identity
        // This prevents an attacker from using their own key to sign a block
        // while claiming to be a different validator.
        let derived_id = IdentityHash::from(Hash256::hash(pubkey.as_bytes()));
        if derived_id != self.validator {
            return Err(ChainError::ValidatorKeyMismatch {
                claimed: self.validator.to_string(),
                derived: derived_id.to_string(),
            });
        }

        // Parse the signature
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| ChainError::InvalidSignature(format!("invalid signature: {}", e)))?;

        // Compute the signing payload
        let payload = self.compute_signing_payload();

        // SECURITY: Verify the signature
        pubkey
            .verify(&payload, &signature)
            .map_err(|_| ChainError::InvalidSignature("signature verification failed".to_string()))
    }

    /// Check if the block has a signature (non-genesis blocks should always have one).
    ///
    /// This is a quick check that doesn't verify the signature validity.
    /// Use [`verify_signature()`] for full verification.
    pub fn has_signature(&self) -> bool {
        !self.signature.is_empty() && !self.validator_pubkey.is_empty()
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
    /// Create a new UNSIGNED block with the given parameters.
    ///
    /// # Warning
    ///
    /// This creates an unsigned block. For production use with non-genesis blocks,
    /// you MUST use [`new_signed()`] instead to create properly signed blocks.
    ///
    /// Unsigned blocks are only valid for:
    /// - Genesis blocks (which don't require signatures)
    /// - Testing purposes
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

    /// Create a new SIGNED block with the given parameters.
    ///
    /// SECURITY (VERITAS-2026-0002): This is the REQUIRED constructor for all
    /// non-genesis blocks in production. The block is signed using the validator's
    /// ML-DSA private key, which cryptographically binds the block to the
    /// validator's identity and prevents block forgery.
    ///
    /// # Arguments
    ///
    /// * `parent_hash` - Hash of the parent block
    /// * `height` - Block height (must be > 0)
    /// * `timestamp` - Unix timestamp in seconds
    /// * `entries` - Chain entries to include
    /// * `validator` - Identity hash of the block producer
    /// * `validator_private_key` - ML-DSA private key for signing
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Signing fails
    /// - Height is 0 (use `new()` or `genesis()` for genesis blocks)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let block = Block::new_signed(
    ///     parent_hash,
    ///     1,
    ///     chrono::Utc::now().timestamp() as u64,
    ///     entries,
    ///     validator_id,
    ///     &validator_private_key,
    /// )?;
    /// ```
    pub fn new_signed(
        parent_hash: Hash256,
        height: u64,
        timestamp: u64,
        entries: Vec<ChainEntry>,
        validator: IdentityHash,
        validator_private_key: &MlDsaPrivateKey,
    ) -> Result<Self> {
        let body = BlockBody::new(entries);
        let merkle_root = body.compute_merkle_root();
        let header = BlockHeader::new_signed(
            parent_hash,
            height,
            timestamp,
            merkle_root,
            validator,
            validator_private_key,
        )?;
        Ok(Self { header, body })
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

    /// Verify block integrity (hash and merkle root only).
    ///
    /// Checks that:
    /// 1. Block hash is correctly computed
    /// 2. Merkle root matches entry hashes
    ///
    /// # Warning
    ///
    /// This method does NOT verify the block signature. For full security
    /// verification including signature checks, use [`verify_with_signature()`].
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

    /// Verify block integrity AND cryptographic signature.
    ///
    /// SECURITY (VERITAS-2026-0002): This is the REQUIRED verification method
    /// for production use. It performs all checks from [`verify()`] plus:
    ///
    /// 3. Signature is present (for non-genesis blocks)
    /// 4. Public key matches claimed validator identity
    /// 5. ML-DSA signature is valid
    ///
    /// # Errors
    ///
    /// Returns an error if any verification fails:
    /// - `ChainError::InvalidBlock` for hash/merkle issues
    /// - `ChainError::MissingSignature` for unsigned non-genesis blocks
    /// - `ChainError::ValidatorKeyMismatch` for pubkey/identity mismatch
    /// - `ChainError::InvalidSignature` for signature verification failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// // ALWAYS use this for production verification
    /// block.verify_with_signature()?;
    /// ```
    pub fn verify_with_signature(&self) -> Result<()> {
        // First verify hash and merkle root
        self.verify()?;

        // Then verify signature (required for non-genesis blocks)
        self.header.verify_signature()
    }

    /// Check if this block has a signature.
    ///
    /// Returns `true` if the block has both a public key and signature.
    /// This is a quick check that doesn't verify validity.
    pub fn has_signature(&self) -> bool {
        self.header.has_signature()
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

    // ==================== Security Tests (VERITAS-2026-0002) ====================
    //
    // These tests verify that block signature verification works correctly
    // and prevents forged block attacks.

    mod security_tests {
        use super::*;

        // ==================== Test: Genesis blocks don't require signature ====================
        #[test]
        fn test_genesis_block_no_signature_required() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Genesis should pass signature verification even without a signature
            assert!(genesis.header.verify_signature().is_ok());
            assert!(genesis.verify_with_signature().is_ok());
        }

        // ==================== Test: Unsigned non-genesis blocks are rejected ====================
        #[test]
        fn test_unsigned_block_rejected() {
            // Create an unsigned non-genesis block
            let block = Block::new(
                test_hash(1), // Non-zero parent = not genesis
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Unsigned blocks should fail signature verification
            let result = block.header.verify_signature();
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Block with empty signature is rejected ====================
        #[test]
        fn test_empty_signature_rejected() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Set pubkey but leave signature empty
            block.header.validator_pubkey = vec![1, 2, 3, 4]; // Fake pubkey

            let result = block.header.verify_signature();
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Block with empty pubkey is rejected ====================
        #[test]
        fn test_empty_pubkey_rejected() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Set signature but leave pubkey empty
            block.header.signature = vec![1, 2, 3, 4]; // Fake signature

            let result = block.header.verify_signature();
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Forged block with invalid signature rejected ====================
        #[test]
        fn test_forged_block_invalid_signature_rejected() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Attacker tries to forge by adding fake pubkey and signature
            // that don't actually verify
            block.header.validator_pubkey = vec![0u8; 100]; // Garbage pubkey
            block.header.signature = vec![0u8; 100]; // Garbage signature

            let result = block.header.verify_signature();
            assert!(result.is_err());
            // Should fail at pubkey parsing stage
            assert!(matches!(result, Err(ChainError::InvalidSignature(_))));
        }

        // ==================== Test: Signing payload is deterministic ====================
        #[test]
        fn test_signing_payload_deterministic() {
            let header = BlockHeader::new(
                test_hash(1),
                1,
                1700000001,
                test_hash(3),
                test_identity(2),
            );

            let payload1 = header.compute_signing_payload();
            let payload2 = header.compute_signing_payload();

            assert_eq!(payload1, payload2);
        }

        // ==================== Test: Different blocks have different signing payloads ====================
        #[test]
        fn test_different_blocks_different_payloads() {
            let header1 = BlockHeader::new(
                test_hash(1),
                1,
                1700000001,
                test_hash(3),
                test_identity(2),
            );

            let header2 = BlockHeader::new(
                test_hash(1),
                2, // Different height
                1700000001,
                test_hash(3),
                test_identity(2),
            );

            let payload1 = header1.compute_signing_payload();
            let payload2 = header2.compute_signing_payload();

            assert_ne!(payload1, payload2);
        }

        // ==================== Test: has_signature() helper ====================
        #[test]
        fn test_has_signature_helper() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Initially no signature
            assert!(!block.has_signature());

            // Add pubkey only
            block.header.validator_pubkey = vec![1, 2, 3];
            assert!(!block.has_signature());

            // Add signature too
            block.header.signature = vec![4, 5, 6];
            assert!(block.has_signature());
        }

        // ==================== Test: Signing payload includes domain separator ====================
        #[test]
        fn test_signing_payload_includes_domain() {
            let header = BlockHeader::new(
                test_hash(1),
                1,
                1700000001,
                test_hash(3),
                test_identity(2),
            );

            let payload = header.compute_signing_payload();

            // Payload should start with the domain separator
            assert!(payload.starts_with(b"VERITAS-BLOCK-SIGNATURE-v1"));
        }

        // ==================== Test: verify_with_signature checks both hash and signature ====================
        #[test]
        fn test_verify_with_signature_full_check() {
            // Create a valid unsigned block
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Basic verify() should pass (hash and merkle are correct)
            assert!(block.verify().is_ok());

            // But verify_with_signature() should fail (no signature)
            let result = block.verify_with_signature();
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));

            // Add invalid signature - should still fail
            block.header.validator_pubkey = vec![0u8; 50];
            block.header.signature = vec![0u8; 50];

            let result = block.verify_with_signature();
            assert!(result.is_err());
        }

        // ==================== Test: Genesis verify_with_signature passes ====================
        #[test]
        fn test_genesis_verify_with_signature_passes() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Both verify methods should pass for genesis
            assert!(genesis.verify().is_ok());
            assert!(genesis.verify_with_signature().is_ok());
        }

        // ==================== Test: Tampered block hash fails verification ====================
        #[test]
        fn test_tampered_hash_fails_signature_verification() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Add fake signature data
            block.header.validator_pubkey = vec![0u8; 50];
            block.header.signature = vec![0u8; 50];

            // Tamper with the hash
            block.header.hash = test_hash(99);

            // Both verifications should fail
            let result = block.verify();
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
        }

        // ==================== Test: new_signed() API exists ====================
        #[test]
        fn test_new_signed_api_exists() {
            // This is a compile-time check that the Block::new_signed API exists
            // Note: We can't actually test signing until ML-DSA is fully implemented,
            // but we verify the API is available and has the correct signature.

            fn _assert_api_exists() {
                fn _uses_new_signed(
                    _parent: Hash256,
                    _height: u64,
                    _ts: u64,
                    _entries: Vec<ChainEntry>,
                    _validator: IdentityHash,
                    _privkey: &MlDsaPrivateKey,
                ) -> Result<Block> {
                    Block::new_signed(_parent, _height, _ts, _entries, _validator, _privkey)
                }
            }
        }

        // ==================== Test: Serialization preserves signature fields ====================
        #[test]
        fn test_serialization_preserves_signature_fields() {
            let mut block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            // Add test signature data
            block.header.validator_pubkey = vec![1, 2, 3, 4, 5];
            block.header.signature = vec![6, 7, 8, 9, 10];

            // Serialize and deserialize
            let bytes = block.to_bytes().unwrap();
            let restored = Block::from_bytes(&bytes).unwrap();

            // Verify signature fields are preserved
            assert_eq!(restored.header.validator_pubkey, vec![1, 2, 3, 4, 5]);
            assert_eq!(restored.header.signature, vec![6, 7, 8, 9, 10]);
        }

        // ==================== Test: Empty signature fields in new blocks ====================
        #[test]
        fn test_new_block_has_empty_signature_fields() {
            let block = Block::new(
                test_hash(1),
                1,
                1700000001,
                vec![],
                test_identity(2),
            );

            assert!(block.header.validator_pubkey.is_empty());
            assert!(block.header.signature.is_empty());
            assert!(!block.has_signature());
        }
    }
}
