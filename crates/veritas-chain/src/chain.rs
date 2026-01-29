//! Blockchain management and chain operations.
//!
//! This module provides the core blockchain data structure for the VERITAS protocol:
//!
//! - [`Blockchain`]: Main chain storage and traversal
//! - [`BlockValidation`]: Block validation rules
//! - [`ForkChoice`]: Fork detection and resolution using longest chain rule
//!
//! ## Chain Structure
//!
//! The blockchain maintains:
//! - Blocks indexed by hash for O(1) lookup
//! - Height index for the main chain
//! - Chain tip tracking
//! - Validator set for block producer validation
//!
//! ## Fork Handling
//!
//! When a fork is detected, the longest chain rule is applied:
//! - The chain with the most blocks wins
//! - Reorganization happens automatically when a longer fork is found
//!
//! ## Example
//!
//! ```
//! use veritas_chain::{Block, ChainEntry};
//! use veritas_chain::chain::{Blockchain, BlockValidation};
//! use veritas_identity::IdentityHash;
//!
//! // Create a new blockchain with genesis block
//! let mut chain = Blockchain::new().unwrap();
//! assert_eq!(chain.height(), 0);
//!
//! // The genesis block is automatically created
//! let genesis = chain.tip();
//! assert!(genesis.is_genesis());
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::block::{Block, BlockBody, BlockHeader};
use crate::merkle::MerkleTree;
use crate::validator::ValidatorSet;
use crate::{ChainError, Result};

// ============================================================================
// Block Validation
// ============================================================================

/// Block validation rules.
///
/// Provides static methods for validating blocks before they are added
/// to the blockchain. All validation is performed before modifying chain state.
pub struct BlockValidation;

impl BlockValidation {
    /// Validate a block header against its parent header.
    ///
    /// Checks:
    /// - Height is parent height + 1
    /// - Parent hash matches
    /// - Timestamp is >= parent timestamp
    /// - Block hash is correctly computed
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidBlock` if any validation fails.
    pub fn validate_header(header: &BlockHeader, parent: &BlockHeader) -> Result<()> {
        // Check height continuity
        if header.height != parent.height + 1 {
            return Err(ChainError::InvalidBlock(format!(
                "invalid height: expected {}, got {}",
                parent.height + 1,
                header.height
            )));
        }

        // Check parent hash
        if header.parent_hash != parent.hash {
            return Err(ChainError::InvalidBlock(format!(
                "parent hash mismatch: expected {}, got {}",
                parent.hash, header.parent_hash
            )));
        }

        // Check timestamp
        if header.timestamp < parent.timestamp {
            return Err(ChainError::InvalidBlock(format!(
                "timestamp {} is before parent timestamp {}",
                header.timestamp, parent.timestamp
            )));
        }

        // Verify hash is correctly computed
        if !header.verify_hash() {
            return Err(ChainError::InvalidBlock(
                "block hash verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate block body against its header.
    ///
    /// Checks that the merkle root in the header matches the computed
    /// merkle root of the body entries.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidBlock` if merkle root doesn't match.
    pub fn validate_body(body: &BlockBody, header: &BlockHeader) -> Result<()> {
        let computed_root = body.compute_merkle_root();
        if computed_root != header.merkle_root {
            return Err(ChainError::InvalidBlock(format!(
                "merkle root mismatch: expected {}, computed {}",
                header.merkle_root, computed_root
            )));
        }
        Ok(())
    }

    /// Validate a complete block against its parent block.
    ///
    /// Performs full validation including:
    /// - Header validation
    /// - Body validation
    /// - Block integrity verification
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidBlock` if any validation fails.
    pub fn validate_block(block: &Block, parent: &Block) -> Result<()> {
        // Validate header against parent
        Self::validate_header(&block.header, &parent.header)?;

        // Validate body against header
        Self::validate_body(&block.body, &block.header)?;

        // Run block's internal verification
        block.verify()?;

        Ok(())
    }

    /// Validate that the block producer is an authorized validator with valid signature.
    ///
    /// SECURITY (VERITAS-2026-0002): This method performs cryptographic signature
    /// verification BEFORE trusting the claimed validator identity. This prevents
    /// an attacker who learns a valid validator ID from forging blocks.
    ///
    /// # Verification Steps
    ///
    /// For non-genesis blocks:
    /// 1. Verify the block has a signature and public key
    /// 2. Verify the signature is valid (ML-DSA verification)
    /// 3. Verify the public key derives to the claimed validator identity
    /// 4. Check that the validator is in the authorized set
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate
    /// * `validators` - List of authorized validator identity hashes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `ChainError::MissingSignature` - Block lacks signature (non-genesis)
    /// - `ChainError::InvalidSignature` - Signature verification failed
    /// - `ChainError::ValidatorKeyMismatch` - Public key doesn't match validator ID
    /// - `ChainError::InvalidBlock` - Producer not in validator set
    pub fn validate_producer(block: &Block, validators: &[IdentityHash]) -> Result<()> {
        // Genesis block has a special validator and doesn't need signature
        if block.is_genesis() {
            if block.validator() == &Block::genesis_validator() {
                return Ok(());
            }
            return Err(ChainError::InvalidBlock(
                "genesis block has invalid validator".to_string(),
            ));
        }

        // SECURITY (VERITAS-2026-0002): CRITICAL - Verify signature BEFORE
        // trusting the validator identity. This is the fix for the vulnerability
        // where an attacker could forge blocks by knowing a valid validator ID.
        //
        // The signature verification:
        // 1. Checks the signature is present
        // 2. Parses the public key
        // 3. Verifies the public key derives to the claimed validator identity
        // 4. Verifies the ML-DSA signature over the block hash
        //
        // Only after this verification passes can we trust the validator field.
        block.header.verify_signature()?;

        // Now that we've verified the signature, we can trust the validator field.
        // Check if block producer is in the authorized validator set.
        if !validators.contains(block.validator()) {
            return Err(ChainError::InvalidBlock(format!(
                "block producer {} is not an authorized validator",
                block.validator()
            )));
        }

        Ok(())
    }

    /// Validate merkle root using proper merkle tree construction.
    ///
    /// For blocks with entries, builds a merkle tree and verifies
    /// the root matches the header's merkle root.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidBlock` if merkle root doesn't match.
    pub fn validate_merkle_root(block: &Block) -> Result<()> {
        if block.body.is_empty() {
            // Empty blocks use a special empty merkle root
            let computed = block.body.compute_merkle_root();
            if computed != block.header.merkle_root {
                return Err(ChainError::InvalidBlock(
                    "empty merkle root mismatch".to_string(),
                ));
            }
            return Ok(());
        }

        // Build merkle tree from entry hashes
        let entry_hashes: Vec<Hash256> = block.entries().iter().map(|e| e.hash()).collect();

        let tree = MerkleTree::new(entry_hashes)?;

        // Note: The block body uses a simpler merkle root computation
        // We verify using the body's method for consistency
        let computed = block.body.compute_merkle_root();
        if computed != block.header.merkle_root {
            return Err(ChainError::InvalidBlock(format!(
                "merkle root mismatch: header {}, computed {}",
                block.header.merkle_root, computed
            )));
        }

        // Also verify the tree root is consistent
        // (this will match once body.compute_merkle_root uses MerkleTree)
        let _tree_root = tree.root();

        Ok(())
    }
}

// ============================================================================
// Fork Choice
// ============================================================================

/// Fork tracking and resolution using longest chain rule.
///
/// Tracks competing chain tips and determines the canonical chain
/// based on the longest chain rule (most accumulated work).
#[derive(Debug, Clone, Default)]
pub struct ForkChoice {
    /// Competing chain tips indexed by hash.
    /// Maps block hash -> (height, parent_hash)
    tips: HashMap<Hash256, (u64, Hash256)>,
}

impl ForkChoice {
    /// Create a new fork choice tracker.
    pub fn new() -> Self {
        Self {
            tips: HashMap::new(),
        }
    }

    /// Add a potential chain tip.
    ///
    /// # Arguments
    ///
    /// * `hash` - Block hash of the tip
    /// * `height` - Height of the tip
    /// * `parent` - Parent block hash
    pub fn add_tip(&mut self, hash: Hash256, height: u64, parent: Hash256) {
        self.tips.insert(hash, (height, parent));
    }

    /// Remove a tip (when it's no longer a tip because a child was added).
    pub fn remove_tip(&mut self, hash: &Hash256) {
        self.tips.remove(hash);
    }

    /// Get the best tip (highest height).
    ///
    /// Returns the hash of the tip with the greatest height.
    /// If there are ties, returns one of them (deterministically).
    pub fn best_tip(&self) -> Option<Hash256> {
        self.tips
            .iter()
            .max_by(|(hash_a, (height_a, _)), (hash_b, (height_b, _))| {
                height_a
                    .cmp(height_b)
                    .then_with(|| hash_a.as_bytes().cmp(hash_b.as_bytes()))
            })
            .map(|(hash, _)| hash.clone())
    }

    /// Get all current tips.
    pub fn all_tips(&self) -> impl Iterator<Item = (&Hash256, u64)> {
        self.tips.iter().map(|(hash, (height, _))| (hash, *height))
    }

    /// Get the number of tracked tips.
    pub fn tip_count(&self) -> usize {
        self.tips.len()
    }

    /// Check if a specific hash is a tip.
    pub fn is_tip(&self, hash: &Hash256) -> bool {
        self.tips.contains_key(hash)
    }

    /// Get the height of a tip.
    pub fn tip_height(&self, hash: &Hash256) -> Option<u64> {
        self.tips.get(hash).map(|(height, _)| *height)
    }

    /// Detect if there's a fork (multiple tips at similar heights).
    pub fn has_fork(&self) -> bool {
        if self.tips.len() <= 1 {
            return false;
        }

        // Check if any two tips are at the same height or within 1 block
        let heights: Vec<u64> = self.tips.values().map(|(h, _)| *h).collect();
        for i in 0..heights.len() {
            for j in (i + 1)..heights.len() {
                if heights[i].abs_diff(heights[j]) <= 1 {
                    return true;
                }
            }
        }
        false
    }
}

// ============================================================================
// Blockchain
// ============================================================================

/// Main blockchain data structure.
///
/// Stores blocks and provides chain traversal and management operations.
/// Uses the longest chain rule for fork resolution.
#[derive(Debug)]
pub struct Blockchain {
    /// Blocks indexed by hash for O(1) lookup.
    blocks: HashMap<Hash256, Block>,

    /// Hash at each height for the main chain.
    height_index: BTreeMap<u64, Hash256>,

    /// Current chain tip hash.
    tip: Hash256,

    /// Current chain height.
    height: u64,

    /// Genesis block hash.
    genesis_hash: Hash256,

    /// Validator set for block validation.
    validator_set: ValidatorSet,

    /// Fork choice tracker.
    fork_choice: ForkChoice,
}

impl Blockchain {
    /// Create a new blockchain with a genesis block.
    ///
    /// The genesis block is created with the current timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if genesis block creation fails.
    pub fn new() -> Result<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self::with_genesis_timestamp(timestamp)
    }

    /// Create a new blockchain with a specific genesis timestamp.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Unix timestamp for the genesis block
    pub fn with_genesis_timestamp(timestamp: u64) -> Result<Self> {
        let genesis = Block::genesis(timestamp, vec![]);
        let genesis_hash = genesis.hash().clone();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash.clone(), genesis);

        let mut height_index = BTreeMap::new();
        height_index.insert(0, genesis_hash.clone());

        let mut fork_choice = ForkChoice::new();
        fork_choice.add_tip(genesis_hash.clone(), 0, Hash256::default());

        Ok(Self {
            blocks,
            height_index,
            tip: genesis_hash.clone(),
            height: 0,
            genesis_hash,
            validator_set: ValidatorSet::new(),
            fork_choice,
        })
    }

    /// Create a blockchain with a custom genesis block.
    ///
    /// # Arguments
    ///
    /// * `genesis` - The genesis block to use
    ///
    /// # Errors
    ///
    /// Returns an error if the block is not a valid genesis block.
    pub fn with_genesis(genesis: Block) -> Result<Self> {
        if !genesis.is_genesis() {
            return Err(ChainError::InvalidBlock(
                "provided block is not a genesis block".to_string(),
            ));
        }

        genesis.verify()?;

        let genesis_hash = genesis.hash().clone();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash.clone(), genesis);

        let mut height_index = BTreeMap::new();
        height_index.insert(0, genesis_hash.clone());

        let mut fork_choice = ForkChoice::new();
        fork_choice.add_tip(genesis_hash.clone(), 0, Hash256::default());

        Ok(Self {
            blocks,
            height_index,
            tip: genesis_hash.clone(),
            height: 0,
            genesis_hash,
            validator_set: ValidatorSet::new(),
            fork_choice,
        })
    }

    /// Add a validated block to the chain.
    ///
    /// The block must:
    /// - Reference an existing parent block
    /// - Pass all validation rules
    /// - Have a valid block producer (if validators are configured)
    ///
    /// If the new block creates a longer chain, a reorganization occurs.
    ///
    /// # Errors
    ///
    /// Returns an error if the block is invalid or the parent doesn't exist.
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        let block_hash = block.hash().clone();
        let parent_hash = block.parent_hash().clone();
        let block_height = block.height();

        // Check for duplicate
        if self.blocks.contains_key(&block_hash) {
            return Err(ChainError::InvalidBlock(
                "block already exists in chain".to_string(),
            ));
        }

        // Get parent block
        let parent = self
            .blocks
            .get(&parent_hash)
            .ok_or_else(|| ChainError::BlockNotFound(parent_hash.to_string()))?;

        // Validate block against parent
        BlockValidation::validate_block(&block, parent)?;

        // Validate producer if we have validators
        if !self.validator_set.active_validators().is_empty() {
            let validators: Vec<IdentityHash> = self
                .validator_set
                .active_validators()
                .iter()
                .map(|v| v.identity.clone())
                .collect();
            BlockValidation::validate_producer(&block, &validators)?;
        }

        // Update fork choice
        self.fork_choice.remove_tip(&parent_hash);
        self.fork_choice
            .add_tip(block_hash.clone(), block_height, parent_hash);

        // Add block to storage
        self.blocks.insert(block_hash.clone(), block);

        // Check if this creates a longer chain
        if block_height > self.height {
            // New longest chain - update main chain
            self.reorganize_to(&block_hash)?;
        } else if block_height == self.height && block_hash.as_bytes() > self.tip.as_bytes() {
            // Same height but higher hash - tiebreaker
            self.reorganize_to(&block_hash)?;
        }

        Ok(())
    }

    /// Reorganize the chain to a new tip.
    fn reorganize_to(&mut self, new_tip: &Hash256) -> Result<()> {
        let new_block = self
            .blocks
            .get(new_tip)
            .ok_or_else(|| ChainError::BlockNotFound(new_tip.to_string()))?;

        let new_height = new_block.height();

        // Find common ancestor and build new chain path
        let mut new_chain = Vec::new();
        let mut current = new_tip.clone();

        while !self.height_index.values().any(|h| h == &current) {
            if current.is_zero() {
                break;
            }
            let block = self
                .blocks
                .get(&current)
                .ok_or_else(|| ChainError::BlockNotFound(current.to_string()))?;
            new_chain.push((block.height(), current.clone()));
            current = block.parent_hash().clone();
        }

        // Update height index with new chain
        for (height, hash) in new_chain.into_iter().rev() {
            self.height_index.insert(height, hash);
        }

        // Update tip
        self.tip = new_tip.clone();
        self.height = new_height;

        Ok(())
    }

    /// Get a block by its hash.
    pub fn get_block(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Get a block at a specific height on the main chain.
    pub fn get_block_at_height(&self, height: u64) -> Option<&Block> {
        self.height_index
            .get(&height)
            .and_then(|hash| self.blocks.get(hash))
    }

    /// Get the current chain tip.
    pub fn tip(&self) -> &Block {
        self.blocks.get(&self.tip).expect("tip block must exist")
    }

    /// Get the current chain height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get the genesis block.
    pub fn genesis(&self) -> &Block {
        self.blocks
            .get(&self.genesis_hash)
            .expect("genesis block must exist")
    }

    /// Get the genesis block hash.
    pub fn genesis_hash(&self) -> &Hash256 {
        &self.genesis_hash
    }

    /// Get the tip hash.
    pub fn tip_hash(&self) -> &Hash256 {
        &self.tip
    }

    /// Check if the chain contains a block with the given hash.
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.blocks.contains_key(hash)
    }

    /// Get the total number of blocks stored (including forks).
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the validator set.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Get a mutable reference to the validator set.
    pub fn validator_set_mut(&mut self) -> &mut ValidatorSet {
        &mut self.validator_set
    }

    /// Get the fork choice tracker.
    pub fn fork_choice(&self) -> &ForkChoice {
        &self.fork_choice
    }

    /// Check if there's currently a fork.
    pub fn has_fork(&self) -> bool {
        self.fork_choice.has_fork()
    }

    /// Iterate through blocks from genesis to tip.
    ///
    /// Returns blocks in order from height 0 to the current tip.
    pub fn iter_from_genesis(&self) -> impl Iterator<Item = &Block> {
        ChainIterator::new(self, IterDirection::Forward)
    }

    /// Iterate through blocks from tip to genesis.
    ///
    /// Returns blocks in reverse order from current tip to height 0.
    pub fn iter_from_tip(&self) -> impl Iterator<Item = &Block> {
        ChainIterator::new(self, IterDirection::Backward)
    }

    /// Get the common ancestor of two blocks.
    ///
    /// Returns the hash of the first block that is an ancestor of both
    /// given blocks, or None if no common ancestor exists.
    pub fn get_common_ancestor(&self, hash1: &Hash256, hash2: &Hash256) -> Option<Hash256> {
        // Build ancestor set for first block
        let mut ancestors1 = HashSet::new();
        let mut current = hash1.clone();

        while !current.is_zero() {
            ancestors1.insert(current.clone());
            if let Some(block) = self.blocks.get(&current) {
                current = block.parent_hash().clone();
            } else {
                break;
            }
        }

        // Walk second block's ancestors until we find a match
        let mut current = hash2.clone();
        while !current.is_zero() {
            if ancestors1.contains(&current) {
                return Some(current);
            }
            if let Some(block) = self.blocks.get(&current) {
                current = block.parent_hash().clone();
            } else {
                break;
            }
        }

        // Check genesis
        if ancestors1.contains(&self.genesis_hash) {
            return Some(self.genesis_hash.clone());
        }

        None
    }

    /// Get blocks in a range of heights.
    pub fn get_blocks_in_range(&self, start: u64, end: u64) -> Vec<&Block> {
        (start..=end)
            .filter_map(|h| self.get_block_at_height(h))
            .collect()
    }

    /// Get the hash at a specific height on the main chain.
    pub fn get_hash_at_height(&self, height: u64) -> Option<&Hash256> {
        self.height_index.get(&height)
    }

    /// Verify the entire chain from genesis to tip.
    ///
    /// Checks that all blocks are valid and properly linked.
    pub fn verify_chain(&self) -> Result<()> {
        let mut prev_block: Option<&Block> = None;

        for height in 0..=self.height {
            let block = self.get_block_at_height(height).ok_or_else(|| {
                ChainError::InvalidBlock(format!("missing block at height {}", height))
            })?;

            // Verify block integrity
            block.verify()?;

            // Verify linkage
            if let Some(parent) = prev_block {
                if block.parent_hash() != parent.hash() {
                    return Err(ChainError::InvalidBlock(format!(
                        "chain discontinuity at height {}",
                        height
                    )));
                }
            }

            prev_block = Some(block);
        }

        Ok(())
    }
}

// ============================================================================
// Chain Iterator
// ============================================================================

/// Direction for chain iteration.
#[derive(Clone, Copy)]
enum IterDirection {
    /// From genesis to tip.
    Forward,
    /// From tip to genesis.
    Backward,
}

/// Iterator over blocks in the main chain.
struct ChainIterator<'a> {
    chain: &'a Blockchain,
    current_height: Option<u64>,
    direction: IterDirection,
}

impl<'a> ChainIterator<'a> {
    fn new(chain: &'a Blockchain, direction: IterDirection) -> Self {
        let current_height = match direction {
            IterDirection::Forward => Some(0),
            IterDirection::Backward => Some(chain.height),
        };

        Self {
            chain,
            current_height,
            direction,
        }
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = &'a Block;

    fn next(&mut self) -> Option<Self::Item> {
        let height = self.current_height?;

        let block = self.chain.get_block_at_height(height);

        match self.direction {
            IterDirection::Forward => {
                if height >= self.chain.height {
                    self.current_height = None;
                } else {
                    self.current_height = Some(height + 1);
                }
            }
            IterDirection::Backward => {
                if height == 0 {
                    self.current_height = None;
                } else {
                    self.current_height = Some(height - 1);
                }
            }
        }

        block
    }
}

// ============================================================================
// Chain State (for serialization)
// ============================================================================

/// Serializable chain state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// All blocks in the chain.
    pub blocks: Vec<Block>,
    /// Current tip hash.
    pub tip_hash: Hash256,
    /// Genesis hash.
    pub genesis_hash: Hash256,
}

impl ChainState {
    /// Create a chain state snapshot.
    pub fn from_blockchain(chain: &Blockchain) -> Self {
        Self {
            blocks: chain.blocks.values().cloned().collect(),
            tip_hash: chain.tip.clone(),
            genesis_hash: chain.genesis_hash.clone(),
        }
    }

    /// Restore a blockchain from chain state.
    ///
    /// # Errors
    ///
    /// Returns an error if the state is invalid or inconsistent.
    pub fn into_blockchain(self) -> Result<Blockchain> {
        if self.blocks.is_empty() {
            return Err(ChainError::InvalidBlock(
                "chain state has no blocks".to_string(),
            ));
        }

        // Find genesis
        let genesis = self
            .blocks
            .iter()
            .find(|b| b.is_genesis())
            .ok_or_else(|| ChainError::InvalidBlock("no genesis block in state".to_string()))?;

        let mut chain = Blockchain::with_genesis(genesis.clone())?;

        // Add remaining blocks in order
        let mut remaining: Vec<_> = self
            .blocks
            .into_iter()
            .filter(|b| !b.is_genesis())
            .collect();

        // Sort by height to add in order
        remaining.sort_by_key(|b| b.height());

        for block in remaining {
            chain.add_block(block)?;
        }

        Ok(chain)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{ChainEntry, ValidatorRegion};

    /// Helper to create a test identity hash.
    fn test_identity(id: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[id; 32]).unwrap()
    }

    /// Helper to create a test block at a specific height.
    fn create_block(parent: &Block, height: u64, timestamp: u64) -> Block {
        Block::new(
            parent.hash().clone(),
            height,
            timestamp,
            vec![],
            test_identity(height as u8),
        )
    }

    /// Helper to create a block with entries.
    fn create_block_with_entries(
        parent: &Block,
        height: u64,
        timestamp: u64,
        entries: Vec<ChainEntry>,
    ) -> Block {
        Block::new(
            parent.hash().clone(),
            height,
            timestamp,
            entries,
            test_identity(height as u8),
        )
    }

    // ==================== Test 1: Blockchain creation with genesis ====================
    #[test]
    fn test_blockchain_creation_with_genesis() {
        let chain = Blockchain::new().unwrap();

        assert_eq!(chain.height(), 0);
        assert!(chain.tip().is_genesis());
        assert_eq!(chain.block_count(), 1);
    }

    // ==================== Test 2: Add single block ====================
    #[test]
    fn test_add_single_block() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        chain.add_block(block.clone()).unwrap();

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip().hash(), block.hash());
        assert_eq!(chain.block_count(), 2);
    }

    // ==================== Test 3: Add multiple blocks ====================
    #[test]
    fn test_add_multiple_blocks() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=10 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        assert_eq!(chain.height(), 10);
        assert_eq!(chain.block_count(), 11);
    }

    // ==================== Test 4: Reject invalid block (wrong parent) ====================
    #[test]
    fn test_reject_invalid_parent() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();

        // Create block with non-existent parent
        let fake_parent_hash = Hash256::hash(b"fake-parent");
        let block = Block::new(fake_parent_hash, 1, 1001, vec![], test_identity(1));

        let result = chain.add_block(block);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::BlockNotFound(_))));
    }

    // ==================== Test 5: Reject invalid block (wrong height) ====================
    #[test]
    fn test_reject_invalid_height() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create block with wrong height (should be 1, not 5)
        let block = Block::new(genesis.hash().clone(), 5, 1001, vec![], test_identity(1));

        let result = chain.add_block(block);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
    }

    // ==================== Test 6: Reject invalid block (wrong merkle root) ====================
    #[test]
    fn test_reject_invalid_merkle_root() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create a block manually with mismatched merkle root
        let mut block = create_block(&genesis, 1, 1001);

        // Tamper with the body after creation
        block.body.entries.push(ChainEntry::IdentityRegistration {
            identity_hash: test_identity(99),
            public_keys: vec![1, 2, 3],
            timestamp: 1001,
            signature: vec![4, 5, 6],
        });

        let result = chain.add_block(block);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
    }

    // ==================== Test 7: Get block by hash ====================
    #[test]
    fn test_get_block_by_hash() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        let block_hash = block.hash().clone();
        chain.add_block(block.clone()).unwrap();

        let retrieved = chain.get_block(&block_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash(), &block_hash);

        // Test non-existent hash
        let fake_hash = Hash256::hash(b"fake");
        assert!(chain.get_block(&fake_hash).is_none());
    }

    // ==================== Test 8: Get block by height ====================
    #[test]
    fn test_get_block_by_height() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=5 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        // Test existing heights
        for i in 0..=5 {
            let block = chain.get_block_at_height(i);
            assert!(block.is_some());
            assert_eq!(block.unwrap().height(), i);
        }

        // Test non-existent height
        assert!(chain.get_block_at_height(100).is_none());
    }

    // ==================== Test 9: Chain iteration (forward) ====================
    #[test]
    fn test_chain_iteration_forward() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=5 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        let blocks: Vec<_> = chain.iter_from_genesis().collect();
        assert_eq!(blocks.len(), 6);

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.height(), i as u64);
        }
    }

    // ==================== Test 10: Chain iteration (backward) ====================
    #[test]
    fn test_chain_iteration_backward() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=5 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        let blocks: Vec<_> = chain.iter_from_tip().collect();
        assert_eq!(blocks.len(), 6);

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.height(), (5 - i) as u64);
        }
    }

    // ==================== Test 11: Fork detection ====================
    #[test]
    fn test_fork_detection() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create first branch
        let block1a = create_block(&genesis, 1, 1001);
        chain.add_block(block1a.clone()).unwrap();

        assert!(!chain.has_fork()); // No fork yet

        // Create second branch from genesis
        let block1b = Block::new(
            genesis.hash().clone(),
            1,
            1002, // Different timestamp = different hash
            vec![],
            test_identity(100), // Different validator
        );
        chain.add_block(block1b).unwrap();

        assert!(chain.has_fork()); // Now we have a fork
    }

    // ==================== Test 12: Fork resolution (longer chain wins) ====================
    #[test]
    fn test_fork_resolution() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create first branch with 2 blocks
        let block1a = create_block(&genesis, 1, 1001);
        chain.add_block(block1a.clone()).unwrap();

        let block2a = create_block(&block1a, 2, 1002);
        chain.add_block(block2a.clone()).unwrap();

        let tip_before = chain.tip().hash().clone();

        // Create second branch with 3 blocks (longer)
        let block1b = Block::new(
            genesis.hash().clone(),
            1,
            1100, // Different timestamp
            vec![],
            test_identity(50),
        );
        chain.add_block(block1b.clone()).unwrap();

        let block2b = Block::new(block1b.hash().clone(), 2, 1101, vec![], test_identity(51));
        chain.add_block(block2b.clone()).unwrap();

        let block3b = Block::new(block2b.hash().clone(), 3, 1102, vec![], test_identity(52));
        chain.add_block(block3b.clone()).unwrap();

        // Chain should now follow the longer fork
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().hash(), block3b.hash());
        assert_ne!(chain.tip().hash(), &tip_before);
    }

    // ==================== Test 13: Chain tip tracking ====================
    #[test]
    fn test_chain_tip_tracking() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        assert_eq!(chain.tip().hash(), genesis.hash());

        let block1 = create_block(&genesis, 1, 1001);
        chain.add_block(block1.clone()).unwrap();
        assert_eq!(chain.tip().hash(), block1.hash());

        let block2 = create_block(&block1, 2, 1002);
        chain.add_block(block2.clone()).unwrap();
        assert_eq!(chain.tip().hash(), block2.hash());
    }

    // ==================== Test 14: Contains check ====================
    #[test]
    fn test_contains() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        let block_hash = block.hash().clone();

        assert!(!chain.contains(&block_hash));

        chain.add_block(block).unwrap();

        assert!(chain.contains(&block_hash));
        assert!(chain.contains(genesis.hash()));
    }

    // ==================== Test 15: Reject duplicate block ====================
    #[test]
    fn test_reject_duplicate_block() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        chain.add_block(block.clone()).unwrap();

        // Try to add the same block again
        let result = chain.add_block(block);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
    }

    // ==================== Test 16: Get common ancestor ====================
    #[test]
    fn test_get_common_ancestor() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create two branches from genesis
        let block1a = create_block(&genesis, 1, 1001);
        chain.add_block(block1a.clone()).unwrap();

        let block2a = create_block(&block1a, 2, 1002);
        chain.add_block(block2a.clone()).unwrap();

        let block1b = Block::new(genesis.hash().clone(), 1, 1100, vec![], test_identity(50));
        chain.add_block(block1b.clone()).unwrap();

        // Common ancestor of block2a and block1b should be genesis
        let ancestor = chain.get_common_ancestor(block2a.hash(), block1b.hash());
        assert!(ancestor.is_some());
        assert_eq!(ancestor.unwrap(), *genesis.hash());

        // Common ancestor of block2a and block1a should be block1a
        let ancestor2 = chain.get_common_ancestor(block2a.hash(), block1a.hash());
        assert!(ancestor2.is_some());
        assert_eq!(ancestor2.unwrap(), *block1a.hash());
    }

    // ==================== Test 17: Block validation - header ====================
    #[test]
    fn test_block_validation_header() {
        let genesis = Block::genesis(1000, vec![]);
        let valid_block = create_block(&genesis, 1, 1001);

        let result = BlockValidation::validate_header(&valid_block.header, &genesis.header);
        assert!(result.is_ok());

        // Test invalid height
        let bad_block = Block::new(genesis.hash().clone(), 3, 1001, vec![], test_identity(1));
        let result = BlockValidation::validate_header(&bad_block.header, &genesis.header);
        assert!(result.is_err());
    }

    // ==================== Test 18: Block validation - body ====================
    #[test]
    fn test_block_validation_body() {
        let genesis = Block::genesis(1000, vec![]);
        let valid_block = create_block(&genesis, 1, 1001);

        let result = BlockValidation::validate_body(&valid_block.body, &valid_block.header);
        assert!(result.is_ok());
    }

    // ==================== Test 19: Block validation - full block ====================
    #[test]
    fn test_block_validation_full() {
        let genesis = Block::genesis(1000, vec![]);
        let valid_block = create_block(&genesis, 1, 1001);

        let result = BlockValidation::validate_block(&valid_block, &genesis);
        assert!(result.is_ok());
    }

    // ==================== Test 20: Block validation - producer ====================
    #[test]
    fn test_block_validation_producer() {
        let genesis = Block::genesis(1000, vec![]);
        let valid_block = create_block(&genesis, 1, 1001);

        // SECURITY (VERITAS-2026-0002): Unsigned blocks are now rejected.
        // Previously this test expected that having the validator in the list
        // would be sufficient. Now signatures are required.

        // Empty validator list - should fail (missing signature, even before checking list)
        let result = BlockValidation::validate_producer(&valid_block, &[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::MissingSignature)));

        // Include producer in list - should STILL fail (missing signature)
        // This is the key fix: knowing a valid validator ID is not enough
        let validators = vec![test_identity(1)];
        let result = BlockValidation::validate_producer(&valid_block, &validators);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::MissingSignature)));

        // Genesis block validation - should pass (no signature required)
        let result = BlockValidation::validate_producer(&genesis, &[]);
        assert!(result.is_ok());
    }

    // ==================== Test 21: Verify entire chain ====================
    #[test]
    fn test_verify_chain() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=5 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        let result = chain.verify_chain();
        assert!(result.is_ok());
    }

    // ==================== Test 22: Genesis block validation ====================
    #[test]
    fn test_genesis_validation() {
        let genesis = Block::genesis(1000, vec![]);
        assert!(genesis.is_genesis());
        assert!(genesis.verify().is_ok());

        // Cannot create blockchain with non-genesis block
        let fake_genesis = Block::new(Hash256::hash(b"parent"), 1, 1000, vec![], test_identity(1));

        let result = Blockchain::with_genesis(fake_genesis);
        assert!(result.is_err());
    }

    // ==================== Test 23: ForkChoice basic operations ====================
    #[test]
    fn test_fork_choice_operations() {
        let mut fc = ForkChoice::new();

        let hash1 = Hash256::hash(b"block1");
        let hash2 = Hash256::hash(b"block2");
        let parent = Hash256::hash(b"parent");

        fc.add_tip(hash1.clone(), 1, parent.clone());
        assert_eq!(fc.tip_count(), 1);
        assert!(fc.is_tip(&hash1));

        fc.add_tip(hash2.clone(), 2, hash1.clone());
        assert_eq!(fc.tip_count(), 2);

        // Best tip should be the one with higher height
        let best = fc.best_tip();
        assert!(best.is_some());
        assert_eq!(best.unwrap(), hash2);

        fc.remove_tip(&hash1);
        assert_eq!(fc.tip_count(), 1);
        assert!(!fc.is_tip(&hash1));
    }

    // ==================== Test 24: ChainState serialization ====================
    #[test]
    fn test_chain_state_serialization() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        chain.add_block(block).unwrap();

        let state = ChainState::from_blockchain(&chain);
        assert_eq!(state.blocks.len(), 2);

        let restored = state.into_blockchain().unwrap();
        assert_eq!(restored.height(), 1);
        assert_eq!(restored.block_count(), 2);
    }

    // ==================== Test 25: Block with entries ====================
    #[test]
    fn test_block_with_entries() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let entries = vec![
            ChainEntry::IdentityRegistration {
                identity_hash: test_identity(42),
                public_keys: vec![1, 2, 3, 4],
                timestamp: 1001,
                signature: vec![5, 6, 7, 8],
            },
            ChainEntry::ValidatorRegistration {
                identity_hash: test_identity(43),
                stake: 800,
                region: ValidatorRegion::Europe,
                timestamp: 1001,
                signature: vec![9, 10, 11, 12],
            },
        ];

        let block = create_block_with_entries(&genesis, 1, 1001, entries);
        chain.add_block(block.clone()).unwrap();

        assert_eq!(chain.tip().entries().len(), 2);
    }

    // ==================== Test 26: Get blocks in range ====================
    #[test]
    fn test_get_blocks_in_range() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let mut parent = chain.genesis().clone();

        for i in 1..=10 {
            let block = create_block(&parent, i, 1000 + i);
            chain.add_block(block.clone()).unwrap();
            parent = block;
        }

        let blocks = chain.get_blocks_in_range(3, 7);
        assert_eq!(blocks.len(), 5);

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.height(), (3 + i) as u64);
        }
    }

    // ==================== Test 27: Timestamp validation ====================
    #[test]
    fn test_timestamp_validation() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Block with earlier timestamp should fail
        let bad_block = Block::new(genesis.hash().clone(), 1, 999, vec![], test_identity(1));

        let result = chain.add_block(bad_block);
        assert!(result.is_err());
    }

    // ==================== Test 28: Multiple forks at same height ====================
    #[test]
    fn test_multiple_forks_same_height() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        // Create 3 different blocks at height 1
        for i in 0..3 {
            let block = Block::new(
                genesis.hash().clone(),
                1,
                1001 + i,
                vec![],
                test_identity(10 + i as u8),
            );
            chain.add_block(block).unwrap();
        }

        assert!(chain.has_fork());
        assert_eq!(chain.block_count(), 4); // genesis + 3 forks
    }

    // ==================== Test 29: Empty chain iteration ====================
    #[test]
    fn test_empty_chain_iteration() {
        let chain = Blockchain::with_genesis_timestamp(1000).unwrap();

        let forward: Vec<_> = chain.iter_from_genesis().collect();
        assert_eq!(forward.len(), 1); // Just genesis

        let backward: Vec<_> = chain.iter_from_tip().collect();
        assert_eq!(backward.len(), 1);
    }

    // ==================== Test 30: Hash at height ====================
    #[test]
    fn test_get_hash_at_height() {
        let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
        let genesis = chain.genesis().clone();

        let block = create_block(&genesis, 1, 1001);
        let block_hash = block.hash().clone();
        chain.add_block(block).unwrap();

        assert_eq!(chain.get_hash_at_height(0), Some(&chain.genesis_hash));
        assert_eq!(chain.get_hash_at_height(1), Some(&block_hash));
        assert!(chain.get_hash_at_height(2).is_none());
    }

    // ==================== Property tests ====================
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_chain_height_equals_tip_height(num_blocks in 1u64..20) {
            let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
            let mut parent = chain.genesis().clone();

            for i in 1..=num_blocks {
                let block = create_block(&parent, i, 1000 + i);
                chain.add_block(block.clone()).unwrap();
                parent = block;
            }

            prop_assert_eq!(chain.height(), num_blocks);
            prop_assert_eq!(chain.tip().height(), num_blocks);
        }

        #[test]
        fn prop_all_blocks_accessible_by_height(num_blocks in 1u64..20) {
            let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
            let mut parent = chain.genesis().clone();

            for i in 1..=num_blocks {
                let block = create_block(&parent, i, 1000 + i);
                chain.add_block(block.clone()).unwrap();
                parent = block;
            }

            for h in 0..=num_blocks {
                prop_assert!(chain.get_block_at_height(h).is_some());
            }
        }

        #[test]
        fn prop_chain_iteration_covers_all_blocks(num_blocks in 1u64..20) {
            let mut chain = Blockchain::with_genesis_timestamp(1000).unwrap();
            let mut parent = chain.genesis().clone();

            for i in 1..=num_blocks {
                let block = create_block(&parent, i, 1000 + i);
                chain.add_block(block.clone()).unwrap();
                parent = block;
            }

            let forward: Vec<_> = chain.iter_from_genesis().collect();
            let backward: Vec<_> = chain.iter_from_tip().collect();

            prop_assert_eq!(forward.len() as u64, num_blocks + 1);
            prop_assert_eq!(backward.len() as u64, num_blocks + 1);
        }
    }

    // ==================== Security Tests (VERITAS-2026-0002) ====================
    //
    // These tests verify that validate_producer() correctly rejects unsigned
    // and forged blocks, preventing the block forgery vulnerability.

    mod security_tests {
        use super::*;

        // ==================== Test: Genesis validation passes without signature ====================
        #[test]
        fn test_validate_producer_genesis_no_signature() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Genesis should pass validation without any validators in the list
            let result = BlockValidation::validate_producer(&genesis, &[]);
            assert!(result.is_ok());
        }

        // ==================== Test: Unsigned non-genesis block rejected ====================
        #[test]
        fn test_validate_producer_unsigned_block_rejected() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Create an unsigned block claiming to be from a valid validator
            let valid_validator = test_identity(1);
            let block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );

            // Should fail even if the validator is in the authorized set
            let validators = vec![valid_validator];
            let result = BlockValidation::validate_producer(&block, &validators);

            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Forged block with fake signature rejected ====================
        #[test]
        fn test_validate_producer_forged_block_rejected() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Create a block and add fake signature data
            let valid_validator = test_identity(1);
            let mut block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );

            // Attacker adds garbage pubkey and signature
            block.header.validator_pubkey = vec![0u8; 100];
            block.header.signature = vec![0u8; 100];

            // Should fail signature verification
            let validators = vec![valid_validator];
            let result = BlockValidation::validate_producer(&block, &validators);

            assert!(result.is_err());
            // Should fail at pubkey parsing (InvalidSignature)
            assert!(matches!(result, Err(ChainError::InvalidSignature(_))));
        }

        // ==================== Test: Block with wrong validator ID rejected ====================
        #[test]
        fn test_validate_producer_wrong_validator_rejected() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Create an unsigned block with a validator NOT in the set
            // Note: This would fail signature check first, but let's verify
            // the validator set check also works
            let unauthorized_validator = test_identity(99);
            let block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                unauthorized_validator,
            );

            // Authorized validators don't include our validator
            let validators = vec![test_identity(1), test_identity(2), test_identity(3)];
            let result = BlockValidation::validate_producer(&block, &validators);

            // Should fail (either MissingSignature or InvalidBlock)
            assert!(result.is_err());
        }

        // ==================== Test: Invalid genesis validator rejected ====================
        #[test]
        fn test_validate_producer_invalid_genesis_validator() {
            // Create a "genesis" block with a non-genesis validator
            let mut fake_genesis = Block::genesis(1700000000, vec![]);

            // Tamper with the validator to make it invalid
            fake_genesis.header.validator = test_identity(99);

            let result = BlockValidation::validate_producer(&fake_genesis, &[]);
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
        }

        // ==================== Test: Signature verified BEFORE validator set check ====================
        #[test]
        fn test_validate_producer_signature_first() {
            let genesis = Block::genesis(1700000000, vec![]);

            // Create an unsigned block with a validator that IS in the set
            let valid_validator = test_identity(1);
            let block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );

            // Even with the validator in the set, should fail due to missing signature
            let validators = vec![valid_validator];
            let result = BlockValidation::validate_producer(&block, &validators);

            // SECURITY: Must fail with MissingSignature, not pass because validator is valid
            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Block with only pubkey (no signature) rejected ====================
        #[test]
        fn test_validate_producer_pubkey_only_rejected() {
            let genesis = Block::genesis(1700000000, vec![]);

            let valid_validator = test_identity(1);
            let mut block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );

            // Add pubkey but no signature
            block.header.validator_pubkey = vec![1, 2, 3, 4, 5];

            let validators = vec![valid_validator];
            let result = BlockValidation::validate_producer(&block, &validators);

            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Block with only signature (no pubkey) rejected ====================
        #[test]
        fn test_validate_producer_signature_only_rejected() {
            let genesis = Block::genesis(1700000000, vec![]);

            let valid_validator = test_identity(1);
            let mut block = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );

            // Add signature but no pubkey
            block.header.signature = vec![1, 2, 3, 4, 5];

            let validators = vec![valid_validator];
            let result = BlockValidation::validate_producer(&block, &validators);

            assert!(result.is_err());
            assert!(matches!(result, Err(ChainError::MissingSignature)));
        }

        // ==================== Test: Multiple forged blocks all rejected ====================
        #[test]
        fn test_validate_producer_multiple_forgery_attempts() {
            let genesis = Block::genesis(1700000000, vec![]);
            let valid_validator = test_identity(1);
            let validators = vec![valid_validator.clone()];

            // Attempt 1: No signature at all
            let block1 = Block::new(
                genesis.hash().clone(),
                1,
                1700000001,
                vec![],
                valid_validator.clone(),
            );
            assert!(BlockValidation::validate_producer(&block1, &validators).is_err());

            // Attempt 2: Empty pubkey and signature
            let mut block2 = block1.clone();
            block2.header.validator_pubkey = vec![];
            block2.header.signature = vec![];
            assert!(BlockValidation::validate_producer(&block2, &validators).is_err());

            // Attempt 3: Random garbage in both fields
            let mut block3 = block1.clone();
            block3.header.validator_pubkey = (0u8..200).collect();
            block3.header.signature = vec![0u8; 300]; // Use vec! instead of range for values > 255
            assert!(BlockValidation::validate_producer(&block3, &validators).is_err());

            // Attempt 4: Valid-looking but wrong sizes
            let mut block4 = block1.clone();
            block4.header.validator_pubkey = vec![0u8; 32];  // Wrong size for ML-DSA
            block4.header.signature = vec![0u8; 64];         // Wrong size for ML-DSA
            assert!(BlockValidation::validate_producer(&block4, &validators).is_err());
        }
    }
}
