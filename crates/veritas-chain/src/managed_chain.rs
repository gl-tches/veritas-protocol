//! Memory-managed blockchain with tiered storage.
//!
//! [`ManagedBlockchain`] replaces the unbounded in-memory chain with a
//! hot cache (LRU) + persistent storage backend architecture. This enables
//! nodes to operate within bounded memory limits regardless of chain height.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │          ManagedBlockchain               │
//! ├─────────────────────┬───────────────────┤
//! │    Hot Cache (LRU)  │  Username Index   │
//! │    MemoryBudget     │  (in-memory map)  │
//! │    - Tip: PINNED    │                   │
//! │    - Genesis: PINNED│                   │
//! ├─────────────────────┴───────────────────┤
//! │         Height Index (BTreeMap)          │
//! │    40 bytes/block — always in memory     │
//! ├─────────────────────────────────────────┤
//! │         Storage Backend                  │
//! │    InMemoryBackend / SledBackend         │
//! │    Compressed if config.compression      │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Block Access Pattern
//!
//! 1. Check hot cache (O(1) LRU lookup)
//! 2. On miss: load from storage backend (disk I/O)
//! 3. Insert loaded block into hot cache (may evict LRU block)
//! 4. Tip and genesis blocks are PINNED (never evicted)
//!
//! ## Memory Guarantees
//!
//! Hot cache respects `BlockchainConfig::memory_budget_mb`. The height index
//! is small (40 bytes/block) and always in memory. Total memory usage is
//! bounded to approximately: memory_budget + (40 * chain_height) + overhead.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::block::Block;
use crate::chain::{BlockValidation, ForkChoice};
use crate::config::BlockchainConfig;
use crate::memory::MemoryBudget;
use crate::pruner::{ChainPruner, PruningStats};
use crate::storage::StorageBackend;
use crate::validator::ValidatorSet;
use crate::{ChainError, Result};

/// Statistics from an index rebuild operation.
#[derive(Debug, Clone, Default)]
pub struct IndexRebuildStats {
    /// Blocks scanned during rebuild.
    pub blocks_scanned: usize,

    /// Height index entries rebuilt.
    pub height_entries: usize,

    /// Username registrations found.
    pub usernames_found: usize,

    /// Chain tip height after rebuild.
    pub tip_height: u64,

    /// Duration of rebuild in milliseconds.
    pub duration_ms: u64,
}

/// Memory usage metrics for the managed blockchain.
#[derive(Debug, Clone, Default)]
pub struct ManagedMemoryMetrics {
    /// Hot cache current bytes.
    pub cache_bytes: usize,

    /// Hot cache capacity (from config).
    pub cache_capacity: usize,

    /// Hot cache block count.
    pub cache_block_count: usize,

    /// Height index entry count.
    pub height_index_entries: usize,

    /// Height index approximate bytes (40 * entries).
    pub height_index_bytes: usize,

    /// Username index entry count.
    pub username_index_entries: usize,

    /// Backend total blocks.
    pub backend_block_count: usize,

    /// Backend total bytes.
    pub backend_total_bytes: usize,

    /// Hot cache hit ratio.
    pub cache_hit_ratio: f64,

    /// Number of pinned blocks.
    pub pinned_blocks: usize,
}

/// Memory-managed blockchain with tiered storage.
///
/// Provides bounded memory usage through a hot cache (LRU) backed by
/// persistent storage. Essential blocks (genesis, tip) are pinned and
/// never evicted.
///
/// ## Thread Safety
///
/// `ManagedBlockchain` is NOT thread-safe. For concurrent access, wrap it
/// in appropriate synchronization primitives.
pub struct ManagedBlockchain {
    /// Hot cache for recent blocks (bounded LRU).
    hot_cache: MemoryBudget,

    /// Persistent storage backend.
    backend: Box<dyn StorageBackend>,

    /// Height → hash index (always in memory: ~40 bytes/block).
    height_index: BTreeMap<u64, Hash256>,

    /// Current chain tip hash.
    tip: Hash256,

    /// Current chain height.
    height: u64,

    /// Genesis block hash (always pinned in hot cache).
    genesis_hash: Hash256,

    /// Validator set for block validation.
    validator_set: ValidatorSet,

    /// Fork choice tracker.
    fork_choice: ForkChoice,

    /// Username index (in-memory HashMap for fast lookups).
    username_index: HashMap<String, IdentityHash>,

    /// Chain pruner for storage management.
    pruner: ChainPruner,

    /// Configuration.
    config: BlockchainConfig,
}

impl std::fmt::Debug for ManagedBlockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBlockchain")
            .field("height", &self.height)
            .field("tip", &hex::encode(&self.tip.as_bytes()[..8]))
            .field("cache_blocks", &self.hot_cache.len())
            .field("height_index_entries", &self.height_index.len())
            .field("username_count", &self.username_index.len())
            .finish()
    }
}

impl ManagedBlockchain {
    /// Create a new managed blockchain with a genesis block.
    ///
    /// # Arguments
    ///
    /// * `config` - Blockchain configuration
    /// * `backend` - Storage backend for persistent block storage
    /// * `genesis` - The genesis block
    ///
    /// # Errors
    ///
    /// Returns an error if the genesis block is invalid or storage fails.
    pub async fn with_genesis(
        config: BlockchainConfig,
        backend: Box<dyn StorageBackend>,
        genesis: Block,
    ) -> Result<Self> {
        config.validate().map_err(ChainError::InvalidBlock)?;

        // Verify genesis block
        if !genesis.is_genesis() {
            return Err(ChainError::InvalidBlock(
                "Block is not a genesis block".to_string(),
            ));
        }
        genesis.verify()?;

        let genesis_hash = genesis.hash().clone();
        let mut hot_cache = MemoryBudget::new(config.memory_budget_bytes());

        // Store genesis in backend
        backend.store_block(&genesis).await?;

        // Insert genesis into hot cache and pin it
        hot_cache.pin(&genesis_hash);
        hot_cache.try_insert(genesis_hash.clone(), Arc::new(genesis))?;

        // Initialize height index
        let mut height_index = BTreeMap::new();
        height_index.insert(0, genesis_hash.clone());

        // Initialize fork choice
        let mut fork_choice = ForkChoice::new();
        fork_choice.add_tip(genesis_hash.clone(), 0, Hash256::default());

        Ok(Self {
            hot_cache,
            backend,
            height_index,
            tip: genesis_hash.clone(),
            height: 0,
            genesis_hash,
            validator_set: ValidatorSet::new(),
            fork_choice,
            username_index: HashMap::new(),
            pruner: ChainPruner::new(config.pruning_mode.clone()),
            config,
        })
    }

    /// Open an existing chain from storage backend.
    ///
    /// Rebuilds the height_index and username_index from stored blocks.
    ///
    /// # Arguments
    ///
    /// * `config` - Blockchain configuration
    /// * `backend` - Storage backend containing existing blocks
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is empty or corrupted.
    pub async fn open(
        config: BlockchainConfig,
        backend: Box<dyn StorageBackend>,
    ) -> Result<Self> {
        config.validate().map_err(ChainError::InvalidBlock)?;

        if backend.count_blocks() == 0 {
            return Err(ChainError::Storage(
                "Cannot open empty backend - use with_genesis instead".to_string(),
            ));
        }

        let mut chain = Self {
            hot_cache: MemoryBudget::new(config.memory_budget_bytes()),
            backend,
            height_index: BTreeMap::new(),
            tip: Hash256::default(),
            height: 0,
            genesis_hash: Hash256::default(),
            validator_set: ValidatorSet::new(),
            fork_choice: ForkChoice::new(),
            username_index: HashMap::new(),
            pruner: ChainPruner::new(config.pruning_mode.clone()),
            config,
        };

        // Rebuild indexes from storage
        chain.rebuild_indexes().await?;

        Ok(chain)
    }

    /// Add a validated block to the chain.
    ///
    /// 1. Validates block (signature, height, parent hash, entries)
    /// 2. Stores in backend (compressed if configured)
    /// 3. Inserts into hot cache
    /// 4. Updates height_index, username_index
    /// 5. Updates tip
    ///
    /// Hot cache may evict old blocks to stay within memory budget.
    /// Tip and genesis are never evicted.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to add
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or storage fails.
    pub async fn add_block(&mut self, block: Block) -> Result<()> {
        // Validate height
        let expected_height = self.height + 1;
        if block.height() != expected_height {
            return Err(ChainError::InvalidBlock(format!(
                "Invalid height: expected {}, got {}",
                expected_height,
                block.height()
            )));
        }

        // Validate parent hash
        if block.parent_hash() != &self.tip {
            return Err(ChainError::InvalidBlock(format!(
                "Invalid parent hash: expected {}, got {}",
                hex::encode(&self.tip.as_bytes()[..8]),
                hex::encode(&block.parent_hash().as_bytes()[..8])
            )));
        }

        // Verify block (signature, entries, etc.)
        block.verify()?;

        // For non-genesis blocks, verify against validator set
        if !block.is_genesis() {
            // Validate the producer is in the validator set
            // (In a full implementation, this would check against active validators)
            BlockValidation::validate_merkle_root(&block)?;
        }

        // Process chain entries (username registrations, etc.)
        self.process_block_entries(&block)?;

        let hash = block.hash().clone();
        let height = block.height();

        // Store in backend
        self.backend.store_block(&block).await?;

        // Update height index
        self.height_index.insert(height, hash.clone());

        // Update fork choice - remove old tip, add new tip
        self.fork_choice.remove_tip(&self.tip);
        self.fork_choice.add_tip(hash.clone(), height, self.tip.clone());

        // Update tip (unpin old tip if not genesis, pin new tip)
        // Genesis must never be unpinned - it's always needed for chain validation
        if self.tip != self.genesis_hash {
            self.hot_cache.unpin(&self.tip);
        }
        self.hot_cache.pin(&hash);

        // Insert into hot cache (may evict unpinned blocks)
        self.hot_cache.try_insert(hash.clone(), Arc::new(block))?;

        // Update chain state
        self.tip = hash;
        self.height = height;

        Ok(())
    }

    /// Get a block by hash.
    ///
    /// Checks hot cache first, falls back to backend on miss.
    /// Cache misses trigger insertion into hot cache.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash of the block to retrieve
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    pub async fn get_block(&mut self, hash: &Hash256) -> Result<Option<Arc<Block>>> {
        // Check hot cache first
        if let Some(block) = self.hot_cache.get(hash) {
            return Ok(Some(block));
        }

        // Cache miss - load from backend
        if let Some(block) = self.backend.load_block(hash).await? {
            let arc_block = Arc::new(block);

            // Insert into hot cache (may evict old blocks, but not pinned ones)
            // Ignore errors here - if cache is full with pinned blocks, that's OK
            let _ = self.hot_cache.try_insert(hash.clone(), Arc::clone(&arc_block));

            return Ok(Some(arc_block));
        }

        Ok(None)
    }

    /// Get block at a given height.
    ///
    /// # Arguments
    ///
    /// * `height` - The height to retrieve
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    pub async fn get_block_at_height(&mut self, height: u64) -> Result<Option<Arc<Block>>> {
        if let Some(hash) = self.height_index.get(&height).cloned() {
            self.get_block(&hash).await
        } else {
            Ok(None)
        }
    }

    /// Get the current tip block.
    ///
    /// This is always a cache hit since tip is pinned.
    pub fn tip_block(&self) -> Option<Arc<Block>> {
        self.hot_cache.peek(&self.tip)
    }

    /// Get current chain tip hash.
    pub fn tip_hash(&self) -> &Hash256 {
        &self.tip
    }

    /// Get current chain height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get genesis block hash.
    pub fn genesis_hash(&self) -> &Hash256 {
        &self.genesis_hash
    }

    /// Get the genesis block.
    ///
    /// This is always a cache hit since genesis is pinned.
    pub fn genesis_block(&self) -> Option<Arc<Block>> {
        self.hot_cache.peek(&self.genesis_hash)
    }

    /// Check if a block exists (in cache or backend).
    pub async fn contains(&self, hash: &Hash256) -> Result<bool> {
        if self.hot_cache.contains(hash) {
            return Ok(true);
        }
        self.backend.block_exists(hash).await
    }

    /// Get the number of blocks in the chain.
    pub fn block_count(&self) -> usize {
        self.height_index.len()
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

    /// Check if there are forks in the chain.
    pub fn has_fork(&self) -> bool {
        self.fork_choice.has_fork()
    }

    // ========= Username Operations =========

    /// Look up identity by username.
    pub fn lookup_username(&self, username: &str) -> Option<&IdentityHash> {
        let normalized = username.to_ascii_lowercase();
        self.username_index.get(&normalized)
    }

    /// Check if username is available.
    pub fn is_username_available(&self, username: &str) -> bool {
        let normalized = username.to_ascii_lowercase();
        !self.username_index.contains_key(&normalized)
    }

    /// Count registered usernames.
    pub fn username_count(&self) -> usize {
        self.username_index.len()
    }

    // ========= Maintenance =========

    /// Run a pruning cycle based on config.pruning_mode.
    ///
    /// # Returns
    ///
    /// Statistics about what was pruned.
    pub async fn prune(&mut self) -> Result<PruningStats> {
        let height_index = &self.height_index;
        let get_height = |hash: &Hash256| -> Option<u64> {
            height_index
                .iter()
                .find(|(_, h)| *h == hash)
                .map(|(height, _)| *height)
        };

        self.pruner.prune(&*self.backend, self.height, get_height).await
    }

    /// Get memory usage metrics.
    pub fn memory_metrics(&self) -> ManagedMemoryMetrics {
        let cache_metrics = self.hot_cache.snapshot_metrics();

        ManagedMemoryMetrics {
            cache_bytes: cache_metrics.current_bytes,
            cache_capacity: cache_metrics.max_bytes,
            cache_block_count: cache_metrics.cached_blocks,
            height_index_entries: self.height_index.len(),
            height_index_bytes: self.height_index.len() * 40, // ~40 bytes per entry
            username_index_entries: self.username_index.len(),
            backend_block_count: self.backend.count_blocks(),
            backend_total_bytes: self.backend.total_size_bytes(),
            cache_hit_ratio: cache_metrics.hit_ratio(),
            pinned_blocks: self.hot_cache.pinned_count(),
        }
    }

    /// Rebuild all indexes from storage.
    ///
    /// This is called during `open()` and can be called manually for recovery.
    pub async fn rebuild_indexes(&mut self) -> Result<IndexRebuildStats> {
        let start = std::time::Instant::now();
        let mut stats = IndexRebuildStats::default();

        // Clear existing indexes
        self.height_index.clear();
        self.username_index.clear();

        // Get all block hashes
        let hashes = self.backend.list_block_hashes().await?;
        stats.blocks_scanned = hashes.len();

        // Load each block and rebuild indexes
        // We need to process in height order, so first collect all blocks
        let mut blocks_by_height: BTreeMap<u64, (Hash256, Block)> = BTreeMap::new();

        for hash in hashes {
            if let Some(block) = self.backend.load_block(&hash).await? {
                blocks_by_height.insert(block.height(), (hash, block));
            }
        }

        // Process in height order
        for (height, (hash, block)) in &blocks_by_height {
            // Add to height index
            self.height_index.insert(*height, hash.clone());
            stats.height_entries += 1;

            // Process username registrations
            for entry in block.entries() {
                if let crate::block::ChainEntry::UsernameRegistration {
                    identity_hash,
                    username,
                    ..
                } = entry
                {
                    let normalized = username.to_ascii_lowercase();
                    // Only insert if not already present (first registration wins)
                    if let std::collections::hash_map::Entry::Vacant(e) = self.username_index.entry(normalized) {
                        e.insert(identity_hash.clone());
                        stats.usernames_found += 1;
                    }
                }
            }
        }

        // Find genesis and tip
        if let Some((&genesis_height, genesis_hash)) = self.height_index.first_key_value() {
            if genesis_height != 0 {
                return Err(ChainError::InvalidBlock(
                    "Missing genesis block (height 0)".to_string(),
                ));
            }
            self.genesis_hash = genesis_hash.clone();

            // Load and pin genesis
            if let Some(genesis) = self.backend.load_block(genesis_hash).await? {
                self.hot_cache.pin(genesis_hash);
                let _ = self.hot_cache.try_insert(genesis_hash.clone(), Arc::new(genesis));
            }
        } else {
            return Err(ChainError::Storage("No blocks found in backend".to_string()));
        }

        if let Some((&tip_height, tip_hash)) = self.height_index.last_key_value() {
            self.tip = tip_hash.clone();
            self.height = tip_height;
            stats.tip_height = tip_height;

            // Load and pin tip
            if let Some(tip_block) = self.backend.load_block(tip_hash).await? {
                self.hot_cache.pin(tip_hash);
                let _ = self.hot_cache.try_insert(tip_hash.clone(), Arc::new(tip_block));

                // Initialize fork choice with tip
                self.fork_choice = ForkChoice::new();
                self.fork_choice.add_tip(
                    tip_hash.clone(),
                    tip_height,
                    self.height_index
                        .get(&(tip_height.saturating_sub(1)))
                        .cloned()
                        .unwrap_or_default(),
                );
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;
        Ok(stats)
    }

    /// Get the blockchain configuration.
    pub fn config(&self) -> &BlockchainConfig {
        &self.config
    }

    // ========= Internal Helpers =========

    /// Process chain entries from a block (username registrations, etc.)
    fn process_block_entries(&mut self, block: &Block) -> Result<()> {
        for entry in block.entries() {
            match entry {
                crate::block::ChainEntry::UsernameRegistration {
                    identity_hash,
                    username,
                    ..
                } => {
                    self.register_username(username, identity_hash)?;
                }
                crate::block::ChainEntry::ValidatorRegistration {
                    identity_hash,
                    stake,
                    region,
                    timestamp,
                    ..
                } => {
                    use crate::validator::ValidatorStake;
                    let validator = ValidatorStake::new(
                        identity_hash.clone(),
                        *stake,
                        format!("{:?}", region), // Convert region to string
                        *timestamp,
                    )?;
                    self.validator_set.register(validator)?;
                }
                crate::block::ChainEntry::ValidatorExit { identity_hash, .. } => {
                    self.validator_set.unregister(identity_hash);
                }
                _ => {
                    // Other entry types don't affect chain state
                }
            }
        }
        Ok(())
    }

    /// Register a username in the index.
    fn register_username(&mut self, username: &str, identity: &IdentityHash) -> Result<()> {
        let normalized = username.to_ascii_lowercase();

        // Check uniqueness (VERITAS-2026-0090)
        if let Some(existing) = self.username_index.get(&normalized) {
            if existing != identity {
                return Err(ChainError::UsernameTaken {
                    username: username.to_string(),
                    owner: hex::encode(existing.as_bytes()),
                });
            }
            return Ok(()); // Re-registration by same identity is idempotent
        }

        self.username_index.insert(normalized, identity.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryBackend;

    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    fn create_genesis() -> Block {
        Block::genesis(1700000000, vec![])
    }

    fn create_block_at_height(height: u64, parent_hash: Hash256) -> Block {
        Block::new(
            parent_hash,
            height,
            1700000000 + height,
            vec![],
            test_identity((height % 256) as u8),
        )
    }

    // ==================== Core Functionality Tests ====================

    #[tokio::test]
    async fn test_managed_create_with_genesis() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        assert_eq!(chain.height(), 0);
        assert!(chain.tip_block().is_some());
        assert!(chain.genesis_block().is_some());
    }

    #[tokio::test]
    async fn test_managed_add_blocks() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis.clone())
            .await
            .unwrap();

        // Add 10 blocks
        let mut parent_hash = genesis.hash().clone();
        for i in 1..=10 {
            let block = create_block_at_height(i, parent_hash.clone());
            parent_hash = block.hash().clone();
            chain.add_block(block).await.unwrap();
        }

        assert_eq!(chain.height(), 10);
        assert_eq!(chain.block_count(), 11); // genesis + 10 blocks
    }

    #[tokio::test]
    async fn test_managed_get_by_hash() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();
        let genesis_hash = genesis.hash().clone();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        let block = chain.get_block(&genesis_hash).await.unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().height(), 0);
    }

    #[tokio::test]
    async fn test_managed_get_by_height() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis.clone())
            .await
            .unwrap();

        // Add some blocks
        let mut parent_hash = genesis.hash().clone();
        for i in 1..=5 {
            let block = create_block_at_height(i, parent_hash.clone());
            parent_hash = block.hash().clone();
            chain.add_block(block).await.unwrap();
        }

        // Get block at height 3
        let block = chain.get_block_at_height(3).await.unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().height(), 3);
    }

    #[tokio::test]
    async fn test_managed_get_nonexistent() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        let hash = test_hash(99);
        let block = chain.get_block(&hash).await.unwrap();
        assert!(block.is_none());
    }

    #[tokio::test]
    async fn test_managed_tip_always_available() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        assert!(chain.tip_block().is_some());
    }

    // ==================== Memory Bounding Tests ====================

    #[tokio::test]
    async fn test_managed_memory_bounded_relay() {
        let config = BlockchainConfig::relay();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config.clone(), backend, genesis.clone())
            .await
            .unwrap();

        // Add many blocks
        let mut parent_hash = genesis.hash().clone();
        for i in 1..=500 {
            let block = create_block_at_height(i, parent_hash.clone());
            parent_hash = block.hash().clone();
            chain.add_block(block).await.unwrap();
        }

        let metrics = chain.memory_metrics();

        // Cache should be within budget
        assert!(
            metrics.cache_bytes <= config.memory_budget_bytes(),
            "Cache {} > budget {}",
            metrics.cache_bytes,
            config.memory_budget_bytes()
        );

        // Genesis and tip should still be available
        assert!(chain.genesis_block().is_some());
        assert!(chain.tip_block().is_some());
    }

    #[tokio::test]
    async fn test_managed_genesis_never_evicted() {
        let config = BlockchainConfig::relay();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();
        let genesis_hash = genesis.hash().clone();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis.clone())
            .await
            .unwrap();

        // Add many blocks to trigger eviction
        let mut parent_hash = genesis.hash().clone();
        for i in 1..=200 {
            let block = create_block_at_height(i, parent_hash.clone());
            parent_hash = block.hash().clone();
            chain.add_block(block).await.unwrap();
        }

        // Genesis should still be directly in cache (no backend load needed)
        assert!(chain.hot_cache.contains(&genesis_hash));
        assert!(chain.hot_cache.is_pinned(&genesis_hash));
    }

    #[tokio::test]
    async fn test_managed_tip_never_evicted() {
        let config = BlockchainConfig::relay();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis.clone())
            .await
            .unwrap();

        // Add many blocks
        let mut parent_hash = genesis.hash().clone();
        for i in 1..=200 {
            let block = create_block_at_height(i, parent_hash.clone());
            parent_hash = block.hash().clone();
            chain.add_block(block).await.unwrap();
        }

        // Tip should be in cache and pinned
        let tip_hash = chain.tip_hash().clone();
        assert!(chain.hot_cache.contains(&tip_hash));
        assert!(chain.hot_cache.is_pinned(&tip_hash));
    }

    // ==================== Profile Tests ====================

    #[tokio::test]
    async fn test_managed_all_profiles_work() {
        for config in [
            BlockchainConfig::relay(),
            BlockchainConfig::full_node(),
            BlockchainConfig::validator(),
            BlockchainConfig::bootstrap(),
            BlockchainConfig::archive(),
        ] {
            let backend = Box::new(InMemoryBackend::new());
            let genesis = create_genesis();

            let mut chain = ManagedBlockchain::with_genesis(config.clone(), backend, genesis.clone())
                .await
                .unwrap();

            // Add some blocks
            let mut parent_hash = genesis.hash().clone();
            for i in 1..=10 {
                let block = create_block_at_height(i, parent_hash.clone());
                parent_hash = block.hash().clone();
                chain.add_block(block).await.unwrap();
            }

            assert_eq!(chain.height(), 10);

            let metrics = chain.memory_metrics();
            assert!(
                metrics.cache_bytes <= config.memory_budget_bytes(),
                "Profile {:?} exceeded budget",
                config.pruning_mode
            );
        }
    }

    // ==================== Username Tests ====================

    #[tokio::test]
    async fn test_managed_username_lookup() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        let identity = test_identity(1);
        chain.register_username("alice", &identity).unwrap();

        assert_eq!(chain.lookup_username("alice"), Some(&identity));
        assert_eq!(chain.lookup_username("Alice"), Some(&identity)); // case insensitive
        assert_eq!(chain.lookup_username("bob"), None);
    }

    #[tokio::test]
    async fn test_managed_username_availability() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        assert!(chain.is_username_available("alice"));

        let identity = test_identity(1);
        chain.register_username("alice", &identity).unwrap();

        assert!(!chain.is_username_available("alice"));
    }

    #[tokio::test]
    async fn test_managed_username_uniqueness() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        let identity1 = test_identity(1);
        let identity2 = test_identity(2);

        chain.register_username("alice", &identity1).unwrap();

        let result = chain.register_username("alice", &identity2);
        assert!(matches!(result, Err(ChainError::UsernameTaken { .. })));
    }

    // ==================== Cache Behavior Tests ====================

    #[tokio::test]
    async fn test_managed_cache_hit_on_recent() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();
        let genesis_hash = genesis.hash().clone();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        // Access genesis (should be cache hit)
        let _ = chain.get_block(&genesis_hash).await;

        let metrics = chain.memory_metrics();
        assert!(metrics.cache_hit_ratio > 0.0);
    }

    // ==================== Rebuild Tests ====================

    #[cfg(feature = "sled-storage")]
    #[tokio::test]
    async fn test_managed_open_from_existing() {
        use crate::sled_backend::SledBackend;
        use crate::config::DEFAULT_SLED_CACHE_MB;

        let tempdir = tempfile::tempdir().unwrap();
        let config = BlockchainConfig::default();
        let genesis = create_genesis();
        let genesis_hash = genesis.hash().clone();

        // Create chain and add blocks
        {
            let backend = Box::new(SledBackend::open(tempdir.path(), DEFAULT_SLED_CACHE_MB, None).unwrap());
            let mut chain = ManagedBlockchain::with_genesis(config.clone(), backend, genesis.clone())
                .await
                .unwrap();

            let mut parent_hash = genesis_hash.clone();
            for i in 1..=5 {
                let block = create_block_at_height(i, parent_hash.clone());
                parent_hash = block.hash().clone();
                chain.add_block(block).await.unwrap();
            }
        }

        // Reopen from backend (sled persists to disk)
        let backend = Box::new(SledBackend::open(tempdir.path(), DEFAULT_SLED_CACHE_MB, None).unwrap());
        let reopened = ManagedBlockchain::open(config, backend).await.unwrap();

        assert_eq!(reopened.height(), 5);
        assert_eq!(reopened.block_count(), 6);
    }

    // ==================== Metrics Tests ====================

    #[tokio::test]
    async fn test_managed_memory_metrics() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let chain = ManagedBlockchain::with_genesis(config.clone(), backend, genesis)
            .await
            .unwrap();

        let metrics = chain.memory_metrics();

        assert_eq!(metrics.cache_capacity, config.memory_budget_bytes());
        assert!(metrics.cache_bytes > 0);
        assert_eq!(metrics.height_index_entries, 1);
        assert_eq!(metrics.backend_block_count, 1);
        assert_eq!(metrics.pinned_blocks, 1); // genesis is pinned
    }

    // ==================== Error Case Tests ====================

    #[tokio::test]
    async fn test_managed_reject_invalid_height() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis.clone())
            .await
            .unwrap();

        // Try to add block with wrong height
        let block = create_block_at_height(5, genesis.hash().clone()); // Should be 1
        let result = chain.add_block(block).await;

        assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
    }

    #[tokio::test]
    async fn test_managed_reject_invalid_parent() {
        let config = BlockchainConfig::default();
        let backend = Box::new(InMemoryBackend::new());
        let genesis = create_genesis();

        let mut chain = ManagedBlockchain::with_genesis(config, backend, genesis)
            .await
            .unwrap();

        // Try to add block with wrong parent
        let block = create_block_at_height(1, test_hash(99));
        let result = chain.add_block(block).await;

        assert!(matches!(result, Err(ChainError::InvalidBlock(_))));
    }
}
