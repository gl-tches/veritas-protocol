//! Lazy block loading with hot cache.
//!
//! This module provides [`LazyBlockLoader`] for on-demand block loading
//! with an in-memory hot cache for frequently accessed blocks.
//!
//! ## Architecture
//!
//! ```text
//! Request -> Hot Cache (LRU) -> Storage Backend
//!               |                    |
//!               v                    v
//!         Fast (memory)        Slow (disk/compressed)
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use veritas_chain::lazy_loader::LazyBlockLoader;
//! use veritas_chain::storage::InMemoryBackend;
//!
//! let backend = InMemoryBackend::new();
//! let loader = LazyBlockLoader::new(Box::new(backend), 1000);
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::block::Block;
use crate::memory::MemoryBudget;
use crate::storage::StorageBackend;
use crate::{ChainError, Result};

/// Default number of blocks to keep in hot cache.
pub const DEFAULT_HOT_CACHE_SIZE: usize = 1000;

/// Metrics for lazy loading operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoaderMetrics {
    /// Total load requests.
    pub total_loads: u64,

    /// Cache hits (loaded from memory).
    pub cache_hits: u64,

    /// Cache misses (loaded from storage).
    pub cache_misses: u64,

    /// Storage load failures.
    pub load_failures: u64,

    /// Blocks prefetched.
    pub prefetched: u64,
}

impl LoaderMetrics {
    /// Calculate cache hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        if self.total_loads == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_loads as f64
        }
    }

    /// Reset metrics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Lazy block loader with hot cache.
///
/// Provides on-demand block loading from a storage backend with an
/// in-memory LRU cache for frequently accessed blocks.
///
/// ## Hot Cache
///
/// The hot cache keeps recent blocks in memory for fast access.
/// When a block is accessed, it's promoted in the LRU cache.
/// When the cache is full, the least recently used blocks are evicted.
///
/// ## Thread Safety
///
/// The loader is NOT thread-safe. For concurrent access, wrap it
/// in a `Mutex` or use a thread-safe storage backend.
pub struct LazyBlockLoader {
    /// Memory budget for hot cache.
    hot_cache: MemoryBudget,

    /// Storage backend for cold blocks.
    storage: Box<dyn StorageBackend>,

    /// Maximum blocks to keep in hot cache.
    max_hot_blocks: usize,

    /// Performance metrics.
    metrics: LoaderMetrics,
}

impl std::fmt::Debug for LazyBlockLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyBlockLoader")
            .field("hot_cache_size", &self.hot_cache.len())
            .field("max_hot_blocks", &self.max_hot_blocks)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl LazyBlockLoader {
    /// Create a new lazy block loader.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend for block persistence
    /// * `max_hot_blocks` - Maximum blocks to keep in hot cache
    pub fn new(storage: Box<dyn StorageBackend>, max_hot_blocks: usize) -> Self {
        // Estimate memory per block (2KB) * max blocks, minimum 64MB
        let memory_budget = (max_hot_blocks * 2048).max(64 * 1024 * 1024);

        Self {
            hot_cache: MemoryBudget::new(memory_budget),
            storage,
            max_hot_blocks,
            metrics: LoaderMetrics::default(),
        }
    }

    /// Create a new lazy block loader with custom memory budget.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend
    /// * `max_hot_blocks` - Maximum blocks in hot cache
    /// * `memory_budget_bytes` - Memory limit in bytes
    pub fn with_memory_budget(
        storage: Box<dyn StorageBackend>,
        max_hot_blocks: usize,
        memory_budget_bytes: usize,
    ) -> Self {
        Self {
            hot_cache: MemoryBudget::new(memory_budget_bytes.max(64 * 1024 * 1024)),
            storage,
            max_hot_blocks,
            metrics: LoaderMetrics::default(),
        }
    }

    /// Get loader metrics.
    pub fn metrics(&self) -> &LoaderMetrics {
        &self.metrics
    }

    /// Get hot cache statistics.
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.hot_cache.len(), self.max_hot_blocks)
    }

    /// Get the storage backend.
    pub fn storage(&self) -> &dyn StorageBackend {
        self.storage.as_ref()
    }

    /// Load a block by hash.
    ///
    /// First checks the hot cache, then falls back to storage.
    /// Loaded blocks are added to the hot cache.
    ///
    /// # Arguments
    ///
    /// * `hash` - Block hash to load
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    pub async fn load_block(&mut self, hash: &Hash256) -> Result<Option<Arc<Block>>> {
        self.metrics.total_loads += 1;

        // Check hot cache first
        if let Some(block) = self.hot_cache.get(hash) {
            self.metrics.cache_hits += 1;
            return Ok(Some(block));
        }

        // Load from storage
        self.metrics.cache_misses += 1;

        match self.storage.load_block(hash).await {
            Ok(Some(block)) => {
                let arc_block = Arc::new(block);

                // Add to hot cache (ignore errors - block is still returned)
                let _ = self.hot_cache.try_insert(hash.clone(), Arc::clone(&arc_block));

                Ok(Some(arc_block))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                self.metrics.load_failures += 1;
                Err(e)
            }
        }
    }

    /// Load a block, returning an error if not found.
    ///
    /// # Arguments
    ///
    /// * `hash` - Block hash to load
    ///
    /// # Errors
    ///
    /// Returns `ChainError::BlockNotFound` if the block doesn't exist.
    pub async fn load_block_required(&mut self, hash: &Hash256) -> Result<Arc<Block>> {
        self.load_block(hash)
            .await?
            .ok_or_else(|| ChainError::BlockNotFound(hash.to_string()))
    }

    /// Check if a block is in the hot cache.
    pub fn is_cached(&self, hash: &Hash256) -> bool {
        self.hot_cache.contains(hash)
    }

    /// Check if a block exists (cache or storage).
    pub async fn block_exists(&self, hash: &Hash256) -> Result<bool> {
        if self.hot_cache.contains(hash) {
            return Ok(true);
        }
        self.storage.block_exists(hash).await
    }

    /// Store a block in both cache and storage.
    ///
    /// # Arguments
    ///
    /// * `block` - Block to store
    pub async fn store_block(&mut self, block: Block) -> Result<()> {
        let hash = block.hash().clone();
        let arc_block = Arc::new(block.clone());

        // Store in storage first
        self.storage.store_block(&block).await?;

        // Add to hot cache
        let _ = self.hot_cache.try_insert(hash, arc_block);

        Ok(())
    }

    /// Prefetch blocks into the hot cache.
    ///
    /// Useful for preloading blocks that are likely to be accessed.
    ///
    /// # Arguments
    ///
    /// * `hashes` - Block hashes to prefetch
    ///
    /// # Returns
    ///
    /// Number of blocks successfully prefetched.
    pub async fn prefetch(&mut self, hashes: &[Hash256]) -> usize {
        let mut prefetched = 0;

        for hash in hashes {
            // Skip if already cached
            if self.hot_cache.contains(hash) {
                continue;
            }

            // Load from storage
            match self.storage.load_block(hash).await {
                Ok(Some(block)) => {
                    let arc_block = Arc::new(block);
                    if self
                        .hot_cache
                        .try_insert(hash.clone(), arc_block)
                        .is_ok()
                    {
                        prefetched += 1;
                        self.metrics.prefetched += 1;
                    }
                }
                _ => continue,
            }
        }

        prefetched
    }

    /// Prefetch the N most recent blocks.
    ///
    /// # Arguments
    ///
    /// * `hashes` - List of hashes sorted by height (descending)
    /// * `count` - Number of blocks to prefetch
    pub async fn prefetch_recent(&mut self, hashes: &[Hash256], count: usize) -> usize {
        let to_prefetch: Vec<_> = hashes.iter().take(count).cloned().collect();
        self.prefetch(&to_prefetch).await
    }

    /// Evict a block from the hot cache.
    ///
    /// The block remains in storage.
    ///
    /// # Arguments
    ///
    /// * `hash` - Block hash to evict
    pub fn evict(&mut self, hash: &Hash256) -> Option<Arc<Block>> {
        self.hot_cache.remove(hash)
    }

    /// Clear the hot cache.
    ///
    /// Blocks remain in storage.
    pub fn clear_cache(&mut self) {
        self.hot_cache.clear();
    }

    /// Get memory usage of the hot cache.
    pub fn cache_memory_bytes(&self) -> usize {
        self.hot_cache.current_bytes()
    }

    /// Shrink the hot cache to target size.
    ///
    /// # Arguments
    ///
    /// * `target_bytes` - Target memory size
    ///
    /// # Returns
    ///
    /// Number of blocks evicted.
    pub fn shrink_cache_to(&mut self, target_bytes: usize) -> usize {
        self.hot_cache.evict_to(target_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryBackend;
    use veritas_identity::IdentityHash;

    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    fn create_test_block(height: u64) -> Block {
        Block::new(
            test_hash(height as u8),
            height,
            1700000000 + height,
            vec![],
            test_identity((height % 256) as u8),
        )
    }

    // ==================== Basic Operations ====================

    #[tokio::test]
    async fn test_loader_creation() {
        let storage = Box::new(InMemoryBackend::new());
        let loader = LazyBlockLoader::new(storage, 1000);

        assert_eq!(loader.cache_stats().1, 1000);
        assert_eq!(loader.metrics().total_loads, 0);
    }

    #[tokio::test]
    async fn test_store_and_load() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        loader.store_block(block.clone()).await.unwrap();

        let loaded = loader.load_block(&hash).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height(), 1);
    }

    #[tokio::test]
    async fn test_load_nonexistent() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let hash = test_hash(99);
        let loaded = loader.load_block(&hash).await.unwrap();
        assert!(loaded.is_none());

        // Should record as miss
        assert_eq!(loader.metrics().cache_misses, 1);
    }

    #[tokio::test]
    async fn test_load_required_error() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let hash = test_hash(99);
        let result = loader.load_block_required(&hash).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::BlockNotFound(_))));
    }

    // ==================== Cache Behavior ====================

    #[tokio::test]
    async fn test_cache_hit() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        loader.store_block(block).await.unwrap();

        // First load - may be miss or hit depending on store behavior
        let _ = loader.load_block(&hash).await.unwrap();

        // Second load - should be cache hit
        let _ = loader.load_block(&hash).await.unwrap();

        assert!(loader.metrics().cache_hits >= 1);
    }

    #[tokio::test]
    async fn test_is_cached() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        assert!(!loader.is_cached(&hash));

        loader.store_block(block).await.unwrap();

        assert!(loader.is_cached(&hash));
    }

    #[tokio::test]
    async fn test_evict() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        loader.store_block(block).await.unwrap();
        assert!(loader.is_cached(&hash));

        let evicted = loader.evict(&hash);
        assert!(evicted.is_some());
        assert!(!loader.is_cached(&hash));

        // Block should still be in storage
        assert!(loader.block_exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        for i in 1..=10 {
            let block = create_test_block(i);
            loader.store_block(block).await.unwrap();
        }

        assert_eq!(loader.cache_stats().0, 10);

        loader.clear_cache();

        assert_eq!(loader.cache_stats().0, 0);
    }

    // ==================== Prefetch ====================

    #[tokio::test]
    async fn test_prefetch() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        // Store blocks directly to storage
        let mut hashes = Vec::new();
        for i in 1..=10 {
            let block = create_test_block(i);
            hashes.push(block.hash().clone());
            loader.storage.store_block(&block).await.unwrap();
        }

        // Clear cache to ensure we test prefetch
        loader.clear_cache();

        let prefetched = loader.prefetch(&hashes).await;
        assert_eq!(prefetched, 10);
        assert_eq!(loader.metrics().prefetched, 10);

        // All should be cached now
        for hash in &hashes {
            assert!(loader.is_cached(hash));
        }
    }

    #[tokio::test]
    async fn test_prefetch_skips_cached() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        loader.store_block(block).await.unwrap();
        assert!(loader.is_cached(&hash));

        // Prefetch should skip already cached
        let prefetched = loader.prefetch(&[hash]).await;
        assert_eq!(prefetched, 0);
    }

    #[tokio::test]
    async fn test_prefetch_recent() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let mut hashes = Vec::new();
        for i in 1..=20 {
            let block = create_test_block(i);
            hashes.push(block.hash().clone());
            loader.storage.store_block(&block).await.unwrap();
        }

        loader.clear_cache();

        // Prefetch only 5 most recent
        let prefetched = loader.prefetch_recent(&hashes, 5).await;
        assert_eq!(prefetched, 5);
    }

    // ==================== Memory Management ====================

    #[tokio::test]
    async fn test_cache_memory_usage() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        assert_eq!(loader.cache_memory_bytes(), 0);

        for i in 1..=10 {
            let block = create_test_block(i);
            loader.store_block(block).await.unwrap();
        }

        assert!(loader.cache_memory_bytes() > 0);
    }

    #[tokio::test]
    async fn test_shrink_cache() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        for i in 1..=100 {
            let block = create_test_block(i);
            loader.store_block(block).await.unwrap();
        }

        let initial_memory = loader.cache_memory_bytes();

        let evicted = loader.shrink_cache_to(initial_memory / 2);
        assert!(evicted > 0);
        assert!(loader.cache_memory_bytes() <= initial_memory / 2);
    }

    // ==================== Block Existence ====================

    #[tokio::test]
    async fn test_block_exists_cached() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        loader.store_block(block).await.unwrap();

        assert!(loader.block_exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_block_exists_storage_only() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        // Store directly to storage, bypass cache
        loader.storage.store_block(&block).await.unwrap();
        loader.clear_cache();

        assert!(loader.block_exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_block_not_exists() {
        let storage = Box::new(InMemoryBackend::new());
        let loader = LazyBlockLoader::new(storage, 1000);

        let hash = test_hash(99);
        assert!(!loader.block_exists(&hash).await.unwrap());
    }

    // ==================== Metrics ====================

    #[tokio::test]
    async fn test_metrics_tracking() {
        let storage = Box::new(InMemoryBackend::new());
        let mut loader = LazyBlockLoader::new(storage, 1000);

        let block = create_test_block(1);
        let hash = block.hash().clone();

        // Store
        loader.store_block(block).await.unwrap();

        // Load (should hit cache)
        let _ = loader.load_block(&hash).await;

        // Load again
        let _ = loader.load_block(&hash).await;

        // Load non-existent (miss)
        let _ = loader.load_block(&test_hash(99)).await;

        let metrics = loader.metrics();
        assert!(metrics.total_loads >= 3);
        assert!(metrics.cache_hits >= 1);
        assert!(metrics.cache_misses >= 1);
    }

    #[test]
    fn test_hit_ratio() {
        let metrics = LoaderMetrics {
            total_loads: 100,
            cache_hits: 75,
            cache_misses: 25,
            load_failures: 0,
            prefetched: 0,
        };

        assert_eq!(metrics.hit_ratio(), 0.75);
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_store_load_roundtrip(height in 1u64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let storage = Box::new(InMemoryBackend::new());
                let mut loader = LazyBlockLoader::new(storage, 1000);

                let block = create_test_block(height);
                let hash = block.hash().clone();

                loader.store_block(block.clone()).await.unwrap();
                let loaded = loader.load_block(&hash).await.unwrap();

                prop_assert!(loaded.is_some());
                prop_assert_eq!(loaded.unwrap().height(), height);

                Ok(())
            })?;
        }
    }
}
