//! Storage backend abstraction for blockchain data.
//!
//! This module provides the [`StorageBackend`] trait for abstracting block storage,
//! enabling different storage implementations (in-memory, sled, compressed, etc.).
//!
//! ## Storage Hierarchy
//!
//! The storage system supports a tiered architecture:
//! - Hot: In-memory LRU cache (via MemoryBudget)
//! - Warm: Fast local storage (uncompressed)
//! - Cold: Compressed storage for older blocks
//!
//! ## Implementations
//!
//! - [`InMemoryBackend`]: Simple in-memory storage for testing
//! - Future: SledBackend, CompressedBackend, TieredBackend
//!
//! ## Example
//!
//! ```
//! use veritas_chain::storage::{StorageBackend, InMemoryBackend};
//!
//! let backend = InMemoryBackend::new();
//! assert_eq!(backend.count_blocks(), 0);
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use veritas_crypto::Hash256;

use crate::block::Block;
use crate::{ChainError, Result};

/// Maximum size of a block in storage (50 MB).
pub const MAX_STORED_BLOCK_SIZE: usize = 50 * 1024 * 1024;

/// Trait for block storage backends.
///
/// Provides a consistent interface for storing and retrieving blocks,
/// regardless of the underlying storage mechanism.
///
/// ## Security
///
/// Implementations MUST:
/// - Validate block sizes before storage
/// - Handle corrupted data gracefully
/// - Never panic on invalid input
///
/// ## Async
///
/// All methods are async to support I/O-bound storage backends.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a block.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The block is too large
    /// - Storage is full
    /// - I/O error occurs
    async fn store_block(&self, block: &Block) -> Result<()>;

    /// Load a block by hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash of the block to load
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Block data is corrupted
    /// - I/O error occurs
    async fn load_block(&self, hash: &Hash256) -> Result<Option<Block>>;

    /// Delete a block by hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash of the block to delete
    ///
    /// # Returns
    ///
    /// Ok(true) if block was deleted, Ok(false) if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O error occurs.
    async fn delete_block(&self, hash: &Hash256) -> Result<bool>;

    /// Check if a block exists.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash of the block to check
    async fn block_exists(&self, hash: &Hash256) -> Result<bool>;

    /// Count the number of stored blocks.
    fn count_blocks(&self) -> usize;

    /// Get the total storage size in bytes.
    fn total_size_bytes(&self) -> usize;

    /// List all stored block hashes.
    async fn list_block_hashes(&self) -> Result<Vec<Hash256>>;

    /// Clear all stored blocks.
    async fn clear(&self) -> Result<()>;

    /// Flush pending writes to durable storage.
    ///
    /// For in-memory backends, this is a no-op.
    async fn flush(&self) -> Result<()>;
}

/// In-memory storage backend for testing and development.
///
/// Stores blocks in a thread-safe HashMap. Does not persist data
/// across restarts.
///
/// ## Thread Safety
///
/// Uses RwLock for concurrent read/write access.
pub struct InMemoryBackend {
    /// Blocks stored by hash.
    blocks: RwLock<HashMap<Hash256, Vec<u8>>>,

    /// Total size of stored data.
    total_size: RwLock<usize>,
}

impl std::fmt::Debug for InMemoryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blocks = self.blocks.read().unwrap();
        let size = self.total_size.read().unwrap();
        f.debug_struct("InMemoryBackend")
            .field("block_count", &blocks.len())
            .field("total_size", &*size)
            .finish()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBackend {
    /// Create a new in-memory backend.
    pub fn new() -> Self {
        Self {
            blocks: RwLock::new(HashMap::new()),
            total_size: RwLock::new(0),
        }
    }

    /// Create an in-memory backend with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            blocks: RwLock::new(HashMap::with_capacity(capacity)),
            total_size: RwLock::new(0),
        }
    }
}

#[async_trait]
impl StorageBackend for InMemoryBackend {
    async fn store_block(&self, block: &Block) -> Result<()> {
        let bytes = block.to_bytes()?;

        // SECURITY: Validate size
        if bytes.len() > MAX_STORED_BLOCK_SIZE {
            return Err(ChainError::Storage(format!(
                "Block too large: {} bytes (max {})",
                bytes.len(),
                MAX_STORED_BLOCK_SIZE
            )));
        }

        let hash = block.hash().clone();
        let size = bytes.len();

        let mut blocks = self.blocks.write().unwrap();
        let mut total = self.total_size.write().unwrap();

        // If replacing, subtract old size
        if let Some(old) = blocks.get(&hash) {
            *total = total.saturating_sub(old.len());
        }

        blocks.insert(hash, bytes);
        *total += size;

        Ok(())
    }

    async fn load_block(&self, hash: &Hash256) -> Result<Option<Block>> {
        let blocks = self.blocks.read().unwrap();

        match blocks.get(hash) {
            Some(bytes) => {
                let block = Block::from_bytes(bytes)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn delete_block(&self, hash: &Hash256) -> Result<bool> {
        let mut blocks = self.blocks.write().unwrap();
        let mut total = self.total_size.write().unwrap();

        if let Some(bytes) = blocks.remove(hash) {
            *total = total.saturating_sub(bytes.len());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn block_exists(&self, hash: &Hash256) -> Result<bool> {
        let blocks = self.blocks.read().unwrap();
        Ok(blocks.contains_key(hash))
    }

    fn count_blocks(&self) -> usize {
        let blocks = self.blocks.read().unwrap();
        blocks.len()
    }

    fn total_size_bytes(&self) -> usize {
        let total = self.total_size.read().unwrap();
        *total
    }

    async fn list_block_hashes(&self) -> Result<Vec<Hash256>> {
        let blocks = self.blocks.read().unwrap();
        Ok(blocks.keys().cloned().collect())
    }

    async fn clear(&self) -> Result<()> {
        let mut blocks = self.blocks.write().unwrap();
        let mut total = self.total_size.write().unwrap();

        blocks.clear();
        *total = 0;

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // No-op for in-memory storage
        Ok(())
    }
}

/// Storage metrics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct StorageMetrics {
    /// Number of blocks stored.
    pub block_count: usize,

    /// Total storage size in bytes.
    pub total_bytes: usize,

    /// Number of store operations.
    pub stores: u64,

    /// Number of load operations.
    pub loads: u64,

    /// Number of load hits.
    pub load_hits: u64,

    /// Number of delete operations.
    pub deletes: u64,
}

impl StorageMetrics {
    /// Calculate load hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        if self.loads == 0 {
            0.0
        } else {
            self.load_hits as f64 / self.loads as f64
        }
    }
}

/// Wrapper that adds metrics tracking to any storage backend.
pub struct MetricsBackend<B: StorageBackend> {
    inner: B,
    metrics: RwLock<StorageMetrics>,
}

impl<B: StorageBackend> MetricsBackend<B> {
    /// Create a new metrics wrapper around a backend.
    pub fn new(backend: B) -> Self {
        Self {
            inner: backend,
            metrics: RwLock::new(StorageMetrics::default()),
        }
    }

    /// Get current metrics snapshot.
    pub fn metrics(&self) -> StorageMetrics {
        self.metrics.read().unwrap().clone()
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for MetricsBackend<B> {
    async fn store_block(&self, block: &Block) -> Result<()> {
        let result = self.inner.store_block(block).await;
        if result.is_ok() {
            let mut metrics = self.metrics.write().unwrap();
            metrics.stores += 1;
            metrics.block_count = self.inner.count_blocks();
            metrics.total_bytes = self.inner.total_size_bytes();
        }
        result
    }

    async fn load_block(&self, hash: &Hash256) -> Result<Option<Block>> {
        let result = self.inner.load_block(hash).await;
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.loads += 1;
            if result.as_ref().map(|r| r.is_some()).unwrap_or(false) {
                metrics.load_hits += 1;
            }
        }
        result
    }

    async fn delete_block(&self, hash: &Hash256) -> Result<bool> {
        let result = self.inner.delete_block(hash).await;
        if result.is_ok() {
            let mut metrics = self.metrics.write().unwrap();
            metrics.deletes += 1;
            metrics.block_count = self.inner.count_blocks();
            metrics.total_bytes = self.inner.total_size_bytes();
        }
        result
    }

    async fn block_exists(&self, hash: &Hash256) -> Result<bool> {
        self.inner.block_exists(hash).await
    }

    fn count_blocks(&self) -> usize {
        self.inner.count_blocks()
    }

    fn total_size_bytes(&self) -> usize {
        self.inner.total_size_bytes()
    }

    async fn list_block_hashes(&self) -> Result<Vec<Hash256>> {
        self.inner.list_block_hashes().await
    }

    async fn clear(&self) -> Result<()> {
        let result = self.inner.clear().await;
        if result.is_ok() {
            let mut metrics = self.metrics.write().unwrap();
            metrics.block_count = 0;
            metrics.total_bytes = 0;
        }
        result
    }

    async fn flush(&self) -> Result<()> {
        self.inner.flush().await
    }
}

/// Arc wrapper for shared storage backend.
pub type SharedBackend = Arc<dyn StorageBackend>;

#[cfg(test)]
mod tests {
    use super::*;
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

    // ==================== InMemoryBackend Tests ====================

    #[tokio::test]
    async fn test_in_memory_store_and_load() {
        let backend = InMemoryBackend::new();
        let block = create_test_block(1);
        let hash = block.hash().clone();

        backend.store_block(&block).await.unwrap();
        assert_eq!(backend.count_blocks(), 1);
        assert!(backend.total_size_bytes() > 0);

        let loaded = backend.load_block(&hash).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_load_nonexistent() {
        let backend = InMemoryBackend::new();
        let hash = test_hash(99);

        let loaded = backend.load_block(&hash).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_delete() {
        let backend = InMemoryBackend::new();
        let block = create_test_block(1);
        let hash = block.hash().clone();

        backend.store_block(&block).await.unwrap();
        assert_eq!(backend.count_blocks(), 1);

        let deleted = backend.delete_block(&hash).await.unwrap();
        assert!(deleted);
        assert_eq!(backend.count_blocks(), 0);
        assert_eq!(backend.total_size_bytes(), 0);

        // Delete again should return false
        let deleted_again = backend.delete_block(&hash).await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_in_memory_exists() {
        let backend = InMemoryBackend::new();
        let block = create_test_block(1);
        let hash = block.hash().clone();

        assert!(!backend.block_exists(&hash).await.unwrap());

        backend.store_block(&block).await.unwrap();
        assert!(backend.block_exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_list_hashes() {
        let backend = InMemoryBackend::new();

        let mut hashes = Vec::new();
        for i in 1..=5 {
            let block = create_test_block(i);
            hashes.push(block.hash().clone());
            backend.store_block(&block).await.unwrap();
        }

        let listed = backend.list_block_hashes().await.unwrap();
        assert_eq!(listed.len(), 5);

        for hash in &hashes {
            assert!(listed.contains(hash));
        }
    }

    #[tokio::test]
    async fn test_in_memory_clear() {
        let backend = InMemoryBackend::new();

        for i in 1..=5 {
            let block = create_test_block(i);
            backend.store_block(&block).await.unwrap();
        }

        assert_eq!(backend.count_blocks(), 5);

        backend.clear().await.unwrap();
        assert_eq!(backend.count_blocks(), 0);
        assert_eq!(backend.total_size_bytes(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_replace() {
        let backend = InMemoryBackend::new();
        let block = create_test_block(1);
        let _hash = block.hash().clone();

        backend.store_block(&block).await.unwrap();
        let size_first = backend.total_size_bytes();

        // Store same block again
        backend.store_block(&block).await.unwrap();
        let size_second = backend.total_size_bytes();

        // Size should be the same (no duplication)
        assert_eq!(size_first, size_second);
        assert_eq!(backend.count_blocks(), 1);
    }

    // ==================== MetricsBackend Tests ====================

    #[tokio::test]
    async fn test_metrics_backend_tracking() {
        let inner = InMemoryBackend::new();
        let backend = MetricsBackend::new(inner);

        // Initial metrics
        let metrics = backend.metrics();
        assert_eq!(metrics.stores, 0);
        assert_eq!(metrics.loads, 0);

        // Store
        let block = create_test_block(1);
        let hash = block.hash().clone();
        backend.store_block(&block).await.unwrap();

        let metrics = backend.metrics();
        assert_eq!(metrics.stores, 1);
        assert_eq!(metrics.block_count, 1);

        // Load (hit)
        let _ = backend.load_block(&hash).await.unwrap();
        let metrics = backend.metrics();
        assert_eq!(metrics.loads, 1);
        assert_eq!(metrics.load_hits, 1);

        // Load (miss)
        let _ = backend.load_block(&test_hash(99)).await.unwrap();
        let metrics = backend.metrics();
        assert_eq!(metrics.loads, 2);
        assert_eq!(metrics.load_hits, 1);
        assert_eq!(metrics.hit_ratio(), 0.5);

        // Delete
        backend.delete_block(&hash).await.unwrap();
        let metrics = backend.metrics();
        assert_eq!(metrics.deletes, 1);
        assert_eq!(metrics.block_count, 0);
    }

    // ==================== Thread Safety Tests ====================

    #[tokio::test]
    async fn test_in_memory_concurrent_access() {
        use tokio::task::JoinSet;

        let backend = Arc::new(InMemoryBackend::new());
        let mut tasks = JoinSet::new();

        // Spawn multiple writers
        for i in 0..10u64 {
            let backend = Arc::clone(&backend);
            tasks.spawn(async move {
                let block = create_test_block(i);
                backend.store_block(&block).await.unwrap();
            });
        }

        // Wait for all writers
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }

        assert_eq!(backend.count_blocks(), 10);

        // Spawn multiple readers
        for i in 0..10u64 {
            let backend = Arc::clone(&backend);
            tasks.spawn(async move {
                let block = create_test_block(i);
                let hash = block.hash().clone();
                let _ = backend.load_block(&hash).await;
            });
        }

        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_store_load_roundtrip(height in 0u64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let backend = InMemoryBackend::new();
                let block = create_test_block(height);
                let hash = block.hash().clone();

                backend.store_block(&block).await.unwrap();
                let loaded = backend.load_block(&hash).await.unwrap();

                prop_assert!(loaded.is_some());
                prop_assert_eq!(loaded.unwrap().height(), height);

                Ok(())
            })?;
        }

        #[test]
        fn prop_delete_removes_block(height in 0u64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let backend = InMemoryBackend::new();
                let block = create_test_block(height);
                let hash = block.hash().clone();

                backend.store_block(&block).await.unwrap();
                prop_assert!(backend.block_exists(&hash).await.unwrap());

                backend.delete_block(&hash).await.unwrap();
                prop_assert!(!backend.block_exists(&hash).await.unwrap());

                Ok(())
            })?;
        }
    }
}
