//! Sled-backed persistent storage for blockchain data.
//!
//! Provides durable block storage using the sled embedded database.
//! Blocks are public data and stored unencrypted for performance.
//!
//! ## Features
//!
//! - Persistent block storage across restarts
//! - Height-indexed block retrieval
//! - Persisted username index with Blake3 integrity verification
//! - Optional zstd compression via BlockCompressor
//! - Configurable sled cache size
//!
//! ## Security
//!
//! - Block size validated before storage (MAX_STORED_BLOCK_SIZE)
//! - Corrupted data handled gracefully (no panics)
//! - Username index integrity verified on startup
//! - Index built ONLY from locally validated blocks (never from network)
//!
//! Requires the `sled-storage` feature flag (enabled by default).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::block::Block;
use crate::compression::BlockCompressor;
use crate::storage::{MAX_STORED_BLOCK_SIZE, StorageBackend};
use crate::{ChainError, Result};

/// Tree name for block storage.
const BLOCKS_TREE: &str = "veritas_blocks";

/// Tree name for height index.
const HEIGHTS_TREE: &str = "veritas_block_heights";

/// Tree name for username index.
const USERNAME_INDEX_TREE: &str = "veritas_username_index";

/// Tree name for username index metadata.
const USERNAME_INDEX_META_TREE: &str = "veritas_username_index_meta";

/// Key for username index metadata.
const INDEX_META_KEY: &[u8] = b"meta";

/// Metadata for the username index, used for integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameIndexMeta {
    /// Height of the last block whose usernames are indexed.
    pub last_indexed_height: u64,

    /// Total number of indexed usernames.
    pub count: u64,

    /// Blake3 hash of all (normalized_name, identity_hash) pairs, sorted by name.
    /// Used for integrity verification on startup.
    pub integrity_hash: [u8; 32],
}

/// Persistent block storage backed by sled.
///
/// Uses four sled trees:
/// - `veritas_blocks`: block_hash (32 bytes) → serialized block bytes
/// - `veritas_block_heights`: height (8-byte BE u64) → block_hash (32 bytes)
/// - `veritas_username_index`: normalized_username → identity_hash (32 bytes)
/// - `veritas_username_index_meta`: "meta" → UsernameIndexMeta (serialized)
///
/// ## Thread Safety
///
/// `SledBackend` is thread-safe. All sled operations are internally synchronized.
pub struct SledBackend {
    /// Sled database instance.
    db: sled::Db,

    /// Tree for block storage.
    blocks_tree: sled::Tree,

    /// Tree for height index.
    heights_tree: sled::Tree,

    /// Tree for username index.
    username_tree: sled::Tree,

    /// Tree for username index metadata.
    username_meta_tree: sled::Tree,

    /// Cached block count (for fast access).
    block_count: AtomicUsize,

    /// Cached total storage size in bytes.
    total_size: AtomicUsize,

    /// Optional block compressor.
    compressor: Option<std::sync::Mutex<BlockCompressor>>,
}

impl std::fmt::Debug for SledBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SledBackend")
            .field("block_count", &self.block_count.load(Ordering::Relaxed))
            .field("total_size", &self.total_size.load(Ordering::Relaxed))
            .field("has_compressor", &self.compressor.is_some())
            .finish()
    }
}

impl SledBackend {
    /// Open or create a sled-backed block store.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory for sled database files
    /// * `cache_mb` - Sled page cache size in megabytes (controls RAM usage)
    /// * `compressor` - Optional block compressor for storage efficiency
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or created.
    pub fn open(path: &Path, cache_mb: usize, compressor: Option<BlockCompressor>) -> Result<Self> {
        let config = sled::Config::new()
            .path(path)
            .cache_capacity((cache_mb * 1024 * 1024) as u64)
            .mode(sled::Mode::LowSpace)
            .flush_every_ms(Some(1000));

        let db = config
            .open()
            .map_err(|e| ChainError::Storage(format!("sled open: {}", e)))?;

        let blocks_tree = db
            .open_tree(BLOCKS_TREE)
            .map_err(|e| ChainError::Storage(format!("open blocks tree: {}", e)))?;
        let heights_tree = db
            .open_tree(HEIGHTS_TREE)
            .map_err(|e| ChainError::Storage(format!("open heights tree: {}", e)))?;
        let username_tree = db
            .open_tree(USERNAME_INDEX_TREE)
            .map_err(|e| ChainError::Storage(format!("open username tree: {}", e)))?;
        let username_meta_tree = db
            .open_tree(USERNAME_INDEX_META_TREE)
            .map_err(|e| ChainError::Storage(format!("open username meta tree: {}", e)))?;

        // Count existing blocks and calculate total size
        let block_count = blocks_tree.len();
        let total_size = blocks_tree
            .iter()
            .filter_map(|r| r.ok())
            .map(|(_, v)| v.len())
            .sum::<usize>();

        Ok(Self {
            db,
            blocks_tree,
            heights_tree,
            username_tree,
            username_meta_tree,
            block_count: AtomicUsize::new(block_count),
            total_size: AtomicUsize::new(total_size),
            compressor: compressor.map(std::sync::Mutex::new),
        })
    }

    /// Open a sled-backed store without compression.
    pub fn open_uncompressed(path: &Path, cache_mb: usize) -> Result<Self> {
        Self::open(path, cache_mb, None)
    }

    /// Get the sled database instance.
    pub fn db(&self) -> &sled::Db {
        &self.db
    }

    // ========= Height Index Methods =========

    /// Load a block by chain height.
    ///
    /// This is more efficient than scanning all blocks when you know the height.
    pub fn load_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let height_key = height.to_be_bytes();
        match self
            .heights_tree
            .get(height_key)
            .map_err(|e| ChainError::Storage(format!("height lookup: {}", e)))?
        {
            Some(hash_bytes) => {
                let hash = Hash256::from_bytes(&hash_bytes)
                    .map_err(|_| ChainError::Storage("corrupt hash in height index".to_string()))?;

                match self
                    .blocks_tree
                    .get(hash.as_bytes())
                    .map_err(|e| ChainError::Storage(format!("load by height: {}", e)))?
                {
                    Some(bytes) => {
                        let block_bytes = self.maybe_decompress(&bytes)?;
                        let block = Block::from_bytes(&block_bytes)?;
                        Ok(Some(block))
                    }
                    None => Ok(None), // Height index stale — block was pruned
                }
            }
            None => Ok(None),
        }
    }

    /// Get the highest stored height.
    pub fn max_height(&self) -> Result<Option<u64>> {
        // sled BTreeMap ordering: last key is highest because we use BE encoding
        match self
            .heights_tree
            .last()
            .map_err(|e| ChainError::Storage(format!("max height: {}", e)))?
        {
            Some((key, _)) => {
                let height = u64::from_be_bytes(
                    key.as_ref()
                        .try_into()
                        .map_err(|_| ChainError::Storage("corrupt height key".to_string()))?,
                );
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Iterate heights in order. Returns (height, hash) pairs.
    ///
    /// Efficient for index rebuilding — reads only the small heights tree.
    pub fn iter_heights(&self) -> impl Iterator<Item = Result<(u64, Hash256)>> + '_ {
        self.heights_tree.iter().map(|r| {
            let (key, value) =
                r.map_err(|e| ChainError::Storage(format!("iter heights: {}", e)))?;
            let height = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| ChainError::Storage("corrupt height key".to_string()))?,
            );
            let hash = Hash256::from_bytes(&value)
                .map_err(|_| ChainError::Storage("corrupt hash in height index".to_string()))?;
            Ok((height, hash))
        })
    }

    /// Delete all height index entries below a given height.
    ///
    /// Used by pruner to clean up after block deletion.
    pub fn prune_height_index_below(&self, min_height: u64) -> Result<usize> {
        let mut pruned = 0;
        let min_key = min_height.to_be_bytes();

        // Iterate from beginning up to (but not including) min_height
        for result in self.heights_tree.range(..min_key) {
            let (key, _) =
                result.map_err(|e| ChainError::Storage(format!("prune height index: {}", e)))?;
            self.heights_tree
                .remove(&key)
                .map_err(|e| ChainError::Storage(format!("remove height entry: {}", e)))?;
            pruned += 1;
        }

        Ok(pruned)
    }

    // ========= Username Index Methods =========

    /// Look up an identity by normalized username.
    pub fn lookup_username(&self, username: &str) -> Result<Option<IdentityHash>> {
        let normalized = username.to_ascii_lowercase();
        match self
            .username_tree
            .get(normalized.as_bytes())
            .map_err(|e| ChainError::Storage(format!("username lookup: {}", e)))?
        {
            Some(bytes) => {
                let hash = IdentityHash::from_bytes(&bytes).map_err(|_| {
                    ChainError::Storage("corrupt identity in username index".to_string())
                })?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Register a username → identity mapping.
    ///
    /// # Security
    ///
    /// MUST only be called after the containing block has passed full
    /// signature verification. Never call with data from unvalidated
    /// network sources.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::UsernameTaken` if the username is already
    /// registered to a different identity.
    pub fn register_username(&self, username: &str, identity: &IdentityHash) -> Result<()> {
        let normalized = username.to_ascii_lowercase();

        // Check uniqueness (VERITAS-2026-0090)
        if let Some(existing_bytes) = self
            .username_tree
            .get(normalized.as_bytes())
            .map_err(|e| ChainError::Storage(format!("username check: {}", e)))?
        {
            let existing = IdentityHash::from_bytes(&existing_bytes).map_err(|_| {
                ChainError::Storage("corrupt identity in username index".to_string())
            })?;
            if existing != *identity {
                return Err(ChainError::UsernameTaken {
                    username: username.to_string(),
                    owner: hex::encode(existing.as_bytes()),
                });
            }
            return Ok(()); // Re-registration by same identity is idempotent
        }

        self.username_tree
            .insert(normalized.as_bytes(), identity.as_bytes())
            .map_err(|e| ChainError::Storage(format!("username register: {}", e)))?;

        Ok(())
    }

    /// Check if a username is available.
    pub fn is_username_available(&self, username: &str) -> Result<bool> {
        let normalized = username.to_ascii_lowercase();
        let exists = self
            .username_tree
            .contains_key(normalized.as_bytes())
            .map_err(|e| ChainError::Storage(format!("username available check: {}", e)))?;
        Ok(!exists)
    }

    /// Count registered usernames.
    pub fn username_count(&self) -> usize {
        self.username_tree.len()
    }

    /// Load username index metadata.
    pub fn load_username_meta(&self) -> Result<Option<UsernameIndexMeta>> {
        match self
            .username_meta_tree
            .get(INDEX_META_KEY)
            .map_err(|e| ChainError::Storage(format!("load username meta: {}", e)))?
        {
            Some(bytes) => {
                let meta: UsernameIndexMeta = bincode::deserialize(&bytes).map_err(|e| {
                    ChainError::Storage(format!("deserialize username meta: {}", e))
                })?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Save username index metadata.
    pub fn save_username_meta(&self, meta: &UsernameIndexMeta) -> Result<()> {
        let bytes = bincode::serialize(meta)
            .map_err(|e| ChainError::Storage(format!("serialize username meta: {}", e)))?;
        self.username_meta_tree
            .insert(INDEX_META_KEY, bytes)
            .map_err(|e| ChainError::Storage(format!("save username meta: {}", e)))?;
        Ok(())
    }

    /// Compute integrity hash of the username index.
    ///
    /// Blake3 hash of all (normalized_name, identity_hash) pairs sorted by name.
    pub fn compute_username_integrity_hash(&self) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VERITAS-USERNAME-INDEX-INTEGRITY-v1"); // Domain separation

        // sled iterates in key order (sorted), which is what we want
        for result in self.username_tree.iter() {
            let (key, value) =
                result.map_err(|e| ChainError::Storage(format!("integrity hash iter: {}", e)))?;
            hasher.update(&key);
            hasher.update(&value);
        }

        Ok(*hasher.finalize().as_bytes())
    }

    /// Clear the username index (for rebuilding).
    pub fn clear_username_index(&self) -> Result<()> {
        self.username_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear username index: {}", e)))?;
        self.username_meta_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear username meta: {}", e)))?;
        Ok(())
    }

    // ========= Internal Helpers =========

    /// Compress bytes if compressor is available.
    fn maybe_compress(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref compressor) = self.compressor {
            // SECURITY: Handle poisoned mutex gracefully instead of panicking
            let mut comp = compressor
                .lock()
                .map_err(|_| ChainError::Storage("compressor mutex poisoned".into()))?;
            comp.compress_bytes(bytes)
        } else {
            Ok(bytes.to_vec())
        }
    }

    /// Decompress bytes if compressor is available.
    fn maybe_decompress(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref compressor) = self.compressor {
            // SECURITY: Handle poisoned mutex gracefully instead of panicking
            let mut comp = compressor
                .lock()
                .map_err(|_| ChainError::Storage("compressor mutex poisoned".into()))?;
            comp.decompress_bytes(bytes)
        } else {
            Ok(bytes.to_vec())
        }
    }
}

#[async_trait]
impl StorageBackend for SledBackend {
    async fn store_block(&self, block: &Block) -> Result<()> {
        let bytes = block.to_bytes()?;

        // SECURITY: Validate size BEFORE storage
        if bytes.len() > MAX_STORED_BLOCK_SIZE {
            return Err(ChainError::Storage(format!(
                "Block too large: {} bytes (max {})",
                bytes.len(),
                MAX_STORED_BLOCK_SIZE
            )));
        }

        let hash = block.hash().clone();
        let height = block.height();

        // Optionally compress
        let store_bytes = self.maybe_compress(&bytes)?;
        let size = store_bytes.len();

        // Check if we're replacing an existing block
        let old_size = self
            .blocks_tree
            .get(hash.as_bytes())
            .map_err(|e| ChainError::Storage(format!("check existing block: {}", e)))?
            .map(|v| v.len())
            .unwrap_or(0);

        // Store block
        self.blocks_tree
            .insert(hash.as_bytes(), store_bytes.as_slice())
            .map_err(|e| ChainError::Storage(format!("store block: {}", e)))?;

        // Store height → hash index
        let height_key = height.to_be_bytes();
        self.heights_tree
            .insert(height_key, hash.as_bytes())
            .map_err(|e| ChainError::Storage(format!("store height index: {}", e)))?;

        // Update counters
        if old_size == 0 {
            self.block_count.fetch_add(1, Ordering::Relaxed);
        }
        self.total_size.fetch_add(size, Ordering::Relaxed);
        if old_size > 0 {
            self.total_size.fetch_sub(old_size, Ordering::Relaxed);
        }

        Ok(())
    }

    async fn load_block(&self, hash: &Hash256) -> Result<Option<Block>> {
        match self
            .blocks_tree
            .get(hash.as_bytes())
            .map_err(|e| ChainError::Storage(format!("load block: {}", e)))?
        {
            Some(bytes) => {
                // Decompress if needed
                let block_bytes = self.maybe_decompress(&bytes)?;

                // Deserialize
                // NOTE: No block.verify() here — blocks are verified on insert and
                // integrity is checked at startup. This keeps cache-miss latency low.
                let block = Block::from_bytes(&block_bytes)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn delete_block(&self, hash: &Hash256) -> Result<bool> {
        match self
            .blocks_tree
            .remove(hash.as_bytes())
            .map_err(|e| ChainError::Storage(format!("delete block: {}", e)))?
        {
            Some(bytes) => {
                self.block_count.fetch_sub(1, Ordering::Relaxed);
                self.total_size.fetch_sub(bytes.len(), Ordering::Relaxed);
                // Note: height index entry is NOT removed here.
                // Pruner handles height index cleanup separately.
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn block_exists(&self, hash: &Hash256) -> Result<bool> {
        self.blocks_tree
            .contains_key(hash.as_bytes())
            .map_err(|e| ChainError::Storage(format!("check block exists: {}", e)))
    }

    fn count_blocks(&self) -> usize {
        self.block_count.load(Ordering::Relaxed)
    }

    fn total_size_bytes(&self) -> usize {
        self.total_size.load(Ordering::Relaxed)
    }

    async fn list_block_hashes(&self) -> Result<Vec<Hash256>> {
        self.blocks_tree
            .iter()
            .map(|r| {
                let (key, _) = r.map_err(|e| ChainError::Storage(format!("iter: {}", e)))?;
                Hash256::from_bytes(&key)
                    .map_err(|_| ChainError::Storage("corrupt hash in block index".to_string()))
            })
            .collect()
    }

    async fn clear(&self) -> Result<()> {
        self.blocks_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear blocks: {}", e)))?;
        self.heights_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear heights: {}", e)))?;
        self.username_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear usernames: {}", e)))?;
        self.username_meta_tree
            .clear()
            .map_err(|e| ChainError::Storage(format!("clear username meta: {}", e)))?;
        self.block_count.store(0, Ordering::Relaxed);
        self.total_size.store(0, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.db
            .flush_async()
            .await
            .map_err(|e| ChainError::Storage(format!("flush: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

    // ==================== Basic StorageBackend Tests ====================

    #[tokio::test]
    async fn test_sled_store_and_load() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

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
    async fn test_sled_load_nonexistent() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let hash = test_hash(99);
        let loaded = backend.load_block(&hash).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_sled_delete() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let block = create_test_block(1);
        let hash = block.hash().clone();

        backend.store_block(&block).await.unwrap();
        assert_eq!(backend.count_blocks(), 1);

        let deleted = backend.delete_block(&hash).await.unwrap();
        assert!(deleted);
        assert_eq!(backend.count_blocks(), 0);

        let deleted_again = backend.delete_block(&hash).await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_sled_exists() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let block = create_test_block(1);
        let hash = block.hash().clone();

        assert!(!backend.block_exists(&hash).await.unwrap());

        backend.store_block(&block).await.unwrap();
        assert!(backend.block_exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_sled_list_hashes() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

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
    async fn test_sled_clear() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

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
    async fn test_sled_replace() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let block = create_test_block(1);

        backend.store_block(&block).await.unwrap();
        let size_first = backend.total_size_bytes();

        // Store same block again
        backend.store_block(&block).await.unwrap();
        let size_second = backend.total_size_bytes();

        // Size should be the same (no duplication)
        assert_eq!(size_first, size_second);
        assert_eq!(backend.count_blocks(), 1);
    }

    // ==================== Height Index Tests ====================

    #[tokio::test]
    async fn test_sled_height_index_roundtrip() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let block = create_test_block(42);
        backend.store_block(&block).await.unwrap();

        let loaded = backend.load_block_by_height(42).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height(), 42);
    }

    #[tokio::test]
    async fn test_sled_max_height() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        assert!(backend.max_height().unwrap().is_none());

        for i in [1, 5, 3, 10, 7] {
            let block = create_test_block(i);
            backend.store_block(&block).await.unwrap();
        }

        assert_eq!(backend.max_height().unwrap(), Some(10));
    }

    #[tokio::test]
    async fn test_sled_iter_heights() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        for i in 1..=5 {
            let block = create_test_block(i);
            backend.store_block(&block).await.unwrap();
        }

        let heights: Vec<u64> = backend.iter_heights().map(|r| r.unwrap().0).collect();

        assert_eq!(heights, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_sled_prune_height_index() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        for i in 1..=10 {
            let block = create_test_block(i);
            backend.store_block(&block).await.unwrap();
        }

        let pruned = backend.prune_height_index_below(5).unwrap();
        assert_eq!(pruned, 4); // Heights 1, 2, 3, 4

        let heights: Vec<u64> = backend.iter_heights().map(|r| r.unwrap().0).collect();

        assert_eq!(heights, vec![5, 6, 7, 8, 9, 10]);
    }

    // ==================== Username Index Tests ====================

    #[tokio::test]
    async fn test_sled_username_register_and_lookup() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let identity = test_identity(1);
        backend.register_username("alice", &identity).unwrap();

        let looked_up = backend.lookup_username("alice").unwrap();
        assert_eq!(looked_up, Some(identity));
    }

    #[tokio::test]
    async fn test_sled_username_uniqueness() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let identity1 = test_identity(1);
        let identity2 = test_identity(2);

        backend.register_username("alice", &identity1).unwrap();

        // Different identity trying to claim same username
        let result = backend.register_username("alice", &identity2);
        assert!(matches!(result, Err(ChainError::UsernameTaken { .. })));
    }

    #[tokio::test]
    async fn test_sled_username_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let identity1 = test_identity(1);
        let identity2 = test_identity(2);

        backend.register_username("Alice", &identity1).unwrap();

        // Different case, different identity
        let result = backend.register_username("alice", &identity2);
        assert!(matches!(result, Err(ChainError::UsernameTaken { .. })));
    }

    #[tokio::test]
    async fn test_sled_username_idempotent() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let identity = test_identity(1);

        backend.register_username("alice", &identity).unwrap();
        // Same identity re-registering same username is OK
        backend.register_username("alice", &identity).unwrap();

        assert_eq!(backend.username_count(), 1);
    }

    #[tokio::test]
    async fn test_sled_username_availability() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        assert!(backend.is_username_available("alice").unwrap());

        let identity = test_identity(1);
        backend.register_username("alice", &identity).unwrap();

        assert!(!backend.is_username_available("alice").unwrap());
    }

    #[tokio::test]
    async fn test_sled_username_integrity_hash() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let hash1 = backend.compute_username_integrity_hash().unwrap();

        let identity = test_identity(1);
        backend.register_username("alice", &identity).unwrap();

        let hash2 = backend.compute_username_integrity_hash().unwrap();

        // Hash should change after mutation
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_sled_username_meta_roundtrip() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

        let meta = UsernameIndexMeta {
            last_indexed_height: 100,
            count: 42,
            integrity_hash: [0xAB; 32],
        };

        backend.save_username_meta(&meta).unwrap();
        let loaded = backend.load_username_meta().unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.last_indexed_height, 100);
        assert_eq!(loaded.count, 42);
        assert_eq!(loaded.integrity_hash, [0xAB; 32]);
    }

    // ==================== Persistence Tests ====================

    #[tokio::test]
    async fn test_sled_persist_across_reopens() {
        let dir = TempDir::new().unwrap();

        // Write some blocks
        {
            let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();
            for i in 1..=5 {
                let block = create_test_block(i);
                backend.store_block(&block).await.unwrap();
            }
            backend.flush().await.unwrap();
        }

        // Reopen and verify
        {
            let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();
            assert_eq!(backend.count_blocks(), 5);

            for i in 1..=5 {
                let loaded = backend.load_block_by_height(i).unwrap();
                assert!(loaded.is_some());
                assert_eq!(loaded.unwrap().height(), i);
            }
        }
    }

    #[tokio::test]
    async fn test_sled_username_index_persists() {
        let dir = TempDir::new().unwrap();

        let identity = test_identity(1);

        // Write username
        {
            let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();
            backend.register_username("alice", &identity).unwrap();
            backend.flush().await.unwrap();
        }

        // Reopen and verify
        {
            let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();
            let looked_up = backend.lookup_username("alice").unwrap();
            assert_eq!(looked_up, Some(identity));
        }
    }

    // ==================== Compression Tests ====================

    #[tokio::test]
    async fn test_sled_compressed_roundtrip() {
        let dir = TempDir::new().unwrap();
        let compressor = BlockCompressor::new(3);
        let backend = SledBackend::open(dir.path(), 16, Some(compressor)).unwrap();

        let block = create_test_block(1);
        let hash = block.hash().clone();

        backend.store_block(&block).await.unwrap();

        let loaded = backend.load_block(&hash).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height(), 1);
    }

    // ==================== Stress Test ====================

    #[tokio::test]
    async fn test_sled_1k_blocks() {
        let dir = TempDir::new().unwrap();
        let backend = SledBackend::open_uncompressed(dir.path(), 32).unwrap();

        for i in 1..=1000 {
            let block = create_test_block(i);
            backend.store_block(&block).await.unwrap();
        }

        assert_eq!(backend.count_blocks(), 1000);
        assert_eq!(backend.max_height().unwrap(), Some(1000));

        // Verify random access
        let loaded = backend.load_block_by_height(500).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height(), 500);
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_sled_store_load_roundtrip(height in 0u64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let dir = TempDir::new().unwrap();
                let backend = SledBackend::open_uncompressed(dir.path(), 16).unwrap();

                let block = create_test_block(height);
                let hash = block.hash().clone();

                backend.store_block(&block).await.unwrap();
                let loaded = backend.load_block(&hash).await.unwrap();

                prop_assert!(loaded.is_some());
                prop_assert_eq!(loaded.unwrap().height(), height);

                Ok(())
            })?;
        }
    }
}
