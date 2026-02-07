//! Chain pruning for storage optimization.
//!
//! This module provides [`ChainPruner`] for removing old blocks from storage
//! while maintaining a configurable retention window.
//!
//! ## Safety
//!
//! - Never prunes blocks within the safety margin of chain tip
//! - Preserves genesis block always
//! - Preserves finalized blocks (when configured)
//!
//! ## Pruning Modes
//!
//! - **Standard**: Keep a fixed number of recent blocks (default: 10,000)
//! - **Aggressive**: Keep only headers + minimal blocks
//! - **Archive**: Never prune (for archive nodes)
//!
//! ## Example
//!
//! ```
//! use veritas_chain::pruner::{ChainPruner, PruningStats};
//! use veritas_chain::config::PruningMode;
//!
//! let pruner = ChainPruner::new(PruningMode::standard());
//! assert!(!pruner.mode().is_archive());
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::Result;
use crate::config::{PRUNING_SAFETY_MARGIN, PruningMode};
use crate::storage::StorageBackend;

/// Statistics from a pruning operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruningStats {
    /// Number of blocks deleted.
    pub blocks_deleted: u64,

    /// Bytes freed.
    pub bytes_freed: u64,

    /// Number of blocks retained.
    pub blocks_retained: u64,

    /// Oldest block height after pruning.
    pub oldest_height: u64,

    /// Newest block height.
    pub newest_height: u64,

    /// Time taken in milliseconds.
    pub duration_ms: u64,
}

impl PruningStats {
    /// Check if any blocks were pruned.
    pub fn pruned_any(&self) -> bool {
        self.blocks_deleted > 0
    }

    /// Calculate storage reduction percentage.
    ///
    /// CHAIN-FIX-10: Uses 2048 bytes as estimated block size (was 1000).
    pub fn reduction_percent(&self) -> f64 {
        let total = self.bytes_freed + (self.blocks_retained * 2048); // Rough estimate
        if total == 0 {
            0.0
        } else {
            (self.bytes_freed as f64 / total as f64) * 100.0
        }
    }
}

/// Chain pruner for storage optimization.
///
/// Removes old blocks from storage based on the configured pruning mode,
/// while maintaining safety margins to ensure chain integrity.
///
/// ## Thread Safety
///
/// The pruner itself is not thread-safe. Use appropriate synchronization
/// when calling from multiple threads.
///
/// ## Safety Guarantees
///
/// 1. Genesis block is NEVER pruned
/// 2. Blocks within PRUNING_SAFETY_MARGIN of tip are NEVER pruned
/// 3. Finalized blocks are preserved (when configured)
/// 4. Pruning is atomic - blocks are either fully deleted or kept
#[derive(Debug)]
pub struct ChainPruner {
    /// Pruning mode.
    mode: PruningMode,

    /// Cumulative pruning statistics.
    total_stats: PruningStats,
}

impl ChainPruner {
    /// Create a new chain pruner with the specified mode.
    pub fn new(mode: PruningMode) -> Self {
        Self {
            mode,
            total_stats: PruningStats::default(),
        }
    }

    /// Get the pruning mode.
    pub fn mode(&self) -> &PruningMode {
        &self.mode
    }

    /// Get cumulative pruning statistics.
    pub fn total_stats(&self) -> &PruningStats {
        &self.total_stats
    }

    /// Set a new pruning mode.
    pub fn set_mode(&mut self, mode: PruningMode) {
        self.mode = mode;
    }

    /// Calculate the pruning threshold height.
    ///
    /// Blocks below this height can be pruned (except genesis and safety margin).
    ///
    /// # Arguments
    ///
    /// * `tip_height` - Current chain tip height
    ///
    /// # Returns
    ///
    /// Height below which blocks can be pruned, or None if pruning is disabled.
    pub fn prune_threshold(&self, tip_height: u64) -> Option<u64> {
        match &self.mode {
            PruningMode::Archive => None,
            PruningMode::Standard { keep_blocks } => {
                // Never prune below safety margin
                let safe_height = tip_height.saturating_sub(PRUNING_SAFETY_MARGIN);
                let keep_height = tip_height.saturating_sub(*keep_blocks);

                // Use the higher of the two (more conservative)
                Some(keep_height.min(safe_height))
            }
            PruningMode::Aggressive { .. } => {
                // Keep minimal blocks but respect safety margin
                let safe_height = tip_height.saturating_sub(PRUNING_SAFETY_MARGIN);
                Some(safe_height.saturating_sub(1000)) // Keep at least 1000 blocks
            }
        }
    }

    /// Check if a block at the given height should be pruned.
    ///
    /// # Arguments
    ///
    /// * `height` - Block height to check
    /// * `tip_height` - Current chain tip height
    ///
    /// # Returns
    ///
    /// True if the block can be pruned.
    pub fn should_prune(&self, height: u64, tip_height: u64) -> bool {
        // Never prune genesis
        if height == 0 {
            return false;
        }

        // Check threshold
        match self.prune_threshold(tip_height) {
            Some(threshold) => height < threshold,
            None => false, // Archive mode - never prune
        }
    }

    /// Prune blocks from storage.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend to prune
    /// * `tip_height` - Current chain tip height
    /// * `get_height` - Function to get block height from hash
    ///
    /// # Returns
    ///
    /// Statistics about the pruning operation.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub async fn prune<B, F>(
        &mut self,
        storage: &B,
        tip_height: u64,
        get_height: F,
    ) -> Result<PruningStats>
    where
        B: StorageBackend + ?Sized,
        F: Fn(&Hash256) -> Option<u64>,
    {
        let start = std::time::Instant::now();

        // Check if pruning is enabled
        let _threshold = match self.prune_threshold(tip_height) {
            Some(t) => t,
            None => {
                // Archive mode - no pruning
                return Ok(PruningStats {
                    oldest_height: 0,
                    newest_height: tip_height,
                    ..Default::default()
                });
            }
        };

        // Get all block hashes
        let hashes = storage.list_block_hashes().await?;

        // Find blocks to prune
        let mut to_delete = Vec::new();
        let mut retained_heights = Vec::new();

        for hash in &hashes {
            if let Some(height) = get_height(hash) {
                if self.should_prune(height, tip_height) {
                    to_delete.push((hash.clone(), height));
                } else {
                    retained_heights.push(height);
                }
            }
        }

        // Delete blocks
        let mut bytes_freed = 0u64;
        let mut blocks_deleted = 0u64;

        // CHAIN-FIX-10: Named constant for estimated bytes per block. The storage
        // backend does not expose per-block size information during deletion, so we
        // use a rough estimate. A more accurate approach would require querying block
        // size before deletion, which is a future improvement.
        const ESTIMATED_BYTES_PER_BLOCK: u64 = 2048;

        for (hash, _height) in &to_delete {
            if storage.delete_block(hash).await? {
                blocks_deleted += 1;
                bytes_freed += ESTIMATED_BYTES_PER_BLOCK;
            }
        }

        // Calculate oldest retained height
        let oldest_height = retained_heights.iter().copied().min().unwrap_or(0);

        let stats = PruningStats {
            blocks_deleted,
            bytes_freed,
            blocks_retained: retained_heights.len() as u64,
            oldest_height,
            newest_height: tip_height,
            duration_ms: start.elapsed().as_millis() as u64,
        };

        // Update cumulative stats
        self.total_stats.blocks_deleted += stats.blocks_deleted;
        self.total_stats.bytes_freed += stats.bytes_freed;

        Ok(stats)
    }

    /// Prune blocks with explicit list of protected hashes.
    ///
    /// Some blocks may need to be protected beyond the normal retention
    /// (e.g., finalized checkpoints, validator attestations).
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend
    /// * `tip_height` - Chain tip height
    /// * `get_height` - Function to get height from hash
    /// * `protected` - Set of hashes that must not be pruned
    pub async fn prune_with_protection<B, F>(
        &mut self,
        storage: &B,
        tip_height: u64,
        get_height: F,
        protected: &HashSet<Hash256>,
    ) -> Result<PruningStats>
    where
        B: StorageBackend + ?Sized,
        F: Fn(&Hash256) -> Option<u64>,
    {
        let start = std::time::Instant::now();

        let _threshold = match self.prune_threshold(tip_height) {
            Some(t) => t,
            None => {
                return Ok(PruningStats {
                    oldest_height: 0,
                    newest_height: tip_height,
                    ..Default::default()
                });
            }
        };

        let hashes = storage.list_block_hashes().await?;

        let mut to_delete = Vec::new();
        let mut retained_heights = Vec::new();

        for hash in &hashes {
            // Skip protected blocks
            if protected.contains(hash) {
                if let Some(height) = get_height(hash) {
                    retained_heights.push(height);
                }
                continue;
            }

            if let Some(height) = get_height(hash) {
                if self.should_prune(height, tip_height) {
                    to_delete.push((hash.clone(), height));
                } else {
                    retained_heights.push(height);
                }
            }
        }

        let mut bytes_freed = 0u64;
        let mut blocks_deleted = 0u64;

        // CHAIN-FIX-10: Use named constant for estimated bytes per block
        const ESTIMATED_BYTES_PER_BLOCK: u64 = 2048;

        for (hash, _height) in &to_delete {
            if storage.delete_block(hash).await? {
                blocks_deleted += 1;
                bytes_freed += ESTIMATED_BYTES_PER_BLOCK;
            }
        }

        let oldest_height = retained_heights.iter().copied().min().unwrap_or(0);

        let stats = PruningStats {
            blocks_deleted,
            bytes_freed,
            blocks_retained: retained_heights.len() as u64,
            oldest_height,
            newest_height: tip_height,
            duration_ms: start.elapsed().as_millis() as u64,
        };

        self.total_stats.blocks_deleted += stats.blocks_deleted;
        self.total_stats.bytes_freed += stats.bytes_freed;

        Ok(stats)
    }

    /// Estimate how many blocks would be pruned.
    ///
    /// This is useful for previewing a pruning operation without
    /// actually deleting anything.
    ///
    /// # Arguments
    ///
    /// * `current_blocks` - Number of blocks in storage
    /// * `tip_height` - Current chain tip height
    ///
    /// # Returns
    ///
    /// Estimated number of blocks that would be pruned.
    pub fn estimate_prunable(&self, current_blocks: u64, tip_height: u64) -> u64 {
        match self.prune_threshold(tip_height) {
            Some(threshold) => {
                // Rough estimate: blocks below threshold
                if tip_height > threshold {
                    threshold.min(current_blocks)
                } else {
                    0
                }
            }
            None => 0,
        }
    }

    /// Get recommended pruning interval based on mode.
    ///
    /// Returns the recommended number of blocks between pruning runs.
    pub fn recommended_interval(&self) -> u64 {
        match &self.mode {
            PruningMode::Archive => u64::MAX,                          // Never
            PruningMode::Standard { keep_blocks } => keep_blocks / 10, // Every 10% of retention
            PruningMode::Aggressive { .. } => 100,                     // Frequent pruning
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Block;
    use crate::config::{DEFAULT_KEEP_BLOCKS, PRUNING_SAFETY_MARGIN};
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

    // ==================== Pruning Mode Tests ====================

    #[test]
    fn test_archive_mode_never_prunes() {
        let pruner = ChainPruner::new(PruningMode::Archive);

        assert!(pruner.prune_threshold(1000).is_none());
        assert!(!pruner.should_prune(1, 1000));
        assert!(!pruner.should_prune(500, 1000));
    }

    #[test]
    fn test_standard_mode_threshold() {
        let pruner = ChainPruner::new(PruningMode::Standard {
            keep_blocks: DEFAULT_KEEP_BLOCKS,
        });

        let tip = 20000;
        let threshold = pruner.prune_threshold(tip).unwrap();

        // Should be tip - keep_blocks
        assert_eq!(threshold, tip - DEFAULT_KEEP_BLOCKS);
    }

    #[test]
    fn test_standard_mode_respects_safety_margin() {
        let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 50 });

        let tip = 200;
        let threshold = pruner.prune_threshold(tip).unwrap();

        // Should respect safety margin
        assert!(threshold <= tip - PRUNING_SAFETY_MARGIN);
    }

    #[test]
    fn test_genesis_never_pruned() {
        let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 10 });

        // Genesis should never be pruned regardless of tip
        assert!(!pruner.should_prune(0, 100));
        assert!(!pruner.should_prune(0, 10000));
        assert!(!pruner.should_prune(0, 1000000));
    }

    #[test]
    fn test_recent_blocks_not_pruned() {
        let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 100 });
        let tip = 1000;

        // Recent blocks should not be pruned
        for height in (tip - PRUNING_SAFETY_MARGIN)..=tip {
            assert!(!pruner.should_prune(height, tip));
        }
    }

    #[test]
    fn test_old_blocks_pruned() {
        let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 100 });
        let tip = 1000;

        // Old blocks should be pruned (except genesis)
        assert!(pruner.should_prune(100, tip));
        assert!(pruner.should_prune(500, tip));
    }

    // ==================== Pruning Execution Tests ====================

    #[tokio::test]
    async fn test_prune_removes_old_blocks() {
        let storage = InMemoryBackend::new();
        // Use keep_blocks = 50 and create 500 blocks to ensure pruning happens
        // (PRUNING_SAFETY_MARGIN is 100, so we need chain > 150 to see any pruning)
        let mut pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 50 });

        // Store 500 blocks (need enough to exceed safety margin + keep_blocks)
        let mut blocks = Vec::new();
        for i in 0..500 {
            let block = create_test_block(i);
            blocks.push(block.clone());
            storage.store_block(&block).await.unwrap();
        }

        assert_eq!(storage.count_blocks(), 500);

        // Create height lookup
        let height_map: std::collections::HashMap<_, _> = blocks
            .iter()
            .map(|b| (b.hash().clone(), b.height()))
            .collect();

        let get_height = |hash: &Hash256| height_map.get(hash).copied();

        // Prune with tip at height 499
        let stats = pruner.prune(&storage, 499, get_height).await.unwrap();

        // With tip=499, safety_margin=100, keep_blocks=50:
        // safe_height = 499 - 100 = 399
        // keep_height = 499 - 50 = 449
        // threshold = min(449, 399) = 399
        // Blocks 1-398 should be pruned (genesis 0 is protected)
        assert!(
            stats.blocks_deleted > 0,
            "Expected some blocks to be deleted"
        );
        assert!(
            storage.count_blocks() < 500,
            "Expected fewer blocks after pruning"
        );
    }

    #[tokio::test]
    async fn test_prune_archive_mode_no_deletion() {
        let storage = InMemoryBackend::new();
        let mut pruner = ChainPruner::new(PruningMode::Archive);

        // Store blocks
        for i in 0..50 {
            let block = create_test_block(i);
            storage.store_block(&block).await.unwrap();
        }

        let initial_count = storage.count_blocks();

        let stats = pruner.prune(&storage, 49, |_| Some(0)).await.unwrap();

        assert_eq!(stats.blocks_deleted, 0);
        assert_eq!(storage.count_blocks(), initial_count);
    }

    #[tokio::test]
    async fn test_prune_with_protection() {
        let storage = InMemoryBackend::new();
        let mut pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 10 });

        // Store blocks
        let mut blocks = Vec::new();
        for i in 0..50 {
            let block = create_test_block(i);
            blocks.push(block.clone());
            storage.store_block(&block).await.unwrap();
        }

        // Protect block at height 5
        let mut protected = HashSet::new();
        protected.insert(blocks[5].hash().clone());

        let height_map: std::collections::HashMap<_, _> = blocks
            .iter()
            .map(|b| (b.hash().clone(), b.height()))
            .collect();

        let get_height = |hash: &Hash256| height_map.get(hash).copied();

        let _ = pruner
            .prune_with_protection(&storage, 49, get_height, &protected)
            .await
            .unwrap();

        // Protected block should still exist
        assert!(
            storage
                .block_exists(&blocks[5].hash().clone())
                .await
                .unwrap()
        );
    }

    // ==================== Statistics Tests ====================

    #[test]
    fn test_pruning_stats() {
        let stats = PruningStats {
            blocks_deleted: 100,
            bytes_freed: 100000,
            blocks_retained: 50,
            oldest_height: 50,
            newest_height: 100,
            duration_ms: 100,
        };

        assert!(stats.pruned_any());
        assert!(stats.reduction_percent() > 0.0);
    }

    #[test]
    fn test_empty_stats() {
        let stats = PruningStats::default();

        assert!(!stats.pruned_any());
        assert_eq!(stats.reduction_percent(), 0.0);
    }

    // ==================== Estimation Tests ====================

    #[test]
    fn test_estimate_prunable() {
        let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 100 });

        let estimate = pruner.estimate_prunable(1000, 500);

        // Should estimate some prunable blocks
        assert!(estimate > 0);
        assert!(estimate < 1000);
    }

    #[test]
    fn test_estimate_prunable_archive() {
        let pruner = ChainPruner::new(PruningMode::Archive);

        let estimate = pruner.estimate_prunable(1000, 500);
        assert_eq!(estimate, 0);
    }

    // ==================== Interval Tests ====================

    #[test]
    fn test_recommended_interval() {
        let standard = ChainPruner::new(PruningMode::Standard { keep_blocks: 1000 });
        assert_eq!(standard.recommended_interval(), 100);

        let aggressive = ChainPruner::new(PruningMode::aggressive());
        assert_eq!(aggressive.recommended_interval(), 100);

        let archive = ChainPruner::new(PruningMode::Archive);
        assert_eq!(archive.recommended_interval(), u64::MAX);
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_genesis_never_pruned(tip_height in 1u64..1000000) {
            let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 100 });
            prop_assert!(!pruner.should_prune(0, tip_height));
        }

        #[test]
        fn prop_safety_margin_respected(
            tip_height in 200u64..1000000,
            offset in 0u64..100
        ) {
            let pruner = ChainPruner::new(PruningMode::Standard { keep_blocks: 100 });
            let height = tip_height - offset;

            if offset < PRUNING_SAFETY_MARGIN {
                prop_assert!(!pruner.should_prune(height, tip_height));
            }
        }

        #[test]
        fn prop_archive_never_prunes(height in 1u64..1000000, tip in 1u64..1000000) {
            let pruner = ChainPruner::new(PruningMode::Archive);
            prop_assert!(!pruner.should_prune(height, tip));
        }
    }
}
