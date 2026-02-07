//! Epoch-based pruning for the VERITAS blockchain.
//!
//! Epochs are 30-day periods. At epoch boundaries, message bodies and signatures
//! are deterministically pruned from all nodes. Only headers remain permanently.
//!
//! ## Pruning Rules (AD-2)
//!
//! During epoch: Full transaction on-chain (ML-DSA sig + encrypted body + header)
//! After epoch ends: Body + signature PRUNED → only header remains permanently
//! Headers are verifiable via Merkle proof against signed block header.
//! Pruning is deterministic — same epoch boundary on all nodes.

use serde::{Deserialize, Serialize};

/// Duration of one epoch in seconds (30 days).
pub const EPOCH_DURATION_SECS: u64 = 30 * 24 * 60 * 60; // 2,592,000

/// Minimum valid epoch number.
pub const MIN_EPOCH: u64 = 0;

/// Epoch manager for tracking and computing epoch boundaries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochManager {
    /// Genesis timestamp (start of epoch 0).
    pub genesis_timestamp: u64,
    /// Current epoch number.
    pub current_epoch: u64,
}

impl EpochManager {
    /// Create a new epoch manager with the given genesis timestamp.
    pub fn new(genesis_timestamp: u64) -> Self {
        Self {
            genesis_timestamp,
            current_epoch: 0,
        }
    }

    /// Get the epoch number for a given timestamp.
    pub fn epoch_for_timestamp(&self, timestamp: u64) -> u64 {
        if timestamp < self.genesis_timestamp {
            return 0;
        }
        (timestamp - self.genesis_timestamp) / EPOCH_DURATION_SECS
    }

    /// Get the start timestamp of a given epoch.
    pub fn epoch_start(&self, epoch: u64) -> u64 {
        self.genesis_timestamp + epoch * EPOCH_DURATION_SECS
    }

    /// Get the end timestamp of a given epoch.
    pub fn epoch_end(&self, epoch: u64) -> u64 {
        self.epoch_start(epoch + 1)
    }

    /// Check if an epoch has ended (eligible for pruning).
    pub fn is_epoch_ended(&self, epoch: u64, current_time: u64) -> bool {
        current_time >= self.epoch_end(epoch)
    }

    /// Update the current epoch based on a timestamp.
    pub fn update_epoch(&mut self, current_time: u64) {
        self.current_epoch = self.epoch_for_timestamp(current_time);
    }

    /// Get all epoch numbers that are eligible for pruning (ended epochs).
    pub fn prunable_epochs(&self, current_time: u64) -> Vec<u64> {
        let current = self.epoch_for_timestamp(current_time);
        if current == 0 {
            return vec![];
        }
        // All epochs before the current one are prunable
        (0..current).collect()
    }

    /// Check if a block at the given height/timestamp should be pruned.
    pub fn should_prune_block(&self, block_timestamp: u64, current_time: u64) -> bool {
        let block_epoch = self.epoch_for_timestamp(block_timestamp);
        self.is_epoch_ended(block_epoch, current_time)
    }
}

/// Result of a pruning operation.
#[derive(Clone, Debug, Default)]
pub struct PruneResult {
    /// Number of transactions pruned.
    pub transactions_pruned: u64,
    /// Number of bytes freed.
    pub bytes_freed: u64,
    /// Epochs that were pruned.
    pub epochs_pruned: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: u64 = 1_700_000_000;

    #[test]
    fn test_epoch_for_timestamp() {
        let em = EpochManager::new(GENESIS);

        assert_eq!(em.epoch_for_timestamp(GENESIS), 0);
        assert_eq!(em.epoch_for_timestamp(GENESIS + 1), 0);
        assert_eq!(em.epoch_for_timestamp(GENESIS + EPOCH_DURATION_SECS - 1), 0);
        assert_eq!(em.epoch_for_timestamp(GENESIS + EPOCH_DURATION_SECS), 1);
        assert_eq!(em.epoch_for_timestamp(GENESIS + 2 * EPOCH_DURATION_SECS), 2);
    }

    #[test]
    fn test_epoch_for_timestamp_before_genesis() {
        let em = EpochManager::new(GENESIS);
        assert_eq!(em.epoch_for_timestamp(GENESIS - 1000), 0);
    }

    #[test]
    fn test_epoch_boundaries() {
        let em = EpochManager::new(GENESIS);

        assert_eq!(em.epoch_start(0), GENESIS);
        assert_eq!(em.epoch_end(0), GENESIS + EPOCH_DURATION_SECS);
        assert_eq!(em.epoch_start(1), GENESIS + EPOCH_DURATION_SECS);
    }

    #[test]
    fn test_is_epoch_ended() {
        let em = EpochManager::new(GENESIS);

        // Epoch 0 hasn't ended yet at genesis
        assert!(!em.is_epoch_ended(0, GENESIS));
        // Epoch 0 hasn't ended 1 second before boundary
        assert!(!em.is_epoch_ended(0, GENESIS + EPOCH_DURATION_SECS - 1));
        // Epoch 0 has ended at the boundary
        assert!(em.is_epoch_ended(0, GENESIS + EPOCH_DURATION_SECS));
    }

    #[test]
    fn test_prunable_epochs() {
        let em = EpochManager::new(GENESIS);

        // No prunable epochs in epoch 0
        assert!(em.prunable_epochs(GENESIS).is_empty());

        // In epoch 1, epoch 0 is prunable
        let time_in_epoch1 = GENESIS + EPOCH_DURATION_SECS + 1;
        assert_eq!(em.prunable_epochs(time_in_epoch1), vec![0]);

        // In epoch 2, epochs 0 and 1 are prunable
        let time_in_epoch2 = GENESIS + 2 * EPOCH_DURATION_SECS + 1;
        assert_eq!(em.prunable_epochs(time_in_epoch2), vec![0, 1]);
    }

    #[test]
    fn test_should_prune_block() {
        let em = EpochManager::new(GENESIS);

        // Block from epoch 0, current time in epoch 1: should prune
        assert!(em.should_prune_block(GENESIS + 100, GENESIS + EPOCH_DURATION_SECS + 1));

        // Block from epoch 0, current time still in epoch 0: should not prune
        assert!(!em.should_prune_block(GENESIS + 100, GENESIS + 100));
    }

    #[test]
    fn test_update_epoch() {
        let mut em = EpochManager::new(GENESIS);
        assert_eq!(em.current_epoch, 0);

        em.update_epoch(GENESIS + EPOCH_DURATION_SECS + 1);
        assert_eq!(em.current_epoch, 1);

        em.update_epoch(GENESIS + 5 * EPOCH_DURATION_SECS + 1);
        assert_eq!(em.current_epoch, 5);
    }
}
