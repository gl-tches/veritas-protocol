//! Verification types for blockchain message proofs and chain synchronization.
//!
//! This module provides types for verifying message inclusion in the blockchain
//! and tracking chain synchronization status.
//!
//! ## Message Proofs
//!
//! A [`MessageProof`] contains all the cryptographic evidence needed to verify
//! that a message was included in a specific block on the VERITAS blockchain.
//! This enables recipients to independently verify message authenticity without
//! trusting relays or intermediaries.
//!
//! ## Sync Status
//!
//! The [`SyncStatus`] struct tracks the progress of blockchain synchronization,
//! allowing clients to understand how far behind they are and monitor sync progress.
//!
//! ## Example
//!
//! ```ignore
//! use veritas_core::verification::{MessageProof, SyncStatus};
//!
//! // Check if we're synced with the network
//! let status = client.get_sync_status().await?;
//! if status.is_synced() {
//!     // Verify a message proof
//!     let proof = client.get_message_proof(&message_hash).await?;
//!     assert!(proof.proof.verify());
//! }
//! ```

use veritas_chain::{ChainEntry, MerkleProof};
use veritas_crypto::Hash256;

/// Cryptographic proof that a message was included in a specific blockchain block.
///
/// A `MessageProof` bundles together:
/// - The Merkle proof demonstrating the message's inclusion in the block's Merkle tree
/// - The block height and hash identifying which block contains the message
/// - The chain entry recording the message on-chain
///
/// This allows recipients to independently verify that a message was recorded
/// on the VERITAS blockchain, providing non-repudiation and tamper evidence.
///
/// ## Verification
///
/// To verify a message proof:
/// 1. Check that `proof.verify()` returns true (Merkle inclusion)
/// 2. Verify the block hash matches a known block at the specified height
/// 3. Confirm the chain entry contains the expected message data
///
/// ## Example
///
/// ```ignore
/// use veritas_core::verification::MessageProof;
///
/// let proof: MessageProof = client.get_message_proof(&msg_hash).await?;
///
/// // Verify Merkle inclusion
/// assert!(proof.proof.verify(), "Invalid Merkle proof");
///
/// // Check block is at expected height
/// println!("Message in block {} at height {}", proof.block_hash, proof.block_height);
/// ```
#[derive(Clone, Debug)]
pub struct MessageProof {
    /// Merkle proof demonstrating the message entry's inclusion in the block.
    ///
    /// Use `proof.verify()` to cryptographically verify inclusion.
    pub proof: MerkleProof,

    /// Height of the block containing this message.
    ///
    /// Block heights are monotonically increasing from 0 (genesis).
    pub block_height: u64,

    /// Hash of the block containing this message.
    ///
    /// This uniquely identifies the block and can be used to verify
    /// the block is part of the canonical chain.
    pub block_hash: Hash256,

    /// The chain entry recording this message on the blockchain.
    ///
    /// Contains message metadata including sender, recipient, timestamp,
    /// and message hash.
    pub entry: ChainEntry,
}

impl MessageProof {
    /// Create a new message proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - Merkle proof for the message entry
    /// * `block_height` - Height of the containing block
    /// * `block_hash` - Hash of the containing block
    /// * `entry` - The chain entry for this message
    pub fn new(
        proof: MerkleProof,
        block_height: u64,
        block_hash: Hash256,
        entry: ChainEntry,
    ) -> Self {
        Self {
            proof,
            block_height,
            block_hash,
            entry,
        }
    }

    /// Verify the Merkle proof is valid.
    ///
    /// This checks that the message entry is correctly included in the
    /// block's Merkle tree. It does NOT verify that the block itself
    /// is valid or part of the canonical chain.
    ///
    /// # Returns
    ///
    /// `true` if the Merkle proof is valid, `false` otherwise.
    pub fn verify_inclusion(&self) -> bool {
        self.proof.verify()
    }
}

/// Status of blockchain synchronization with the network.
///
/// `SyncStatus` tracks the progress of syncing the local blockchain state
/// with the broader VERITAS network. Clients use this to:
///
/// - Determine if they have the latest chain state
/// - Monitor sync progress during initial sync or after network reconnection
/// - Estimate time to completion based on pending work
///
/// ## Sync States
///
/// - **Synced**: `is_synced()` returns true when local state matches network
/// - **Syncing**: `is_syncing` is true while actively downloading blocks
/// - **Behind**: `local_height < network_height` indicates missing blocks
///
/// ## Example
///
/// ```ignore
/// use veritas_core::verification::SyncStatus;
///
/// let status = client.get_sync_status().await?;
///
/// if status.is_synced() {
///     println!("Fully synced at height {}", status.local_height);
/// } else {
///     println!(
///         "Syncing: {:.1}% complete ({} headers, {} blocks pending)",
///         status.progress_percent,
///         status.pending_headers,
///         status.pending_blocks
///     );
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SyncStatus {
    /// Current height of the local blockchain.
    ///
    /// This is the height of the latest block we have fully validated
    /// and stored locally.
    pub local_height: u64,

    /// Highest known block height on the network.
    ///
    /// Determined from peer announcements and header downloads.
    /// May be 0 if we haven't connected to any peers yet.
    pub network_height: u64,

    /// Whether synchronization is currently in progress.
    ///
    /// `true` when actively downloading and processing blocks,
    /// `false` when idle (either synced or paused).
    pub is_syncing: bool,

    /// Number of block headers waiting to be processed.
    ///
    /// Headers are downloaded first during sync, then full blocks
    /// are requested for valid headers.
    pub pending_headers: usize,

    /// Number of full blocks waiting to be processed.
    ///
    /// These are blocks that have been downloaded but not yet
    /// validated and added to the chain.
    pub pending_blocks: usize,

    /// Estimated sync progress as a percentage (0.0 to 100.0).
    ///
    /// Calculated as `(local_height / network_height) * 100`.
    /// May be 100.0 even if `is_syncing` is true if we're processing
    /// the final blocks.
    pub progress_percent: f32,
}

impl SyncStatus {
    /// Create a new sync status.
    ///
    /// # Arguments
    ///
    /// * `local_height` - Current local chain height
    /// * `network_height` - Known network chain height
    /// * `is_syncing` - Whether actively syncing
    /// * `pending_headers` - Headers awaiting processing
    /// * `pending_blocks` - Blocks awaiting processing
    /// * `progress_percent` - Sync progress percentage
    pub fn new(
        local_height: u64,
        network_height: u64,
        is_syncing: bool,
        pending_headers: usize,
        pending_blocks: usize,
        progress_percent: f32,
    ) -> Self {
        Self {
            local_height,
            network_height,
            is_syncing,
            pending_headers,
            pending_blocks,
            progress_percent,
        }
    }

    /// Create a status indicating we are fully synced.
    ///
    /// # Arguments
    ///
    /// * `height` - The current chain height (both local and network)
    pub fn synced(height: u64) -> Self {
        Self {
            local_height: height,
            network_height: height,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        }
    }

    /// Check if the local chain is fully synchronized with the network.
    ///
    /// Returns `true` when:
    /// - We are not actively syncing (`!is_syncing`)
    /// - Our local height is at or above the known network height
    ///
    /// Note: This may briefly return `false` even when synced if we
    /// just learned about a new block. Check `pending_blocks` to see
    /// if there's actually work to do.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let status = client.get_sync_status().await?;
    /// if status.is_synced() {
    ///     // Safe to verify proofs against current chain state
    /// }
    /// ```
    pub fn is_synced(&self) -> bool {
        !self.is_syncing && self.local_height >= self.network_height
    }

    /// Get the number of blocks we are behind the network.
    ///
    /// Returns 0 if we are at or ahead of the network height.
    pub fn blocks_behind(&self) -> u64 {
        self.network_height.saturating_sub(self.local_height)
    }

    /// Check if we have any pending work.
    ///
    /// Returns `true` if there are headers or blocks waiting to be processed.
    pub fn has_pending_work(&self) -> bool {
        self.pending_headers > 0 || self.pending_blocks > 0
    }
}

impl Default for SyncStatus {
    /// Create a default sync status indicating no sync has started.
    ///
    /// All values are zero/false, representing a fresh node that
    /// hasn't connected to the network yet.
    fn default() -> Self {
        Self {
            local_height: 0,
            network_height: 0,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_chain::merkle::MerkleTree;
    use veritas_identity::IdentityHash;

    // Helper to create a test identity hash
    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    // Helper to create a test hash
    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    // ==================== MessageProof Tests ====================

    #[test]
    fn test_message_proof_creation() {
        // Create a simple Merkle tree for the proof
        let leaves = vec![Hash256::hash(b"message1"), Hash256::hash(b"message2")];
        let tree = MerkleTree::new(leaves).unwrap();
        let merkle_proof = tree.generate_proof(0).unwrap();

        // Create a chain entry
        let entry = ChainEntry::MessageProof {
            message_hash: test_hash(1),
            sender_hash: test_identity(2),
            recipient_hash: test_identity(3),
            timestamp: 1700000000,
            merkle_proof: None,
        };

        let proof = MessageProof::new(merkle_proof.clone(), 100, test_hash(10), entry.clone());

        assert_eq!(proof.block_height, 100);
        assert_eq!(proof.block_hash, test_hash(10));
        assert!(proof.verify_inclusion());
    }

    #[test]
    fn test_message_proof_verify_inclusion() {
        let leaves = vec![
            Hash256::hash(b"tx1"),
            Hash256::hash(b"tx2"),
            Hash256::hash(b"tx3"),
        ];
        let tree = MerkleTree::new(leaves).unwrap();
        let merkle_proof = tree.generate_proof(1).unwrap();

        let entry = ChainEntry::MessageProof {
            message_hash: test_hash(1),
            sender_hash: test_identity(2),
            recipient_hash: test_identity(3),
            timestamp: 1700000000,
            merkle_proof: None,
        };

        let proof = MessageProof::new(merkle_proof, 50, test_hash(5), entry);

        assert!(proof.verify_inclusion());
    }

    // ==================== SyncStatus Tests ====================

    #[test]
    fn test_sync_status_is_synced_when_matching() {
        let status = SyncStatus {
            local_height: 100,
            network_height: 100,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        };

        assert!(status.is_synced());
    }

    #[test]
    fn test_sync_status_is_synced_when_ahead() {
        let status = SyncStatus {
            local_height: 105,
            network_height: 100,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        };

        assert!(status.is_synced());
    }

    #[test]
    fn test_sync_status_not_synced_when_behind() {
        let status = SyncStatus {
            local_height: 90,
            network_height: 100,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 90.0,
        };

        assert!(!status.is_synced());
    }

    #[test]
    fn test_sync_status_not_synced_when_syncing() {
        let status = SyncStatus {
            local_height: 100,
            network_height: 100,
            is_syncing: true, // Still syncing
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        };

        assert!(!status.is_synced());
    }

    #[test]
    fn test_sync_status_blocks_behind() {
        let status = SyncStatus {
            local_height: 80,
            network_height: 100,
            is_syncing: true,
            pending_headers: 10,
            pending_blocks: 5,
            progress_percent: 80.0,
        };

        assert_eq!(status.blocks_behind(), 20);
    }

    #[test]
    fn test_sync_status_blocks_behind_when_ahead() {
        let status = SyncStatus {
            local_height: 110,
            network_height: 100,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        };

        assert_eq!(status.blocks_behind(), 0);
    }

    #[test]
    fn test_sync_status_has_pending_work() {
        let status_with_headers = SyncStatus {
            local_height: 50,
            network_height: 100,
            is_syncing: true,
            pending_headers: 10,
            pending_blocks: 0,
            progress_percent: 50.0,
        };
        assert!(status_with_headers.has_pending_work());

        let status_with_blocks = SyncStatus {
            local_height: 50,
            network_height: 100,
            is_syncing: true,
            pending_headers: 0,
            pending_blocks: 5,
            progress_percent: 50.0,
        };
        assert!(status_with_blocks.has_pending_work());

        let status_no_pending = SyncStatus {
            local_height: 100,
            network_height: 100,
            is_syncing: false,
            pending_headers: 0,
            pending_blocks: 0,
            progress_percent: 100.0,
        };
        assert!(!status_no_pending.has_pending_work());
    }

    #[test]
    fn test_sync_status_synced_constructor() {
        let status = SyncStatus::synced(150);

        assert_eq!(status.local_height, 150);
        assert_eq!(status.network_height, 150);
        assert!(!status.is_syncing);
        assert_eq!(status.pending_headers, 0);
        assert_eq!(status.pending_blocks, 0);
        assert_eq!(status.progress_percent, 100.0);
        assert!(status.is_synced());
    }

    #[test]
    fn test_sync_status_new_constructor() {
        let status = SyncStatus::new(50, 100, true, 20, 10, 50.0);

        assert_eq!(status.local_height, 50);
        assert_eq!(status.network_height, 100);
        assert!(status.is_syncing);
        assert_eq!(status.pending_headers, 20);
        assert_eq!(status.pending_blocks, 10);
        assert_eq!(status.progress_percent, 50.0);
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();

        assert_eq!(status.local_height, 0);
        assert_eq!(status.network_height, 0);
        assert!(!status.is_syncing);
        assert_eq!(status.pending_headers, 0);
        assert_eq!(status.pending_blocks, 0);
        assert_eq!(status.progress_percent, 0.0);
    }

    #[test]
    fn test_sync_status_clone() {
        let status = SyncStatus::new(75, 100, true, 15, 8, 75.0);
        let cloned = status.clone();

        assert_eq!(status.local_height, cloned.local_height);
        assert_eq!(status.network_height, cloned.network_height);
        assert_eq!(status.is_syncing, cloned.is_syncing);
        assert_eq!(status.pending_headers, cloned.pending_headers);
        assert_eq!(status.pending_blocks, cloned.pending_blocks);
        assert_eq!(status.progress_percent, cloned.progress_percent);
    }

    #[test]
    fn test_message_proof_clone() {
        let leaves = vec![Hash256::hash(b"leaf1")];
        let tree = MerkleTree::new(leaves).unwrap();
        let merkle_proof = tree.generate_proof(0).unwrap();

        let entry = ChainEntry::MessageProof {
            message_hash: test_hash(1),
            sender_hash: test_identity(2),
            recipient_hash: test_identity(3),
            timestamp: 1700000000,
            merkle_proof: None,
        };

        let proof = MessageProof::new(merkle_proof, 100, test_hash(10), entry);
        let cloned = proof.clone();

        assert_eq!(proof.block_height, cloned.block_height);
        assert_eq!(proof.block_hash, cloned.block_hash);
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_sync_status_is_synced_consistent(
            local in 0u64..1000,
            network in 0u64..1000,
            syncing in any::<bool>()
        ) {
            let status = SyncStatus {
                local_height: local,
                network_height: network,
                is_syncing: syncing,
                pending_headers: 0,
                pending_blocks: 0,
                progress_percent: if network == 0 { 0.0 } else { (local as f32 / network as f32) * 100.0 },
            };

            // is_synced should be true iff not syncing AND local >= network
            let expected = !syncing && local >= network;
            prop_assert_eq!(status.is_synced(), expected);
        }

        #[test]
        fn prop_blocks_behind_correct(local in 0u64..1000, network in 0u64..1000) {
            let status = SyncStatus {
                local_height: local,
                network_height: network,
                is_syncing: false,
                pending_headers: 0,
                pending_blocks: 0,
                progress_percent: 0.0,
            };

            let expected = network.saturating_sub(local);
            prop_assert_eq!(status.blocks_behind(), expected);
        }

        #[test]
        fn prop_has_pending_work_correct(headers in 0usize..100, blocks in 0usize..100) {
            let status = SyncStatus {
                local_height: 0,
                network_height: 100,
                is_syncing: true,
                pending_headers: headers,
                pending_blocks: blocks,
                progress_percent: 0.0,
            };

            let expected = headers > 0 || blocks > 0;
            prop_assert_eq!(status.has_pending_work(), expected);
        }

        #[test]
        fn prop_synced_constructor_always_synced(height in 0u64..1000000) {
            let status = SyncStatus::synced(height);
            prop_assert!(status.is_synced());
            prop_assert_eq!(status.local_height, height);
            prop_assert_eq!(status.network_height, height);
            prop_assert_eq!(status.blocks_behind(), 0);
        }
    }
}
