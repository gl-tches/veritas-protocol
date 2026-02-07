//! Epoch-based pruning for the VERITAS blockchain.
//!
//! Epochs are 30-day periods. At epoch boundaries:
//! - Message bodies + ML-DSA signatures are pruned
//! - Only `MessageHeader` remains permanently
//! - Pruning is deterministic (same boundary on all nodes)
//!
//! Headers are verifiable via Merkle proof against signed block headers.

use crate::transaction::Transaction;
use veritas_crypto::Hash256;

/// Epoch duration in seconds (30 days).
pub const EPOCH_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Get the epoch number for a given timestamp.
pub fn epoch_for_timestamp(timestamp: u64) -> u64 {
    timestamp / EPOCH_DURATION_SECS
}

/// Get the start timestamp of an epoch.
pub fn epoch_start(epoch: u64) -> u64 {
    epoch * EPOCH_DURATION_SECS
}

/// Get the end timestamp of an epoch.
pub fn epoch_end(epoch: u64) -> u64 {
    (epoch + 1) * EPOCH_DURATION_SECS
}

/// Check if an epoch has ended relative to the current time.
pub fn is_epoch_ended(epoch: u64, current_timestamp: u64) -> bool {
    current_timestamp >= epoch_end(epoch)
}

/// Get the current epoch number.
pub fn current_epoch() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();
    epoch_for_timestamp(now)
}

/// Statistics from a pruning operation.
#[derive(Debug, Clone, Default)]
pub struct EpochPruningStats {
    /// Number of transactions examined.
    pub transactions_examined: u64,
    /// Number of message bodies pruned.
    pub bodies_pruned: u64,
    /// Number of signatures pruned.
    pub signatures_pruned: u64,
    /// Approximate bytes freed.
    pub bytes_freed: u64,
    /// Epoch that was pruned.
    pub pruned_epoch: u64,
}

/// Prune a list of transactions for a completed epoch.
///
/// Removes message bodies and signatures from `MessageTransaction`s.
/// Headers are preserved permanently.
///
/// # Arguments
/// * `transactions` - The transactions to prune (modified in place)
/// * `epoch` - The epoch that has completed
/// * `current_timestamp` - Current time for epoch boundary check
///
/// # Returns
/// Pruning statistics.
pub fn prune_epoch_transactions(
    transactions: &mut [Transaction],
    epoch: u64,
    current_timestamp: u64,
) -> EpochPruningStats {
    let mut stats = EpochPruningStats {
        pruned_epoch: epoch,
        ..Default::default()
    };

    if !is_epoch_ended(epoch, current_timestamp) {
        return stats;
    }

    for tx in transactions.iter_mut() {
        stats.transactions_examined += 1;

        if let Transaction::Message(msg_tx) = tx {
            if !msg_tx.is_pruned() {
                // Calculate bytes being freed
                if let Some(ref body) = msg_tx.body {
                    stats.bytes_freed +=
                        body.ciphertext.len() as u64 + 32 + 24; // ciphertext + ephemeral + nonce
                }
                if let Some(ref sig) = msg_tx.signature {
                    stats.bytes_freed += sig.len() as u64;
                }

                msg_tx.prune();
                stats.bodies_pruned += 1;
                stats.signatures_pruned += 1;
            }
        }
    }

    stats
}

/// Verify a pruned transaction header against a Merkle proof.
///
/// After pruning, headers can be verified by:
/// 1. Computing the header hash
/// 2. Verifying the Merkle proof against the block's `merkle_root`
/// 3. The block header itself is ML-DSA signed by the validator
pub fn verify_pruned_header(
    header_hash: &Hash256,
    merkle_proof: &[Hash256],
    merkle_root: &Hash256,
    leaf_index: usize,
) -> bool {
    let mut current = header_hash.clone();
    let mut index = leaf_index;

    for sibling in merkle_proof {
        current = if index % 2 == 0 {
            Hash256::hash_many(&[current.as_bytes(), sibling.as_bytes()])
        } else {
            Hash256::hash_many(&[sibling.as_bytes(), current.as_bytes()])
        };
        index /= 2;
    }

    current == *merkle_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{EncryptedBody, MessageHeader, MessageTransaction};

    #[test]
    fn test_epoch_for_timestamp() {
        assert_eq!(epoch_for_timestamp(0), 0);
        assert_eq!(epoch_for_timestamp(EPOCH_DURATION_SECS - 1), 0);
        assert_eq!(epoch_for_timestamp(EPOCH_DURATION_SECS), 1);
        assert_eq!(epoch_for_timestamp(EPOCH_DURATION_SECS * 3 + 100), 3);
    }

    #[test]
    fn test_epoch_start_end() {
        assert_eq!(epoch_start(0), 0);
        assert_eq!(epoch_end(0), EPOCH_DURATION_SECS);
        assert_eq!(epoch_start(1), EPOCH_DURATION_SECS);
        assert_eq!(epoch_end(1), EPOCH_DURATION_SECS * 2);
    }

    #[test]
    fn test_is_epoch_ended() {
        assert!(!is_epoch_ended(0, 0));
        assert!(!is_epoch_ended(0, EPOCH_DURATION_SECS - 1));
        assert!(is_epoch_ended(0, EPOCH_DURATION_SECS));
        assert!(is_epoch_ended(0, EPOCH_DURATION_SECS + 1));
    }

    #[test]
    fn test_current_epoch_is_reasonable() {
        let epoch = current_epoch();
        // After 2024-01-01 we should be at least epoch 20+
        assert!(epoch > 0);
    }

    fn make_test_tx() -> Transaction {
        Transaction::Message(MessageTransaction::new(
            MessageHeader::new([0xAA; 32], 1700000000, Hash256::hash(b"body"), 100, 0),
            EncryptedBody {
                ephemeral_public: [0xBB; 32],
                nonce: [0xCC; 24],
                ciphertext: vec![0xDD; 1024],
            },
            vec![0xEE; 3309],
        ))
    }

    #[test]
    fn test_prune_epoch_transactions() {
        let mut txs = vec![make_test_tx(), make_test_tx()];
        let stats = prune_epoch_transactions(&mut txs, 0, EPOCH_DURATION_SECS);

        assert_eq!(stats.transactions_examined, 2);
        assert_eq!(stats.bodies_pruned, 2);
        assert_eq!(stats.signatures_pruned, 2);
        assert!(stats.bytes_freed > 0);

        for tx in &txs {
            assert!(tx.as_message().unwrap().is_pruned());
            // Header survives
            assert_eq!(tx.as_message().unwrap().header.block_height, 100);
        }
    }

    #[test]
    fn test_prune_skips_non_ended_epoch() {
        let mut txs = vec![make_test_tx()];
        let stats = prune_epoch_transactions(&mut txs, 0, EPOCH_DURATION_SECS - 1);

        assert_eq!(stats.bodies_pruned, 0);
        assert!(!txs[0].as_message().unwrap().is_pruned());
    }

    #[test]
    fn test_prune_skips_already_pruned() {
        let mut txs = vec![make_test_tx()];
        // First pruning
        prune_epoch_transactions(&mut txs, 0, EPOCH_DURATION_SECS);
        // Second pruning — should not count again
        let stats = prune_epoch_transactions(&mut txs, 0, EPOCH_DURATION_SECS);
        assert_eq!(stats.bodies_pruned, 0);
        assert_eq!(stats.bytes_freed, 0);
    }

    #[test]
    fn test_prune_skips_non_message_transactions() {
        let mut txs = vec![Transaction::IdentityRegistration {
            identity_hash: veritas_identity::IdentityHash::from_bytes(&[1u8; 32]).unwrap(),
            public_keys: vec![0; 100],
            timestamp: 1700000000,
            signature: vec![0; 3309],
        }];
        let stats = prune_epoch_transactions(&mut txs, 0, EPOCH_DURATION_SECS);
        assert_eq!(stats.transactions_examined, 1);
        assert_eq!(stats.bodies_pruned, 0);
    }

    #[test]
    fn test_verify_pruned_header_single_leaf() {
        // Single leaf = the leaf IS the root
        let leaf = Hash256::hash(b"leaf");
        assert!(verify_pruned_header(&leaf, &[], &leaf, 0));
    }

    #[test]
    fn test_verify_pruned_header_two_leaves() {
        let leaf0 = Hash256::hash(b"leaf0");
        let leaf1 = Hash256::hash(b"leaf1");
        let root = Hash256::hash_many(&[leaf0.as_bytes(), leaf1.as_bytes()]);

        // Prove leaf0 (index 0) — sibling is leaf1
        assert!(verify_pruned_header(&leaf0, &[leaf1.clone()], &root, 0));
        // Prove leaf1 (index 1) — sibling is leaf0
        assert!(verify_pruned_header(&leaf1, &[leaf0.clone()], &root, 1));
    }

    #[test]
    fn test_verify_pruned_header_wrong_root_fails() {
        let leaf = Hash256::hash(b"leaf");
        let wrong_root = Hash256::hash(b"wrong");
        assert!(!verify_pruned_header(&leaf, &[], &wrong_root, 0));
    }

    #[test]
    fn test_epoch_duration_is_30_days() {
        assert_eq!(EPOCH_DURATION_SECS, 30 * 24 * 60 * 60);
        assert_eq!(EPOCH_DURATION_SECS, 2_592_000);
    }
}
