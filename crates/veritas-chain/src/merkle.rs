//! Merkle tree implementation for blockchain verification.
//!
//! Provides efficient proof generation and verification for transaction inclusion.
//!
//! ## Security
//!
//! - Uses domain separation for internal node hashing to prevent second preimage attacks
//! - All hashes use BLAKE3 via veritas_crypto::Hash256
//!
//! ## Example
//!
//! ```
//! use veritas_crypto::Hash256;
//! use veritas_chain::merkle::{MerkleTree, verify_proof};
//!
//! // Create leaves from transaction hashes
//! let leaves = vec![
//!     Hash256::hash(b"tx1"),
//!     Hash256::hash(b"tx2"),
//!     Hash256::hash(b"tx3"),
//! ];
//!
//! // Build the tree
//! let tree = MerkleTree::new(leaves).unwrap();
//!
//! // Generate a proof for the second leaf (index 1)
//! let proof = tree.generate_proof(1).unwrap();
//!
//! // Verify the proof
//! assert!(proof.verify());
//! assert!(verify_proof(&proof.leaf_hash, &proof, &tree.root()));
//! ```

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::{ChainError, Result};

/// Domain separator for internal Merkle node hashing.
///
/// This prevents second preimage attacks where an attacker could
/// construct a leaf that looks like an internal node.
const MERKLE_DOMAIN: &[u8] = b"VERITAS-MERKLE-v1";

/// Direction indicator for Merkle proof siblings.
///
/// Indicates whether the sibling hash should be placed on the left or right
/// when computing the parent hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Sibling is on the left side.
    Left,
    /// Sibling is on the right side.
    Right,
}

/// A Merkle tree built from a list of leaf hashes.
///
/// The tree is stored as a complete binary tree with leaves at the bottom.
/// For non-power-of-2 leaf counts, the tree is padded by duplicating the
/// last leaf at each level as needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree {
    /// The original leaf hashes.
    leaves: Vec<Hash256>,
    /// The tree levels, from leaves (level 0) to root (last level).
    /// Each level contains the hashes at that height.
    levels: Vec<Vec<Hash256>>,
    /// The root hash of the tree.
    root: Hash256,
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaf hashes.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::EmptyTree` if the leaves vector is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_crypto::Hash256;
    /// use veritas_chain::merkle::MerkleTree;
    ///
    /// let leaves = vec![
    ///     Hash256::hash(b"leaf1"),
    ///     Hash256::hash(b"leaf2"),
    /// ];
    /// let tree = MerkleTree::new(leaves).unwrap();
    /// ```
    pub fn new(leaves: Vec<Hash256>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(ChainError::EmptyTree);
        }

        let mut levels = Vec::new();

        // Level 0 is the leaves
        let mut current_level = leaves.clone();
        levels.push(current_level.clone());

        // Build up the tree until we reach the root
        while current_level.len() > 1 {
            current_level = Self::compute_next_level(&current_level);
            levels.push(current_level.clone());
        }

        // The root is the single element at the top level
        let root = current_level[0].clone();

        Ok(Self {
            leaves,
            levels,
            root,
        })
    }

    /// Compute the next level up from the current level.
    ///
    /// For odd-length levels, the last element is duplicated.
    fn compute_next_level(current: &[Hash256]) -> Vec<Hash256> {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));

        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            // If we're at the last element and it's odd, duplicate it
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                &current[i]
            };

            next.push(hash_pair(left, right));
            i += 2;
        }

        next
    }

    /// Get the root hash of the Merkle tree.
    pub fn root(&self) -> Hash256 {
        self.root.clone()
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty.
    ///
    /// Note: A valid MerkleTree can never be empty (construction fails for empty leaves).
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the leaves of the tree.
    pub fn leaves(&self) -> &[Hash256] {
        &self.leaves
    }

    /// Generate a Merkle proof for the leaf at the given index.
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InvalidLeafIndex` if the index is out of bounds.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_crypto::Hash256;
    /// use veritas_chain::merkle::MerkleTree;
    ///
    /// let leaves = vec![
    ///     Hash256::hash(b"leaf1"),
    ///     Hash256::hash(b"leaf2"),
    ///     Hash256::hash(b"leaf3"),
    /// ];
    /// let tree = MerkleTree::new(leaves).unwrap();
    ///
    /// // Generate proof for leaf at index 1
    /// let proof = tree.generate_proof(1).unwrap();
    /// assert!(proof.verify());
    /// ```
    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.leaves.len() {
            return Err(ChainError::InvalidLeafIndex {
                index,
                size: self.leaves.len(),
            });
        }

        let leaf_hash = self.leaves[index].clone();
        let mut siblings = Vec::new();
        let mut current_index = index;

        // Walk up the tree, collecting siblings at each level
        for level in 0..self.levels.len() - 1 {
            let level_nodes = &self.levels[level];
            let sibling_index = if current_index % 2 == 0 {
                // We're on the left, sibling is on the right
                current_index + 1
            } else {
                // We're on the right, sibling is on the left
                current_index - 1
            };

            // Get sibling hash (handle odd-length levels)
            let sibling_hash = if sibling_index < level_nodes.len() {
                level_nodes[sibling_index].clone()
            } else {
                // Sibling doesn't exist (odd length), use our own hash
                level_nodes[current_index].clone()
            };

            // Direction indicates where the sibling goes in the hash
            let direction = if current_index % 2 == 0 {
                Direction::Right
            } else {
                Direction::Left
            };

            siblings.push((sibling_hash, direction));

            // Move to the parent index
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash,
            siblings,
            root: self.root.clone(),
        })
    }
}

/// A Merkle proof for a specific leaf in the tree.
///
/// Contains all the information needed to verify that a leaf is included
/// in a Merkle tree with a given root, without needing the entire tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The index of the leaf in the original tree.
    pub leaf_index: usize,
    /// The hash of the leaf being proven.
    pub leaf_hash: Hash256,
    /// The sibling hashes and their directions, from leaf to root.
    pub siblings: Vec<(Hash256, Direction)>,
    /// The expected root hash.
    pub root: Hash256,
}

impl MerkleProof {
    /// Verify the proof is valid.
    ///
    /// This computes the root from the leaf and siblings and compares
    /// it to the stored root hash.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_crypto::Hash256;
    /// use veritas_chain::merkle::MerkleTree;
    ///
    /// let leaves = vec![Hash256::hash(b"data")];
    /// let tree = MerkleTree::new(leaves).unwrap();
    /// let proof = tree.generate_proof(0).unwrap();
    ///
    /// assert!(proof.verify());
    /// ```
    pub fn verify(&self) -> bool {
        verify_proof(&self.leaf_hash, self, &self.root)
    }

    /// Get the computed root by walking up from the leaf.
    ///
    /// This is useful if you want to compare against a different root
    /// than the one stored in the proof.
    pub fn compute_root(&self) -> Hash256 {
        let mut current = self.leaf_hash.clone();

        for (sibling, direction) in &self.siblings {
            current = match direction {
                Direction::Left => hash_pair(sibling, &current),
                Direction::Right => hash_pair(&current, sibling),
            };
        }

        current
    }
}

/// Verify a Merkle proof against an expected root.
///
/// This is a standalone verification function that doesn't require
/// access to the original tree.
///
/// # Arguments
///
/// * `leaf` - The leaf hash to verify
/// * `proof` - The Merkle proof containing siblings and directions
/// * `expected_root` - The expected root hash to verify against
///
/// # Returns
///
/// `true` if the proof is valid and the computed root matches the expected root.
///
/// # Example
///
/// ```
/// use veritas_crypto::Hash256;
/// use veritas_chain::merkle::{MerkleTree, verify_proof};
///
/// let leaves = vec![
///     Hash256::hash(b"tx1"),
///     Hash256::hash(b"tx2"),
/// ];
/// let tree = MerkleTree::new(leaves.clone()).unwrap();
/// let proof = tree.generate_proof(0).unwrap();
///
/// // Verify using the standalone function
/// assert!(verify_proof(&leaves[0], &proof, &tree.root()));
///
/// // Verification fails with wrong leaf
/// let wrong_leaf = Hash256::hash(b"wrong");
/// assert!(!verify_proof(&wrong_leaf, &proof, &tree.root()));
/// ```
pub fn verify_proof(leaf: &Hash256, proof: &MerkleProof, expected_root: &Hash256) -> bool {
    let mut current = leaf.clone();

    for (sibling, direction) in &proof.siblings {
        current = match direction {
            Direction::Left => hash_pair(sibling, &current),
            Direction::Right => hash_pair(&current, sibling),
        };
    }

    current == *expected_root
}

/// Hash two nodes together with domain separation.
///
/// Uses the VERITAS-MERKLE-v1 domain separator to prevent
/// second preimage attacks.
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    Hash256::hash_many(&[MERKLE_DOMAIN, left.as_bytes(), right.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a leaf hash from a string.
    fn leaf(s: &str) -> Hash256 {
        Hash256::hash(s.as_bytes())
    }

    // ===== Empty Tree Tests =====

    #[test]
    fn test_empty_tree_errors() {
        let result = MerkleTree::new(vec![]);
        assert!(matches!(result, Err(ChainError::EmptyTree)));
    }

    // ===== Single Leaf Tests =====

    #[test]
    fn test_single_leaf_tree() {
        let leaves = vec![leaf("only")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), leaves[0]);
        assert_eq!(tree.leaves(), &leaves);
    }

    #[test]
    fn test_single_leaf_proof() {
        let leaves = vec![leaf("only")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, leaves[0]);
        assert!(proof.siblings.is_empty());
        assert!(proof.verify());
    }

    // ===== Two Leaf Tests =====

    #[test]
    fn test_two_leaf_tree() {
        let leaves = vec![leaf("left"), leaf("right")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(tree.len(), 2);
        assert!(!tree.is_empty());

        // Root should be hash of the two leaves
        let expected_root = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_two_leaf_proofs() {
        let leaves = vec![leaf("left"), leaf("right")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Proof for index 0 (left leaf)
        let proof0 = tree.generate_proof(0).unwrap();
        assert_eq!(proof0.leaf_index, 0);
        assert_eq!(proof0.siblings.len(), 1);
        assert_eq!(proof0.siblings[0].0, leaves[1]); // Sibling is right leaf
        assert_eq!(proof0.siblings[0].1, Direction::Right);
        assert!(proof0.verify());

        // Proof for index 1 (right leaf)
        let proof1 = tree.generate_proof(1).unwrap();
        assert_eq!(proof1.leaf_index, 1);
        assert_eq!(proof1.siblings.len(), 1);
        assert_eq!(proof1.siblings[0].0, leaves[0]); // Sibling is left leaf
        assert_eq!(proof1.siblings[0].1, Direction::Left);
        assert!(proof1.verify());
    }

    // ===== Power of 2 Tests =====

    #[test]
    fn test_four_leaf_tree() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(tree.len(), 4);

        // Verify structure:
        //        root
        //       /    \
        //     h01    h23
        //    /  \   /  \
        //   0   1  2   3
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h23 = hash_pair(&leaves[2], &leaves[3]);
        let expected_root = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), expected_root);

        // All proofs should verify
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
            assert_eq!(proof.siblings.len(), 2); // log2(4) = 2
        }
    }

    #[test]
    fn test_eight_leaf_tree() {
        let leaves: Vec<Hash256> = (0..8).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        assert_eq!(tree.len(), 8);

        // All proofs should verify
        for i in 0..8 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
            assert_eq!(proof.siblings.len(), 3); // log2(8) = 3
        }
    }

    // ===== Non-Power of 2 Tests =====

    #[test]
    fn test_three_leaf_tree() {
        let leaves: Vec<Hash256> = (0..3).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(tree.len(), 3);

        // Verify structure (last leaf duplicated at odd levels):
        //        root
        //       /    \
        //     h01    h22
        //    /  \   /  \
        //   0   1  2   2(dup)
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h22 = hash_pair(&leaves[2], &leaves[2]); // Duplicated
        let expected_root = hash_pair(&h01, &h22);
        assert_eq!(tree.root(), expected_root);

        // All proofs should verify
        for i in 0..3 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
        }
    }

    #[test]
    fn test_five_leaf_tree() {
        let leaves: Vec<Hash256> = (0..5).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        assert_eq!(tree.len(), 5);

        // All proofs should verify
        for i in 0..5 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
        }
    }

    #[test]
    fn test_seven_leaf_tree() {
        let leaves: Vec<Hash256> = (0..7).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        assert_eq!(tree.len(), 7);

        // All proofs should verify
        for i in 0..7 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
        }
    }

    // ===== Proof Verification Tests =====

    #[test]
    fn test_proof_valid() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        let proof = tree.generate_proof(2).unwrap();
        assert!(proof.verify());
        assert!(verify_proof(&leaves[2], &proof, &tree.root()));
    }

    #[test]
    fn test_proof_invalid_wrong_leaf() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        let proof = tree.generate_proof(2).unwrap();

        // Try to verify with wrong leaf
        let wrong_leaf = leaf("wrong");
        assert!(!verify_proof(&wrong_leaf, &proof, &tree.root()));
    }

    #[test]
    fn test_proof_invalid_tampered_sibling() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with a sibling
        proof.siblings[0].0 = leaf("tampered");

        assert!(!proof.verify());
    }

    #[test]
    fn test_proof_invalid_wrong_root() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        let proof = tree.generate_proof(1).unwrap();

        // Verify against wrong root
        let wrong_root = leaf("wrong_root");
        assert!(!verify_proof(&leaves[1], &proof, &wrong_root));
    }

    #[test]
    fn test_proof_invalid_wrong_direction() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        let mut proof = tree.generate_proof(0).unwrap();

        // Flip a direction
        proof.siblings[0].1 = Direction::Left; // Was Right

        assert!(!proof.verify());
    }

    // ===== Boundary Tests =====

    #[test]
    fn test_proof_index_out_of_bounds() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c")];
        let tree = MerkleTree::new(leaves).unwrap();

        let result = tree.generate_proof(3);
        assert!(matches!(
            result,
            Err(ChainError::InvalidLeafIndex { index: 3, size: 3 })
        ));

        let result = tree.generate_proof(100);
        assert!(matches!(
            result,
            Err(ChainError::InvalidLeafIndex {
                index: 100,
                size: 3
            })
        ));
    }

    // ===== Serialization Tests =====

    #[test]
    fn test_tree_serialization_roundtrip() {
        let leaves: Vec<Hash256> = (0..5).map(|i| leaf(&format!("data{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        let serialized = bincode::serialize(&tree).unwrap();
        let deserialized: MerkleTree = bincode::deserialize(&serialized).unwrap();

        assert_eq!(tree, deserialized);
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(2).unwrap();

        let serialized = bincode::serialize(&proof).unwrap();
        let deserialized: MerkleProof = bincode::deserialize(&serialized).unwrap();

        assert_eq!(proof, deserialized);
        assert!(deserialized.verify());
    }

    #[test]
    fn test_direction_serialization() {
        let left = Direction::Left;
        let right = Direction::Right;

        let left_ser = bincode::serialize(&left).unwrap();
        let right_ser = bincode::serialize(&right).unwrap();

        let left_de: Direction = bincode::deserialize(&left_ser).unwrap();
        let right_de: Direction = bincode::deserialize(&right_ser).unwrap();

        assert_eq!(left, left_de);
        assert_eq!(right, right_de);
    }

    // ===== Compute Root Tests =====

    #[test]
    fn test_compute_root() {
        let leaves: Vec<Hash256> = (0..4).map(|i| leaf(&format!("tx{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(1).unwrap();

        let computed = proof.compute_root();
        assert_eq!(computed, tree.root());
    }

    // ===== Large Tree Tests =====

    #[test]
    fn test_large_tree() {
        let leaves: Vec<Hash256> = (0..100).map(|i| leaf(&format!("leaf{}", i))).collect();
        let tree = MerkleTree::new(leaves).unwrap();

        assert_eq!(tree.len(), 100);

        // Verify a sample of proofs
        for i in [0, 1, 49, 50, 98, 99] {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof for leaf {} failed", i);
        }
    }

    // ===== Determinism Tests =====

    #[test]
    fn test_tree_deterministic() {
        let leaves: Vec<Hash256> = (0..5).map(|i| leaf(&format!("item{}", i))).collect();

        let tree1 = MerkleTree::new(leaves.clone()).unwrap();
        let tree2 = MerkleTree::new(leaves).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_different_root() {
        let leaves1: Vec<Hash256> = (0..4).map(|i| leaf(&format!("a{}", i))).collect();
        let leaves2: Vec<Hash256> = (0..4).map(|i| leaf(&format!("b{}", i))).collect();

        let tree1 = MerkleTree::new(leaves1).unwrap();
        let tree2 = MerkleTree::new(leaves2).unwrap();

        assert_ne!(tree1.root(), tree2.root());
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_duplicate_leaves() {
        let leaf_hash = leaf("duplicate");
        let leaves = vec![leaf_hash.clone(), leaf_hash.clone(), leaf_hash.clone()];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(tree.len(), 3);

        // All proofs should still work
        for i in 0..3 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify());
        }
    }

    #[test]
    fn test_proof_each_position_four_leaves() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Test each leaf position explicitly
        for (i, expected_leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(&proof.leaf_hash, expected_leaf);
            assert!(proof.verify());
            assert!(verify_proof(expected_leaf, &proof, &tree.root()));
        }
    }

    // ===== Property-Based Tests =====

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_all_proofs_valid(leaf_count in 1usize..50) {
            let leaves: Vec<Hash256> = (0..leaf_count)
                .map(|i| leaf(&format!("leaf{}", i)))
                .collect();
            let tree = MerkleTree::new(leaves).unwrap();

            for i in 0..leaf_count {
                let proof = tree.generate_proof(i).unwrap();
                prop_assert!(proof.verify());
            }
        }

        #[test]
        fn prop_tree_size_preserved(leaf_count in 1usize..100) {
            let leaves: Vec<Hash256> = (0..leaf_count)
                .map(|i| leaf(&format!("item{}", i)))
                .collect();
            let tree = MerkleTree::new(leaves.clone()).unwrap();

            prop_assert_eq!(tree.len(), leaf_count);
            prop_assert_eq!(tree.leaves().len(), leaf_count);
        }

        #[test]
        fn prop_serialization_roundtrip(leaf_count in 1usize..20) {
            let leaves: Vec<Hash256> = (0..leaf_count)
                .map(|i| leaf(&format!("data{}", i)))
                .collect();
            let tree = MerkleTree::new(leaves).unwrap();

            let serialized = bincode::serialize(&tree).unwrap();
            let deserialized: MerkleTree = bincode::deserialize(&serialized).unwrap();

            prop_assert_eq!(tree.root(), deserialized.root());
            prop_assert_eq!(tree.len(), deserialized.len());
        }

        #[test]
        fn prop_wrong_leaf_fails(leaf_count in 2usize..20, target_idx in 0usize..20) {
            let target_idx = target_idx % leaf_count;
            let leaves: Vec<Hash256> = (0..leaf_count)
                .map(|i| leaf(&format!("leaf{}", i)))
                .collect();
            let tree = MerkleTree::new(leaves.clone()).unwrap();

            let proof = tree.generate_proof(target_idx).unwrap();
            let wrong_leaf = leaf("definitely_wrong");

            // Should fail with wrong leaf (unless by astronomical chance it collides)
            prop_assert!(!verify_proof(&wrong_leaf, &proof, &tree.root()));
        }
    }
}
