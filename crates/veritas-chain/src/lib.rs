//! # veritas-chain
//!
//! Blockchain layer for VERITAS message verification.
//!
//! Provides:
//! - Block structure and storage
//! - Merkle tree proofs
//! - Chain management and validation
//! - PoS validator selection with SLA
//! - Validator slashing and penalties
//! - Chain synchronization
//!
//! ## Block Structure
//!
//! The blockchain is composed of blocks, each containing:
//! - A header with metadata (hash, parent hash, height, timestamp, etc.)
//! - A body with chain entries (identity registrations, messages, etc.)
//!
//! ## Chain Entries
//!
//! The following entry types can be stored on-chain:
//! - Identity registrations
//! - Username registrations
//! - Key rotations
//! - Message proofs
//! - Reputation changes
//! - Validator registrations/exits/slashes
//!
//! ## Blockchain Management
//!
//! The [`chain::Blockchain`] struct provides full chain management:
//! - Block storage and retrieval
//! - Chain validation
//! - Fork detection and resolution
//! - Chain traversal (iteration)
//!
//! ## Example
//!
//! ```
//! use veritas_chain::{Block, ChainEntry, ValidatorRegion, Blockchain};
//! use veritas_identity::IdentityHash;
//!
//! // Create a genesis block
//! let genesis = Block::genesis(1700000000, vec![]);
//! assert!(genesis.is_genesis());
//! assert!(genesis.verify().is_ok());
//!
//! // Create a blockchain with genesis
//! let mut chain = Blockchain::with_genesis(genesis.clone()).unwrap();
//! assert_eq!(chain.height(), 0);
//!
//! // Create a block with entries
//! let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
//! let entry = ChainEntry::ValidatorRegistration {
//!     identity_hash: identity.clone(),
//!     stake: 800,
//!     region: ValidatorRegion::Europe,
//!     timestamp: 1700000000,
//!     signature: vec![1, 2, 3],
//! };
//!
//! let block = Block::new(
//!     genesis.hash().clone(),
//!     1,
//!     1700000001,
//!     vec![entry],
//!     identity,
//! );
//! assert!(block.verify().is_ok());
//!
//! // Add block to chain
//! chain.add_block(block).unwrap();
//! assert_eq!(chain.height(), 1);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod block;
pub mod chain;
pub mod error;
pub mod merkle;
pub mod slashing;
pub mod sync;
pub mod validator;

pub use block::{
    Block, BlockBody, BlockHeader, ChainEntry, ReputationChangeReason, SlashReason, ValidatorRegion,
};
pub use chain::{BlockValidation, Blockchain, ChainState, ForkChoice};
pub use error::{ChainError, Result};
pub use merkle::{Direction, MerkleProof, MerkleTree};
pub use slashing::{
    SlaViolationType, SlashResult, SlashingConfig, SlashingManager, SlashingOffense,
};
pub use sync::{
    PendingRequest, SyncAction, SyncManager, SyncMessage, SyncState,
    DEFAULT_MAX_BLOCKS_PER_REQUEST, DEFAULT_MAX_HEADERS_PER_REQUEST, DEFAULT_REQUEST_TIMEOUT_MS,
};
pub use validator::{
    ValidatorEpochMetrics, ValidatorSelection, ValidatorSet, ValidatorSla, ValidatorStake,
};
