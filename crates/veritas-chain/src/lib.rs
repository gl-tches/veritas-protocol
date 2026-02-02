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
//! - Memory-optimized block storage with LRU caching
//! - Block compression and chain pruning
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
//! ## Storage Optimization
//!
//! The blockchain includes several optimization features:
//! - [`memory::MemoryBudget`]: LRU cache with configurable memory limits
//! - [`compression::BlockCompressor`]: zstd compression for storage efficiency
//! - [`pruner::ChainPruner`]: Configurable chain pruning for storage reduction
//! - [`lazy_loader::LazyBlockLoader`]: On-demand block loading with hot cache
//! - [`storage::StorageBackend`]: Pluggable storage backends
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
pub mod compression;
pub mod config;
pub mod error;
pub mod lazy_loader;
pub mod managed_chain;
pub mod memory;
pub mod merkle;
pub mod pruner;
pub mod slashing;
pub mod storage;
pub mod sync;
pub mod validator;

#[cfg(feature = "sled-storage")]
pub mod sled_backend;

pub use block::{
    Block, BlockBody, BlockHeader, ChainEntry, ReputationChangeReason, SlashReason, ValidatorRegion,
};
pub use chain::{BlockValidation, Blockchain, ChainState, ForkChoice};
pub use compression::{BlockCompressor, CompressionMetrics};
pub use config::{BlockchainConfig, NodeRole, PruningMode, DEFAULT_SLED_CACHE_MB};
pub use error::{ChainError, Result};
pub use managed_chain::{IndexRebuildStats, ManagedBlockchain, ManagedMemoryMetrics};

#[cfg(feature = "sled-storage")]
pub use sled_backend::{SledBackend, UsernameIndexMeta};
pub use lazy_loader::{LazyBlockLoader, LoaderMetrics};
pub use memory::{MemoryBudget, MemoryMetrics};
pub use merkle::{Direction, MerkleProof, MerkleTree};
pub use pruner::{ChainPruner, PruningStats};
pub use slashing::{
    SlaViolationType, SlashResult, SlashingConfig, SlashingManager, SlashingOffense,
};
pub use storage::{InMemoryBackend, MetricsBackend, SharedBackend, StorageBackend, StorageMetrics};
pub use sync::{
    PendingRequest, SyncAction, SyncManager, SyncMessage, SyncState,
    DEFAULT_MAX_BLOCKS_PER_REQUEST, DEFAULT_MAX_HEADERS_PER_REQUEST, DEFAULT_REQUEST_TIMEOUT_MS,
};
pub use validator::{
    ValidatorEpochMetrics, ValidatorSelection, ValidatorSet, ValidatorSla, ValidatorStake,
};
