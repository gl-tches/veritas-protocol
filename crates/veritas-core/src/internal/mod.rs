//! Internal service modules for VERITAS core.
//!
//! This module contains the internal implementation of core services:
//!
//! - [`IdentityManager`]: Manages identity keypairs and slot limits
//! - [`MessageService`]: Handles message encryption/decryption and queues
//! - [`ChainService`]: Manages blockchain interaction and synchronization
//! - [`ReputationService`]: Tracks and manages reputation scores
//!
//! These services coordinate between the low-level crates (veritas-crypto,
//! veritas-identity, veritas-store, etc.) and provide a unified interface
//! for the high-level VeritasClient API.

pub mod chain_service;
pub mod identity_manager;
pub mod message_service;
pub mod reputation_service;

pub use chain_service::ChainService;
pub use identity_manager::{IdentityInfo, IdentityManager, PersistentIdentityManager};
pub use message_service::MessageService;
pub use reputation_service::ReputationService;
