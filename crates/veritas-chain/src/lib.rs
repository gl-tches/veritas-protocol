//! # veritas-chain
//!
//! Blockchain layer for the VERITAS Protocol.
//!
//! This crate provides:
//! - **Block**: Block structure with Merkle root
//! - **Chain**: Chain management and validation
//! - **MerkleTree**: Proof generation and verification
//! - **Consensus**: Proof-of-Stake validator selection with SLA
//! - **Sync**: Block synchronization protocol
//!
//! ## On-Chain Data
//!
//! - Message hashes (proof of existence)
//! - Delivery receipts
//! - Identity registrations
//! - Username claims
//! - Reputation updates

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{ChainError, Result};
