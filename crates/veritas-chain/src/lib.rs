//! # veritas-chain
//!
//! Blockchain layer for VERITAS message verification.
//!
//! Provides:
//! - Block structure and storage
//! - Merkle tree proofs
//! - Chain management and validation
//! - PoS validator selection with SLA
//! - Chain synchronization

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{ChainError, Result};
