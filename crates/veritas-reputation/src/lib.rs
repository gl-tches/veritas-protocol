//! # veritas-reputation
//!
//! Reputation scoring system for VERITAS protocol.
//!
//! Provides:
//! - Reputation scoring with rate limiting
//! - Weighted negative reports
//! - Collusion detection via graph analysis
//! - Reputation decay and effects

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{ReputationError, Result};
