//! # veritas-reputation
//!
//! Reputation scoring system for the VERITAS Protocol.
//!
//! This crate provides:
//! - **Score**: Reputation score tracking
//! - **RateLimiter**: Anti-gaming rate limits
//! - **ReportAggregator**: Weighted negative reports
//! - **CollusionDetector**: Graph-based gaming detection
//!
//! ## Anti-Gaming Measures
//!
//! - 60s minimum between messages to same peer
//! - 30 points/day max from one peer
//! - 100 points/day total max
//! - Reports weighted by reporter reputation
//! - Cluster detection for collusion

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{ReputationError, Result};
