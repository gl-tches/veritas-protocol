//! # veritas-protocol
//!
//! Wire protocol and message formats for VERITAS.
//!
//! Provides:
//! - Minimal metadata envelope structure
//! - Message encryption and signing
//! - Message chunking for large messages
//! - Delivery receipts
//! - Group message formats
//! - Protocol limits and constants

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod limits;

pub use error::{ProtocolError, Result};
pub use limits::*;
