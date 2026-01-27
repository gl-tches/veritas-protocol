//! # veritas-protocol
//!
//! Wire protocol and message formats for the VERITAS Protocol.
//!
//! This crate provides:
//! - **MinimalEnvelope**: Privacy-preserving message wrapper
//! - **Message**: Encrypted message structure with chunking support
//! - **DeliveryReceipt**: Proof of message delivery
//! - **Group**: Group messaging with key rotation
//!
//! ## Privacy Design
//!
//! The envelope structure hides all identifiable metadata:
//! - Mailbox key derived from recipient + epoch (unlinkable)
//! - Ephemeral key per message (no correlation)
//! - Fixed-size padding buckets (256/512/1024)
//! - Sender ID and timestamp inside encrypted payload

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;
pub mod limits;

pub use error::{ProtocolError, Result};
