//! # veritas-core
//!
//! High-level API for the VERITAS Protocol.
//!
//! This crate provides the main entry point for applications:
//! - **VeritasClient**: Main client interface
//! - Identity management (create, rotate, revoke)
//! - Messaging (send, receive, decrypt)
//! - Groups (create, manage, messaging)
//! - Verification (proofs, safety numbers)
//!
//! ## Example
//!
//! ```ignore
//! use veritas_core::VeritasClient;
//!
//! // Create identity
//! let client = VeritasClient::create_identity().await?;
//!
//! // Send message
//! let hash = client.send_message(&recipient_id, "Hello!").await?;
//!
//! // Receive messages
//! let messages = client.receive_messages().await?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{CoreError, Result};

// Re-export commonly used types from sub-crates
pub use veritas_crypto::{CryptoError, Result as CryptoResult};
pub use veritas_identity::{IdentityError, Result as IdentityResult};
pub use veritas_protocol::{limits, ProtocolError, Result as ProtocolResult};
