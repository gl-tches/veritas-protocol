//! # veritas-core
//!
//! High-level API for VERITAS protocol.
//!
//! This is the main entry point for applications using VERITAS.
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
//! let hash = client.send_message(&bob_id, "Hello!").await?;
//!
//! // Receive messages
//! let messages = client.receive_messages().await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{CoreError, Result};

// Re-export commonly used types
pub use veritas_crypto::Hash256;
pub use veritas_protocol::limits;
