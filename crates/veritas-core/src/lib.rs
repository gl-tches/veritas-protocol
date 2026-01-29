//! # veritas-core
//!
//! High-level API for VERITAS protocol.
//!
//! This is the main entry point for applications using VERITAS.
//!
//! ## Quick Start
//!
//! ```ignore
//! use veritas_core::{VeritasClient, ClientConfig};
//!
//! // Create client with default configuration
//! let client = VeritasClient::new(ClientConfig::default()).await?;
//!
//! // Unlock with password
//! client.unlock(b"secure_password").await?;
//!
//! // Create an identity
//! let hash = client.create_identity(Some("Personal")).await?;
//! println!("Created identity: {}", hash);
//!
//! // Lock when done
//! client.lock().await?;
//! ```
//!
//! ## Client States
//!
//! The [`VeritasClient`] follows a state machine pattern:
//!
//! - **Created**: Client is created but not initialized
//! - **Locked**: Client has been unlocked before but is currently locked
//! - **Unlocked**: Ready for operations
//! - **ShuttingDown**: Client is shutting down
//!
//! ## Safety Numbers
//!
//! For identity verification, use [`SafetyNumber`] to verify you are
//! communicating with the intended party:
//!
//! ```
//! use veritas_core::SafetyNumber;
//! use veritas_identity::IdentityKeyPair;
//!
//! let alice = IdentityKeyPair::generate();
//! let bob = IdentityKeyPair::generate();
//!
//! // Both parties compute the same safety number
//! let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
//!
//! // Display for verbal comparison (60 digits in groups of 5)
//! println!("Verify: {}", safety);
//!
//! // Or use QR code format
//! println!("QR: {}", safety.to_qr_string());
//! ```
//!
//! ## Architecture
//!
//! The client uses a service-based architecture:
//!
//! - **IdentityManager**: Manages identities, keys, and authentication
//! - **MessageService**: Handles message encryption, sending, and receiving
//! - **ChainService**: Blockchain operations and proof verification
//! - **ReputationService**: Reputation tracking and anti-gaming

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod error;
pub mod groups;
pub mod internal;
pub mod messaging;
pub mod safety;
pub mod verification;

// Main client export
pub use client::{ClientState, VeritasClient};

pub use config::{
    ClientConfig, ClientConfigBuilder, ConfigError, FeatureConfig, NetworkConfig, ReputationConfig,
    StorageConfig,
};
pub use error::{CoreError, Result};
pub use messaging::{MessageHash, MessageStatus, ReceivedMessage, SendOptions};
pub use safety::SafetyNumber;
pub use verification::{MessageProof, SyncStatus};

// Re-export commonly used types
pub use veritas_crypto::Hash256;
pub use veritas_protocol::limits;

// Re-export group types for convenience
pub use groups::{GroupId, GroupInfo, GroupMessage, GroupRole};

// Re-export identity info from internal module
pub use internal::IdentityInfo;

// Re-export identity types for convenience
pub use veritas_identity::{IdentityHash, IdentityPublicKeys, IdentitySlotInfo};
