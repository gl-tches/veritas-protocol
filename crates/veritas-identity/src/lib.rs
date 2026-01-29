//! # veritas-identity
//!
//! Decentralized identity system for the VERITAS protocol.
//!
//! Provides:
//! - Identity hash generation from public keys
//! - Identity keypair management
//! - Username registration and linking
//! - Key lifecycle (rotation, revocation, expiry)
//! - Identity limits per device origin
//!
//! ## Core Types
//!
//! - [`IdentityHash`]: A unique identifier derived from a public key using BLAKE3
//! - [`IdentityKeyPair`]: Complete identity with exchange and signing keys
//! - [`IdentityPublicKeys`]: Public keys that can be shared with others
//! - [`KeyLifecycle`]: Tracks key creation, expiry, and state
//! - [`IdentityLimiter`]: Enforces max 3 identities per device origin
//!
//! ## Key Lifecycle
//!
//! Keys have a 30-day lifecycle:
//! - **Active**: Key is valid for all operations
//! - **Expiring**: Within 5 days of expiry (warning period)
//! - **Expired**: Cannot be used for new operations
//! - **Rotated**: Key was replaced with a new identity
//! - **Revoked**: Key was manually revoked
//!
//! ## Identity Limits
//!
//! Each device origin is limited to 3 identities. Slots are recycled
//! 24 hours after an identity expires.
//!
//! ## Quick Start
//!
//! ```
//! use veritas_identity::IdentityKeyPair;
//!
//! // Generate a new identity
//! let identity = IdentityKeyPair::generate();
//!
//! // Get the unique identity hash
//! let hash = identity.identity_hash();
//! println!("Identity: {}", hash);
//!
//! // Share public keys with others
//! let public_keys = identity.public_keys();
//! ```
//!
//! ## Key Exchange
//!
//! ```
//! use veritas_identity::IdentityKeyPair;
//!
//! let alice = IdentityKeyPair::generate();
//! let bob = IdentityKeyPair::generate();
//!
//! // Both parties derive the same shared secret
//! let alice_key = alice.derive_encryption_key(&bob.public_keys().exchange);
//! let bob_key = bob.derive_encryption_key(&alice.public_keys().exchange);
//! assert_eq!(alice_key, bob_key);
//! ```
//!
//! ## Encrypted Storage
//!
//! ```
//! use veritas_identity::IdentityKeyPair;
//! use veritas_crypto::SymmetricKey;
//!
//! let identity = IdentityKeyPair::generate();
//!
//! // Encrypt for storage (use password-derived key in practice)
//! let storage_key = SymmetricKey::generate();
//! let encrypted = identity.to_encrypted(&storage_key).unwrap();
//!
//! // Later, restore from storage
//! let restored = IdentityKeyPair::from_encrypted(&encrypted, &storage_key).unwrap();
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod hardware;
pub mod identity_hash;
pub mod keypair;
pub mod lifecycle;
pub mod limits;
#[cfg(test)]
mod proptests;
pub mod username;

pub use error::{IdentityError, Result};
pub use hardware::{
    AttestationPlatform, HardwareAttestation, HardwareFingerprint, ATTESTATION_MAX_AGE_SECS,
};
pub use identity_hash::IdentityHash;
pub use keypair::{EncryptedIdentityKeyPair, IdentityKeyPair, IdentityPublicKeys};
pub use lifecycle::{
    KeyLifecycle, KeyState, EXPIRY_GRACE_PERIOD_SECS, KEY_EXPIRY_SECS, KEY_WARNING_SECS,
};
pub use limits::{IdentityLimiter, IdentitySlotInfo, OriginFingerprint, MAX_IDENTITIES_PER_ORIGIN};
pub use username::{Username, UsernameRegistration, MAX_USERNAME_LEN, MIN_USERNAME_LEN};
