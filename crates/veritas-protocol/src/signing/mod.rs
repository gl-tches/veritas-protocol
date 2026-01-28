//! Message signing and verification for the VERITAS protocol.
//!
//! This module provides cryptographic signatures for message authentication:
//! - Domain-separated signing data computation
//! - Message signature creation and verification
//! - Support for multiple signature versions (placeholder HMAC-BLAKE3, future ML-DSA)
//!
//! ## Security Note
//!
//! **IMPORTANT**: The current implementation uses HMAC-BLAKE3 as a PLACEHOLDER
//! until the ML-DSA post-quantum signature crate stabilizes. The placeholder
//! scheme is NOT cryptographically secure for production use - it exists only
//! to establish the API surface and allow development to proceed.
//!
//! Once ML-DSA is available, signatures will provide:
//! - Post-quantum security against signature forgery
//! - Non-repudiation (sender cannot deny signing)
//! - Proper public-key verification
//!
//! ## Usage
//!
//! ```ignore
//! use veritas_protocol::signing::{sign_message, verify_signature, SigningData};
//! use veritas_identity::IdentityKeyPair;
//! use veritas_crypto::Hash256;
//!
//! let sender = IdentityKeyPair::generate();
//! let content_hash = Hash256::hash(b"Hello, VERITAS!");
//!
//! // Create signing data
//! let signing_data = SigningData::new(
//!     sender.identity_hash(),
//!     1234567890,
//!     &content_hash,
//! );
//!
//! // Sign the message
//! let signature = sign_message(&sender, &signing_data)?;
//!
//! // Verify the signature (placeholder - see security note)
//! verify_signature(sender.public_keys(), &signing_data, &signature)?;
//! ```

pub mod message_sig;

pub use message_sig::{
    sign_message, verify_signature, MessageSignature, SignatureVersion, SigningData,
    DOMAIN_SEPARATOR, SIGNATURE_SIZE,
};
