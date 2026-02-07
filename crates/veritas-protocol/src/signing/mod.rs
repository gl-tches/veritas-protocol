//! Message signing and verification for the VERITAS protocol.
//!
//! This module provides ML-DSA-65 (FIPS 204) post-quantum digital signatures
//! for message authentication:
//! - Domain-separated signing data computation
//! - Message signature creation and verification
//! - Post-quantum security at NIST security level 3
//!
//! ## Security
//!
//! All signatures use ML-DSA-65 which provides:
//! - Post-quantum security against signature forgery
//! - Non-repudiation (sender cannot deny signing)
//! - Proper public-key verification
//! - 3,309-byte signatures per FIPS 204 specification
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
//! // Sign the message with ML-DSA-65
//! let signature = sign_message(&sender, &signing_data)?;
//!
//! // Verify the signature
//! verify_signature(sender.public_keys(), &signing_data, &signature)?;
//! ```

pub mod message_sig;

pub use message_sig::{
    DOMAIN_SEPARATOR, MessageSignature, SIGNATURE_SIZE, SignatureVersion, SigningData,
    sign_message, verify_signature,
};
