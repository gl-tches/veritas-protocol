//! End-to-end encryption for VERITAS messages.
//!
//! This module provides the complete E2E encryption layer that ties together:
//! - Ephemeral key exchange (X25519)
//! - Symmetric encryption (XChaCha20-Poly1305)
//! - Message signing (placeholder HMAC-BLAKE3, future ML-DSA)
//! - Minimal metadata envelopes
//! - Privacy-preserving mailbox key derivation
//!
//! ## Security Properties
//!
//! - **Forward Secrecy**: Ephemeral X25519 keys ensure compromise of long-term
//!   keys doesn't reveal past messages
//! - **Sender Privacy**: Sender identity is encrypted inside the payload
//! - **Recipient Privacy**: Mailbox keys are derived, not raw identity hashes
//! - **Traffic Analysis Resistance**: Messages are padded to fixed buckets
//! - **Timing Privacy**: Optional jitter delays prevent timing correlation
//!
//! ## Usage
//!
//! ### Encrypting a Message
//!
//! ```ignore
//! use veritas_protocol::encryption::{encrypt_for_recipient, EncryptedMessage};
//! use veritas_protocol::envelope::MessageContent;
//! use veritas_identity::IdentityKeyPair;
//!
//! let sender = IdentityKeyPair::generate();
//! let recipient_public = recipient.public_keys();
//!
//! let content = MessageContent::text("Hello, VERITAS!").unwrap();
//! let encrypted = encrypt_for_recipient(&sender, recipient_public, content, None)?;
//!
//! // Send encrypted.envelope over the network
//! // Include encrypted.mailbox_salt for recipient to verify mailbox key
//! ```
//!
//! ### Decrypting a Message
//!
//! ```ignore
//! use veritas_protocol::encryption::{decrypt_as_recipient, DecryptionContext};
//!
//! // One-shot decryption
//! let payload = decrypt_as_recipient(&recipient, &envelope, &mailbox_salt)?;
//!
//! // Or use context for multiple messages
//! let ctx = DecryptionContext::new(recipient);
//! let payload1 = ctx.decrypt(&envelope1)?;
//! let payload2 = ctx.decrypt(&envelope2)?;
//! ```
//!
//! ### Adding Timing Jitter
//!
//! ```ignore
//! use veritas_protocol::encryption::add_timing_jitter;
//! use tokio::time::sleep;
//!
//! // Before sending
//! let jitter = add_timing_jitter();
//! sleep(jitter).await;
//! send(encrypted).await;
//! ```

pub mod e2e;

pub use e2e::{
    add_timing_jitter, decrypt_and_verify, decrypt_as_recipient, encrypt_for_recipient,
    DecryptionContext, EncryptedMessage, MESSAGE_ENCRYPTION_CONTEXT,
};
