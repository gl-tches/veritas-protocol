//! End-to-end encryption for VERITAS messages.
//!
//! This module provides the complete E2E encryption layer that ties together:
//! - Ephemeral key exchange (X25519)
//! - Symmetric encryption (XChaCha20-Poly1305)
//! - Message signing (ML-DSA-65, FIPS 204)
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
//! ### Sending with Mandatory Timing Jitter (Recommended)
//!
//! ```ignore
//! use veritas_protocol::encryption::{prepare_for_send, SendConfig};
//! use tokio::time::sleep;
//!
//! // Prepare message with mandatory jitter
//! let prepared = prepare_for_send(&sender, recipient_public, content, None, SendConfig::default())?;
//!
//! // MANDATORY: Apply the jitter before sending
//! sleep(prepared.required_jitter).await;
//!
//! // Now safe to send
//! send(prepared.into_message()).await;
//! ```
//!
//! ### Legacy: Manual Timing Jitter (Deprecated)
//!
//! ```ignore
//! use veritas_protocol::encryption::add_timing_jitter;
//! use tokio::time::sleep;
//!
//! // Before sending (caller must remember to apply jitter)
//! let jitter = add_timing_jitter();
//! sleep(jitter).await;
//! send(encrypted).await;
//! ```

pub mod e2e;

pub use e2e::{
    DecryptionContext, EncryptedMessage, MESSAGE_ENCRYPTION_CONTEXT, PreparedMessage, SendConfig,
    add_timing_jitter, decrypt_and_verify, decrypt_as_recipient, encrypt_for_recipient,
    prepare_for_send,
};
