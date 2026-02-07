//! Minimal metadata envelope for privacy-preserving message transport.
//!
//! This module provides the core envelope structures for VERITAS messaging.
//! The envelope is designed to leak NO identifiable information to relays.
//!
//! ## Architecture
//!
//! ```text
//! +-------------------+
//! | MinimalEnvelope   | <-- Visible to relays (minimal metadata)
//! +-------------------+
//! | - mailbox_key     |     Derived, unlinkable to recipient
//! | - ephemeral_public|     Single-use, unlinkable to sender
//! | - nonce           |     Random per message
//! | - ciphertext      | --> Contains encrypted InnerPayload
//! +-------------------+
//!         |
//!         v (Encrypted + Padded)
//! +-------------------+
//! | InnerPayload      | <-- Hidden from relays
//! +-------------------+
//! | - sender_id       |     Sender's identity hash
//! | - timestamp       |     Message creation time
//! | - content         |     The actual message
//! | - signature       |     Sender's signature
//! | - message_id      |     Unique identifier
//! | - reply_to        |     Optional thread reference
//! +-------------------+
//! ```
//!
//! ## Privacy Guarantees
//!
//! | What Relays See           | What Relays DON'T See    |
//! |---------------------------|--------------------------|
//! | Derived mailbox key       | Recipient identity       |
//! | Ephemeral public key      | Sender identity          |
//! | Encryption nonce          | Timestamp                |
//! | Padded ciphertext size    | True message size        |
//! | (256, 512, or 1024 bytes) | Message content          |
//!
//! ## Modules
//!
//! - [`minimal`]: The `MinimalEnvelope` structure
//! - [`inner`]: The `InnerPayload` and `MessageContent` types
//! - [`mailbox`]: Mailbox key derivation for recipient privacy
//! - [`padding`]: Message padding for traffic analysis resistance
//!
//! ## Example
//!
//! ```ignore
//! use veritas_protocol::envelope::{
//!     MinimalEnvelope, MinimalEnvelopeBuilder,
//!     InnerPayload, MessageContent,
//!     MailboxKeyParams,
//!     pad_to_bucket,
//! };
//! use veritas_crypto::{X25519EphemeralKeyPair, encrypt};
//! use veritas_identity::IdentityHash;
//!
//! // Sender creates a message
//! let sender_id = IdentityHash::from_public_key(b"sender-pubkey");
//! let content = MessageContent::text("Hello, VERITAS!").unwrap();
//! let inner = InnerPayload::new(sender_id, content, None);
//!
//! // Serialize and pad the inner payload
//! let inner_bytes = inner.to_bytes().unwrap();
//! let padded = pad_to_bucket(&inner_bytes).unwrap();
//!
//! // Derive mailbox key (never use recipient ID directly!)
//! let recipient = IdentityHash::from_public_key(b"recipient-pubkey");
//! let mailbox_params = MailboxKeyParams::new_current(&recipient);
//! let mailbox_key = mailbox_params.derive();
//!
//! // Generate ephemeral key and encrypt
//! let ephemeral = X25519EphemeralKeyPair::generate();
//! // ... derive shared secret and encrypt padded ...
//!
//! // Build the envelope
//! let envelope = MinimalEnvelopeBuilder::new()
//!     .mailbox_key(mailbox_key)
//!     .ephemeral_public(ephemeral.public_key().clone())
//!     .nonce(nonce)
//!     .ciphertext(ciphertext)
//!     .build()
//!     .unwrap();
//! ```

#![deny(unsafe_code)]

pub mod inner;
pub mod mailbox;
pub mod minimal;
pub mod padding;

// Re-export main types for convenience
pub use inner::{InnerPayload, MessageContent};
pub use mailbox::{
    MAILBOX_KEY_SIZE, MAILBOX_SALT_SIZE, MailboxKey, MailboxKeyParams, current_epoch,
    derive_mailbox_key, epoch_from_timestamp, generate_mailbox_salt,
};
pub use minimal::{
    ENVELOPE_NONCE_SIZE, MIN_CIPHERTEXT_SIZE, MinimalEnvelope, MinimalEnvelopeBuilder,
};
pub use padding::{
    LENGTH_PREFIX_SIZE, PADDING_MARKER, PaddingError, bucket_for_size, is_valid_padded,
    max_bucket_size, max_data_size, pad_to_bucket, unpad,
};
