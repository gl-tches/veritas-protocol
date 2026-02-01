//! # veritas-protocol
//!
//! Wire protocol and message formats for VERITAS.
//!
//! Provides:
//! - Minimal metadata envelope structure
//! - Message encryption and signing
//! - End-to-end encryption
//! - Message chunking for large messages
//! - Delivery receipts
//! - Group message formats
//! - Protocol limits and constants
//!
//! ## Privacy-First Design
//!
//! The VERITAS protocol is designed to minimize metadata leakage:
//!
//! - **Sender Privacy**: Sender ID is encrypted inside the payload
//! - **Recipient Privacy**: Mailbox keys are derived, not raw identity hashes
//! - **Traffic Analysis Resistance**: Messages are padded to fixed buckets
//! - **Temporal Privacy**: Timestamps are encrypted inside the payload
//! - **Forward Secrecy**: Ephemeral keys are used per message
//!
//! ## Core Types
//!
//! - [`MinimalEnvelope`]: The outer envelope visible to relays
//! - [`InnerPayload`]: The encrypted inner content with all metadata
//! - [`MessageContent`]: The actual message (text, receipt, or group message)
//! - [`MailboxKeyParams`]: Parameters for deriving unlinkable mailbox keys
//! - [`EncryptedMessage`]: Complete encrypted message ready for transport
//! - [`DecryptionContext`]: Context for decrypting multiple messages

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod chunking;
pub mod encryption;
pub mod envelope;
pub mod error;
pub mod groups;
pub mod limits;
#[cfg(test)]
mod proptests;
pub mod receipts;
pub mod signing;

pub use chunking::{split_into_chunks, ChunkInfo, ChunkReassembler, MessageChunk};
pub use encryption::{
    add_timing_jitter, decrypt_and_verify, decrypt_as_recipient, encrypt_for_recipient,
    prepare_for_send, DecryptionContext, EncryptedMessage, PreparedMessage, SendConfig,
    MESSAGE_ENCRYPTION_CONTEXT,
};
pub use envelope::{
    bucket_for_size, current_epoch, derive_mailbox_key, epoch_from_timestamp,
    generate_mailbox_salt, is_valid_padded, max_bucket_size, max_data_size, pad_to_bucket, unpad,
    InnerPayload, MailboxKey, MailboxKeyParams, MessageContent, MinimalEnvelope,
    MinimalEnvelopeBuilder, PaddingError, ENVELOPE_NONCE_SIZE, LENGTH_PREFIX_SIZE,
    MAILBOX_KEY_SIZE, MAILBOX_SALT_SIZE, MIN_CIPHERTEXT_SIZE, PADDING_MARKER,
};
pub use error::{ProtocolError, Result};
pub use groups::{
    EncryptedGroupKey, GroupId, GroupKey, GroupKeyManager, GroupMember, GroupMessageData,
    GroupMetadata, GroupRole, KeyRotationManager, RotationResult, RotationTrigger,
};
pub use limits::*;
pub use receipts::{DeliveryError, DeliveryReceipt, DeliveryReceiptData, ReceiptType};
pub use signing::{
    sign_message, verify_signature, MessageSignature, SignatureVersion, SigningData,
    DOMAIN_SEPARATOR, SIGNATURE_SIZE,
};
