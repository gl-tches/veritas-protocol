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
pub mod domain_separation;
pub mod encryption;
pub mod envelope;
pub mod error;
pub mod groups;
pub mod image_transfer;
pub mod limits;
#[cfg(test)]
mod proptests;
pub mod receipts;
pub mod session;
pub mod signing;
pub mod transcript;
pub mod wire_error;

pub use chunking::{ChunkInfo, ChunkReassembler, MessageChunk, split_into_chunks};
pub use encryption::{
    BurstConfig, DecryptionContext, EncryptedMessage, MESSAGE_ENCRYPTION_CONTEXT, PreparedMessage,
    SendConfig, add_timing_jitter, decrypt_and_verify, decrypt_as_recipient,
    encrypt_for_recipient, prepare_for_send,
};
pub use envelope::{
    ENVELOPE_NONCE_SIZE, InnerPayload, LENGTH_PREFIX_SIZE, MAILBOX_KEY_SIZE, MAILBOX_SALT_SIZE,
    MIN_CIPHERTEXT_SIZE, MailboxKey, MailboxKeyParams, MessageContent, MinimalEnvelope,
    MinimalEnvelopeBuilder, PADDING_MARKER, PaddingError, bucket_for_size, current_epoch,
    derive_mailbox_key, derive_mailbox_key_dh, epoch_from_timestamp, generate_mailbox_salt,
    is_valid_padded, max_bucket_size, max_data_size, pad_to_bucket, unpad,
};
pub use error::{ProtocolError, Result};
pub use image_transfer::{
    IMAGE_TRANSFER_WARNING, IMAGE_TRANSFER_WARNING_SHORT, ImageContentType, ImageTransferError,
    ImageTransferProof, ImageTransferRequest, MAX_IMAGE_SIZE, validate_transfer_request,
};
pub use groups::{
    AuthenticatedGroupMessage, EncryptedGroupKey, GroupAuthMode, GroupId, GroupKey, GroupKeyManager,
    GroupMember, GroupMessageData, GroupMetadata, GroupRole, GroupSenderAuth,
    GROUP_SENDER_AUTH_TAG_SIZE, KeyRotationManager, RotationResult, RotationTrigger,
    compute_group_sender_auth, compute_group_sender_auth_mldsa, verify_group_sender_auth,
};
pub use limits::*;
pub use receipts::{DeliveryError, DeliveryReceipt, DeliveryReceiptData, ReceiptType};
pub use signing::{
    DOMAIN_SEPARATOR, MessageSignature, SIGNATURE_SIZE, SignatureVersion, SigningData,
    sign_message, verify_signature,
};
pub use session::{
    AuthMode, InitialSessionMessage, PersistedSession, Session, SessionId, SessionInfo,
    SessionMessage,
};
pub use wire_error::{WireError, WireErrorCode};
