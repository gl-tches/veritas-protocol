//! Delivery receipts for message acknowledgment.
//!
//! This module provides delivery receipt functionality for the VERITAS protocol,
//! enabling senders to confirm message delivery status.
//!
//! ## Receipt Types
//!
//! - **Delivered**: Message has been delivered to the recipient's device
//! - **Read**: Message has been opened/read by the recipient
//! - **Error**: Delivery failed with an error code
//!
//! ## Usage
//!
//! ```ignore
//! use veritas_protocol::receipts::{DeliveryReceipt, ReceiptType};
//! use veritas_identity::IdentityKeyPair;
//!
//! let identity = IdentityKeyPair::generate();
//! let message_id = Hash256::hash(b"message content");
//!
//! // Create a delivery receipt
//! let receipt = DeliveryReceipt::delivered(&message_id, &identity)?;
//!
//! // Create a read receipt
//! let read_receipt = DeliveryReceipt::read(&message_id, &identity)?;
//! ```
//!
//! ## Security Notes
//!
//! - Receipts are signed by the issuer to prevent forgery
//! - Receipt hashes include domain separation for cross-protocol safety
//! - Timestamps are included to prevent replay attacks

mod delivery;

pub use delivery::{
    DeliveryError, DeliveryReceipt, DeliveryReceiptData, ReceiptType, RECEIPT_DOMAIN_SEPARATOR,
};
