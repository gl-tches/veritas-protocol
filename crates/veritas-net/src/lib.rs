//! # veritas-net
//!
//! P2P networking layer for VERITAS protocol.
//!
//! Provides:
//! - Network-first transport selection
//! - libp2p integration (DHT, Gossipsub)
//! - Local network discovery (mDNS)
//! - Bluetooth relay transport
//! - Store-and-forward for offline peers

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::{NetError, Result};
