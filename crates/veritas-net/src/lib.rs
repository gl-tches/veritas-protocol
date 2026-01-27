//! # veritas-net
//!
//! P2P networking layer for the VERITAS Protocol.
//!
//! This crate provides:
//! - **Transport**: Network-first transport selection
//! - **libp2p**: Primary internet networking
//! - **DHT**: Distributed hash table for message storage
//! - **Gossip**: Message announcement protocol
//! - **mDNS**: Local network peer discovery
//! - **Bluetooth**: BLE relay transport (pure relay, no security)
//! - **Store-and-Forward**: Offline message delivery
//!
//! ## Transport Priority
//!
//! 1. Internet (libp2p) - always tried first
//! 2. Local WiFi (mDNS) - relay via connected peer
//! 3. Bluetooth (BLE) - relay via any VERITAS node
//! 4. Queue locally - send when connected

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;

pub use error::{NetError, Result};
