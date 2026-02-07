//! Message chunking and reassembly.
//!
//! This module provides functionality for splitting large messages into
//! smaller chunks that fit within protocol limits, and reassembling
//! those chunks back into complete messages.
//!
//! # Protocol Limits
//!
//! - Maximum 300 characters per chunk
//! - Maximum 3 chunks per message (900 characters total)
//! - Uses character count, not byte length (supports Unicode)
//!
//! # Example
//!
//! ```
//! use veritas_protocol::chunking::{split_into_chunks, ChunkReassembler};
//!
//! // Sender side: split a message
//! let message = "This is a short message";
//! let chunks = split_into_chunks(message).unwrap();
//! assert_eq!(chunks.len(), 1); // Fits in one chunk
//!
//! // Receiver side: reassemble chunks
//! let mut reassembler = ChunkReassembler::new(300);
//! for chunk in chunks {
//!     let current_time = 1000; // Unix timestamp
//!     if let Some(complete) = reassembler.add_chunk(chunk, current_time).unwrap() {
//!         assert_eq!(complete, message);
//!     }
//! }
//! ```
//!
//! # Multi-Chunk Messages
//!
//! Messages longer than 300 characters are automatically split:
//!
//! ```
//! use veritas_protocol::chunking::split_into_chunks;
//!
//! let long_message: String = "a".repeat(600); // 600 characters
//! let chunks = split_into_chunks(&long_message).unwrap();
//! assert_eq!(chunks.len(), 2); // Split into 2 chunks
//!
//! // Each chunk has metadata linking it to the original message
//! assert_eq!(chunks[0].info().chunk_index(), 0);
//! assert_eq!(chunks[0].info().total_chunks(), 2);
//! ```

mod chunk;
mod reassembly;

pub use chunk::{ChunkInfo, MessageChunk, split_into_chunks};
pub use reassembly::ChunkReassembler;
