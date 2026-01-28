//! Message chunk reassembly logic.
//!
//! Provides the `ChunkReassembler` type for collecting message chunks
//! and reassembling them into complete messages.

use std::collections::HashMap;

use veritas_crypto::Hash256;

use crate::error::{ProtocolError, Result};

use super::chunk::MessageChunk;

/// Internal state for a partially received message.
#[derive(Debug)]
struct PendingMessage {
    /// Total number of chunks expected.
    total_chunks: u8,
    /// Chunks received so far, indexed by chunk_index.
    chunks: HashMap<u8, MessageChunk>,
    /// Timestamp when the first chunk was received (Unix seconds).
    first_received: u64,
}

impl PendingMessage {
    /// Create a new pending message from its first received chunk.
    fn new(chunk: MessageChunk, timestamp: u64) -> Self {
        let total_chunks = chunk.info().total_chunks();
        let mut chunks = HashMap::with_capacity(total_chunks as usize);
        chunks.insert(chunk.info().chunk_index(), chunk);

        Self {
            total_chunks,
            chunks,
            first_received: timestamp,
        }
    }

    /// Add a chunk to this pending message.
    ///
    /// Returns `true` if the message is now complete.
    fn add_chunk(&mut self, chunk: MessageChunk) -> bool {
        // Ignore duplicate chunks
        let index = chunk.info().chunk_index();
        if self.chunks.contains_key(&index) {
            return self.is_complete();
        }

        self.chunks.insert(index, chunk);
        self.is_complete()
    }

    /// Check if all chunks have been received.
    fn is_complete(&self) -> bool {
        self.chunks.len() == self.total_chunks as usize
    }

    /// Check if this pending message has expired.
    fn is_expired(&self, current_time: u64, max_age_secs: u64) -> bool {
        current_time.saturating_sub(self.first_received) > max_age_secs
    }

    /// Reassemble the chunks into the complete message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message is not complete
    /// - The reassembled hash doesn't match the expected message hash
    fn reassemble(&self) -> Result<String> {
        if !self.is_complete() {
            return Err(ProtocolError::IncompleteMessage {
                received: self.chunks.len(),
                expected: self.total_chunks as usize,
            });
        }

        // Get expected message hash from any chunk (they all have the same one)
        let expected_hash = self
            .chunks
            .values()
            .next()
            .map(|c| c.info().message_hash().clone())
            .ok_or(ProtocolError::IncompleteMessage {
                received: 0,
                expected: self.total_chunks as usize,
            })?;

        // Reconstruct message in order
        let mut content = String::new();
        for i in 0..self.total_chunks {
            let chunk = self
                .chunks
                .get(&i)
                .ok_or(ProtocolError::IncompleteMessage {
                    received: self.chunks.len(),
                    expected: self.total_chunks as usize,
                })?;

            // Verify each chunk's integrity
            if !chunk.verify() {
                return Err(ProtocolError::ChunkHashMismatch { chunk_index: i });
            }

            content.push_str(chunk.content());
        }

        // Verify the complete message hash
        let computed_hash = Hash256::hash(content.as_bytes());
        if computed_hash != expected_hash {
            return Err(ProtocolError::MessageHashMismatch);
        }

        Ok(content)
    }
}

/// Reassembles message chunks into complete messages.
///
/// Tracks partially received messages and automatically expires
/// incomplete messages after a configurable timeout.
///
/// # Example
///
/// ```
/// use veritas_protocol::chunking::{ChunkReassembler, split_into_chunks};
///
/// let mut reassembler = ChunkReassembler::new(300); // 5 minute timeout
///
/// // Split a message and simulate receiving chunks
/// let message = "Hello, world!";
/// let chunks = split_into_chunks(message).unwrap();
///
/// for chunk in chunks {
///     let current_time = 1000; // Unix timestamp
///     if let Some(complete) = reassembler.add_chunk(chunk, current_time).unwrap() {
///         assert_eq!(complete, message);
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ChunkReassembler {
    /// Pending messages indexed by their message hash.
    pending: HashMap<Hash256, PendingMessage>,
    /// Maximum age in seconds before a pending message expires.
    max_pending_age_secs: u64,
}

impl ChunkReassembler {
    /// Create a new chunk reassembler.
    ///
    /// # Arguments
    ///
    /// * `max_pending_age_secs` - Maximum time to wait for all chunks
    ///   before expiring a pending message.
    pub fn new(max_pending_age_secs: u64) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending_age_secs,
        }
    }

    /// Add a chunk to the reassembler.
    ///
    /// If this completes a message, returns the reassembled content.
    /// If more chunks are needed, returns `None`.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The message chunk to add.
    /// * `current_time` - Current Unix timestamp for expiry tracking.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(message))` - The complete reassembled message.
    /// - `Ok(None)` - More chunks are needed.
    /// - `Err(...)` - An error occurred (invalid chunk, hash mismatch, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The chunk fails validation
    /// - Hash verification fails during reassembly
    pub fn add_chunk(&mut self, chunk: MessageChunk, current_time: u64) -> Result<Option<String>> {
        // Validate chunk info
        chunk.info().validate()?;

        // Verify chunk content integrity
        if !chunk.verify() {
            return Err(ProtocolError::ChunkHashMismatch {
                chunk_index: chunk.info().chunk_index(),
            });
        }

        // Single-chunk messages can be returned immediately
        if chunk.info().total_chunks() == 1 {
            return Ok(Some(chunk.into_content()));
        }

        let message_hash = chunk.info().message_hash().clone();

        // Check if we already have a pending message for this hash
        if let Some(pending) = self.pending.get_mut(&message_hash) {
            let is_complete = pending.add_chunk(chunk);

            if is_complete {
                // Remove from pending and reassemble
                let pending = self.pending.remove(&message_hash).unwrap();
                let message = pending.reassemble()?;
                return Ok(Some(message));
            }
        } else {
            // Start tracking a new pending message
            let pending = PendingMessage::new(chunk, current_time);

            // Check if it's already complete (shouldn't happen for multi-chunk)
            if pending.is_complete() {
                let message = pending.reassemble()?;
                return Ok(Some(message));
            }

            self.pending.insert(message_hash, pending);
        }

        Ok(None)
    }

    /// Remove expired pending messages.
    ///
    /// Should be called periodically to prevent memory buildup
    /// from incomplete message streams.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp.
    ///
    /// # Returns
    ///
    /// The number of expired messages that were removed.
    pub fn cleanup_expired(&mut self, current_time: u64) -> usize {
        let max_age = self.max_pending_age_secs;
        let before_count = self.pending.len();

        self.pending
            .retain(|_, pending| !pending.is_expired(current_time, max_age));

        before_count - self.pending.len()
    }

    /// Get the number of pending (incomplete) messages.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if a message with the given hash is pending.
    pub fn is_pending(&self, message_hash: &Hash256) -> bool {
        self.pending.contains_key(message_hash)
    }

    /// Get pending chunk info for a message.
    ///
    /// Returns `(received, total)` if the message is pending, `None` otherwise.
    pub fn pending_progress(&self, message_hash: &Hash256) -> Option<(usize, u8)> {
        self.pending
            .get(message_hash)
            .map(|p| (p.chunks.len(), p.total_chunks))
    }
}

impl Default for ChunkReassembler {
    fn default() -> Self {
        // Default to 5 minutes
        Self::new(300)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::split_into_chunks;

    #[test]
    fn test_reassembler_single_chunk() {
        let mut reassembler = ChunkReassembler::new(300);
        let message = "Hello, world!";
        let chunks = split_into_chunks(message).unwrap();

        let result = reassembler.add_chunk(chunks.into_iter().next().unwrap(), 1000);
        assert_eq!(result.unwrap(), Some(message.to_string()));
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_reassembler_multi_chunk_in_order() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "a".repeat(450); // 2 chunks
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 2);

        // Add first chunk
        let result = reassembler.add_chunk(chunks[0].clone(), 1000);
        assert_eq!(result.unwrap(), None);
        assert_eq!(reassembler.pending_count(), 1);

        // Add second chunk
        let result = reassembler.add_chunk(chunks[1].clone(), 1001);
        assert_eq!(result.unwrap(), Some(message));
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_reassembler_multi_chunk_out_of_order() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "b".repeat(600); // 2 chunks
        let chunks = split_into_chunks(&message).unwrap();

        // Add chunks in reverse order
        let result = reassembler.add_chunk(chunks[1].clone(), 1000);
        assert_eq!(result.unwrap(), None);

        let result = reassembler.add_chunk(chunks[0].clone(), 1001);
        assert_eq!(result.unwrap(), Some(message));
    }

    #[test]
    fn test_reassembler_three_chunks() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "c".repeat(900);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 3);

        // Add in order: 2, 0, 1
        let result = reassembler.add_chunk(chunks[2].clone(), 1000);
        assert_eq!(result.unwrap(), None);

        let result = reassembler.add_chunk(chunks[0].clone(), 1001);
        assert_eq!(result.unwrap(), None);

        let result = reassembler.add_chunk(chunks[1].clone(), 1002);
        assert_eq!(result.unwrap(), Some(message));
    }

    #[test]
    fn test_reassembler_duplicate_chunk_ignored() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "d".repeat(450);
        let chunks = split_into_chunks(&message).unwrap();

        // Add first chunk twice
        let result = reassembler.add_chunk(chunks[0].clone(), 1000);
        assert_eq!(result.unwrap(), None);

        let result = reassembler.add_chunk(chunks[0].clone(), 1001);
        assert_eq!(result.unwrap(), None);

        // Still only 1 pending chunk
        let progress = reassembler
            .pending_progress(chunks[0].info().message_hash())
            .unwrap();
        assert_eq!(progress, (1, 2));

        // Complete with second chunk
        let result = reassembler.add_chunk(chunks[1].clone(), 1002);
        assert_eq!(result.unwrap(), Some(message));
    }

    #[test]
    fn test_reassembler_expiry() {
        let mut reassembler = ChunkReassembler::new(60); // 60 second timeout
        let message: String = "e".repeat(450);
        let chunks = split_into_chunks(&message).unwrap();

        // Add first chunk at time 1000
        reassembler.add_chunk(chunks[0].clone(), 1000).unwrap();
        assert_eq!(reassembler.pending_count(), 1);

        // Cleanup at time 1030 - should still be pending
        let expired = reassembler.cleanup_expired(1030);
        assert_eq!(expired, 0);
        assert_eq!(reassembler.pending_count(), 1);

        // Cleanup at time 1061 - should expire
        let expired = reassembler.cleanup_expired(1061);
        assert_eq!(expired, 1);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_reassembler_multiple_pending() {
        let mut reassembler = ChunkReassembler::new(300);

        // Create two different messages
        let message1: String = "f".repeat(450);
        let message2: String = "g".repeat(600);
        let chunks1 = split_into_chunks(&message1).unwrap();
        let chunks2 = split_into_chunks(&message2).unwrap();

        // Add first chunk from each message
        reassembler.add_chunk(chunks1[0].clone(), 1000).unwrap();
        reassembler.add_chunk(chunks2[0].clone(), 1001).unwrap();
        assert_eq!(reassembler.pending_count(), 2);

        // Complete message 2 first
        reassembler.add_chunk(chunks2[1].clone(), 1002).unwrap();
        assert_eq!(reassembler.pending_count(), 1);

        // Complete message 1
        let result = reassembler.add_chunk(chunks1[1].clone(), 1003).unwrap();
        assert_eq!(result, Some(message1));
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn test_reassembler_unicode_preservation() {
        let mut reassembler = ChunkReassembler::new(300);
        // Mix of multi-byte characters
        let message: String = "\u{1F600}\u{1F601}\u{1F602}".repeat(110); // 330 chars, 2 chunks
        let chunks = split_into_chunks(&message).unwrap();

        for chunk in chunks {
            if let Some(result) = reassembler.add_chunk(chunk, 1000).unwrap() {
                assert_eq!(result, message);
            }
        }
    }

    #[test]
    fn test_pending_progress() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "h".repeat(900);
        let chunks = split_into_chunks(&message).unwrap();

        let hash = chunks[0].info().message_hash().clone();

        // Initially not pending
        assert!(reassembler.pending_progress(&hash).is_none());

        // After first chunk
        reassembler.add_chunk(chunks[0].clone(), 1000).unwrap();
        assert_eq!(reassembler.pending_progress(&hash), Some((1, 3)));

        // After second chunk
        reassembler.add_chunk(chunks[1].clone(), 1001).unwrap();
        assert_eq!(reassembler.pending_progress(&hash), Some((2, 3)));

        // After third chunk - no longer pending
        reassembler.add_chunk(chunks[2].clone(), 1002).unwrap();
        assert!(reassembler.pending_progress(&hash).is_none());
    }

    #[test]
    fn test_is_pending() {
        let mut reassembler = ChunkReassembler::new(300);
        let message: String = "i".repeat(450);
        let chunks = split_into_chunks(&message).unwrap();

        let hash = chunks[0].info().message_hash().clone();

        assert!(!reassembler.is_pending(&hash));

        reassembler.add_chunk(chunks[0].clone(), 1000).unwrap();
        assert!(reassembler.is_pending(&hash));

        reassembler.add_chunk(chunks[1].clone(), 1001).unwrap();
        assert!(!reassembler.is_pending(&hash));
    }

    #[test]
    fn test_default_timeout() {
        let reassembler = ChunkReassembler::default();
        assert_eq!(reassembler.max_pending_age_secs, 300);
    }
}
