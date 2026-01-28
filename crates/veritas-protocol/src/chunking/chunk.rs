//! Message chunk types and splitting logic.
//!
//! Provides types for splitting large messages into smaller chunks that
//! fit within protocol limits (300 characters per chunk, max 3 chunks).

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::error::{ProtocolError, Result};
use crate::limits::{MAX_CHUNKS_PER_MESSAGE, MAX_MESSAGE_CHARS, MAX_TOTAL_MESSAGE_CHARS};

/// Metadata about a message chunk's position within its parent message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// Zero-based index of this chunk within the message.
    chunk_index: u8,
    /// Total number of chunks in the message.
    total_chunks: u8,
    /// Hash of the complete original message (before chunking).
    /// Used to group chunks and verify reassembly.
    message_hash: Hash256,
}

impl ChunkInfo {
    /// Create chunk info for a single-chunk message.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - Hash of the complete message content.
    pub fn single(message_hash: Hash256) -> Self {
        Self {
            chunk_index: 0,
            total_chunks: 1,
            message_hash,
        }
    }

    /// Create chunk info for a multi-chunk message.
    ///
    /// # Arguments
    ///
    /// * `chunk_index` - Zero-based index of this chunk.
    /// * `total_chunks` - Total number of chunks in the message.
    /// * `message_hash` - Hash of the complete message content.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn new(chunk_index: u8, total_chunks: u8, message_hash: Hash256) -> Result<Self> {
        let info = Self {
            chunk_index,
            total_chunks,
            message_hash,
        };
        info.validate()?;
        Ok(info)
    }

    /// Check if this is the first chunk (index 0).
    pub fn is_first(&self) -> bool {
        self.chunk_index == 0
    }

    /// Check if this is the last chunk.
    pub fn is_last(&self) -> bool {
        self.chunk_index == self.total_chunks.saturating_sub(1)
    }

    /// Validate the chunk info.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `total_chunks` is 0 or exceeds `MAX_CHUNKS_PER_MESSAGE`
    /// - `chunk_index` >= `total_chunks`
    pub fn validate(&self) -> Result<()> {
        if self.total_chunks == 0 || self.total_chunks as usize > MAX_CHUNKS_PER_MESSAGE {
            return Err(ProtocolError::TooManyChunks {
                max: MAX_CHUNKS_PER_MESSAGE,
                actual: self.total_chunks as usize,
            });
        }

        if self.chunk_index >= self.total_chunks {
            return Err(ProtocolError::InvalidChunkIndex {
                index: self.chunk_index,
                total: self.total_chunks,
            });
        }

        Ok(())
    }

    /// Get the chunk index.
    pub fn chunk_index(&self) -> u8 {
        self.chunk_index
    }

    /// Get the total number of chunks.
    pub fn total_chunks(&self) -> u8 {
        self.total_chunks
    }

    /// Get the message hash.
    pub fn message_hash(&self) -> &Hash256 {
        &self.message_hash
    }
}

/// A single chunk of a potentially larger message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageChunk {
    /// Chunk position and parent message info.
    info: ChunkInfo,
    /// The chunk's text content (max 300 characters).
    content: String,
    /// Hash of this chunk's content for integrity verification.
    chunk_hash: Hash256,
}

impl MessageChunk {
    /// Create a new message chunk.
    ///
    /// # Arguments
    ///
    /// * `info` - Chunk metadata (index, total, message hash).
    /// * `content` - The chunk's text content.
    ///
    /// # Errors
    ///
    /// Returns an error if the content exceeds `MAX_MESSAGE_CHARS`.
    pub fn new(info: ChunkInfo, content: String) -> Result<Self> {
        let char_count = content.chars().count();
        if char_count > MAX_MESSAGE_CHARS {
            return Err(ProtocolError::MessageTooLong {
                max: MAX_MESSAGE_CHARS,
                actual: char_count,
            });
        }

        let chunk_hash = Hash256::hash(content.as_bytes());

        Ok(Self {
            info,
            content,
            chunk_hash,
        })
    }

    /// Verify that the chunk's content matches its stored hash.
    pub fn verify(&self) -> bool {
        let computed = Hash256::hash(self.content.as_bytes());
        computed == self.chunk_hash
    }

    /// Get the chunk info.
    pub fn info(&self) -> &ChunkInfo {
        &self.info
    }

    /// Get the chunk content.
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Get the chunk hash.
    pub fn chunk_hash(&self) -> &Hash256 {
        &self.chunk_hash
    }

    /// Consume the chunk and return its content.
    pub fn into_content(self) -> String {
        self.content
    }
}

/// Split a message into chunks that fit within protocol limits.
///
/// Messages of 300 characters or fewer are returned as a single chunk.
/// Longer messages are split into multiple chunks (max 3) at character
/// boundaries, preserving Unicode characters.
///
/// # Arguments
///
/// * `message` - The complete message text to split.
///
/// # Returns
///
/// A vector of `MessageChunk` instances, each containing at most
/// `MAX_MESSAGE_CHARS` (300) characters.
///
/// # Errors
///
/// Returns an error if the message exceeds `MAX_TOTAL_MESSAGE_CHARS` (900).
///
/// # Example
///
/// ```
/// use veritas_protocol::chunking::split_into_chunks;
///
/// let short_message = "Hello, world!";
/// let chunks = split_into_chunks(short_message).unwrap();
/// assert_eq!(chunks.len(), 1);
///
/// // A longer message would be split into multiple chunks
/// ```
pub fn split_into_chunks(message: &str) -> Result<Vec<MessageChunk>> {
    let char_count = message.chars().count();

    // Check total message length
    if char_count > MAX_TOTAL_MESSAGE_CHARS {
        return Err(ProtocolError::MessageTooLong {
            max: MAX_TOTAL_MESSAGE_CHARS,
            actual: char_count,
        });
    }

    // Compute hash of complete original message
    let message_hash = Hash256::hash(message.as_bytes());

    // Single chunk case
    if char_count <= MAX_MESSAGE_CHARS {
        let info = ChunkInfo::single(message_hash);
        let chunk = MessageChunk::new(info, message.to_string())?;
        return Ok(vec![chunk]);
    }

    // Multi-chunk case: split by character boundaries
    let chars: Vec<char> = message.chars().collect();
    let total_chunks = char_count.div_ceil(MAX_MESSAGE_CHARS);

    // Validate we don't exceed max chunks
    if total_chunks > MAX_CHUNKS_PER_MESSAGE {
        return Err(ProtocolError::TooManyChunks {
            max: MAX_CHUNKS_PER_MESSAGE,
            actual: total_chunks,
        });
    }

    let mut chunks = Vec::with_capacity(total_chunks);

    for (i, chunk_chars) in chars.chunks(MAX_MESSAGE_CHARS).enumerate() {
        let content: String = chunk_chars.iter().collect();
        let info = ChunkInfo::new(i as u8, total_chunks as u8, message_hash.clone())?;
        let chunk = MessageChunk::new(info, content)?;
        chunks.push(chunk);
    }

    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_info_single() {
        let hash = Hash256::hash(b"test");
        let info = ChunkInfo::single(hash.clone());

        assert!(info.is_first());
        assert!(info.is_last());
        assert_eq!(info.chunk_index(), 0);
        assert_eq!(info.total_chunks(), 1);
        assert_eq!(info.message_hash(), &hash);
    }

    #[test]
    fn test_chunk_info_multi() {
        let hash = Hash256::hash(b"test");

        let first = ChunkInfo::new(0, 3, hash.clone()).unwrap();
        assert!(first.is_first());
        assert!(!first.is_last());

        let middle = ChunkInfo::new(1, 3, hash.clone()).unwrap();
        assert!(!middle.is_first());
        assert!(!middle.is_last());

        let last = ChunkInfo::new(2, 3, hash).unwrap();
        assert!(!last.is_first());
        assert!(last.is_last());
    }

    #[test]
    fn test_chunk_info_validation() {
        let hash = Hash256::hash(b"test");

        // Invalid: zero total chunks
        let result = ChunkInfo::new(0, 0, hash.clone());
        assert!(result.is_err());

        // Invalid: too many chunks
        let result = ChunkInfo::new(0, 4, hash.clone());
        assert!(result.is_err());

        // Invalid: index >= total
        let result = ChunkInfo::new(3, 3, hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_chunk_new() {
        let hash = Hash256::hash(b"Hello");
        let info = ChunkInfo::single(hash);
        let chunk = MessageChunk::new(info, "Hello".to_string()).unwrap();

        assert_eq!(chunk.content(), "Hello");
        assert!(chunk.verify());
    }

    #[test]
    fn test_message_chunk_too_long() {
        let long_content: String = "a".repeat(301);
        let hash = Hash256::hash(long_content.as_bytes());
        let info = ChunkInfo::single(hash);

        let result = MessageChunk::new(info, long_content);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooLong {
                max: 300,
                actual: 301
            })
        ));
    }

    #[test]
    fn test_split_single_chunk() {
        let message = "Hello, world!";
        let chunks = split_into_chunks(message).unwrap();

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].info().is_first());
        assert!(chunks[0].info().is_last());
        assert_eq!(chunks[0].content(), message);
    }

    #[test]
    fn test_split_exactly_300_chars() {
        let message: String = "a".repeat(300);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content().chars().count(), 300);
    }

    #[test]
    fn test_split_two_chunks() {
        let message: String = "a".repeat(450); // 300 + 150
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 2);

        // First chunk
        assert!(chunks[0].info().is_first());
        assert!(!chunks[0].info().is_last());
        assert_eq!(chunks[0].content().chars().count(), 300);

        // Second chunk
        assert!(!chunks[1].info().is_first());
        assert!(chunks[1].info().is_last());
        assert_eq!(chunks[1].content().chars().count(), 150);

        // Same message hash
        assert_eq!(
            chunks[0].info().message_hash(),
            chunks[1].info().message_hash()
        );
    }

    #[test]
    fn test_split_three_chunks() {
        let message: String = "a".repeat(900);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 3);

        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.info().chunk_index() as usize, i);
            assert_eq!(chunk.info().total_chunks(), 3);
            assert_eq!(chunk.content().chars().count(), 300);
        }
    }

    #[test]
    fn test_split_message_too_long() {
        let message: String = "a".repeat(901);
        let result = split_into_chunks(&message);

        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooLong {
                max: 900,
                actual: 901
            })
        ));
    }

    #[test]
    fn test_split_unicode_boundary() {
        // Use multi-byte Unicode characters
        let emoji = "\u{1F600}"; // 4 bytes, but 1 character
        let message: String = emoji.repeat(301); // 301 characters
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].content().chars().count(), 300);
        assert_eq!(chunks[1].content().chars().count(), 1);

        // Verify content wasn't corrupted
        let reconstructed: String = chunks.iter().map(|c| c.content()).collect();
        assert_eq!(reconstructed, message);
    }

    #[test]
    fn test_chunk_hash_verification() {
        let hash = Hash256::hash(b"Test message");
        let info = ChunkInfo::single(hash);
        let chunk = MessageChunk::new(info, "Test message".to_string()).unwrap();

        assert!(chunk.verify());
    }

    #[test]
    fn test_empty_message() {
        let chunks = split_into_chunks("").unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content(), "");
        assert!(chunks[0].info().is_first());
        assert!(chunks[0].info().is_last());
    }
}
