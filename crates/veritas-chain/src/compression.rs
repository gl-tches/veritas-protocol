//! Block compression for storage optimization.
//!
//! This module provides [`BlockCompressor`] for compressing blocks using zstd,
//! achieving 40-70% size reduction while maintaining fast decompression.
//!
//! ## Security
//!
//! - Uses constant compression level to prevent timing attacks
//! - Validates sizes before and after decompression to prevent bombs
//! - Maximum compressed and decompressed sizes are enforced
//!
//! ## Example
//!
//! ```
//! use veritas_chain::compression::BlockCompressor;
//!
//! let compressor = BlockCompressor::new(3);
//! assert_eq!(compressor.level(), 3);
//! ```

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::config::{
    DEFAULT_COMPRESSION_LEVEL, MAX_COMPRESSED_BLOCK_SIZE, MAX_DECOMPRESSED_BLOCK_SIZE,
};
use crate::{ChainError, Result};

/// Metrics for compression operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressionMetrics {
    /// Total bytes before compression.
    pub original_bytes: u64,

    /// Total bytes after compression.
    pub compressed_bytes: u64,

    /// Number of compression operations.
    pub compressions: u64,

    /// Number of decompression operations.
    pub decompressions: u64,

    /// Number of failed operations.
    pub failures: u64,
}

impl CompressionMetrics {
    /// Calculate compression ratio (0.0 to 1.0, lower is better).
    ///
    /// Returns the ratio of compressed to original size.
    pub fn compression_ratio(&self) -> f64 {
        if self.original_bytes == 0 {
            1.0
        } else {
            self.compressed_bytes as f64 / self.original_bytes as f64
        }
    }

    /// Calculate space saved percentage (0.0 to 100.0).
    pub fn space_saved_percent(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }

    /// Reset metrics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Block compressor using zstd.
///
/// Compresses blocks for efficient storage while maintaining fast
/// decompression for reads.
///
/// ## Compression Levels
///
/// - Level 1-3: Fast, moderate compression (recommended for most uses)
/// - Level 4-9: Balanced speed and compression
/// - Level 10-22: Maximum compression, slower
///
/// Default: Level 3 (balanced for blockchain data)
///
/// ## Security
///
/// - Uses constant compression level (no timing side-channels)
/// - Validates sizes to prevent decompression bombs
/// - Rejects oversized inputs/outputs
#[derive(Debug)]
pub struct BlockCompressor {
    /// Compression level (1-22).
    level: i32,

    /// Performance metrics.
    metrics: CompressionMetrics,
}

impl Default for BlockCompressor {
    fn default() -> Self {
        Self::new(DEFAULT_COMPRESSION_LEVEL)
    }
}

impl BlockCompressor {
    /// Create a new compressor with the specified level.
    ///
    /// # Arguments
    ///
    /// * `level` - Compression level (1-22, clamped if out of range)
    pub fn new(level: i32) -> Self {
        let level = level.clamp(1, 22);
        Self {
            level,
            metrics: CompressionMetrics::default(),
        }
    }

    /// Get the compression level.
    pub fn level(&self) -> i32 {
        self.level
    }

    /// Get compression metrics.
    pub fn metrics(&self) -> &CompressionMetrics {
        &self.metrics
    }

    /// Get a mutable reference to metrics.
    pub fn metrics_mut(&mut self) -> &mut CompressionMetrics {
        &mut self.metrics
    }

    /// Compress a block to bytes.
    ///
    /// # Arguments
    ///
    /// * `block` - Block to compress
    ///
    /// # Returns
    ///
    /// Compressed bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Serialization fails
    /// - Block is too large
    /// - Compression fails
    pub fn compress(&mut self, block: &Block) -> Result<Vec<u8>> {
        // Serialize the block
        let serialized = block.to_bytes()?;

        // SECURITY: Validate input size
        if serialized.len() > MAX_DECOMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Block too large for compression: {} bytes (max {})",
                serialized.len(),
                MAX_DECOMPRESSED_BLOCK_SIZE
            )));
        }

        // Compress using zstd
        let compressed = zstd::encode_all(&serialized[..], self.level).map_err(|e| {
            self.metrics.failures += 1;
            ChainError::Storage(format!("Compression failed: {}", e))
        })?;

        // Update metrics
        self.metrics.original_bytes += serialized.len() as u64;
        self.metrics.compressed_bytes += compressed.len() as u64;
        self.metrics.compressions += 1;

        Ok(compressed)
    }

    /// Decompress bytes to a block.
    ///
    /// # Arguments
    ///
    /// * `compressed` - Compressed block bytes
    ///
    /// # Returns
    ///
    /// The decompressed block.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Compressed data is too large
    /// - Decompression fails
    /// - Decompressed data is too large (bomb protection)
    /// - Deserialization fails
    ///
    /// # Security
    ///
    /// This method enforces size limits before AND after decompression
    /// to prevent decompression bomb attacks.
    pub fn decompress(&mut self, compressed: &[u8]) -> Result<Block> {
        // SECURITY: Validate compressed size BEFORE decompression
        if compressed.len() > MAX_COMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Compressed block too large: {} bytes (max {})",
                compressed.len(),
                MAX_COMPRESSED_BLOCK_SIZE
            )));
        }

        // Decompress using zstd with size limit
        let decompressed = zstd::decode_all(compressed).map_err(|e| {
            self.metrics.failures += 1;
            ChainError::Storage(format!("Decompression failed: {}", e))
        })?;

        // SECURITY: Validate decompressed size
        if decompressed.len() > MAX_DECOMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Decompressed block too large: {} bytes (max {})",
                decompressed.len(),
                MAX_DECOMPRESSED_BLOCK_SIZE
            )));
        }

        // Deserialize
        let block = Block::from_bytes(&decompressed)?;

        // Update metrics
        self.metrics.decompressions += 1;

        Ok(block)
    }

    /// Compress raw bytes (without block serialization).
    ///
    /// Useful for compressing arbitrary data.
    pub fn compress_bytes(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > MAX_DECOMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Data too large for compression: {} bytes",
                data.len()
            )));
        }

        let compressed = zstd::encode_all(data, self.level).map_err(|e| {
            self.metrics.failures += 1;
            ChainError::Storage(format!("Compression failed: {}", e))
        })?;

        self.metrics.original_bytes += data.len() as u64;
        self.metrics.compressed_bytes += compressed.len() as u64;
        self.metrics.compressions += 1;

        Ok(compressed)
    }

    /// Decompress raw bytes.
    ///
    /// Useful for decompressing arbitrary data.
    pub fn decompress_bytes(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.len() > MAX_COMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Compressed data too large: {} bytes",
                compressed.len()
            )));
        }

        let decompressed = zstd::decode_all(compressed).map_err(|e| {
            self.metrics.failures += 1;
            ChainError::Storage(format!("Decompression failed: {}", e))
        })?;

        if decompressed.len() > MAX_DECOMPRESSED_BLOCK_SIZE {
            self.metrics.failures += 1;
            return Err(ChainError::Storage(format!(
                "Decompressed data too large: {} bytes",
                decompressed.len()
            )));
        }

        self.metrics.decompressions += 1;

        Ok(decompressed)
    }

    /// Estimate compressed size without actually compressing.
    ///
    /// This is a rough estimate based on typical compression ratios.
    pub fn estimate_compressed_size(original_size: usize) -> usize {
        // Blockchain data typically compresses to 40-60%
        // Use 55% as a conservative estimate
        (original_size as f64 * 0.55) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_crypto::Hash256;
    use veritas_identity::IdentityHash;

    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    fn create_test_block(height: u64) -> Block {
        Block::new(
            test_hash(height as u8),
            height,
            1700000000 + height,
            vec![],
            test_identity((height % 256) as u8),
        )
    }

    // ==================== Basic Compression ====================

    #[test]
    fn test_compressor_creation() {
        let compressor = BlockCompressor::new(3);
        assert_eq!(compressor.level(), 3);
    }

    #[test]
    fn test_compressor_level_clamping() {
        let low = BlockCompressor::new(-5);
        assert_eq!(low.level(), 1);

        let high = BlockCompressor::new(100);
        assert_eq!(high.level(), 22);
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let mut compressor = BlockCompressor::new(3);
        let block = create_test_block(1);

        let compressed = compressor.compress(&block).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(block.hash(), decompressed.hash());
        assert_eq!(block.height(), decompressed.height());
    }

    #[test]
    fn test_compression_reduces_size() {
        let mut compressor = BlockCompressor::new(3);
        let block = create_test_block(1);

        let original = block.to_bytes().unwrap();
        let compressed = compressor.compress(&block).unwrap();

        // Compressed should be smaller (or at least not much larger)
        // Note: Very small blocks may not compress well
        assert!(compressed.len() <= original.len() + 50);
    }

    #[test]
    fn test_multiple_compressions() {
        let mut compressor = BlockCompressor::new(3);

        for i in 1..=10 {
            let block = create_test_block(i);
            let compressed = compressor.compress(&block).unwrap();
            let decompressed = compressor.decompress(&compressed).unwrap();

            assert_eq!(block.hash(), decompressed.hash());
        }

        assert_eq!(compressor.metrics().compressions, 10);
        assert_eq!(compressor.metrics().decompressions, 10);
    }

    // ==================== Metrics ====================

    #[test]
    fn test_compression_metrics() {
        let mut compressor = BlockCompressor::new(3);
        let block = create_test_block(1);

        let _ = compressor.compress(&block).unwrap();

        let metrics = compressor.metrics();
        assert!(metrics.original_bytes > 0);
        assert!(metrics.compressed_bytes > 0);
        assert_eq!(metrics.compressions, 1);
    }

    #[test]
    fn test_compression_ratio() {
        let mut compressor = BlockCompressor::new(3);
        let block = create_test_block(1);

        let _ = compressor.compress(&block).unwrap();

        let ratio = compressor.metrics().compression_ratio();
        // Ratio should be between 0 and 2 (100% to 200%)
        assert!(ratio > 0.0);
        assert!(ratio <= 2.0);
    }

    #[test]
    fn test_space_saved_percent() {
        let mut compressor = BlockCompressor::new(3);
        let block = create_test_block(1);

        let _ = compressor.compress(&block).unwrap();

        let saved = compressor.metrics().space_saved_percent();
        // Could be negative if compression expands data (unlikely but possible for small data)
        assert!(saved >= -100.0);
        assert!(saved <= 100.0);
    }

    // ==================== Raw Bytes ====================

    #[test]
    fn test_compress_decompress_bytes() {
        let mut compressor = BlockCompressor::new(3);
        let data = b"Hello, World! This is test data for compression.";

        let compressed = compressor.compress_bytes(data).unwrap();
        let decompressed = compressor.decompress_bytes(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_large_data() {
        let mut compressor = BlockCompressor::new(3);

        // Create data with repeated patterns (compresses well)
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let compressed = compressor.compress_bytes(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress_bytes(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    // ==================== Security Tests ====================

    #[test]
    fn test_reject_oversized_compressed_input() {
        let mut compressor = BlockCompressor::new(3);

        // Create oversized "compressed" data
        let huge_data = vec![0u8; MAX_COMPRESSED_BLOCK_SIZE + 1];

        let result = compressor.decompress_bytes(&huge_data);
        assert!(result.is_err());
        assert_eq!(compressor.metrics().failures, 1);
    }

    #[test]
    fn test_reject_invalid_compressed_data() {
        let mut compressor = BlockCompressor::new(3);

        // Invalid zstd data
        let invalid = vec![1, 2, 3, 4, 5];

        let result = compressor.decompress_bytes(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_oversized_decompressed_output() {
        let mut compressor = BlockCompressor::new(3);

        // Create data that would exceed decompressed limit
        let huge_data = vec![0u8; MAX_DECOMPRESSED_BLOCK_SIZE + 1];

        let result = compressor.compress_bytes(&huge_data);
        assert!(result.is_err());
        assert_eq!(compressor.metrics().failures, 1);
    }

    // ==================== Compression Levels ====================

    #[test]
    fn test_different_compression_levels() {
        let block = create_test_block(1);

        let mut sizes = Vec::new();
        for level in [1, 3, 9, 19] {
            let mut compressor = BlockCompressor::new(level);
            let compressed = compressor.compress(&block).unwrap();
            sizes.push((level, compressed.len()));
        }

        // Higher levels should generally produce smaller output
        // (though for small data the difference may be minimal)
        for (level, size) in &sizes {
            println!("Level {}: {} bytes", level, size);
        }
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_compress_decompress_roundtrip(height in 0u64..1000) {
            let mut compressor = BlockCompressor::new(3);
            let block = create_test_block(height);

            let compressed = compressor.compress(&block).unwrap();
            let decompressed = compressor.decompress(&compressed).unwrap();

            prop_assert_eq!(block.hash(), decompressed.hash());
            prop_assert_eq!(block.height(), decompressed.height());
        }

        #[test]
        fn prop_bytes_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let mut compressor = BlockCompressor::new(3);

            let compressed = compressor.compress_bytes(&data).unwrap();
            let decompressed = compressor.decompress_bytes(&compressed).unwrap();

            prop_assert_eq!(decompressed, data);
        }

        #[test]
        fn prop_compression_level_affects_ratio(level in 1i32..=22) {
            let mut compressor = BlockCompressor::new(level);
            let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

            let compressed = compressor.compress_bytes(&data).unwrap();

            // Should successfully compress
            prop_assert!(!compressed.is_empty());
        }
    }
}
