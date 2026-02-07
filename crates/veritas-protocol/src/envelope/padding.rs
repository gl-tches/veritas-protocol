//! Message padding for privacy.
//!
//! Implements length-prefixed padding with random fill to hide message sizes.
//! Messages are padded to fixed bucket sizes to prevent traffic analysis.
//!
//! ## Security Properties
//!
//! - All messages in the same bucket are indistinguishable by size
//! - Random padding bytes prevent pattern analysis
//! - Length prefix ensures reliable unpadding

use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

use crate::limits::PADDING_BUCKETS;

/// Size of the length prefix in bytes (allows up to 4GB payloads).
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Padding marker byte (legacy, for documentation).
pub const PADDING_MARKER: u8 = 0x80;

/// Errors that can occur during padding operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PaddingError {
    /// Data is too large for any padding bucket.
    #[error("Data too large: {actual} bytes exceeds maximum bucket size {max}")]
    DataTooLarge {
        /// Actual data size in bytes.
        actual: usize,
        /// Maximum supported size.
        max: usize,
    },

    /// Data is too short to contain a valid length prefix.
    #[error("Data too short to contain length prefix")]
    DataTooShort,

    /// Length prefix indicates more data than available.
    #[error("Invalid length prefix: claims {claimed} bytes but only {available} available")]
    InvalidLengthPrefix {
        /// Length claimed by prefix.
        claimed: usize,
        /// Bytes actually available.
        available: usize,
    },
}

/// Result type for padding operations.
pub type Result<T> = std::result::Result<T, PaddingError>;

/// Get the smallest bucket size that can hold the given data.
///
/// Returns `None` if the data is too large for any bucket.
///
/// # Arguments
///
/// * `data_len` - The length of the data in bytes
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::envelope::padding::bucket_for_size;
///
/// assert_eq!(bucket_for_size(100), Some(1024));
/// assert_eq!(bucket_for_size(1500), Some(2048));
/// assert_eq!(bucket_for_size(3000), Some(4096));
/// assert_eq!(bucket_for_size(8189), None);
/// ```
pub fn bucket_for_size(data_len: usize) -> Option<usize> {
    // Need space for length prefix (4 bytes) + data
    let required_size = data_len.saturating_add(LENGTH_PREFIX_SIZE);
    PADDING_BUCKETS
        .iter()
        .find(|&&bucket| bucket >= required_size)
        .copied()
}

/// Get the maximum bucket size.
pub fn max_bucket_size() -> usize {
    *PADDING_BUCKETS.last().unwrap_or(&1024)
}

/// Get the maximum data size that can fit in any bucket.
pub fn max_data_size() -> usize {
    max_bucket_size().saturating_sub(LENGTH_PREFIX_SIZE)
}

/// Pad data to the appropriate bucket size.
///
/// Uses length-prefixed padding:
/// - First 4 bytes: big-endian length of original data
/// - Next N bytes: original data
/// - Remaining bytes: random padding
///
/// # Arguments
///
/// * `data` - The data to pad
///
/// # Returns
///
/// Padded data with length equal to a bucket size.
///
/// # Errors
///
/// Returns `PaddingError::DataTooLarge` if the data (plus prefix) exceeds
/// the largest bucket size.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::envelope::padding::{pad_to_bucket, unpad};
///
/// let data = b"Hello, VERITAS!";
/// let padded = pad_to_bucket(data).unwrap();
///
/// assert_eq!(padded.len(), 1024); // Smallest bucket
///
/// let unpadded = unpad(&padded).unwrap();
/// assert_eq!(&unpadded, data);
/// ```
pub fn pad_to_bucket(data: &[u8]) -> Result<Vec<u8>> {
    let bucket_size = bucket_for_size(data.len()).ok_or(PaddingError::DataTooLarge {
        actual: data.len(),
        max: max_data_size(),
    })?;

    let mut padded = Vec::with_capacity(bucket_size);

    // Write length prefix (big-endian u32)
    let length = data.len() as u32;
    padded.extend_from_slice(&length.to_be_bytes());

    // Write data
    padded.extend_from_slice(data);

    // Fill the rest with random bytes
    let padding_len = bucket_size - padded.len();
    if padding_len > 0 {
        let mut random_padding = vec![0u8; padding_len];
        OsRng.fill_bytes(&mut random_padding);
        padded.extend_from_slice(&random_padding);
    }

    debug_assert_eq!(padded.len(), bucket_size);
    Ok(padded)
}

/// Remove padding from data.
///
/// Reads the length prefix and returns exactly that many bytes.
///
/// # Arguments
///
/// * `padded` - The padded data
///
/// # Returns
///
/// The original data without padding.
///
/// # Errors
///
/// Returns `PaddingError::DataTooShort` if the data is too small to contain a length prefix.
/// Returns `PaddingError::InvalidLengthPrefix` if the length prefix is invalid.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::envelope::padding::{pad_to_bucket, unpad};
///
/// let data = b"Secret message";
/// let padded = pad_to_bucket(data).unwrap();
/// let unpadded = unpad(&padded).unwrap();
///
/// assert_eq!(&unpadded, data);
/// ```
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < LENGTH_PREFIX_SIZE {
        return Err(PaddingError::DataTooShort);
    }

    // Read length prefix
    let length_bytes: [u8; 4] = padded[..LENGTH_PREFIX_SIZE]
        .try_into()
        .expect("slice is correct size");
    let length = u32::from_be_bytes(length_bytes) as usize;

    // Validate length
    let available = padded.len() - LENGTH_PREFIX_SIZE;
    if length > available {
        return Err(PaddingError::InvalidLengthPrefix {
            claimed: length,
            available,
        });
    }

    // Extract data
    Ok(padded[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + length].to_vec())
}

/// Verify that data is properly padded to a bucket size.
///
/// # Arguments
///
/// * `data` - The data to check
///
/// # Returns
///
/// `true` if the data length matches a bucket size and contains a valid length prefix.
pub fn is_valid_padded(data: &[u8]) -> bool {
    // Check if length matches a bucket
    if !PADDING_BUCKETS.contains(&data.len()) {
        return false;
    }

    // Check for valid length prefix
    unpad(data).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_for_size() {
        // Small data goes to smallest bucket (1024)
        assert_eq!(bucket_for_size(0), Some(1024));
        assert_eq!(bucket_for_size(100), Some(1024));
        assert_eq!(bucket_for_size(1020), Some(1024)); // 1020 + 4 = 1024

        // Needs prefix, so 1021 data bytes need next bucket
        assert_eq!(bucket_for_size(1021), Some(2048));

        // Medium data
        assert_eq!(bucket_for_size(1500), Some(2048));
        assert_eq!(bucket_for_size(2044), Some(2048)); // 2044 + 4 = 2048
        assert_eq!(bucket_for_size(2045), Some(4096));

        // Large data
        assert_eq!(bucket_for_size(3000), Some(4096));
        assert_eq!(bucket_for_size(4092), Some(4096)); // 4092 + 4 = 4096
        assert_eq!(bucket_for_size(4093), Some(8192));

        // Too large
        assert_eq!(bucket_for_size(8189), None); // 8189 + 4 = 8193 > 8192
        assert_eq!(bucket_for_size(10000), None);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"Hello, VERITAS!";
        let padded = pad_to_bucket(data).unwrap();
        let unpadded = unpad(&padded).unwrap();

        assert_eq!(&unpadded, data);
    }

    #[test]
    fn test_pad_empty_data() {
        let data = b"";
        let padded = pad_to_bucket(data).unwrap();

        assert_eq!(padded.len(), 1024); // Smallest bucket
                                        // First 4 bytes should be zero length
        assert_eq!(&padded[..4], &[0, 0, 0, 0]);

        let unpadded = unpad(&padded).unwrap();
        assert_eq!(&unpadded, data);
    }

    #[test]
    fn test_pad_max_size_for_bucket() {
        // Max data that fits in 1024-byte bucket (1020 data + 4 prefix = 1024)
        let data = vec![0x42u8; 1020];
        let padded = pad_to_bucket(&data).unwrap();

        assert_eq!(padded.len(), 1024);

        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_to_correct_bucket() {
        // 100 bytes -> 1024 bucket
        let small = vec![0x42u8; 100];
        assert_eq!(pad_to_bucket(&small).unwrap().len(), 1024);

        // 1500 bytes -> 2048 bucket
        let medium = vec![0x42u8; 1500];
        assert_eq!(pad_to_bucket(&medium).unwrap().len(), 2048);

        // 3000 bytes -> 4096 bucket
        let large = vec![0x42u8; 3000];
        assert_eq!(pad_to_bucket(&large).unwrap().len(), 4096);
    }

    #[test]
    fn test_pad_too_large() {
        let data = vec![0x42u8; 8189]; // 8189 + 4 = 8193 > 8192
        let result = pad_to_bucket(&data);

        assert!(matches!(
            result,
            Err(PaddingError::DataTooLarge { actual: 8189, .. })
        ));
    }

    #[test]
    fn test_unpad_too_short() {
        // Data without enough for length prefix
        let data = vec![0u8; 2];
        let result = unpad(&data);

        assert!(matches!(result, Err(PaddingError::DataTooShort)));
    }

    #[test]
    fn test_unpad_invalid_length() {
        // Length prefix claims more data than available
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&2000u32.to_be_bytes()); // Claims 2000 bytes

        let result = unpad(&data);
        assert!(matches!(
            result,
            Err(PaddingError::InvalidLengthPrefix {
                claimed: 2000,
                available: 1020
            })
        ));
    }

    #[test]
    fn test_padding_is_random() {
        let data = b"Test data";

        let padded1 = pad_to_bucket(data).unwrap();
        let padded2 = pad_to_bucket(data).unwrap();

        // Same data portion
        let data_end = LENGTH_PREFIX_SIZE + data.len();
        assert_eq!(&padded1[..data_end], &padded2[..data_end]);

        // Random padding should differ (with overwhelming probability)
        if padded1.len() > data_end {
            assert_ne!(
                &padded1[data_end..],
                &padded2[data_end..],
                "Random padding should differ"
            );
        }
    }

    #[test]
    fn test_is_valid_padded() {
        let data = b"Valid padded data";
        let padded = pad_to_bucket(data).unwrap();

        assert!(is_valid_padded(&padded));

        // Wrong size
        let wrong_size = vec![0u8; 100];
        assert!(!is_valid_padded(&wrong_size));

        // Correct size but invalid length prefix
        let mut invalid_prefix = vec![0u8; 1024];
        invalid_prefix[0..4].copy_from_slice(&2000u32.to_be_bytes()); // Claims too much
        assert!(!is_valid_padded(&invalid_prefix));
    }

    #[test]
    fn test_data_with_any_byte_values() {
        // Data that contains all byte values including what was the marker
        let data: Vec<u8> = (0u8..=255u8).collect();
        let padded = pad_to_bucket(&data).unwrap();
        let unpadded = unpad(&padded).unwrap();

        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_max_bucket_size() {
        assert_eq!(max_bucket_size(), 8192);
    }

    #[test]
    fn test_max_data_size() {
        assert_eq!(max_data_size(), 8188);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pad_unpad_roundtrip(data: Vec<u8>) {
            // Only test data that fits in a bucket
            prop_assume!(data.len() <= max_data_size());

            let padded = pad_to_bucket(&data).unwrap();
            let unpadded = unpad(&padded).unwrap();

            prop_assert_eq!(data, unpadded);
        }

        #[test]
        fn padded_size_is_bucket_size(data: Vec<u8>) {
            prop_assume!(data.len() <= max_data_size());

            let padded = pad_to_bucket(&data).unwrap();

            prop_assert!(PADDING_BUCKETS.contains(&padded.len()));
        }

        #[test]
        fn padded_data_is_valid(data: Vec<u8>) {
            prop_assume!(data.len() <= max_data_size());

            let padded = pad_to_bucket(&data).unwrap();

            prop_assert!(is_valid_padded(&padded));
        }
    }
}
