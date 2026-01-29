//! Fuzz target for message padding.
//!
//! Tests that padding/unpadding handles arbitrary data safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_protocol::{pad_to_bucket, unpad, is_valid_padded, max_data_size, PADDING_BUCKETS};

fuzz_target!(|data: &[u8]| {
    // Test unpadding arbitrary data
    // Should succeed or fail gracefully - never panic
    let unpad_result = unpad(data);

    // If it claims to be valid padded data, unpad should work
    if is_valid_padded(data) {
        assert!(unpad_result.is_ok());
    }

    // Test padding (only for data that fits)
    if data.len() <= max_data_size() {
        let padded = pad_to_bucket(data).unwrap();

        // Padded size should be a bucket size
        assert!(PADDING_BUCKETS.contains(&padded.len()));

        // Should validate as properly padded
        assert!(is_valid_padded(&padded));

        // Unpadding should recover original data
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(data, unpadded.as_slice());
    }
});
