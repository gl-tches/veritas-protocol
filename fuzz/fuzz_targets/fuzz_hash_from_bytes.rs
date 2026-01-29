//! Fuzz target for Hash256::from_bytes.
//!
//! Tests that parsing arbitrary bytes as a hash is handled safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_crypto::Hash256;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse bytes as a Hash256
    // Should succeed for exactly 32 bytes, fail otherwise - never panic
    let result = Hash256::from_bytes(data);

    // If successful, verify roundtrip
    if let Ok(hash) = result {
        assert_eq!(hash.as_bytes().len(), 32);
        let roundtrip = Hash256::from_bytes(hash.as_bytes()).unwrap();
        assert_eq!(hash, roundtrip);
    }
});
