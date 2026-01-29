//! Fuzz target for IdentityHash::from_hex.
//!
//! Tests that parsing arbitrary strings as hex identity hashes is handled safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_identity::IdentityHash;

fuzz_target!(|data: &[u8]| {
    // Try to interpret input as a string
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse as hex identity hash
        // Should succeed for valid 64-char hex, fail otherwise - never panic
        let result = IdentityHash::from_hex(s);

        // If successful, verify roundtrip
        if let Ok(hash) = result {
            let hex = hash.to_hex();
            let roundtrip = IdentityHash::from_hex(&hex).unwrap();
            assert_eq!(hash, roundtrip);
        }
    }
});
