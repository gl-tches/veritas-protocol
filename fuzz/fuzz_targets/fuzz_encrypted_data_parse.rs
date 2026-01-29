//! Fuzz target for EncryptedData::from_bytes.
//!
//! Tests that parsing arbitrary bytes as encrypted data is handled safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_crypto::EncryptedData;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse bytes as EncryptedData
    // Should succeed for valid format, fail otherwise - never panic
    let result = EncryptedData::from_bytes(data);

    // If successful, verify basic properties
    if let Ok(encrypted) = result {
        // Nonce should be 24 bytes
        assert_eq!(encrypted.nonce.as_bytes().len(), 24);

        // Length should be correct
        let expected_len = 24 + encrypted.ciphertext.len();
        assert_eq!(encrypted.len(), expected_len);

        // Roundtrip through to_bytes
        let bytes = encrypted.to_bytes();
        let roundtrip = EncryptedData::from_bytes(&bytes).unwrap();
        assert_eq!(encrypted.nonce.as_bytes(), roundtrip.nonce.as_bytes());
        assert_eq!(encrypted.ciphertext, roundtrip.ciphertext);
    }
});
