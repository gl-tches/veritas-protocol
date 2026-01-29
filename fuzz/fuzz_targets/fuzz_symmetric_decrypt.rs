//! Fuzz target for symmetric decryption.
//!
//! Tests that decrypt handles arbitrary ciphertext gracefully without panicking.
//! The function should reject invalid input but never panic or crash.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_crypto::{decrypt, EncryptedData, SymmetricKey};

fuzz_target!(|data: &[u8]| {
    // Try to parse as EncryptedData
    if let Ok(encrypted) = EncryptedData::from_bytes(data) {
        // Generate a random key for testing
        let key = SymmetricKey::generate();

        // Attempt decryption - should either succeed or return error, never panic
        let _ = decrypt(&key, &encrypted);
    }
});
