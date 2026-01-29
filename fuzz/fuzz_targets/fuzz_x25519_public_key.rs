//! Fuzz target for X25519 public key parsing.
//!
//! Tests that parsing arbitrary bytes as X25519 public keys is handled safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_crypto::{X25519PublicKey, X25519StaticPrivateKey};

fuzz_target!(|data: &[u8]| {
    // Attempt to parse bytes as an X25519 public key
    // Should succeed for exactly 32 bytes, fail otherwise - never panic
    let result = X25519PublicKey::from_bytes(data);

    // If successful, verify properties
    if let Ok(public_key) = result {
        // Public key should be 32 bytes
        assert_eq!(public_key.as_bytes().len(), 32);

        // Roundtrip should work
        let bytes = public_key.to_bytes();
        let roundtrip = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, roundtrip);

        // Key exchange should work (even if the key is not a valid point)
        // The x25519 implementation handles clamping
        let private = X25519StaticPrivateKey::generate();
        let _shared = private.diffie_hellman(&public_key);
        // Just verify it doesn't panic
    }
});
