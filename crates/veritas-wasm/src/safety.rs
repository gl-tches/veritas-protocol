//! Safety Number implementation for WASM.
//!
//! Wraps the safety number computation for JavaScript usage.

use wasm_bindgen::prelude::*;

use veritas_crypto::Hash256;
use veritas_identity::IdentityPublicKeys;

use crate::error::{WasmError, WasmResult};

/// Domain separation prefix for safety number computation.
const DOMAIN: &[u8] = b"VERITAS-SAFETY-NUMBER-v1";

/// A safety number derived from two identities' public keys.
///
/// Safety numbers allow users to verify they are communicating with the
/// correct party by comparing these values out-of-band.
#[wasm_bindgen]
pub struct WasmSafetyNumber {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl WasmSafetyNumber {
    /// Compute a safety number from two identities' public keys.
    ///
    /// Both parties will compute the same safety number regardless of order.
    ///
    /// # Arguments
    ///
    /// * `our_keys_bytes` - Our public keys serialized as bytes
    /// * `their_keys_bytes` - Their public keys serialized as bytes
    ///
    /// # Returns
    ///
    /// A safety number that both parties can compare.
    #[wasm_bindgen]
    pub fn compute(
        our_keys_bytes: &[u8],
        their_keys_bytes: &[u8],
    ) -> Result<WasmSafetyNumber, JsValue> {
        let result = Self::compute_internal(our_keys_bytes, their_keys_bytes);
        result.map_err(|e| e.into())
    }

    /// Format as a 60-digit numeric string for verbal comparison.
    ///
    /// Returns a string like: "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
    #[wasm_bindgen(js_name = toNumericString)]
    pub fn to_numeric_string(&self) -> String {
        // Convert first 30 bytes to 60 digits (each byte -> 2 digits via byte % 100)
        let mut all_digits = String::with_capacity(60);
        for &byte in self.bytes.iter().take(30) {
            let two_digits = byte % 100;
            all_digits.push_str(&format!("{:02}", two_digits));
        }

        // Format into 12 groups of 5 digits separated by spaces
        let mut result = String::with_capacity(71); // 60 digits + 11 spaces
        for (i, chunk) in all_digits.as_bytes().chunks(5).enumerate() {
            if i > 0 {
                result.push(' ');
            }
            result.push_str(std::str::from_utf8(chunk).unwrap());
        }

        result
    }

    /// Format as a hex string for QR code scanning.
    ///
    /// Returns a 64-character hex string.
    #[wasm_bindgen(js_name = toQrString)]
    pub fn to_qr_string(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in &self.bytes {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    /// Get the raw bytes of the safety number.
    #[wasm_bindgen(js_name = asBytes)]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl WasmSafetyNumber {
    fn compute_internal(our_keys_bytes: &[u8], their_keys_bytes: &[u8]) -> WasmResult<Self> {
        // Deserialize public keys
        let our_keys = IdentityPublicKeys::from_bytes(our_keys_bytes)
            .map_err(|_| WasmError::new("Failed to deserialize our public keys"))?;
        let their_keys = IdentityPublicKeys::from_bytes(their_keys_bytes)
            .map_err(|_| WasmError::new("Failed to deserialize their public keys"))?;

        // Get identity hashes for sorting
        let our_hash = our_keys.identity_hash();
        let their_hash = their_keys.identity_hash();

        // Sort keys lexicographically by identity hash to ensure symmetric computation
        let (first_keys, second_keys) = if our_hash.as_bytes() <= their_hash.as_bytes() {
            (&our_keys, &their_keys)
        } else {
            (&their_keys, &our_keys)
        };

        // Build inputs for hashing
        let first_exchange = first_keys.exchange.as_bytes();
        let first_signing: &[u8] = first_keys
            .signing
            .as_ref()
            .map(|k| k.as_bytes())
            .unwrap_or(&[]);

        let second_exchange = second_keys.exchange.as_bytes();
        let second_signing: &[u8] = second_keys
            .signing
            .as_ref()
            .map(|k| k.as_bytes())
            .unwrap_or(&[]);

        // Hash all components with domain separation
        let hash = Hash256::hash_many(&[
            DOMAIN,
            first_exchange,
            first_signing,
            second_exchange,
            second_signing,
        ]);

        Ok(Self {
            bytes: hash.to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_identity::IdentityKeyPair;

    #[test]
    fn test_safety_number_symmetric() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_keys_bytes = alice.public_keys().to_bytes();
        let bob_keys_bytes = bob.public_keys().to_bytes();

        let alice_computes =
            WasmSafetyNumber::compute_internal(&alice_keys_bytes, &bob_keys_bytes).unwrap();
        let bob_computes =
            WasmSafetyNumber::compute_internal(&bob_keys_bytes, &alice_keys_bytes).unwrap();

        assert_eq!(alice_computes.bytes, bob_computes.bytes);
    }

    #[test]
    fn test_numeric_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_keys_bytes = alice.public_keys().to_bytes();
        let bob_keys_bytes = bob.public_keys().to_bytes();

        let safety =
            WasmSafetyNumber::compute_internal(&alice_keys_bytes, &bob_keys_bytes).unwrap();
        let numeric = safety.to_numeric_string();

        // Should be 60 digits + 11 spaces = 71 characters
        assert_eq!(numeric.len(), 71);

        // Should have 11 spaces
        assert_eq!(numeric.chars().filter(|&c| c == ' ').count(), 11);

        // Each group should be 5 digits
        let groups: Vec<&str> = numeric.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for group in groups {
            assert_eq!(group.len(), 5);
            assert!(group.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_qr_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_keys_bytes = alice.public_keys().to_bytes();
        let bob_keys_bytes = bob.public_keys().to_bytes();

        let safety =
            WasmSafetyNumber::compute_internal(&alice_keys_bytes, &bob_keys_bytes).unwrap();
        let qr = safety.to_qr_string();

        // Should be 64 hex characters
        assert_eq!(qr.len(), 64);

        // Should be valid lowercase hex
        assert!(qr
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }
}
