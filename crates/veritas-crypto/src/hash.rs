//! BLAKE3 hashing primitives.
//!
//! Provides a 256-bit hash type with serialization support.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A 256-bit (32-byte) hash value using BLAKE3.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Hash size in bytes.
    pub const SIZE: usize = 32;

    /// Create a Hash256 from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(crate::CryptoError::InvalidHashLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to owned byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Hash a single input.
    pub fn hash(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    /// Hash multiple inputs (domain separation).
    ///
    /// Each input is length-prefixed to prevent ambiguity.
    pub fn hash_many(inputs: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for input in inputs {
            // Length-prefix each input for domain separation
            hasher.update(&(input.len() as u64).to_le_bytes());
            hasher.update(input);
        }
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Create a keyed hash (MAC).
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Self {
        let hash = blake3::keyed_hash(key, data);
        Self(*hash.as_bytes())
    }

    /// Derive a key from this hash using BLAKE3 key derivation.
    pub fn derive_key(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.0)
    }

    /// Check if this hash is all zeros.
    ///
    /// Uses constant-time comparison to prevent timing side-channels (CRYPTO-FIX-4).
    pub fn is_zero(&self) -> bool {
        self.0.ct_eq(&[0u8; 32]).into()
    }

    /// Format as hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    /// Parse from hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a valid 64-character hex string.
    pub fn from_hex(s: &str) -> crate::Result<Self> {
        if s.len() != 64 {
            return Err(crate::CryptoError::InvalidHashLength {
                expected: 64,
                actual: s.len(),
            });
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            // CRYPTO-FIX-5: Use InvalidHexFormat for parsing errors instead of InvalidHashLength
            let hex_str =
                std::str::from_utf8(chunk).map_err(|_| {
                    crate::CryptoError::InvalidHexFormat("invalid UTF-8 in hex string".to_string())
                })?;
            bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| {
                crate::CryptoError::InvalidHexFormat(format!(
                    "invalid hex character at position {}",
                    i * 2
                ))
            })?;
        }
        Ok(Self(bytes))
    }
}

impl ConstantTimeEq for Hash256 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Hash256 {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        self.ct_eq(other).into()
    }
}

impl Eq for Hash256 {}

impl std::hash::Hash for Hash256 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the raw bytes for HashMap usage.
        // Note: This is NOT a cryptographic operation - it's only used
        // for hash table bucket selection, not security.
        self.0.hash(state);
    }
}

impl std::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash256({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"hello world";
        let h1 = Hash256::hash(data);
        let h2 = Hash256::hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = Hash256::hash(b"hello");
        let h2 = Hash256::hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_many() {
        let h1 = Hash256::hash_many(&[b"hello", b"world"]);
        let h2 = Hash256::hash_many(&[b"helloworld"]);
        // Should be different due to length prefixing
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0u8; 32];
        let h1 = Hash256::keyed_hash(&key, b"data");
        let h2 = Hash256::keyed_hash(&key, b"data");
        assert_eq!(h1, h2);

        let different_key = [1u8; 32];
        let h3 = Hash256::keyed_hash(&different_key, b"data");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hex_roundtrip() {
        let h = Hash256::hash(b"test");
        let hex = h.to_hex();
        let h2 = Hash256::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [42u8; 32];
        let h = Hash256::from_bytes(&bytes).unwrap();
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = [0u8; 16];
        assert!(Hash256::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_derive_key() {
        let h = Hash256::hash(b"seed");
        let k1 = h.derive_key("context1");
        let k2 = h.derive_key("context2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_is_zero() {
        let zero = Hash256::default();
        assert!(zero.is_zero());

        let non_zero = Hash256::hash(b"data");
        assert!(!non_zero.is_zero());
    }
}
