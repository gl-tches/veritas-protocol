//! Identity hash generation and management.
//!
//! An `IdentityHash` is a unique identifier derived from a user's public key
//! using BLAKE3 hashing. This provides a compact, fixed-size identifier that
//! can be shared without exposing the full public key.
//!
//! ## Security Properties
//!
//! - **Collision Resistance**: BLAKE3 provides strong collision resistance
//! - **Pre-image Resistance**: Cannot derive public key from hash
//! - **Constant-Time Comparison**: Prevents timing attacks
//! - **Domain Separation**: Uses a context prefix to prevent cross-protocol attacks

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use veritas_crypto::Hash256;

use crate::Result;

/// Domain separator for identity hash generation.
///
/// This prefix ensures that identity hashes cannot be confused with
/// other types of hashes in the VERITAS protocol.
const IDENTITY_HASH_DOMAIN: &[u8] = b"VERITAS-IDENTITY-HASH-v1";

/// A unique identifier for an identity, derived from the public key.
///
/// The `IdentityHash` is a 256-bit (32-byte) value computed as:
/// ```text
/// BLAKE3(IDENTITY_HASH_DOMAIN || public_key_bytes)
/// ```
///
/// ## Usage
///
/// ```ignore
/// use veritas_identity::IdentityHash;
///
/// // Create from a public key (any key type that provides as_bytes())
/// let hash = IdentityHash::from_public_key(public_key.as_bytes());
///
/// // Serialize to hex for sharing
/// let hex_string = hash.to_hex();
///
/// // Deserialize from hex
/// let restored = IdentityHash::from_hex(&hex_string)?;
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityHash(Hash256);

impl IdentityHash {
    /// Size of the identity hash in bytes.
    pub const SIZE: usize = 32;

    /// Create an identity hash from a public key.
    ///
    /// This method accepts raw public key bytes and computes the BLAKE3 hash
    /// with domain separation. It works with any public key type that can
    /// provide its bytes (ML-DSA, X25519, etc.).
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - The raw bytes of the public key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let identity_hash = IdentityHash::from_public_key(ml_dsa_pubkey.as_bytes());
    /// ```
    pub fn from_public_key(public_key_bytes: &[u8]) -> Self {
        // Use domain separation to prevent cross-protocol hash collisions
        let hash = Hash256::hash_many(&[IDENTITY_HASH_DOMAIN, public_key_bytes]);
        Self(hash)
    }

    /// Create an identity hash from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Crypto` if the input is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let bytes = [0u8; 32];
    /// let hash = IdentityHash::from_bytes(&bytes)?;
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let hash = Hash256::from_bytes(bytes)?;
        Ok(Self(hash))
    }

    /// Get the identity hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert to an owned byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Format as a lowercase hexadecimal string (64 characters).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let hash = IdentityHash::from_public_key(pubkey_bytes);
    /// let hex = hash.to_hex();
    /// assert_eq!(hex.len(), 64);
    /// ```
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parse from a hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Crypto` if the input is not a valid
    /// 64-character hexadecimal string.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let hex = "a1b2c3..."; // 64 hex characters
    /// let hash = IdentityHash::from_hex(hex)?;
    /// ```
    pub fn from_hex(s: &str) -> Result<Self> {
        let hash = Hash256::from_hex(s)?;
        Ok(Self(hash))
    }

    /// Get a truncated representation for display purposes.
    ///
    /// Returns the first 16 hex characters followed by "...".
    /// Useful for logging and user interfaces where the full hash
    /// would be too long.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let hash = IdentityHash::from_public_key(pubkey_bytes);
    /// println!("User: {}", hash.short()); // "User: a1b2c3d4e5f67890..."
    /// ```
    pub fn short(&self) -> String {
        let hex = self.to_hex();
        format!("{}...", &hex[..16])
    }

    /// Check if this identity hash equals another in constant time.
    ///
    /// This method should be used when comparing identity hashes
    /// in security-sensitive contexts to prevent timing attacks.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Get the underlying Hash256.
    ///
    /// This is useful when you need to use the hash with other
    /// cryptographic operations that expect a Hash256.
    pub fn as_hash256(&self) -> &Hash256 {
        &self.0
    }
}

impl ConstantTimeEq for IdentityHash {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for IdentityHash {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        self.0 == other.0
    }
}

impl Eq for IdentityHash {}

impl std::fmt::Debug for IdentityHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityHash({})", self.short())
    }
}

impl std::fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for IdentityHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::hash::Hash for IdentityHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl From<Hash256> for IdentityHash {
    fn from(hash: Hash256) -> Self {
        Self(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_public_key_deterministic() {
        let pubkey = b"test-public-key-bytes-1234567890";

        let hash1 = IdentityHash::from_public_key(pubkey);
        let hash2 = IdentityHash::from_public_key(pubkey);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_keys_produce_different_hashes() {
        let pubkey1 = b"public-key-1";
        let pubkey2 = b"public-key-2";

        let hash1 = IdentityHash::from_public_key(pubkey1);
        let hash2 = IdentityHash::from_public_key(pubkey2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_from_bytes_valid() {
        let bytes = [42u8; 32];
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = [0u8; 16]; // Too short
        let result = IdentityHash::from_bytes(&bytes);
        assert!(result.is_err());

        let bytes = [0u8; 64]; // Too long
        let result = IdentityHash::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let pubkey = b"test-key-for-hex-roundtrip";
        let hash = IdentityHash::from_public_key(pubkey);

        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);

        let restored = IdentityHash::from_hex(&hex).unwrap();
        assert_eq!(hash, restored);
    }

    #[test]
    fn test_from_hex_invalid() {
        // Too short
        let result = IdentityHash::from_hex("abcd");
        assert!(result.is_err());

        // Invalid characters
        let result = IdentityHash::from_hex(&"g".repeat(64));
        assert!(result.is_err());

        // Too long
        let result = IdentityHash::from_hex(&"a".repeat(128));
        assert!(result.is_err());
    }

    #[test]
    fn test_display_format() {
        let pubkey = b"display-test-key";
        let hash = IdentityHash::from_public_key(pubkey);

        let display = format!("{}", hash);
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_debug_format() {
        let pubkey = b"debug-test-key";
        let hash = IdentityHash::from_public_key(pubkey);

        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("IdentityHash("));
        assert!(debug.ends_with("...)"));
    }

    #[test]
    fn test_short_format() {
        let pubkey = b"short-format-key";
        let hash = IdentityHash::from_public_key(pubkey);

        let short = hash.short();
        assert_eq!(short.len(), 19); // 16 hex chars + "..."
        assert!(short.ends_with("..."));
    }

    #[test]
    fn test_constant_time_eq() {
        let hash1 = IdentityHash::from_public_key(b"key1");
        let hash2 = IdentityHash::from_public_key(b"key1");
        let hash3 = IdentityHash::from_public_key(b"key2");

        assert!(hash1.ct_eq(&hash2));
        assert!(!hash1.ct_eq(&hash3));
    }

    #[test]
    fn test_domain_separation() {
        // The identity hash should not equal a plain hash of the public key
        let pubkey = b"test-public-key";

        let identity_hash = IdentityHash::from_public_key(pubkey);
        let plain_hash = Hash256::hash(pubkey);

        // These should be different due to domain separation
        assert_ne!(identity_hash.as_bytes(), plain_hash.as_bytes());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let pubkey = b"serialization-test-key";
        let hash = IdentityHash::from_public_key(pubkey);

        // Serialize to bincode
        let serialized = bincode::serialize(&hash).unwrap();

        // Deserialize
        let deserialized: IdentityHash = bincode::deserialize(&serialized).unwrap();

        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_to_bytes() {
        let pubkey = b"to-bytes-test";
        let hash = IdentityHash::from_public_key(pubkey);

        let bytes = hash.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes, hash.as_bytes());
    }

    #[test]
    fn test_as_hash256() {
        let pubkey = b"hash256-test";
        let identity_hash = IdentityHash::from_public_key(pubkey);

        let hash256 = identity_hash.as_hash256();
        assert_eq!(hash256.as_bytes(), identity_hash.as_bytes());
    }

    #[test]
    fn test_from_hash256() {
        let hash256 = Hash256::hash(b"some data");
        let identity_hash = IdentityHash::from(hash256.clone());

        assert_eq!(identity_hash.as_bytes(), hash256.as_bytes());
    }

    #[test]
    fn test_std_hash() {
        use std::collections::HashSet;

        let hash1 = IdentityHash::from_public_key(b"key1");
        let hash2 = IdentityHash::from_public_key(b"key2");
        let hash1_clone = IdentityHash::from_public_key(b"key1");

        let mut set = HashSet::new();
        set.insert(hash1.clone());
        set.insert(hash2);
        set.insert(hash1_clone);

        // hash1 and hash1_clone should be deduplicated
        assert_eq!(set.len(), 2);
        assert!(set.contains(&hash1));
    }

    #[test]
    fn test_as_ref() {
        let hash = IdentityHash::from_public_key(b"as-ref-test");
        let bytes: &[u8] = hash.as_ref();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, hash.as_bytes());
    }

    #[test]
    fn test_size_constant() {
        assert_eq!(IdentityHash::SIZE, 32);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn from_public_key_always_produces_valid_hash(key_bytes: Vec<u8>) {
            let hash = IdentityHash::from_public_key(&key_bytes);
            prop_assert_eq!(hash.as_bytes().len(), 32);
            prop_assert_eq!(hash.to_hex().len(), 64);
        }

        #[test]
        fn hex_roundtrip_always_succeeds(key_bytes: Vec<u8>) {
            let hash = IdentityHash::from_public_key(&key_bytes);
            let hex = hash.to_hex();
            let restored = IdentityHash::from_hex(&hex).unwrap();
            prop_assert_eq!(hash, restored);
        }

        #[test]
        fn bytes_roundtrip_always_succeeds(key_bytes: Vec<u8>) {
            let hash = IdentityHash::from_public_key(&key_bytes);
            let bytes = hash.to_bytes();
            let restored = IdentityHash::from_bytes(&bytes).unwrap();
            prop_assert_eq!(hash, restored);
        }

        #[test]
        fn equal_keys_produce_equal_hashes(key_bytes: Vec<u8>) {
            let hash1 = IdentityHash::from_public_key(&key_bytes);
            let hash2 = IdentityHash::from_public_key(&key_bytes);
            prop_assert!(hash1.ct_eq(&hash2));
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn different_keys_usually_produce_different_hashes(
            key1 in any::<Vec<u8>>(),
            key2 in any::<Vec<u8>>()
        ) {
            // Skip if keys are identical
            prop_assume!(key1 != key2);

            let hash1 = IdentityHash::from_public_key(&key1);
            let hash2 = IdentityHash::from_public_key(&key2);

            // With overwhelming probability, different inputs produce different hashes
            prop_assert_ne!(hash1, hash2);
        }
    }
}
