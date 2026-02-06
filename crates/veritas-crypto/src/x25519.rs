//! X25519 Diffie-Hellman key exchange.
//!
//! Provides elliptic curve Diffie-Hellman key exchange using Curve25519.
//! This is used as part of the hybrid key exchange (X25519 + ML-KEM).
//!
//! ## Security Notes
//!
//! - Private keys are zeroized on drop
//! - Uses OsRng for key generation
//! - Shared secrets are zeroized after use

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// Size of X25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// X25519 public key for key exchange.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl X25519PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the key as bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "X25519PublicKey({:02x}{:02x}..)",
            self.bytes[0], self.bytes[1]
        )
    }
}

impl From<PublicKey> for X25519PublicKey {
    fn from(key: PublicKey) -> Self {
        Self {
            bytes: key.to_bytes(),
        }
    }
}

impl From<&X25519PublicKey> for PublicKey {
    fn from(key: &X25519PublicKey) -> Self {
        PublicKey::from(key.bytes)
    }
}

/// X25519 private key (static) for key exchange.
///
/// Use this for long-term identity keys that need persistence.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519StaticPrivateKey {
    bytes: [u8; PRIVATE_KEY_SIZE],
}

impl X25519StaticPrivateKey {
    /// Generate a new random private key.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        Self {
            bytes: secret.to_bytes(),
        }
    }

    /// Create from raw bytes.
    ///
    /// # Security
    ///
    /// Only use bytes from a secure source.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PRIVATE_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PRIVATE_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        let secret = StaticSecret::from(self.bytes);
        let public = PublicKey::from(&secret);
        X25519PublicKey::from(public)
    }

    /// Perform Diffie-Hellman key exchange.
    ///
    /// Returns the shared secret derived from this private key and the peer's public key.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> SharedSecret {
        let secret = StaticSecret::from(self.bytes);
        let peer = PublicKey::from(peer_public);
        let shared = secret.diffie_hellman(&peer);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }

    /// Get raw bytes (for serialization).
    ///
    /// # Security
    ///
    /// Handle with care - this exposes the private key.
    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for X25519StaticPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519StaticPrivateKey([REDACTED])")
    }
}

// SECURITY: Clone intentionally NOT implemented for X25519StaticPrivateKey.
// Private keys should not be cloneable to prevent accidental duplication
// of secret material in memory (CRYPTO-FIX-3).

/// X25519 ephemeral key pair for single-use key exchange.
///
/// Use this for per-message encryption where the private key is
/// discarded immediately after deriving the shared secret.
pub struct X25519EphemeralKeyPair {
    secret: EphemeralSecret,
    public: X25519PublicKey,
}

impl X25519EphemeralKeyPair {
    /// Generate a new ephemeral key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self {
            secret,
            public: X25519PublicKey::from(public_key),
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman and consume the ephemeral key.
    ///
    /// The private key is destroyed after this operation.
    pub fn diffie_hellman(self, peer_public: &X25519PublicKey) -> SharedSecret {
        let peer = PublicKey::from(peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }
}

impl std::fmt::Debug for X25519EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519EphemeralKeyPair {{ public: {:?} }}", self.public)
    }
}

/// Shared secret derived from Diffie-Hellman key exchange.
///
/// This should be used as input to a KDF, not directly as an encryption key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl SharedSecret {
    /// Get the shared secret as bytes.
    ///
    /// # Security
    ///
    /// Use this to derive actual encryption keys via a KDF.
    /// Don't use directly as an encryption key.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }

    /// Derive an encryption key using BLAKE3.
    ///
    /// Uses BLAKE3's key derivation mode with a context string.
    pub fn derive_key(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.bytes)
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_key_generation() {
        let key = X25519StaticPrivateKey::generate();
        let public = key.public_key();

        // Public key should be 32 bytes
        assert_eq!(public.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_static_key_exchange() {
        let alice_private = X25519StaticPrivateKey::generate();
        let alice_public = alice_private.public_key();

        let bob_private = X25519StaticPrivateKey::generate();
        let bob_public = bob_private.public_key();

        // Both parties derive the same shared secret
        let alice_shared = alice_private.diffie_hellman(&bob_public);
        let bob_shared = bob_private.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let alice = X25519EphemeralKeyPair::generate();
        let alice_public = alice.public_key().clone();

        let bob = X25519EphemeralKeyPair::generate();
        let bob_public = bob.public_key().clone();

        // Both parties derive the same shared secret
        let alice_shared = alice.diffie_hellman(&bob_public);
        let bob_shared = bob.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_mixed_key_exchange() {
        // Static key can exchange with ephemeral
        let alice_static = X25519StaticPrivateKey::generate();
        let alice_public = alice_static.public_key();

        let bob_ephemeral = X25519EphemeralKeyPair::generate();
        let bob_public = bob_ephemeral.public_key().clone();

        let alice_shared = alice_static.diffie_hellman(&bob_public);
        let bob_shared = bob_ephemeral.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let alice = X25519StaticPrivateKey::generate();
        let _alice_public = alice.public_key();

        let bob = X25519StaticPrivateKey::generate();
        let carol = X25519StaticPrivateKey::generate();

        let shared_ab = alice.diffie_hellman(&bob.public_key());
        let shared_ac = alice.diffie_hellman(&carol.public_key());

        assert_ne!(shared_ab.as_bytes(), shared_ac.as_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let shared = alice.diffie_hellman(&bob.public_key());

        // Derive keys for different purposes
        let encryption_key = shared.derive_key("VERITAS encryption v1");
        let mac_key = shared.derive_key("VERITAS mac v1");

        // Different contexts produce different keys
        assert_ne!(encryption_key, mac_key);
    }

    #[test]
    fn test_public_key_serialization() {
        let private = X25519StaticPrivateKey::generate();
        let public = private.public_key();

        let bytes = public.to_bytes();
        let restored = X25519PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(public, restored);
    }

    #[test]
    fn test_private_key_serialization() {
        let original = X25519StaticPrivateKey::generate();
        let public = original.public_key();

        let bytes = original.as_bytes();
        let restored = X25519StaticPrivateKey::from_bytes(bytes).unwrap();

        // Same public key means same private key
        assert_eq!(restored.public_key(), public);
    }

    #[test]
    fn test_invalid_key_length() {
        let short = [0u8; 16];
        assert!(X25519PublicKey::from_bytes(&short).is_err());
        assert!(X25519StaticPrivateKey::from_bytes(&short).is_err());
    }

    #[test]
    fn test_debug_redacted() {
        let private = X25519StaticPrivateKey::generate();
        let shared = SharedSecret {
            bytes: [0u8; SHARED_SECRET_SIZE],
        };

        let private_debug = format!("{:?}", private);
        let shared_debug = format!("{:?}", shared);

        assert!(private_debug.contains("REDACTED"));
        assert!(shared_debug.contains("REDACTED"));
    }

    #[test]
    fn test_public_key_debug() {
        let private = X25519StaticPrivateKey::generate();
        let public = private.public_key();
        let debug = format!("{:?}", public);

        // Should show partial hex, not REDACTED
        assert!(debug.contains("X25519PublicKey"));
        assert!(!debug.contains("REDACTED"));
    }

}
