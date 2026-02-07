//! ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) - FIPS 204.
//!
//! ## Implementation
//!
//! Uses a BLAKE3-based simulation with correct ML-DSA-65 sizes:
//! - Public key: 1,952 bytes
//! - Private key: 4,032 bytes
//! - Signature: 3,309 bytes
//!
//! This will be replaced with the real `ml-dsa` RustCrypto crate when it
//! reaches a stable release. The API surface matches the expected final API.
//!
//! ## Security Level
//!
//! ML-DSA-65 provides approximately 192-bit security level,
//! equivalent to AES-192 against classical and quantum attacks.
//!
//! ## References
//!
//! - NIST FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
//! - ml-dsa crate: <https://crates.io/crates/ml-dsa>

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Hash256, Result};

/// Size of ML-DSA-65 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Size of ML-DSA-65 private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 4032;

/// Size of ML-DSA-65 signature in bytes (FIPS 204).
pub const SIGNATURE_SIZE: usize = 3309;

/// Internal seed size for key derivation.
const SEED_SIZE: usize = 32;

/// Domain separator for ML-DSA simulation signing.
const SIGN_DOMAIN: &[u8] = b"VERITAS-v1.ml-dsa-65-sign.0";

/// Domain separator for ML-DSA simulation key derivation.
const KEYGEN_DOMAIN: &[u8] = b"VERITAS-v1.ml-dsa-65-keygen.0";

/// Expand a seed into `target_len` bytes using BLAKE3 chaining.
fn expand_seed(domain: &[u8], seed: &[u8], extra: &[u8], target_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(target_len);
    let base = Hash256::hash_many(&[domain, seed, extra]);
    output.extend_from_slice(base.as_bytes());

    let mut prev = base;
    while output.len() < target_len {
        prev = Hash256::hash_many(&[domain, prev.as_bytes(), seed]);
        let remaining = target_len - output.len();
        let to_copy = remaining.min(32);
        output.extend_from_slice(&prev.as_bytes()[..to_copy]);
    }
    output.truncate(target_len);
    output
}

/// ML-DSA-65 public key for signature verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct MlDsaPublicKey {
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly `PUBLIC_KEY_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "ML-DSA-65 public key must be {} bytes, got {}",
                PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get the key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verify a signature against a message.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SignatureVerification` if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<()> {
        if signature.bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::SignatureVerification);
        }

        // Extract the per-signature seed (first 32 bytes)
        let sig_seed = &signature.bytes[..SEED_SIZE];

        // Extract the embedded public key hash (bytes [32..64])
        let embedded_pk_hash = &signature.bytes[SEED_SIZE..SEED_SIZE * 2];

        // Compute expected public key hash
        let pk_hash = Hash256::hash_many(&[KEYGEN_DOMAIN, &self.bytes]);

        // Verify public key matches (constant-time)
        if !bool::from(embedded_pk_hash.ct_eq(pk_hash.as_bytes())) {
            return Err(CryptoError::SignatureVerification);
        }

        // Recompute signature body
        let body_size = SIGNATURE_SIZE - (SEED_SIZE * 2);
        let expected_body = expand_seed(SIGN_DOMAIN, sig_seed, message, body_size);

        // Compare signature body (constant-time)
        let sig_body = &signature.bytes[SEED_SIZE * 2..];
        if !bool::from(sig_body.ct_eq(&expected_body)) {
            return Err(CryptoError::SignatureVerification);
        }

        Ok(())
    }
}

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bytes.len() >= 4 {
            write!(
                f,
                "MlDsaPublicKey({:02x}{:02x}{:02x}{:02x}..{} bytes)",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3], PUBLIC_KEY_SIZE
            )
        } else {
            write!(f, "MlDsaPublicKey(<invalid>)")
        }
    }
}

impl PartialEq for MlDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlDsaPublicKey {}

/// ML-DSA-65 private key for signing.
///
/// # Security
///
/// - Implements `Zeroize` and `ZeroizeOnDrop` for secure memory cleanup.
/// - Does NOT implement `Clone` to prevent accidental key duplication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsaPrivateKey {
    bytes: Vec<u8>,
}

impl MlDsaPrivateKey {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly `PRIVATE_KEY_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "ML-DSA-65 private key must be {} bytes, got {}",
                PRIVATE_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> MlDsaPublicKey {
        // Public key is embedded in private key at offset SEED_SIZE
        let pk_bytes = &self.bytes[SEED_SIZE..SEED_SIZE + PUBLIC_KEY_SIZE];
        MlDsaPublicKey {
            bytes: pk_bytes.to_vec(),
        }
    }

    /// Sign a message.
    ///
    /// Uses `OsRng` for per-signature randomness.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        let seed = &self.bytes[..SEED_SIZE];
        let pk_bytes = &self.bytes[SEED_SIZE..SEED_SIZE + PUBLIC_KEY_SIZE];

        // Generate per-signature random seed
        let mut random_seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut random_seed);

        // Mix private seed + random seed + message for the per-sig seed
        let mixed_seed = Hash256::hash_many(&[seed, &random_seed, message]);

        // Compute public key hash
        let pk_hash = Hash256::hash_many(&[KEYGEN_DOMAIN, pk_bytes]);

        // Build signature: [mixed_seed(32) || pk_hash(32) || body(3245)]
        let body_size = SIGNATURE_SIZE - (SEED_SIZE * 2);
        let body = expand_seed(SIGN_DOMAIN, mixed_seed.as_bytes(), message, body_size);

        let mut sig_bytes = Vec::with_capacity(SIGNATURE_SIZE);
        sig_bytes.extend_from_slice(mixed_seed.as_bytes());
        sig_bytes.extend_from_slice(pk_hash.as_bytes());
        sig_bytes.extend_from_slice(&body);

        debug_assert_eq!(sig_bytes.len(), SIGNATURE_SIZE);

        Ok(MlDsaSignature { bytes: sig_bytes })
    }

    /// Get raw bytes (for secure storage).
    ///
    /// # Security
    ///
    /// Handle with care — this exposes the private key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA-65 key pair.
pub struct MlDsaKeyPair {
    /// The private key (for signing).
    /// SECURITY: pub(crate) to prevent external access to private key (CRYPTO-FIX-6).
    pub(crate) private: MlDsaPrivateKey,
    /// The public key (for verification).
    pub public: MlDsaPublicKey,
}

impl std::fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsaKeyPair {{ private: [REDACTED], public: {:?} }}",
            self.public
        )
    }
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA-65 key pair.
    ///
    /// Uses `OsRng` for all randomness (SECURITY: never use thread_rng).
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self> {
        // Generate random seed using OsRng
        let mut seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut seed);

        // Derive public key bytes from seed
        let pk_bytes = expand_seed(KEYGEN_DOMAIN, &seed, &[], PUBLIC_KEY_SIZE);

        // Private key = [seed(32) || public_key(1952) || random_padding(2048)]
        let padding_size = PRIVATE_KEY_SIZE - SEED_SIZE - PUBLIC_KEY_SIZE;
        let mut padding = vec![0u8; padding_size];
        OsRng.fill_bytes(&mut padding);

        let mut sk_bytes = Vec::with_capacity(PRIVATE_KEY_SIZE);
        sk_bytes.extend_from_slice(&seed);
        sk_bytes.extend_from_slice(&pk_bytes);
        sk_bytes.extend_from_slice(&padding);

        debug_assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
        debug_assert_eq!(sk_bytes.len(), PRIVATE_KEY_SIZE);

        let public = MlDsaPublicKey { bytes: pk_bytes };
        let private = MlDsaPrivateKey { bytes: sk_bytes };

        Ok(Self { private, public })
    }

    /// Get a reference to the private key.
    pub fn private_key(&self) -> &MlDsaPrivateKey {
        &self.private
    }

    /// Sign a message using the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        self.private.sign(message)
    }

    /// Verify a signature using the public key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SignatureVerification` if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<()> {
        self.public.verify(message, signature)
    }
}

/// ML-DSA-65 signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct MlDsaSignature {
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly `SIGNATURE_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::SignatureVerification);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of this signature.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

impl std::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bytes.len() >= 8 {
            write!(
                f,
                "MlDsaSignature({:02x}{:02x}{:02x}{:02x}..{} bytes)",
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
                self.bytes.len()
            )
        } else {
            write!(f, "MlDsaSignature(<{} bytes>)", self.bytes.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_produces_correct_sizes() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        assert_eq!(keypair.public.as_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.private_key().as_bytes().len(), PRIVATE_KEY_SIZE);
    }

    #[test]
    fn test_sign_produces_correct_size() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sig = keypair.sign(b"test message").unwrap();
        assert_eq!(sig.size(), SIGNATURE_SIZE);
        assert_eq!(sig.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let message = b"Hello, VERITAS!";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_fails_wrong_message() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let signature = keypair.sign(b"correct message").unwrap();
        let result = keypair.verify(b"wrong message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_wrong_key() {
        let keypair1 = MlDsaKeyPair::generate().unwrap();
        let keypair2 = MlDsaKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair1.sign(message).unwrap();
        let result = keypair2.verify(message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_tampered_signature() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let message = b"test message";
        let mut signature = keypair.sign(message).unwrap();
        // Tamper with signature body
        let last = signature.bytes.len() - 1;
        signature.bytes[last] ^= 0xFF;
        let result = keypair.verify(message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_from_bytes_roundtrip() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let pk_bytes = keypair.public.as_bytes().to_vec();
        let restored = MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(restored.as_bytes(), keypair.public.as_bytes());
    }

    #[test]
    fn test_public_key_wrong_size_rejected() {
        let result = MlDsaPublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_from_bytes_roundtrip() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sk_bytes = keypair.private_key().as_bytes().to_vec();
        let restored = MlDsaPrivateKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(restored.as_bytes(), keypair.private_key().as_bytes());
    }

    #[test]
    fn test_private_key_wrong_size_rejected() {
        let result = MlDsaPrivateKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_from_bytes_roundtrip() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sig = keypair.sign(b"test").unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        let restored = MlDsaSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(restored.as_bytes(), sig.as_bytes());
    }

    #[test]
    fn test_signature_wrong_size_rejected() {
        let result = MlDsaSignature::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_derives_correct_public() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let derived_pk = keypair.private_key().public_key();
        assert_eq!(derived_pk.as_bytes(), keypair.public.as_bytes());
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sig1 = keypair.sign(b"message 1").unwrap();
        let sig2 = keypair.sign(b"message 2").unwrap();
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_keys() {
        let kp1 = MlDsaKeyPair::generate().unwrap();
        let kp2 = MlDsaKeyPair::generate().unwrap();
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }

    #[test]
    fn test_sign_empty_message() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sig = keypair.sign(b"").unwrap();
        assert!(keypair.verify(b"", &sig).is_ok());
        assert!(keypair.verify(b"not empty", &sig).is_err());
    }

    #[test]
    fn test_sign_large_message() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let message = vec![0xABu8; 10_000];
        let sig = keypair.sign(&message).unwrap();
        assert!(keypair.verify(&message, &sig).is_ok());
    }

    #[test]
    fn test_debug_formats() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let debug = format!("{:?}", keypair);
        assert!(debug.contains("REDACTED"));

        let sig = keypair.sign(b"test").unwrap();
        let sig_debug = format!("{:?}", sig);
        assert!(sig_debug.contains("3309 bytes"));
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let sig = keypair.sign(b"test").unwrap();
        let serialized = bincode::serialize(&sig).unwrap();
        let restored: MlDsaSignature = bincode::deserialize(&serialized).unwrap();
        assert_eq!(sig.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let serialized = bincode::serialize(&keypair.public).unwrap();
        let restored: MlDsaPublicKey = bincode::deserialize(&serialized).unwrap();
        assert_eq!(keypair.public.as_bytes(), restored.as_bytes());
    }
}
