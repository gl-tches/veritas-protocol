//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) - FIPS 204.
//!
//! Implements ML-DSA-65 (NIST security level 3) for post-quantum digital
//! signatures. This is the primary signing algorithm for the VERITAS protocol.
//!
//! ## Security Level
//!
//! ML-DSA-65 provides approximately 192-bit security level,
//! equivalent to AES-192 against classical and quantum attacks.
//!
//! ## Key Sizes (FIPS 204)
//!
//! - Public key:  1,952 bytes
//! - Private key: 4,032 bytes (seed: 32 bytes)
//! - Signature:   3,309 bytes
//!
//! ## References
//!
//! - NIST FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
//! - ml-dsa crate: <https://crates.io/crates/ml-dsa>

use crate::{CryptoError, Result};
use ml_dsa::MlDsa65;
use zeroize::Zeroize;

/// Size of ML-DSA-65 public key in bytes (FIPS 204).
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Size of ML-DSA-65 private key in bytes (FIPS 204).
pub const PRIVATE_KEY_SIZE: usize = 4032;

/// Size of ML-DSA-65 signature in bytes (FIPS 204).
pub const SIGNATURE_SIZE: usize = 3309;

/// Size of ML-DSA-65 seed in bytes (compact private key representation).
pub const SEED_SIZE: usize = 32;

/// ML-DSA public key for signature verification.
#[derive(Clone)]
pub struct MlDsaPublicKey {
    inner: ml_dsa::VerifyingKey<MlDsa65>,
}

impl MlDsaPublicKey {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not the correct size (1,952 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "ML-DSA-65 public key must be {} bytes, got {}",
                PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }

        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        let encoded = hybrid_array::Array::from(arr);
        let inner = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);

        Ok(Self { inner })
    }

    /// Get the key as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let encoded: ml_dsa::EncodedVerifyingKey<MlDsa65> = self.inner.encode();
        encoded.0.to_vec()
    }

    /// Verify a signature.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SignatureVerification` if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<()> {
        use ml_dsa::signature::Verifier;
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| CryptoError::SignatureVerification)
    }
}

/// ML-DSA private key for signing.
///
/// Stored as a compact 32-byte seed from which the full signing key
/// can be derived deterministically.
///
/// # Security
///
/// - Does NOT implement `Clone` to prevent accidental duplication
/// - Implements `Zeroize` and zeroizes on drop
pub struct MlDsaPrivateKey {
    seed: [u8; SEED_SIZE],
}

impl Zeroize for MlDsaPrivateKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl MlDsaPrivateKey {
    /// Create from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEED_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "ML-DSA-65 seed must be {} bytes, got {}",
                SEED_SIZE,
                seed.len()
            )));
        }
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(seed);
        Ok(Self { seed: s })
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> MlDsaPublicKey {
        let seed_arr = hybrid_array::Array::from(self.seed);
        let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_arr);
        MlDsaPublicKey {
            inner: sk.verifying_key().clone(),
        }
    }

    /// Sign a message.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        use ml_dsa::signature::Signer;
        let seed_arr = hybrid_array::Array::from(self.seed);
        let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_arr);
        let sig = sk.sign(message);
        Ok(MlDsaSignature { inner: sig })
    }

    /// Get raw bytes (the 32-byte seed).
    ///
    /// # Security
    ///
    /// Handle with care - this exposes the private key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.seed
    }
}

/// ML-DSA key pair.
pub struct MlDsaKeyPair {
    /// The private key (for signing).
    /// SECURITY: pub(crate) to prevent external access to private key (CRYPTO-FIX-6).
    pub(crate) private: MlDsaPrivateKey,
    /// The public key (for verification).
    pub public: MlDsaPublicKey,
}

impl std::fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaKeyPair {{ private: [REDACTED], public: ... }}")
    }
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA-65 key pair.
    ///
    /// Uses `OsRng` for cryptographically secure random seed generation.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut seed = [0u8; SEED_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Create a key pair from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is invalid.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let private = MlDsaPrivateKey::from_seed(seed)?;
        let public = private.public_key();
        Ok(Self { private, public })
    }

    /// Consume the keypair and return its parts.
    ///
    /// This is the only way to extract the private key from a keypair
    /// across crate boundaries (since `private` is `pub(crate)`).
    pub fn into_parts(self) -> (MlDsaPrivateKey, MlDsaPublicKey) {
        (self.private, self.public)
    }

    /// Get a reference to the private key.
    pub(crate) fn private_key(&self) -> &MlDsaPrivateKey {
        &self.private
    }

    /// Get a reference to the public key.
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public
    }

    /// Get the seed bytes.
    pub fn seed(&self) -> &[u8] {
        self.private.as_bytes()
    }
}

/// ML-DSA signature.
#[derive(Clone)]
pub struct MlDsaSignature {
    inner: ml_dsa::Signature<MlDsa65>,
}

impl MlDsaSignature {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid ML-DSA-65 signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::SignatureVerification);
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(bytes);
        let encoded = hybrid_array::Array::from(arr);
        let inner = ml_dsa::Signature::<MlDsa65>::decode(&encoded)
            .ok_or(CryptoError::SignatureVerification)?;
        Ok(Self { inner })
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let encoded: ml_dsa::EncodedSignature<MlDsa65> = self.inner.encode();
        encoded.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_key_generation() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let pk_bytes = kp.public.as_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp.seed().len(), SEED_SIZE);
    }

    #[test]
    fn test_mldsa_sign_and_verify() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let message = b"Hello, post-quantum world!";

        let sig = kp.private.sign(message).unwrap();
        let sig_bytes = sig.as_bytes();
        assert_eq!(sig_bytes.len(), SIGNATURE_SIZE);

        // Verify with the public key
        let result = kp.public.verify(message, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mldsa_verify_wrong_message_fails() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let sig = kp.private.sign(b"correct message").unwrap();

        let result = kp.public.verify(b"wrong message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_verify_wrong_key_fails() {
        let kp1 = MlDsaKeyPair::generate().unwrap();
        let kp2 = MlDsaKeyPair::generate().unwrap();

        let sig = kp1.private.sign(b"test message").unwrap();

        // Verify with wrong public key should fail
        let result = kp2.public.verify(b"test message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_public_key_roundtrip() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let pk_bytes = kp.public.as_bytes();

        let restored = MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(restored.as_bytes(), pk_bytes);
    }

    #[test]
    fn test_mldsa_signature_roundtrip() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let sig = kp.private.sign(b"roundtrip test").unwrap();
        let sig_bytes = sig.as_bytes();

        let restored = MlDsaSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(restored.as_bytes(), sig_bytes);

        // Restored signature should still verify
        let result = kp.public.verify(b"roundtrip test", &restored);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mldsa_from_seed_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let kp1 = MlDsaKeyPair::from_seed(&seed).unwrap();
        let kp2 = MlDsaKeyPair::from_seed(&seed).unwrap();

        // Same seed produces same public key
        assert_eq!(kp1.public.as_bytes(), kp2.public.as_bytes());

        // Same seed produces same signature
        let msg = b"deterministic";
        let sig1 = kp1.private.sign(msg).unwrap();
        let sig2 = kp2.private.sign(msg).unwrap();
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_mldsa_into_parts() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let pk_bytes = kp.public.as_bytes();

        let (private, public) = kp.into_parts();
        assert_eq!(public.as_bytes(), pk_bytes);

        // Private key still works
        let sig = private.sign(b"test").unwrap();
        assert!(public.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_mldsa_invalid_public_key_size() {
        let result = MlDsaPublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_invalid_signature_size() {
        let result = MlDsaSignature::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_invalid_seed_size() {
        let result = MlDsaPrivateKey::from_seed(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_constants_match_fips204() {
        // FIPS 204 ML-DSA-65 sizes
        assert_eq!(PUBLIC_KEY_SIZE, 1952);
        assert_eq!(PRIVATE_KEY_SIZE, 4032);
        assert_eq!(SIGNATURE_SIZE, 3309);
        assert_eq!(SEED_SIZE, 32);
    }
}
