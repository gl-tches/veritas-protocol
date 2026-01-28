//! ChaCha20-Poly1305 symmetric encryption.
//!
//! Provides AEAD encryption with 256-bit keys and 192-bit nonces (XChaCha20-Poly1305).
//!
//! ## Security Notes
//!
//! - Keys are zeroized on drop
//! - Nonces are randomly generated using OsRng
//! - Constant-time comparison for authentication tags
//! - NEVER reuse a nonce with the same key

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// Size of symmetric key in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Size of nonce in bytes (192 bits for XChaCha20).
pub const NONCE_SIZE: usize = 24;

/// Size of authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// A 256-bit symmetric key for ChaCha20-Poly1305 encryption.
///
/// The key is automatically zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    bytes: [u8; KEY_SIZE],
}

impl SymmetricKey {
    /// Generate a new random symmetric key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the key as a byte slice.
    ///
    /// # Security
    ///
    /// Be careful with this - avoid logging or persisting the returned bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// A 192-bit nonce for XChaCha20-Poly1305.
#[derive(Clone, Serialize, Deserialize)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
}

impl Nonce {
    /// Generate a new random nonce.
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a nonce from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 24 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; NONCE_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the nonce as a byte slice.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({:02x}{:02x}..)", self.bytes[0], self.bytes[1])
    }
}

/// Encrypted data with nonce prepended.
///
/// Format: `[nonce (24 bytes)][ciphertext + tag]`
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The nonce used for encryption.
    pub nonce: Nonce,
    /// The ciphertext with authentication tag appended.
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Get the total size of the encrypted data.
    pub fn len(&self) -> usize {
        NONCE_SIZE + self.ciphertext.len()
    }

    /// Check if the encrypted data is empty.
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }

    /// Serialize to bytes (nonce || ciphertext).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len());
        result.extend_from_slice(self.nonce.as_bytes());
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short to contain a nonce.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::Decryption);
        }
        let nonce = Nonce::from_bytes(&bytes[..NONCE_SIZE])?;
        let ciphertext = bytes[NONCE_SIZE..].to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// Returns encrypted data containing the nonce and ciphertext with authentication tag.
///
/// # Security
///
/// - Uses a random 192-bit nonce (safe for random generation)
/// - Provides authenticated encryption (detects tampering)
///
/// # Example
///
/// ```
/// use veritas_crypto::symmetric::{encrypt, decrypt, SymmetricKey};
///
/// let key = SymmetricKey::generate();
/// let plaintext = b"Hello, VERITAS!";
///
/// let encrypted = encrypt(&key, plaintext).unwrap();
/// let decrypted = decrypt(&key, &encrypted).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = Nonce::generate();
    let xnonce = XNonce::from_slice(nonce.as_bytes());

    let ciphertext = cipher
        .encrypt(xnonce, plaintext)
        .map_err(|_| CryptoError::Encryption("XChaCha20-Poly1305 encryption failed".into()))?;

    Ok(EncryptedData { nonce, ciphertext })
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns `CryptoError::Decryption` if:
/// - The ciphertext has been tampered with
/// - The wrong key is used
/// - The ciphertext format is invalid
pub fn decrypt(key: &SymmetricKey, encrypted: &EncryptedData) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(encrypted.nonce.as_bytes());

    cipher
        .decrypt(xnonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption)
}

/// Encrypt plaintext with additional authenticated data (AAD).
///
/// AAD is authenticated but not encrypted - useful for headers/metadata
/// that need integrity protection but can be public.
pub fn encrypt_with_aad(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData> {
    use chacha20poly1305::aead::Payload;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = Nonce::generate();
    let xnonce = XNonce::from_slice(nonce.as_bytes());

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::Encryption("XChaCha20-Poly1305 encryption failed".into()))?;

    Ok(EncryptedData { nonce, ciphertext })
}

/// Decrypt ciphertext with additional authenticated data (AAD).
///
/// The same AAD used during encryption must be provided for decryption.
pub fn decrypt_with_aad(
    key: &SymmetricKey,
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(encrypted.nonce.as_bytes());

    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad,
    };

    cipher.decrypt(xnonce, payload).map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, VERITAS!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let plaintext = b"Secret message";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(matches!(result, Err(CryptoError::Decryption)));
    }

    #[test]
    fn test_decrypt_fails_with_tampered_ciphertext() {
        let key = SymmetricKey::generate();
        let plaintext = b"Secret message";

        let mut encrypted = encrypt(&key, plaintext).unwrap();
        // Tamper with the ciphertext
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }
        let result = decrypt(&key, &encrypted);

        assert!(matches!(result, Err(CryptoError::Decryption)));
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = SymmetricKey::generate();
        let plaintext = b"Same message";

        let encrypted1 = encrypt(&key, plaintext).unwrap();
        let encrypted2 = encrypt(&key, plaintext).unwrap();

        // Nonces should be different (random)
        assert_ne!(encrypted1.nonce.as_bytes(), encrypted2.nonce.as_bytes());
        // Ciphertexts should be different due to different nonces
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = SymmetricKey::generate();
        let plaintext = b"";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = SymmetricKey::generate();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1MB

        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = SymmetricKey::generate();
        let plaintext = b"Test serialization";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let bytes = encrypted.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.nonce.as_bytes(), restored.nonce.as_bytes());
        assert_eq!(encrypted.ciphertext, restored.ciphertext);

        // Verify decryption still works
        let decrypted = decrypt(&key, &restored).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = SymmetricKey::generate();
        let plaintext = b"Secret message";
        let aad = b"public header";

        let encrypted = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aad_mismatch_fails() {
        let key = SymmetricKey::generate();
        let plaintext = b"Secret message";
        let aad = b"public header";
        let wrong_aad = b"different header";

        let encrypted = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let result = decrypt_with_aad(&key, &encrypted, wrong_aad);

        assert!(matches!(result, Err(CryptoError::Decryption)));
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [0x42u8; KEY_SIZE];
        let key = SymmetricKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_from_bytes_invalid_length() {
        let bytes = [0u8; 16]; // Too short
        let result = SymmetricKey::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_nonce_from_bytes() {
        let bytes = [0x42u8; NONCE_SIZE];
        let nonce = Nonce::from_bytes(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_from_bytes_invalid_length() {
        let bytes = [0u8; 12]; // Too short
        let result = Nonce::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: 12
            })
        ));
    }

    #[test]
    fn test_key_debug_redacted() {
        let key = SymmetricKey::generate();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42")); // Shouldn't leak any bytes
    }

    #[test]
    fn test_encrypted_data_len() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello";
        let encrypted = encrypt(&key, plaintext).unwrap();

        // Length should be nonce + ciphertext (plaintext + tag)
        assert_eq!(
            encrypted.len(),
            NONCE_SIZE + plaintext.len() + TAG_SIZE
        );
    }
}
