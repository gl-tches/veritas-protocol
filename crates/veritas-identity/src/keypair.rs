//! Identity keypair management for VERITAS protocol.
//!
//! Provides identity creation, key management, and cryptographic operations
//! for the decentralized identity system.
//!
//! ## Security Notes
//!
//! - All private keys implement `Zeroize` for secure memory cleanup
//! - Encrypted serialization uses ChaCha20-Poly1305
//! - Identity hashes are derived from public keys using BLAKE3

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use veritas_crypto::{
    decrypt, encrypt, EncryptedData, Hash256, MlDsaKeyPair, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, SharedSecret, SymmetricKey, X25519PublicKey, X25519StaticPrivateKey,
};

use crate::{IdentityError, IdentityHash, Result};

/// Domain separation context for keypair identity hash derivation.
/// This is different from the single-key context to ensure domain separation.
const KEYPAIR_IDENTITY_HASH_CONTEXT: &[u8] = b"VERITAS-KEYPAIR-IDENTITY-v1";

/// Domain separation context for key exchange derivation.
const KEY_EXCHANGE_CONTEXT: &str = "VERITAS key exchange v1";

/// Maximum size of serialized `IdentityPublicKeys` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
/// Public keys are small, so 4096 bytes is generous.
pub const MAX_IDENTITY_PUBLIC_KEYS_SIZE: usize = 4096;

/// Maximum size of serialized `EncryptedIdentityKeyPair` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
pub const MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE: usize = 8192;

/// Derive an identity hash from multiple public keys.
///
/// This function creates a unique identity hash by combining:
/// - A domain separator
/// - The X25519 exchange public key
/// - The ML-DSA signing public key (if available)
fn derive_identity_hash(
    exchange_public: &X25519PublicKey,
    signing_public: Option<&MlDsaPublicKey>,
) -> IdentityHash {
    // Bind signing bytes to a variable so they live long enough for the hash
    let signing_bytes = signing_public.map(|s| s.as_bytes());
    let mut inputs: Vec<&[u8]> = vec![KEYPAIR_IDENTITY_HASH_CONTEXT, exchange_public.as_bytes()];

    if let Some(ref bytes) = signing_bytes {
        inputs.push(bytes);
    }

    let hash = Hash256::hash_many(&inputs);
    IdentityHash::from(hash)
}

/// Custom serde module for ML-DSA public key serialization.
///
/// ML-DSA's `VerifyingKey` doesn't implement Serialize/Deserialize directly,
/// so we serialize as raw bytes and reconstruct on deserialization.
mod signing_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &Option<MlDsaPublicKey>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match key {
            Some(k) => serializer.serialize_some(&k.as_bytes()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<MlDsaPublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match bytes {
            Some(b) => {
                let key = MlDsaPublicKey::from_bytes(&b)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }
}

/// Public keys associated with an identity.
///
/// Contains the public components that can be freely shared:
/// - X25519 public key for key exchange
/// - ML-DSA public key for signature verification (post-quantum)
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityPublicKeys {
    /// X25519 public key for key exchange.
    pub exchange: X25519PublicKey,
    /// ML-DSA public key for signature verification (post-quantum, FIPS 204).
    #[serde(with = "signing_serde")]
    pub signing: Option<MlDsaPublicKey>,
}

impl IdentityPublicKeys {
    /// Derive the identity hash from these public keys.
    pub fn identity_hash(&self) -> IdentityHash {
        derive_identity_hash(&self.exchange, self.signing.as_ref())
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("IdentityPublicKeys serialization should not fail")
    }

    /// Deserialize from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input exceeds [`MAX_IDENTITY_PUBLIC_KEYS_SIZE`]
    /// or if deserialization fails.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_IDENTITY_PUBLIC_KEYS_SIZE {
            return Err(IdentityError::Validation(format!(
                "IdentityPublicKeys data too large: {} bytes (max: {})",
                bytes.len(),
                MAX_IDENTITY_PUBLIC_KEYS_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|_| IdentityError::Crypto(veritas_crypto::CryptoError::Decryption))
    }
}

impl std::fmt::Debug for IdentityPublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPublicKeys")
            .field("exchange", &self.exchange)
            .field("signing", &self.signing.is_some())
            .finish()
    }
}

/// An identity keypair containing both private and public keys.
///
/// This is the main identity type for the VERITAS protocol.
/// It provides:
/// - Key exchange (X25519) for establishing shared secrets
/// - Digital signatures (ML-DSA, when available) for authentication
/// - Identity hash derivation for unique identification
///
/// # Security
///
/// Private keys are zeroized on drop. Use encrypted serialization
/// for persistent storage.
///
/// # Example
///
/// ```
/// use veritas_identity::IdentityKeyPair;
///
/// // Generate a new identity
/// let identity = IdentityKeyPair::generate();
///
/// // Get the identity hash for sharing
/// let hash = identity.identity_hash();
/// println!("Identity: {}", hash.to_hex());
///
/// // Get public keys to share with others
/// let public_keys = identity.public_keys();
/// ```
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    /// X25519 private key for key exchange.
    exchange_private: X25519StaticPrivateKey,
    /// ML-DSA private key for signing (placeholder until crate stabilizes).
    #[zeroize(skip)]
    signing_private: Option<MlDsaPrivateKey>,
    /// Cached identity hash (derived from public keys).
    #[zeroize(skip)]
    identity_hash: IdentityHash,
    /// Cached public keys.
    #[zeroize(skip)]
    public_keys: IdentityPublicKeys,
}

impl IdentityKeyPair {
    /// Generate a new random identity keypair.
    ///
    /// Creates a new identity with:
    /// - Fresh X25519 keypair for key exchange
    /// - Fresh ML-DSA-65 keypair for post-quantum signing (FIPS 204)
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let identity = IdentityKeyPair::generate();
    /// println!("New identity: {}", identity.identity_hash());
    /// ```
    pub fn generate() -> Self {
        let exchange_private = X25519StaticPrivateKey::generate();
        let exchange_public = exchange_private.public_key();

        // Generate ML-DSA-65 keypair for post-quantum signing
        let mldsa_kp = MlDsaKeyPair::generate()
            .expect("ML-DSA key generation should not fail with OsRng");
        let (signing_priv, signing_pub) = mldsa_kp.into_parts();

        let identity_hash = derive_identity_hash(&exchange_public, Some(&signing_pub));

        let public_keys = IdentityPublicKeys {
            exchange: exchange_public,
            signing: Some(signing_pub),
        };

        Self {
            exchange_private,
            signing_private: Some(signing_priv),
            identity_hash,
            public_keys,
        }
    }

    /// Get the identity hash.
    ///
    /// This is the unique identifier for this identity, derived from
    /// the public keys using BLAKE3.
    pub fn identity_hash(&self) -> &IdentityHash {
        &self.identity_hash
    }

    /// Get the public keys.
    ///
    /// Returns the public components that can be freely shared with others.
    pub fn public_keys(&self) -> &IdentityPublicKeys {
        &self.public_keys
    }

    /// Perform Diffie-Hellman key exchange with a peer.
    ///
    /// Derives a shared secret using X25519, suitable for establishing
    /// encrypted communication channels.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - The peer's X25519 public key
    ///
    /// # Returns
    ///
    /// A shared secret that can be used to derive encryption keys.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let alice = IdentityKeyPair::generate();
    /// let bob = IdentityKeyPair::generate();
    ///
    /// // Both parties derive the same shared secret
    /// let alice_secret = alice.key_exchange(&bob.public_keys().exchange);
    /// let bob_secret = bob.key_exchange(&alice.public_keys().exchange);
    ///
    /// // Derive encryption key
    /// let alice_key = alice_secret.derive_key("VERITAS encryption v1");
    /// let bob_key = bob_secret.derive_key("VERITAS encryption v1");
    /// assert_eq!(alice_key, bob_key);
    /// ```
    pub fn key_exchange(&self, peer_public: &X25519PublicKey) -> SharedSecret {
        self.exchange_private.diffie_hellman(peer_public)
    }

    /// Derive an encryption key for a specific peer.
    ///
    /// Performs key exchange and derives a symmetric key suitable for
    /// encrypting messages to the peer.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - The peer's X25519 public key
    ///
    /// # Returns
    ///
    /// A 32-byte symmetric key.
    pub fn derive_encryption_key(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        let shared = self.key_exchange(peer_public);
        shared.derive_key(KEY_EXCHANGE_CONTEXT)
    }

    /// Sign a message using ML-DSA-65 (FIPS 204).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - ML-DSA signing key is not available
    /// - Signing fails for any reason
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        match &self.signing_private {
            Some(private_key) => Ok(private_key.sign(message)?),
            None => Err(IdentityError::Crypto(
                veritas_crypto::CryptoError::KeyGeneration(
                    "ML-DSA signing not available - waiting for crate to stabilize".into(),
                ),
            )),
        }
    }

    /// Check if ML-DSA signing is available.
    ///
    /// Returns `true` if this identity has an ML-DSA keypair and can
    /// perform post-quantum signatures.
    pub fn has_signing_key(&self) -> bool {
        self.signing_private.is_some()
    }

    /// Serialize the keypair for encrypted storage.
    ///
    /// Encrypts the private keys using the provided password-derived key.
    ///
    /// # Arguments
    ///
    /// * `storage_key` - A symmetric key derived from the user's password
    ///
    /// # Returns
    ///
    /// An encrypted representation suitable for persistent storage.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_identity::IdentityKeyPair;
    /// use veritas_crypto::SymmetricKey;
    ///
    /// let identity = IdentityKeyPair::generate();
    /// let storage_key = SymmetricKey::generate(); // In practice, derive from password
    ///
    /// // Encrypt for storage
    /// let encrypted = identity.to_encrypted(&storage_key).unwrap();
    ///
    /// // Later, restore from storage
    /// let restored = IdentityKeyPair::from_encrypted(&encrypted, &storage_key).unwrap();
    /// assert_eq!(identity.identity_hash(), restored.identity_hash());
    /// ```
    pub fn to_encrypted(&self, storage_key: &SymmetricKey) -> Result<EncryptedIdentityKeyPair> {
        let serializable = SerializableKeyPair {
            exchange_private_bytes: self.exchange_private.as_bytes().to_vec(),
            signing_private_bytes: self.signing_private.as_ref().map(|k| k.as_bytes().to_vec()),
        };

        let plaintext = bincode::serialize(&serializable).map_err(|_| {
            IdentityError::Crypto(veritas_crypto::CryptoError::Encryption(
                "Failed to serialize keypair".into(),
            ))
        })?;

        let encrypted_keys = encrypt(storage_key, &plaintext)?;

        Ok(EncryptedIdentityKeyPair {
            encrypted_keys,
            public_keys: self.public_keys.clone(),
        })
    }

    /// Restore a keypair from encrypted storage.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted keypair from `to_encrypted`
    /// * `storage_key` - The same symmetric key used for encryption
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The storage key is incorrect
    /// - The encrypted data is corrupted
    /// - Deserialization fails
    pub fn from_encrypted(
        encrypted: &EncryptedIdentityKeyPair,
        storage_key: &SymmetricKey,
    ) -> Result<Self> {
        // SECURITY: Wrap decrypted key material in Zeroizing to ensure it is
        // cleared from memory when no longer needed.
        let plaintext = zeroize::Zeroizing::new(decrypt(storage_key, &encrypted.encrypted_keys)?);

        let serializable: SerializableKeyPair = bincode::deserialize(&plaintext)
            .map_err(|_| IdentityError::Crypto(veritas_crypto::CryptoError::Decryption))?;

        let exchange_private =
            X25519StaticPrivateKey::from_bytes(&serializable.exchange_private_bytes)?;

        // Verify that the restored private key matches the stored public key
        let restored_public = exchange_private.public_key();
        if restored_public != encrypted.public_keys.exchange {
            return Err(IdentityError::Crypto(
                veritas_crypto::CryptoError::Decryption,
            ));
        }

        // Restore ML-DSA signing key from seed
        let signing_private: Option<MlDsaPrivateKey> =
            serializable
                .signing_private_bytes
                .as_ref()
                .and_then(|seed| MlDsaPrivateKey::from_seed(seed).ok());

        let identity_hash = encrypted.public_keys.identity_hash();

        Ok(Self {
            exchange_private,
            signing_private,
            identity_hash,
            public_keys: encrypted.public_keys.clone(),
        })
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("identity_hash", &self.identity_hash)
            .field("has_signing_key", &self.has_signing_key())
            .field("exchange_private", &"[REDACTED]")
            .finish()
    }
}

impl Clone for IdentityKeyPair {
    fn clone(&self) -> Self {
        // SECURITY: Reconstruct private key from bytes rather than cloning,
        // since X25519StaticPrivateKey intentionally does not implement Clone
        // to prevent accidental duplication of secret material (CRYPTO-FIX-3).
        let exchange_private =
            X25519StaticPrivateKey::from_bytes(self.exchange_private.as_bytes())
                .expect("cloning existing valid private key should not fail");

        // Reconstruct ML-DSA key from seed (MlDsaPrivateKey doesn't implement Clone by design)
        let signing_private = self
            .signing_private
            .as_ref()
            .and_then(|sk| MlDsaPrivateKey::from_seed(sk.as_bytes()).ok());

        Self {
            exchange_private,
            signing_private,
            identity_hash: self.identity_hash.clone(),
            public_keys: self.public_keys.clone(),
        }
    }
}

/// Internal serializable representation of private keys.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializableKeyPair {
    exchange_private_bytes: Vec<u8>,
    signing_private_bytes: Option<Vec<u8>>,
}

/// Encrypted identity keypair for persistent storage.
///
/// Contains:
/// - Encrypted private keys (ChaCha20-Poly1305)
/// - Public keys in plaintext (for identity verification)
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedIdentityKeyPair {
    /// Encrypted private keys.
    encrypted_keys: EncryptedData,
    /// Public keys (unencrypted for identification).
    pub public_keys: IdentityPublicKeys,
}

impl EncryptedIdentityKeyPair {
    /// Get the identity hash without decrypting.
    pub fn identity_hash(&self) -> IdentityHash {
        self.public_keys.identity_hash()
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("EncryptedIdentityKeyPair serialization should not fail")
    }

    /// Deserialize from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input exceeds [`MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE`]
    /// or if deserialization fails.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE {
            return Err(IdentityError::Validation(format!(
                "EncryptedIdentityKeyPair data too large: {} bytes (max: {})",
                bytes.len(),
                MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|_| IdentityError::Crypto(veritas_crypto::CryptoError::Decryption))
    }
}

impl std::fmt::Debug for EncryptedIdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedIdentityKeyPair")
            .field("identity_hash", &self.identity_hash())
            .field("public_keys", &self.public_keys)
            .field("encrypted_keys", &"[ENCRYPTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = IdentityKeyPair::generate();

        // Should have a valid identity hash
        assert!(!identity.identity_hash().as_bytes().iter().all(|&b| b == 0));

        // Should have public keys
        let public_keys = identity.public_keys();
        assert!(!public_keys.exchange.as_bytes().iter().all(|&b| b == 0));

        // ML-DSA should now be available
        assert!(identity.has_signing_key());
        assert!(public_keys.signing.is_some());
    }

    #[test]
    fn test_different_identities_have_different_hashes() {
        let identity1 = IdentityKeyPair::generate();
        let identity2 = IdentityKeyPair::generate();

        assert_ne!(
            identity1.identity_hash().as_bytes(),
            identity2.identity_hash().as_bytes()
        );
    }

    #[test]
    fn test_key_exchange() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Both parties derive the same shared secret
        let alice_secret = alice.key_exchange(&bob.public_keys().exchange);
        let bob_secret = bob.key_exchange(&alice.public_keys().exchange);

        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn test_derive_encryption_key() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Both parties derive the same encryption key
        let alice_key = alice.derive_encryption_key(&bob.public_keys().exchange);
        let bob_key = bob.derive_encryption_key(&alice.public_keys().exchange);

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_encrypted_serialization_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        // Encrypt
        let encrypted = identity.to_encrypted(&storage_key).unwrap();

        // Decrypt
        let restored = IdentityKeyPair::from_encrypted(&encrypted, &storage_key).unwrap();

        // Same identity hash
        assert_eq!(identity.identity_hash(), restored.identity_hash());

        // Same public keys
        assert_eq!(
            identity.public_keys().exchange,
            restored.public_keys().exchange
        );

        // Key exchange still works
        let peer = IdentityKeyPair::generate();
        let original_secret = identity.key_exchange(&peer.public_keys().exchange);
        let restored_secret = restored.key_exchange(&peer.public_keys().exchange);
        assert_eq!(original_secret.as_bytes(), restored_secret.as_bytes());
    }

    #[test]
    fn test_encrypted_serialization_wrong_key_fails() {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();
        let wrong_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();
        let result = IdentityKeyPair::from_encrypted(&encrypted, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_identity_hash_hex_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let hash = identity.identity_hash();

        let hex = hash.to_hex();
        let restored = IdentityHash::from_hex(&hex).unwrap();

        assert_eq!(hash, &restored);
    }

    #[test]
    fn test_identity_hash_bytes_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let hash = identity.identity_hash();

        let bytes = hash.to_bytes();
        let restored = IdentityHash::from_bytes(&bytes).unwrap();

        assert_eq!(hash, &restored);
    }

    #[test]
    fn test_public_keys_identity_hash_matches() {
        let identity = IdentityKeyPair::generate();

        let hash_from_identity = identity.identity_hash();
        let hash_from_public_keys = identity.public_keys().identity_hash();

        assert_eq!(hash_from_identity, &hash_from_public_keys);
    }

    #[test]
    fn test_encrypted_identity_hash_without_decrypting() {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();

        // Can get identity hash without decrypting
        let hash = encrypted.identity_hash();
        assert_eq!(identity.identity_hash(), &hash);
    }

    #[test]
    fn test_encrypted_keypair_bytes_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();
        let bytes = encrypted.to_bytes();
        let restored_encrypted = EncryptedIdentityKeyPair::from_bytes(&bytes).unwrap();

        // Can decrypt the restored encrypted keypair
        let restored = IdentityKeyPair::from_encrypted(&restored_encrypted, &storage_key).unwrap();
        assert_eq!(identity.identity_hash(), restored.identity_hash());
    }

    #[test]
    fn test_identity_debug_redacted() {
        let identity = IdentityKeyPair::generate();
        let debug = format!("{:?}", identity);

        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("IdentityKeyPair"));
    }

    #[test]
    fn test_identity_hash_display() {
        let identity = IdentityKeyPair::generate();
        let hash = identity.identity_hash();

        let display = format!("{}", hash);
        let debug = format!("{:?}", hash);

        // Display shows full hex
        assert_eq!(display.len(), 64);

        // Debug shows truncated
        assert!(debug.contains("..."));
    }

    #[test]
    fn test_clone_identity() {
        let identity = IdentityKeyPair::generate();
        let cloned = identity.clone();

        // Same identity hash
        assert_eq!(identity.identity_hash(), cloned.identity_hash());

        // Same public keys
        assert_eq!(
            identity.public_keys().exchange,
            cloned.public_keys().exchange
        );

        // Key exchange works the same
        let peer = IdentityKeyPair::generate();
        let original_secret = identity.key_exchange(&peer.public_keys().exchange);
        let cloned_secret = cloned.key_exchange(&peer.public_keys().exchange);
        assert_eq!(original_secret.as_bytes(), cloned_secret.as_bytes());
    }

    #[test]
    fn test_sign_and_verify_with_mldsa() {
        let identity = IdentityKeyPair::generate();
        let message = b"test message";

        // Signing should succeed with ML-DSA
        let signature = identity.sign(message).unwrap();

        // Verify with the public key
        let public_keys = identity.public_keys();
        let signing_pub = public_keys.signing.as_ref().unwrap();
        let result = signing_pub.verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_verify_wrong_message_fails() {
        let identity = IdentityKeyPair::generate();
        let signature = identity.sign(b"correct message").unwrap();

        let signing_pub = identity.public_keys().signing.as_ref().unwrap();
        let result = signing_pub.verify(b"wrong message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_keys_serialization() {
        let identity = IdentityKeyPair::generate();
        let public_keys = identity.public_keys();

        let bytes = public_keys.to_bytes();
        let restored = IdentityPublicKeys::from_bytes(&bytes).unwrap();

        assert_eq!(public_keys.exchange, restored.exchange);
        assert_eq!(public_keys.identity_hash(), restored.identity_hash());
    }

    // ========================================================================
    // Pre-deserialization size check tests (VERITAS-2026-0003)
    // ========================================================================

    #[test]
    fn test_identity_public_keys_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_IDENTITY_PUBLIC_KEYS_SIZE + 1];
        let result = IdentityPublicKeys::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_identity_public_keys_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_IDENTITY_PUBLIC_KEYS_SIZE];
        let result = IdentityPublicKeys::from_bytes(&at_limit);
        // If it fails, it should NOT be because of the size check
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_identity_public_keys_roundtrip_within_limit() {
        let identity = IdentityKeyPair::generate();
        let public_keys = identity.public_keys();
        let bytes = public_keys.to_bytes();

        assert!(
            bytes.len() <= MAX_IDENTITY_PUBLIC_KEYS_SIZE,
            "Serialized IdentityPublicKeys ({} bytes) exceeds MAX_IDENTITY_PUBLIC_KEYS_SIZE ({})",
            bytes.len(),
            MAX_IDENTITY_PUBLIC_KEYS_SIZE
        );

        let restored = IdentityPublicKeys::from_bytes(&bytes).unwrap();
        assert_eq!(public_keys.exchange, restored.exchange);
    }

    #[test]
    fn test_encrypted_identity_keypair_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE + 1];
        let result = EncryptedIdentityKeyPair::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_encrypted_identity_keypair_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE];
        let result = EncryptedIdentityKeyPair::from_bytes(&at_limit);
        // If it fails, it should NOT be because of the size check
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_encrypted_identity_keypair_roundtrip_within_limit() {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();
        let encrypted = identity.to_encrypted(&storage_key).unwrap();

        let bytes = encrypted.to_bytes();
        assert!(
            bytes.len() <= MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE,
            "Serialized EncryptedIdentityKeyPair ({} bytes) exceeds MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE ({})",
            bytes.len(),
            MAX_ENCRYPTED_IDENTITY_KEYPAIR_SIZE
        );

        let restored = EncryptedIdentityKeyPair::from_bytes(&bytes).unwrap();
        let restored_keypair = IdentityKeyPair::from_encrypted(&restored, &storage_key).unwrap();
        assert_eq!(identity.identity_hash(), restored_keypair.identity_hash());
    }
}
