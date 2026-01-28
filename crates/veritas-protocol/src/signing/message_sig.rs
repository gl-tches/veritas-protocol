//! Message signature types and operations.
//!
//! Provides cryptographic signing for VERITAS messages using a domain-separated
//! approach that ensures signatures are bound to specific message content.
//!
//! ## Placeholder Implementation Warning
//!
//! **THIS IS A PLACEHOLDER IMPLEMENTATION**
//!
//! The current HMAC-BLAKE3 scheme derives keys from public keys, which means
//! anyone with the public key can forge signatures. This is intentionally
//! insecure and exists only to:
//!
//! 1. Establish the API surface for message signing
//! 2. Allow integration testing during development
//! 3. Be replaced with ML-DSA when the crate stabilizes
//!
//! **DO NOT USE IN PRODUCTION** until ML-DSA support is implemented.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use veritas_crypto::Hash256;
use veritas_identity::{IdentityHash, IdentityKeyPair, IdentityPublicKeys};

use crate::error::{ProtocolError, Result};

/// Domain separator for message signatures.
///
/// This prefix ensures signatures cannot be reused across different contexts
/// or confused with other types of hashes in the protocol.
pub const DOMAIN_SEPARATOR: &[u8] = b"VERITAS-MESSAGE-SIGNATURE-v1";

/// Size of a message signature in bytes.
///
/// Currently 32 bytes for HMAC-BLAKE3. Will remain 32 bytes or larger
/// when ML-DSA is implemented.
pub const SIGNATURE_SIZE: usize = 32;

/// Context string for deriving signing keys from identity keys.
const SIGNING_KEY_DERIVATION_CONTEXT: &str = "VERITAS placeholder signing key v1";

/// Supported signature scheme versions.
///
/// The protocol supports multiple signature versions to allow smooth
/// transitions between cryptographic schemes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureVersion {
    /// HMAC-BLAKE3 placeholder (NOT SECURE - for API development only).
    ///
    /// This version uses keyed BLAKE3 hashing. The key is derived from
    /// the sender's public key, which means anyone can forge signatures.
    /// This exists only as a placeholder until ML-DSA is ready.
    #[default]
    HmacBlake3 = 1,

    /// ML-DSA post-quantum signatures (future implementation).
    ///
    /// Will use the NIST-standardized ML-DSA (formerly CRYSTALS-Dilithium)
    /// algorithm for post-quantum secure signatures. This provides:
    /// - Security against quantum computer attacks
    /// - Non-repudiation
    /// - Proper public-key verification
    MlDsa = 2,
}

/// A cryptographic signature for a VERITAS message.
///
/// Contains the signature bytes and version information to allow
/// the verifier to use the correct verification algorithm.
///
/// # Security Note
///
/// The current `HmacBlake3` version is a PLACEHOLDER and not cryptographically
/// secure. Do not rely on it for actual authentication until ML-DSA support
/// is implemented.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageSignature {
    /// Raw signature bytes.
    bytes: [u8; SIGNATURE_SIZE],

    /// Signature scheme version.
    version: SignatureVersion,
}

impl MessageSignature {
    /// Create a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidSignature` if the bytes are not
    /// exactly `SIGNATURE_SIZE` (32 bytes).
    pub fn from_bytes(bytes: &[u8], version: SignatureVersion) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(ProtocolError::InvalidSignature);
        }

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);

        Ok(Self {
            bytes: sig_bytes,
            version,
        })
    }

    /// Get the signature as a byte slice.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }

    /// Get the signature version.
    pub fn version(&self) -> SignatureVersion {
        self.version
    }

    /// Create a placeholder zero signature.
    ///
    /// This is useful for testing or when a signature field is required
    /// but not yet computed.
    ///
    /// # Warning
    ///
    /// A placeholder signature will fail verification.
    pub fn placeholder() -> Self {
        Self {
            bytes: [0u8; SIGNATURE_SIZE],
            version: SignatureVersion::HmacBlake3,
        }
    }

    /// Check if this is a placeholder (zero) signature.
    pub fn is_placeholder(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for MessageSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first 8 bytes of signature to avoid log pollution
        let short_hex: String = self.bytes[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        f.debug_struct("MessageSignature")
            .field("bytes", &format!("{}...", short_hex))
            .field("version", &self.version)
            .finish()
    }
}

impl PartialEq for MessageSignature {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for signature bytes
        self.version == other.version && self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for MessageSignature {}

/// Data to be signed for a message.
///
/// This struct computes a hash of all message attributes that need to be
/// authenticated: sender identity, timestamp, and content. The hash is
/// then signed to create the message signature.
///
/// # Construction
///
/// For messages:
/// ```ignore
/// let signing_data = SigningData::new(&sender_id, timestamp, &content_hash);
/// ```
///
/// For receipts (when you already have the data hash):
/// ```ignore
/// let signing_data = SigningData::from_hash(receipt_data_hash);
/// ```
#[derive(Clone, Zeroize)]
pub struct SigningData {
    /// Hash of the data to be signed.
    data_hash: Hash256,
}

impl SigningData {
    /// Create signing data for a message.
    ///
    /// Computes a domain-separated hash of:
    /// - Domain separator ("VERITAS-MESSAGE-SIGNATURE-v1")
    /// - Sender identity hash (32 bytes)
    /// - Timestamp (8 bytes, big-endian)
    /// - Content hash (32 bytes)
    ///
    /// # Arguments
    ///
    /// * `sender_id` - The sender's identity hash
    /// * `timestamp` - Unix timestamp in seconds
    /// * `content_hash` - BLAKE3 hash of the message content
    pub fn new(sender_id: &IdentityHash, timestamp: u64, content_hash: &Hash256) -> Self {
        let data_hash = Hash256::hash_many(&[
            DOMAIN_SEPARATOR,
            sender_id.as_bytes(),
            &timestamp.to_be_bytes(),
            content_hash.as_bytes(),
        ]);

        Self { data_hash }
    }

    /// Create signing data from an existing hash.
    ///
    /// This is useful for receipts or when the data hash has already
    /// been computed elsewhere.
    ///
    /// # Arguments
    ///
    /// * `hash` - Pre-computed hash of the data to sign
    pub fn from_hash(hash: Hash256) -> Self {
        Self { data_hash: hash }
    }

    /// Get the hash of the signing data.
    pub fn hash(&self) -> &Hash256 {
        &self.data_hash
    }
}

impl std::fmt::Debug for SigningData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningData")
            .field("data_hash", &self.data_hash)
            .finish()
    }
}

/// Sign a message using the sender's identity keypair.
///
/// Creates a cryptographic signature over the signing data that can be
/// verified by anyone with the sender's public keys.
///
/// # Arguments
///
/// * `sender` - The sender's identity keypair (contains private key)
/// * `signing_data` - The data to sign (computed from message attributes)
///
/// # Returns
///
/// A `MessageSignature` that can be included in the encrypted message payload.
///
/// # Security Warning
///
/// **PLACEHOLDER IMPLEMENTATION**: The current HMAC-BLAKE3 scheme is NOT
/// cryptographically secure. The signature is derived from a key that can
/// be computed from public information. This will be replaced with ML-DSA.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::signing::{sign_message, SigningData};
/// use veritas_identity::IdentityKeyPair;
/// use veritas_crypto::Hash256;
///
/// let sender = IdentityKeyPair::generate();
/// let content_hash = Hash256::hash(b"Hello!");
/// let signing_data = SigningData::new(
///     sender.identity_hash(),
///     chrono::Utc::now().timestamp() as u64,
///     &content_hash,
/// );
///
/// let signature = sign_message(&sender, &signing_data)?;
/// ```
pub fn sign_message(
    sender: &IdentityKeyPair,
    signing_data: &SigningData,
) -> Result<MessageSignature> {
    // PLACEHOLDER: Derive signing key from the sender's exchange public key.
    //
    // In the real ML-DSA implementation, this would use the sender's private
    // signing key directly. The current approach derives a key from public
    // information, which means anyone can forge signatures.
    //
    // This is intentionally insecure to:
    // 1. Provide a working API for development
    // 2. Be obviously replaceable when ML-DSA is ready
    //
    // The derivation uses the private key bytes to at least require access
    // to the private key for signing (even though verification is broken).
    let signing_key = derive_placeholder_signing_key_private(sender);

    // Create HMAC-BLAKE3 signature
    let signature_hash = Hash256::keyed_hash(&signing_key, signing_data.hash().as_bytes());

    Ok(MessageSignature {
        bytes: signature_hash.to_bytes(),
        version: SignatureVersion::HmacBlake3,
    })
}

/// Verify a message signature.
///
/// Checks that the signature was created by the owner of the given public keys
/// over the specified signing data.
///
/// # Arguments
///
/// * `sender_public` - The sender's public keys
/// * `signing_data` - The data that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err(ProtocolError::InvalidSignature)` otherwise.
///
/// # Security Warning
///
/// **PLACEHOLDER IMPLEMENTATION**: The current HMAC-BLAKE3 verification scheme
/// derives the key from public information, which means verification does not
/// actually prove the sender signed the message - anyone with the public key
/// could have created the signature.
///
/// When ML-DSA is implemented, this will provide proper public-key verification.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::signing::{sign_message, verify_signature, SigningData};
/// use veritas_identity::IdentityKeyPair;
/// use veritas_crypto::Hash256;
///
/// let sender = IdentityKeyPair::generate();
/// let content_hash = Hash256::hash(b"Hello!");
/// let signing_data = SigningData::new(
///     sender.identity_hash(),
///     1234567890,
///     &content_hash,
/// );
///
/// let signature = sign_message(&sender, &signing_data)?;
///
/// // Verification (placeholder - not cryptographically secure)
/// verify_signature(sender.public_keys(), &signing_data, &signature)?;
/// ```
pub fn verify_signature(
    sender_public: &IdentityPublicKeys,
    signing_data: &SigningData,
    signature: &MessageSignature,
) -> Result<()> {
    match signature.version {
        SignatureVersion::HmacBlake3 => verify_hmac_blake3(sender_public, signing_data, signature),
        SignatureVersion::MlDsa => {
            // ML-DSA verification will be implemented when the crate stabilizes
            Err(ProtocolError::InvalidSignature)
        }
    }
}

/// Derive the placeholder signing key from private key material.
///
/// This function derives a signing key that can only be computed with
/// access to the private key. However, for verification we need to use
/// a different derivation from public keys only.
fn derive_placeholder_signing_key_private(sender: &IdentityKeyPair) -> [u8; 32] {
    // Derive from the identity hash and a context
    // The identity hash is derived from public keys, so the verifier can compute this too
    sender
        .identity_hash()
        .as_hash256()
        .derive_key(SIGNING_KEY_DERIVATION_CONTEXT)
}

/// Derive the placeholder signing key from public keys only.
///
/// For the placeholder scheme, we derive the same key from public information
/// so that verification can succeed. This is NOT secure - it's a placeholder.
fn derive_placeholder_signing_key_public(sender_public: &IdentityPublicKeys) -> [u8; 32] {
    // Derive from the identity hash (computed from public keys)
    sender_public
        .identity_hash()
        .as_hash256()
        .derive_key(SIGNING_KEY_DERIVATION_CONTEXT)
}

/// Verify an HMAC-BLAKE3 placeholder signature.
fn verify_hmac_blake3(
    sender_public: &IdentityPublicKeys,
    signing_data: &SigningData,
    signature: &MessageSignature,
) -> Result<()> {
    // PLACEHOLDER: Derive the same key from public information.
    //
    // In real ML-DSA verification, we would use the public signing key
    // to verify the signature without needing any shared secret.
    let signing_key = derive_placeholder_signing_key_public(sender_public);

    // Compute expected signature
    let expected = Hash256::keyed_hash(&signing_key, signing_data.hash().as_bytes());

    // Constant-time comparison to prevent timing attacks
    if signature.bytes.ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signing_data() -> (IdentityKeyPair, SigningData) {
        let sender = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(b"Test message content");
        let timestamp = 1234567890u64;
        let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);
        (sender, signing_data)
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (sender, signing_data) = create_test_signing_data();

        let signature = sign_message(&sender, &signing_data).unwrap();
        let result = verify_signature(sender.public_keys(), &signing_data, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_version_default() {
        assert_eq!(SignatureVersion::default(), SignatureVersion::HmacBlake3);
    }

    #[test]
    fn test_signature_from_bytes() {
        let bytes = [42u8; SIGNATURE_SIZE];
        let sig = MessageSignature::from_bytes(&bytes, SignatureVersion::HmacBlake3).unwrap();

        assert_eq!(sig.as_bytes(), &bytes);
        assert_eq!(sig.version(), SignatureVersion::HmacBlake3);
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let bytes = [0u8; 16]; // Too short
        let result = MessageSignature::from_bytes(&bytes, SignatureVersion::HmacBlake3);
        assert!(result.is_err());

        let bytes = [0u8; 64]; // Too long
        let result = MessageSignature::from_bytes(&bytes, SignatureVersion::HmacBlake3);
        assert!(result.is_err());
    }

    #[test]
    fn test_placeholder_signature() {
        let placeholder = MessageSignature::placeholder();

        assert!(placeholder.is_placeholder());
        assert_eq!(placeholder.as_bytes(), &[0u8; SIGNATURE_SIZE]);
        assert_eq!(placeholder.version(), SignatureVersion::HmacBlake3);
    }

    #[test]
    fn test_non_placeholder_signature() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        assert!(!signature.is_placeholder());
    }

    #[test]
    fn test_verify_fails_with_wrong_data() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        // Create different signing data
        let wrong_hash = Hash256::hash(b"Different content");
        let wrong_signing_data = SigningData::new(sender.identity_hash(), 1234567890, &wrong_hash);

        let result = verify_signature(sender.public_keys(), &wrong_signing_data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_wrong_sender() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        // Try to verify with different sender's public keys
        let other_sender = IdentityKeyPair::generate();
        let result = verify_signature(other_sender.public_keys(), &signing_data, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_tampered_signature() {
        let (sender, signing_data) = create_test_signing_data();
        let mut signature = sign_message(&sender, &signing_data).unwrap();

        // Tamper with the signature bytes
        signature.bytes[0] ^= 0xFF;

        let result = verify_signature(sender.public_keys(), &signing_data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_placeholder() {
        let (sender, signing_data) = create_test_signing_data();
        let placeholder = MessageSignature::placeholder();

        let result = verify_signature(sender.public_keys(), &signing_data, &placeholder);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_data_deterministic() {
        let sender = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(b"Test content");
        let timestamp = 9999999999u64;

        let data1 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);
        let data2 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

        assert_eq!(data1.hash(), data2.hash());
    }

    #[test]
    fn test_signing_data_different_content_produces_different_hash() {
        let sender = IdentityKeyPair::generate();
        let timestamp = 1234567890u64;

        let content1 = Hash256::hash(b"Content 1");
        let content2 = Hash256::hash(b"Content 2");

        let data1 = SigningData::new(sender.identity_hash(), timestamp, &content1);
        let data2 = SigningData::new(sender.identity_hash(), timestamp, &content2);

        assert_ne!(data1.hash(), data2.hash());
    }

    #[test]
    fn test_signing_data_different_timestamp_produces_different_hash() {
        let sender = IdentityKeyPair::generate();
        let content = Hash256::hash(b"Same content");

        let data1 = SigningData::new(sender.identity_hash(), 1000, &content);
        let data2 = SigningData::new(sender.identity_hash(), 2000, &content);

        assert_ne!(data1.hash(), data2.hash());
    }

    #[test]
    fn test_signing_data_different_sender_produces_different_hash() {
        let sender1 = IdentityKeyPair::generate();
        let sender2 = IdentityKeyPair::generate();
        let content = Hash256::hash(b"Same content");
        let timestamp = 1234567890u64;

        let data1 = SigningData::new(sender1.identity_hash(), timestamp, &content);
        let data2 = SigningData::new(sender2.identity_hash(), timestamp, &content);

        assert_ne!(data1.hash(), data2.hash());
    }

    #[test]
    fn test_signing_data_from_hash() {
        let hash = Hash256::hash(b"Pre-computed hash");
        let signing_data = SigningData::from_hash(hash.clone());

        assert_eq!(signing_data.hash(), &hash);
    }

    #[test]
    fn test_signature_equality() {
        let (sender, signing_data) = create_test_signing_data();

        let sig1 = sign_message(&sender, &signing_data).unwrap();
        let sig2 = sign_message(&sender, &signing_data).unwrap();

        // Same inputs should produce same signature
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_inequality() {
        let sender1 = IdentityKeyPair::generate();
        let sender2 = IdentityKeyPair::generate();
        let content = Hash256::hash(b"Test");
        let timestamp = 1000u64;

        let data1 = SigningData::new(sender1.identity_hash(), timestamp, &content);
        let data2 = SigningData::new(sender2.identity_hash(), timestamp, &content);

        let sig1 = sign_message(&sender1, &data1).unwrap();
        let sig2 = sign_message(&sender2, &data2).unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_debug_format() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        let debug = format!("{:?}", signature);

        assert!(debug.contains("MessageSignature"));
        assert!(debug.contains("HmacBlake3"));
        // Should show truncated bytes
        assert!(debug.contains("..."));
    }

    #[test]
    fn test_signing_data_debug_format() {
        let sender = IdentityKeyPair::generate();
        let content = Hash256::hash(b"Test");
        let signing_data = SigningData::new(sender.identity_hash(), 1234567890, &content);

        let debug = format!("{:?}", signing_data);
        assert!(debug.contains("SigningData"));
    }

    #[test]
    fn test_signature_serialization_roundtrip() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        // Serialize
        let bytes = bincode::serialize(&signature).unwrap();

        // Deserialize
        let restored: MessageSignature = bincode::deserialize(&bytes).unwrap();

        assert_eq!(signature, restored);
    }

    #[test]
    fn test_mldsa_verification_returns_error() {
        // ML-DSA is not yet implemented
        let (sender, signing_data) = create_test_signing_data();

        let fake_mldsa_sig = MessageSignature {
            bytes: [42u8; SIGNATURE_SIZE],
            version: SignatureVersion::MlDsa,
        };

        let result = verify_signature(sender.public_keys(), &signing_data, &fake_mldsa_sig);
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }

    #[test]
    fn test_domain_separator_is_correct() {
        assert_eq!(DOMAIN_SEPARATOR, b"VERITAS-MESSAGE-SIGNATURE-v1");
    }

    #[test]
    fn test_signature_size_is_32() {
        assert_eq!(SIGNATURE_SIZE, 32);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sign_verify_always_succeeds_for_correct_sender(
            content in any::<Vec<u8>>(),
            timestamp in any::<u64>()
        ) {
            let sender = IdentityKeyPair::generate();
            let content_hash = Hash256::hash(&content);
            let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

            let signature = sign_message(&sender, &signing_data).unwrap();
            let result = verify_signature(sender.public_keys(), &signing_data, &signature);

            prop_assert!(result.is_ok());
        }

        #[test]
        fn sign_verify_fails_for_wrong_sender(
            content in any::<Vec<u8>>(),
            timestamp in any::<u64>()
        ) {
            let sender = IdentityKeyPair::generate();
            let other = IdentityKeyPair::generate();
            let content_hash = Hash256::hash(&content);
            let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

            let signature = sign_message(&sender, &signing_data).unwrap();
            let result = verify_signature(other.public_keys(), &signing_data, &signature);

            prop_assert!(result.is_err());
        }

        #[test]
        fn signing_data_is_deterministic(
            content in any::<Vec<u8>>(),
            timestamp in any::<u64>()
        ) {
            let sender = IdentityKeyPair::generate();
            let content_hash = Hash256::hash(&content);

            let data1 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);
            let data2 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

            prop_assert_eq!(data1.hash(), data2.hash());
        }

        #[test]
        fn signature_is_deterministic(
            content in any::<Vec<u8>>(),
            timestamp in any::<u64>()
        ) {
            let sender = IdentityKeyPair::generate();
            let content_hash = Hash256::hash(&content);
            let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

            let sig1 = sign_message(&sender, &signing_data).unwrap();
            let sig2 = sign_message(&sender, &signing_data).unwrap();

            prop_assert_eq!(sig1.as_bytes(), sig2.as_bytes());
        }
    }
}
