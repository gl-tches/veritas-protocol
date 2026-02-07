//! Message signature types and operations.
//!
//! Provides cryptographic signing for VERITAS messages using ML-DSA-65
//! (FIPS 204) post-quantum digital signatures with domain separation.
//!
//! ## Security
//!
//! - All signatures use ML-DSA-65 (NIST security level 3)
//! - Domain-separated signing prevents cross-context forgery
//! - Constant-time comparison prevents timing attacks on verification
//! - Signature size is 3,309 bytes per FIPS 204 specification

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use veritas_crypto::Hash256;
use veritas_identity::{IdentityKeyPair, IdentityPublicKeys};

use crate::error::{ProtocolError, Result};

/// Domain separator for message signatures.
///
/// This prefix ensures signatures cannot be reused across different contexts
/// or confused with other types of hashes in the protocol.
pub const DOMAIN_SEPARATOR: &[u8] = b"VERITAS-v1.message-signature";

/// Size of a message signature in bytes (ML-DSA-65, FIPS 204).
pub const SIGNATURE_SIZE: usize = 3309;

/// Supported signature scheme versions.
///
/// The protocol supports multiple signature versions to allow smooth
/// transitions between cryptographic schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureVersion {
    /// HMAC-BLAKE3 placeholder (DEPRECATED — for backwards compat only).
    ///
    /// This version is no longer generated. It exists only so old
    /// serialized data can be identified.
    HmacBlake3 = 1,

    /// ML-DSA-65 post-quantum signatures (FIPS 204).
    ///
    /// Uses the NIST-standardized ML-DSA algorithm for post-quantum
    /// secure signatures. This provides:
    /// - Security against quantum computer attacks
    /// - Non-repudiation
    /// - Proper public-key verification
    MlDsa = 2,
}

impl Default for SignatureVersion {
    fn default() -> Self {
        Self::MlDsa
    }
}

/// A cryptographic signature for a VERITAS message.
///
/// Contains the signature bytes and version information to allow
/// the verifier to use the correct verification algorithm.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageSignature {
    /// Raw signature bytes (3,309 bytes for ML-DSA-65).
    bytes: Vec<u8>,

    /// Signature scheme version.
    version: SignatureVersion,
}

impl MessageSignature {
    /// Create a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidSignature` if the bytes do not match
    /// the expected size for the given version.
    pub fn from_bytes(bytes: &[u8], version: SignatureVersion) -> Result<Self> {
        match version {
            SignatureVersion::MlDsa => {
                if bytes.len() != SIGNATURE_SIZE {
                    return Err(ProtocolError::InvalidSignature);
                }
            }
            SignatureVersion::HmacBlake3 => {
                if bytes.len() != 32 {
                    return Err(ProtocolError::InvalidSignature);
                }
            }
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            version,
        })
    }

    /// Get the signature as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signature version.
    pub fn version(&self) -> SignatureVersion {
        self.version
    }

    /// Create a placeholder zero signature.
    ///
    /// # Warning
    ///
    /// A placeholder signature will fail verification.
    pub fn placeholder() -> Self {
        Self {
            bytes: vec![0u8; SIGNATURE_SIZE],
            version: SignatureVersion::MlDsa,
        }
    }

    /// Check if this is a placeholder (zero) signature.
    pub fn is_placeholder(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for MessageSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let preview_len = self.bytes.len().min(8);
        let short_hex: String = self.bytes[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        f.debug_struct("MessageSignature")
            .field("bytes", &format!("{}... ({} bytes)", short_hex, self.bytes.len()))
            .field("version", &self.version)
            .finish()
    }
}

impl PartialEq for MessageSignature {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for signature bytes
        self.version == other.version
            && self.bytes.len() == other.bytes.len()
            && self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for MessageSignature {}

/// Data to be signed for a message.
///
/// This struct computes a domain-separated hash of all message attributes
/// that need to be authenticated: sender identity, timestamp, and content.
/// The hash is then signed with ML-DSA to create the message signature.
#[derive(Clone, Zeroize)]
pub struct SigningData {
    /// Hash of the data to be signed.
    data_hash: Hash256,
}

impl SigningData {
    /// Create signing data for a message.
    ///
    /// Computes a domain-separated hash of:
    /// - Domain separator ("VERITAS-v1.message-signature")
    /// - Sender identity hash (32 bytes)
    /// - Timestamp (8 bytes, big-endian)
    /// - Content hash (32 bytes)
    pub fn new(sender_id: &veritas_identity::IdentityHash, timestamp: u64, content_hash: &Hash256) -> Self {
        let data_hash = Hash256::hash_many(&[
            DOMAIN_SEPARATOR,
            sender_id.as_bytes(),
            &timestamp.to_be_bytes(),
            content_hash.as_bytes(),
        ]);

        Self { data_hash }
    }

    /// Create signing data from an existing hash.
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

/// Sign a message using ML-DSA-65 via the sender's identity keypair.
///
/// Creates a post-quantum digital signature over the signing data that
/// can be verified by anyone with the sender's public keys.
///
/// # Arguments
///
/// * `sender` - The sender's identity keypair (contains ML-DSA private key)
/// * `signing_data` - The data to sign (computed from message attributes)
///
/// # Returns
///
/// A `MessageSignature` using ML-DSA-65 (3,309 bytes).
///
/// # Errors
///
/// Returns an error if the sender doesn't have an ML-DSA signing key.
pub fn sign_message(
    sender: &IdentityKeyPair,
    signing_data: &SigningData,
) -> Result<MessageSignature> {
    // Sign the data hash with ML-DSA
    let ml_dsa_sig = sender
        .sign(signing_data.hash().as_bytes())
        .map_err(|_| ProtocolError::InvalidSignature)?;

    Ok(MessageSignature {
        bytes: ml_dsa_sig.as_bytes(),
        version: SignatureVersion::MlDsa,
    })
}

/// Verify a message signature.
///
/// Checks that the signature was created by the owner of the given public keys
/// over the specified signing data using ML-DSA-65 verification.
///
/// # Arguments
///
/// * `sender_public` - The sender's public keys (must include ML-DSA key)
/// * `signing_data` - The data that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err(ProtocolError::InvalidSignature)` otherwise.
pub fn verify_signature(
    sender_public: &IdentityPublicKeys,
    signing_data: &SigningData,
    signature: &MessageSignature,
) -> Result<()> {
    match signature.version {
        SignatureVersion::MlDsa => verify_mldsa(sender_public, signing_data, signature),
        SignatureVersion::HmacBlake3 => {
            // DEPRECATED: HmacBlake3 signatures are no longer accepted
            Err(ProtocolError::InvalidSignature)
        }
    }
}

/// Verify an ML-DSA-65 signature.
fn verify_mldsa(
    sender_public: &IdentityPublicKeys,
    signing_data: &SigningData,
    signature: &MessageSignature,
) -> Result<()> {
    let signing_key = sender_public
        .signing
        .as_ref()
        .ok_or(ProtocolError::InvalidSignature)?;

    let ml_dsa_sig = veritas_crypto::MlDsaSignature::from_bytes(&signature.bytes)
        .map_err(|_| ProtocolError::InvalidSignature)?;

    signing_key
        .verify(signing_data.hash().as_bytes(), &ml_dsa_sig)
        .map_err(|_| ProtocolError::InvalidSignature)
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
        assert_eq!(signature.version(), SignatureVersion::MlDsa);
        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);

        let result = verify_signature(sender.public_keys(), &signing_data, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_version_default() {
        assert_eq!(SignatureVersion::default(), SignatureVersion::MlDsa);
    }

    #[test]
    fn test_signature_from_bytes_mldsa() {
        // Create a real signature to get valid bytes
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        let restored = MessageSignature::from_bytes(signature.as_bytes(), SignatureVersion::MlDsa).unwrap();
        assert_eq!(restored.as_bytes(), signature.as_bytes());
        assert_eq!(restored.version(), SignatureVersion::MlDsa);
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let bytes = [0u8; 16]; // Too short for ML-DSA
        let result = MessageSignature::from_bytes(&bytes, SignatureVersion::MlDsa);
        assert!(result.is_err());
    }

    #[test]
    fn test_placeholder_signature() {
        let placeholder = MessageSignature::placeholder();
        assert!(placeholder.is_placeholder());
        assert_eq!(placeholder.as_bytes().len(), SIGNATURE_SIZE);
        assert_eq!(placeholder.version(), SignatureVersion::MlDsa);
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

        let wrong_hash = Hash256::hash(b"Different content");
        let wrong_signing_data = SigningData::new(sender.identity_hash(), 1234567890, &wrong_hash);

        let result = verify_signature(sender.public_keys(), &wrong_signing_data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_wrong_sender() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

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
    fn test_signature_debug_format() {
        let (sender, signing_data) = create_test_signing_data();
        let signature = sign_message(&sender, &signing_data).unwrap();

        let debug = format!("{:?}", signature);

        assert!(debug.contains("MessageSignature"));
        assert!(debug.contains("MlDsa"));
        assert!(debug.contains("3309 bytes"));
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
    fn test_hmacblake3_verification_rejected() {
        // HmacBlake3 signatures are no longer accepted
        let (sender, signing_data) = create_test_signing_data();

        let fake_hmac_sig = MessageSignature {
            bytes: vec![42u8; 32],
            version: SignatureVersion::HmacBlake3,
        };

        let result = verify_signature(sender.public_keys(), &signing_data, &fake_hmac_sig);
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }

    #[test]
    fn test_domain_separator_is_correct() {
        assert_eq!(DOMAIN_SEPARATOR, b"VERITAS-v1.message-signature");
    }

    #[test]
    fn test_signature_size_is_3309() {
        assert_eq!(SIGNATURE_SIZE, 3309);
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
    }
}
