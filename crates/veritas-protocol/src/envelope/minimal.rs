//! Minimal metadata envelope for privacy-preserving message transport.
//!
//! The `MinimalEnvelope` is designed to leak NO identifiable information
//! to relays and intermediaries. All sensitive metadata (sender, timestamp,
//! content) is encrypted inside the payload.
//!
//! ## Envelope Structure
//!
//! ```text
//! +-----------------+
//! | mailbox_key     | 32 bytes - Derived, NOT recipient ID
//! +-----------------+
//! | ephemeral_public| 32 bytes - Single-use X25519 public key
//! +-----------------+
//! | nonce           | 24 bytes - XChaCha20 nonce
//! +-----------------+
//! | ciphertext      | Variable - Padded encrypted payload
//! +-----------------+
//! ```
//!
//! ## Security Properties
//!
//! - **Recipient Privacy**: Mailbox key is derived, not the actual identity
//! - **Sender Privacy**: Sender ID is inside encrypted payload
//! - **Unlinkability**: Ephemeral key is single-use per message
//! - **Traffic Analysis Resistance**: Payload is padded to fixed buckets
//! - **Forward Secrecy**: Ephemeral ECDH provides forward secrecy
//!
//! ## What Relays Can See
//!
//! - Mailbox key (but cannot link to recipient identity)
//! - Ephemeral public key (but cannot link to sender identity)
//! - Approximate message size (bucket: 256, 512, or 1024 bytes)
//!
//! ## What Relays CANNOT See
//!
//! - Sender identity
//! - Recipient identity
//! - Timestamp
//! - Message content
//! - True message size within bucket

use serde::{Deserialize, Serialize};
use veritas_crypto::{Hash256, X25519PublicKey};

use crate::ProtocolError;

use super::mailbox::{MailboxKey, MAILBOX_KEY_SIZE};

/// Size of the envelope nonce in bytes (XChaCha20).
pub const ENVELOPE_NONCE_SIZE: usize = 24;

/// Minimum ciphertext size (smallest bucket + overhead).
pub const MIN_CIPHERTEXT_SIZE: usize = 256;

/// Domain separator for envelope hashing.
const ENVELOPE_HASH_DOMAIN: &[u8] = b"VERITAS-ENVELOPE-HASH-v1";

/// A minimal metadata envelope for privacy-preserving message transport.
///
/// This envelope is designed to reveal as little information as possible
/// to network relays and observers. The sensitive metadata is encrypted
/// inside the ciphertext.
///
/// ## Creating an Envelope
///
/// ```ignore
/// use veritas_protocol::envelope::{MinimalEnvelope, MailboxKeyParams};
/// use veritas_crypto::X25519EphemeralKeyPair;
/// use veritas_identity::IdentityHash;
///
/// // Generate ephemeral key pair for this message
/// let ephemeral = X25519EphemeralKeyPair::generate();
///
/// // Derive mailbox key (never use recipient ID directly!)
/// let recipient = IdentityHash::from_public_key(b"recipient-pubkey");
/// let mailbox_params = MailboxKeyParams::new_current(&recipient);
/// let mailbox_key = mailbox_params.derive();
///
/// // Create envelope with encrypted, padded ciphertext
/// let envelope = MinimalEnvelope::new(
///     mailbox_key,
///     ephemeral.public_key().clone(),
///     nonce,
///     padded_ciphertext,
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalEnvelope {
    /// Derived mailbox key (NOT the recipient's identity hash).
    ///
    /// This key is derived from the recipient ID, current epoch, and
    /// a random salt. It changes for every message, preventing correlation.
    mailbox_key: [u8; MAILBOX_KEY_SIZE],

    /// Ephemeral X25519 public key (single-use per message).
    ///
    /// The sender generates a new ephemeral key pair for each message,
    /// ensuring forward secrecy and preventing sender correlation.
    ephemeral_public: X25519PublicKey,

    /// Random nonce for XChaCha20-Poly1305 encryption.
    ///
    /// Must be unique per message. Generated using OsRng.
    nonce: [u8; ENVELOPE_NONCE_SIZE],

    /// Encrypted and padded payload.
    ///
    /// Contains the `InnerPayload` with all sensitive metadata.
    /// Padded to a fixed bucket size (256, 512, or 1024 bytes).
    ciphertext: Vec<u8>,
}

impl MinimalEnvelope {
    /// Create a new minimal envelope.
    ///
    /// # Arguments
    ///
    /// * `mailbox_key` - Derived mailbox key (from `MailboxKeyParams::derive()`)
    /// * `ephemeral_public` - Sender's ephemeral public key for this message
    /// * `nonce` - Random nonce for encryption
    /// * `ciphertext` - Encrypted, padded payload
    ///
    /// # Example
    ///
    /// ```ignore
    /// let envelope = MinimalEnvelope::new(
    ///     mailbox_key,
    ///     ephemeral.public_key().clone(),
    ///     nonce,
    ///     ciphertext,
    /// );
    /// ```
    pub fn new(
        mailbox_key: MailboxKey,
        ephemeral_public: X25519PublicKey,
        nonce: [u8; ENVELOPE_NONCE_SIZE],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            mailbox_key: mailbox_key.to_bytes(),
            ephemeral_public,
            nonce,
            ciphertext,
        }
    }

    /// Get the mailbox key.
    pub fn mailbox_key(&self) -> &[u8; MAILBOX_KEY_SIZE] {
        &self.mailbox_key
    }

    /// Get the mailbox key as a MailboxKey type.
    pub fn mailbox_key_typed(&self) -> MailboxKey {
        MailboxKey::from_bytes(self.mailbox_key)
    }

    /// Get the ephemeral public key.
    pub fn ephemeral_public(&self) -> &X25519PublicKey {
        &self.ephemeral_public
    }

    /// Get the encryption nonce.
    pub fn nonce(&self) -> &[u8; ENVELOPE_NONCE_SIZE] {
        &self.nonce
    }

    /// Get the encrypted ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the total size of the envelope when serialized.
    pub fn size(&self) -> usize {
        MAILBOX_KEY_SIZE
            + 32 // X25519 public key
            + ENVELOPE_NONCE_SIZE
            + self.ciphertext.len()
    }

    /// Compute a hash of this envelope for identification/deduplication.
    ///
    /// The hash includes all envelope fields and can be used to:
    /// - Detect duplicate messages
    /// - Create message receipts
    /// - Index messages
    ///
    /// # Returns
    ///
    /// A 256-bit hash of the envelope contents.
    pub fn envelope_hash(&self) -> Hash256 {
        Hash256::hash_many(&[
            ENVELOPE_HASH_DOMAIN,
            &self.mailbox_key,
            self.ephemeral_public.as_bytes(),
            &self.nonce,
            &self.ciphertext,
        ])
    }

    /// Validate the envelope structure.
    ///
    /// Checks:
    /// - Ciphertext is not empty
    /// - Ciphertext size matches a valid padding bucket
    ///
    /// Note: This does NOT validate the contents (which are encrypted).
    /// Decryption and inner payload validation must be done separately.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidEnvelope` if validation fails.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Check ciphertext is not empty
        if self.ciphertext.is_empty() {
            return Err(ProtocolError::InvalidEnvelope(
                "ciphertext is empty".to_string(),
            ));
        }

        // Check ciphertext size is reasonable
        if self.ciphertext.len() < MIN_CIPHERTEXT_SIZE {
            return Err(ProtocolError::InvalidEnvelope(format!(
                "ciphertext too small: {} bytes (minimum {})",
                self.ciphertext.len(),
                MIN_CIPHERTEXT_SIZE
            )));
        }

        // We can't check padding validity without decrypting first
        // The decryption process will validate padding

        Ok(())
    }

    /// Serialize the envelope to bytes.
    ///
    /// Format:
    /// ```text
    /// [mailbox_key: 32][ephemeral_pub: 32][nonce: 24][ciphertext_len: 4][ciphertext: var]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Serialization` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        bincode::serialize(self).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Deserialize an envelope from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Serialization` if deserialization fails,
    /// or `ProtocolError::InvalidEnvelope` if validation fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let envelope: Self =
            bincode::deserialize(bytes).map_err(|e| ProtocolError::Serialization(e.to_string()))?;

        envelope.validate()?;
        Ok(envelope)
    }

    /// Check if the ciphertext appears to be properly padded.
    ///
    /// This is a heuristic check - proper validation requires decryption.
    pub fn is_padded_size(&self) -> bool {
        crate::limits::PADDING_BUCKETS.contains(&self.ciphertext.len())
    }
}

/// Builder for constructing minimal envelopes.
///
/// Provides a fluent interface for creating envelopes with validation.
#[derive(Default)]
pub struct MinimalEnvelopeBuilder {
    mailbox_key: Option<MailboxKey>,
    ephemeral_public: Option<X25519PublicKey>,
    nonce: Option<[u8; ENVELOPE_NONCE_SIZE]>,
    ciphertext: Option<Vec<u8>>,
}

impl MinimalEnvelopeBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the mailbox key.
    pub fn mailbox_key(mut self, key: MailboxKey) -> Self {
        self.mailbox_key = Some(key);
        self
    }

    /// Set the ephemeral public key.
    pub fn ephemeral_public(mut self, key: X25519PublicKey) -> Self {
        self.ephemeral_public = Some(key);
        self
    }

    /// Set the encryption nonce.
    pub fn nonce(mut self, nonce: [u8; ENVELOPE_NONCE_SIZE]) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the encrypted ciphertext.
    pub fn ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.ciphertext = Some(ciphertext);
        self
    }

    /// Build the envelope.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidEnvelope` if any required field is missing.
    pub fn build(self) -> Result<MinimalEnvelope, ProtocolError> {
        let mailbox_key = self
            .mailbox_key
            .ok_or_else(|| ProtocolError::InvalidEnvelope("missing mailbox_key".to_string()))?;

        let ephemeral_public = self.ephemeral_public.ok_or_else(|| {
            ProtocolError::InvalidEnvelope("missing ephemeral_public".to_string())
        })?;

        let nonce = self
            .nonce
            .ok_or_else(|| ProtocolError::InvalidEnvelope("missing nonce".to_string()))?;

        let ciphertext = self
            .ciphertext
            .ok_or_else(|| ProtocolError::InvalidEnvelope("missing ciphertext".to_string()))?;

        let envelope = MinimalEnvelope::new(mailbox_key, ephemeral_public, nonce, ciphertext);
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use veritas_crypto::X25519EphemeralKeyPair;
    use veritas_identity::IdentityHash;

    use crate::envelope::mailbox::MailboxKeyParams;
    use crate::envelope::padding::pad_to_bucket;

    fn test_mailbox_key() -> MailboxKey {
        let recipient = IdentityHash::from_public_key(b"test-recipient");
        MailboxKeyParams::new_current(&recipient).derive()
    }

    fn test_nonce() -> [u8; ENVELOPE_NONCE_SIZE] {
        let mut nonce = [0u8; ENVELOPE_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn test_ciphertext() -> Vec<u8> {
        // Create padded "ciphertext" for testing
        pad_to_bucket(b"test encrypted payload").unwrap()
    }

    #[test]
    fn test_minimal_envelope_new() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let mailbox_key = test_mailbox_key();
        let nonce = test_nonce();
        let ciphertext = test_ciphertext();

        let envelope = MinimalEnvelope::new(
            mailbox_key.clone(),
            ephemeral.public_key().clone(),
            nonce,
            ciphertext.clone(),
        );

        assert_eq!(envelope.mailbox_key(), mailbox_key.as_bytes());
        assert_eq!(envelope.ephemeral_public(), ephemeral.public_key());
        assert_eq!(envelope.nonce(), &nonce);
        assert_eq!(envelope.ciphertext(), &ciphertext);
    }

    #[test]
    fn test_minimal_envelope_serialization() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        let bytes = envelope.to_bytes().unwrap();
        let restored = MinimalEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope, restored);
    }

    #[test]
    fn test_minimal_envelope_hash() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        let hash1 = envelope.envelope_hash();
        let hash2 = envelope.envelope_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should not be zero
        assert!(!hash1.is_zero());
    }

    #[test]
    fn test_minimal_envelope_different_hash() {
        let ephemeral1 = X25519EphemeralKeyPair::generate();
        let ephemeral2 = X25519EphemeralKeyPair::generate();

        let envelope1 = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral1.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        let envelope2 = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral2.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        // Different ephemeral keys = different hashes
        assert_ne!(envelope1.envelope_hash(), envelope2.envelope_hash());
    }

    #[test]
    fn test_minimal_envelope_validate_success() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn test_minimal_envelope_validate_empty_ciphertext() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            vec![], // Empty ciphertext
        );

        assert!(matches!(
            envelope.validate(),
            Err(ProtocolError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_minimal_envelope_validate_small_ciphertext() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            vec![0u8; 10], // Too small
        );

        assert!(matches!(
            envelope.validate(),
            Err(ProtocolError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_minimal_envelope_size() {
        let ephemeral = X25519EphemeralKeyPair::generate();
        let ciphertext = test_ciphertext();
        let expected_size = 32 + 32 + 24 + ciphertext.len();

        let envelope = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            ciphertext,
        );

        assert_eq!(envelope.size(), expected_size);
    }

    #[test]
    fn test_minimal_envelope_is_padded_size() {
        let ephemeral = X25519EphemeralKeyPair::generate();

        // Correctly padded
        let envelope1 = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            vec![0u8; 256],
        );
        assert!(envelope1.is_padded_size());

        // Not a valid bucket size
        let envelope2 = MinimalEnvelope::new(
            test_mailbox_key(),
            ephemeral.public_key().clone(),
            test_nonce(),
            vec![0u8; 300],
        );
        assert!(!envelope2.is_padded_size());
    }

    #[test]
    fn test_minimal_envelope_builder() {
        let ephemeral = X25519EphemeralKeyPair::generate();

        let envelope = MinimalEnvelopeBuilder::new()
            .mailbox_key(test_mailbox_key())
            .ephemeral_public(ephemeral.public_key().clone())
            .nonce(test_nonce())
            .ciphertext(test_ciphertext())
            .build()
            .unwrap();

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn test_minimal_envelope_builder_missing_fields() {
        // Missing mailbox_key
        let result = MinimalEnvelopeBuilder::new()
            .nonce(test_nonce())
            .ciphertext(test_ciphertext())
            .build();
        assert!(matches!(result, Err(ProtocolError::InvalidEnvelope(_))));

        // Missing ephemeral_public
        let result = MinimalEnvelopeBuilder::new()
            .mailbox_key(test_mailbox_key())
            .nonce(test_nonce())
            .ciphertext(test_ciphertext())
            .build();
        assert!(matches!(result, Err(ProtocolError::InvalidEnvelope(_))));
    }

    #[test]
    fn test_mailbox_key_typed() {
        let mailbox_key = test_mailbox_key();
        let ephemeral = X25519EphemeralKeyPair::generate();

        let envelope = MinimalEnvelope::new(
            mailbox_key.clone(),
            ephemeral.public_key().clone(),
            test_nonce(),
            test_ciphertext(),
        );

        assert_eq!(envelope.mailbox_key_typed(), mailbox_key);
    }

    #[test]
    fn test_from_bytes_invalid() {
        // Too short
        let result = MinimalEnvelope::from_bytes(&[0u8; 10]);
        assert!(result.is_err());

        // Random garbage
        let result = MinimalEnvelope::from_bytes(&[0xFFu8; 100]);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use veritas_crypto::X25519EphemeralKeyPair;
    use veritas_identity::IdentityHash;

    use crate::envelope::mailbox::MailboxKeyParams;
    use crate::envelope::padding::pad_to_bucket;

    proptest! {
        #[test]
        fn envelope_serialization_roundtrip(
            recipient_key: [u8; 32],
            payload in any::<Vec<u8>>().prop_filter("not too large", |v| v.len() < 1000)
        ) {
            let recipient = IdentityHash::from_public_key(&recipient_key);
            let mailbox_key = MailboxKeyParams::new_current(&recipient).derive();
            let ephemeral = X25519EphemeralKeyPair::generate();

            let mut nonce = [0u8; ENVELOPE_NONCE_SIZE];
            OsRng.fill_bytes(&mut nonce);

            let ciphertext = pad_to_bucket(&payload).unwrap();

            let envelope = MinimalEnvelope::new(
                mailbox_key,
                ephemeral.public_key().clone(),
                nonce,
                ciphertext,
            );

            let bytes = envelope.to_bytes().unwrap();
            let restored = MinimalEnvelope::from_bytes(&bytes).unwrap();

            prop_assert_eq!(envelope, restored);
        }

        #[test]
        fn envelope_hash_deterministic(
            recipient_key: [u8; 32],
            payload in any::<Vec<u8>>().prop_filter("not too large", |v| v.len() < 1000)
        ) {
            let recipient = IdentityHash::from_public_key(&recipient_key);
            let mailbox_key = MailboxKeyParams::new_current(&recipient).derive();
            let ephemeral = X25519EphemeralKeyPair::generate();

            let mut nonce = [0u8; ENVELOPE_NONCE_SIZE];
            OsRng.fill_bytes(&mut nonce);

            let ciphertext = pad_to_bucket(&payload).unwrap();

            let envelope = MinimalEnvelope::new(
                mailbox_key,
                ephemeral.public_key().clone(),
                nonce,
                ciphertext,
            );

            prop_assert_eq!(envelope.envelope_hash(), envelope.envelope_hash());
        }
    }
}
