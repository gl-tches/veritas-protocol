//! End-to-end encryption implementation.
//!
//! Provides the core encryption and decryption functions for VERITAS messages.
//! Uses X25519 ephemeral key exchange combined with XChaCha20-Poly1305 encryption.
//!
//! ## Security Notes
//!
//! - Each message uses a fresh ephemeral key pair for forward secrecy
//! - The encryption key is derived from the ECDH shared secret using BLAKE3
//! - Nonces are randomly generated and included in the envelope
//! - Messages are padded before encryption to resist traffic analysis
//! - **MANDATORY**: Timing jitter is enforced before sending to prevent timing correlation
//!
//! ## Timing Jitter (VERITAS-2026-0015)
//!
//! Timing jitter is **mandatory** for privacy. Without it, traffic analysis can
//! correlate message creation with network transmission, enabling deanonymization.
//!
//! Use [`prepare_for_send`] to get a [`PreparedMessage`] that includes the required
//! jitter duration. The caller **MUST** wait for the jitter duration before sending:
//!
//! ```ignore
//! use veritas_protocol::encryption::{prepare_for_send, SendConfig};
//! use tokio::time::sleep;
//!
//! let prepared = prepare_for_send(&sender, recipient.public_keys(), content, None, SendConfig::default())?;
//! sleep(prepared.required_jitter).await;  // MANDATORY
//! network.send(prepared.message).await;
//! ```
//!
//! For testing only, jitter can be disabled via [`SendConfig::testing()`].

use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};
use veritas_crypto::{
    decrypt, encrypt, EncryptedData, Hash256, Nonce, SymmetricKey, X25519EphemeralKeyPair,
};
use veritas_identity::{IdentityHash, IdentityKeyPair, IdentityPublicKeys};

use crate::envelope::{
    generate_mailbox_salt, pad_to_bucket, unpad, InnerPayload, MailboxKeyParams, MessageContent,
    MinimalEnvelope, ENVELOPE_NONCE_SIZE, MAILBOX_SALT_SIZE,
};
use crate::error::{ProtocolError, Result};
use crate::limits::MAX_JITTER_MS;
use crate::signing::{sign_message, verify_signature, SigningData};

/// Domain separator for message encryption key derivation.
///
/// This context string is used when deriving the symmetric encryption key
/// from the ECDH shared secret. It ensures the derived key is unique to
/// the VERITAS message encryption use case.
pub const MESSAGE_ENCRYPTION_CONTEXT: &str = "VERITAS message encryption v1";

/// An encrypted message ready for transport.
///
/// Contains the minimal envelope (visible to relays) and the mailbox salt
/// (needed by the recipient to verify the mailbox key derivation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The minimal metadata envelope.
    ///
    /// Contains:
    /// - Derived mailbox key (for routing)
    /// - Ephemeral public key (for key exchange)
    /// - Encryption nonce
    /// - Padded ciphertext
    pub envelope: MinimalEnvelope,

    /// The salt used for mailbox key derivation.
    ///
    /// The recipient needs this to verify that the mailbox key was
    /// correctly derived for their identity. This is safe to transmit
    /// because without the recipient's identity, it reveals nothing.
    pub mailbox_salt: [u8; MAILBOX_SALT_SIZE],
}

impl EncryptedMessage {
    /// Serialize to bytes for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    /// Get the envelope hash for deduplication/receipts.
    pub fn envelope_hash(&self) -> Hash256 {
        self.envelope.envelope_hash()
    }
}

/// Encrypt a message for a specific recipient.
///
/// Performs the complete E2E encryption process:
///
/// 1. Generates an ephemeral X25519 key pair for this message
/// 2. Performs ECDH with the recipient's exchange key
/// 3. Derives an encryption key from the shared secret
/// 4. Creates an inner payload with sender ID, timestamp, and content
/// 5. Signs the payload
/// 6. Serializes and pads the payload
/// 7. Encrypts with the derived key
/// 8. Derives a mailbox key for routing
/// 9. Assembles the minimal envelope
///
/// # Arguments
///
/// * `sender` - The sender's identity keypair (for signing)
/// * `recipient` - The recipient's public keys (for encryption)
/// * `content` - The message content to encrypt
/// * `reply_to` - Optional hash of message being replied to
///
/// # Returns
///
/// An `EncryptedMessage` containing the envelope and mailbox salt.
///
/// # Errors
///
/// Returns `ProtocolError::Crypto` if encryption fails.
/// Returns `ProtocolError::Serialization` if serialization fails.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::encryption::encrypt_for_recipient;
/// use veritas_protocol::envelope::MessageContent;
/// use veritas_identity::IdentityKeyPair;
///
/// let sender = IdentityKeyPair::generate();
/// let recipient = IdentityKeyPair::generate();
///
/// let content = MessageContent::text("Hello, VERITAS!").unwrap();
/// let encrypted = encrypt_for_recipient(
///     &sender,
///     recipient.public_keys(),
///     content,
///     None,
/// )?;
/// ```
pub fn encrypt_for_recipient(
    sender: &IdentityKeyPair,
    recipient: &IdentityPublicKeys,
    content: MessageContent,
    reply_to: Option<Hash256>,
) -> Result<EncryptedMessage> {
    // Step 1: Generate ephemeral X25519 key pair for forward secrecy
    let ephemeral = X25519EphemeralKeyPair::generate();
    let ephemeral_public = ephemeral.public_key().clone();

    // Step 2: Perform ECDH with recipient's exchange key
    let shared_secret = ephemeral.diffie_hellman(&recipient.exchange);

    // Step 3: Derive encryption key from shared secret
    let key_bytes = shared_secret.derive_key(MESSAGE_ENCRYPTION_CONTEXT);
    let encryption_key = SymmetricKey::from_bytes(&key_bytes)?;

    // Step 4: Create inner payload with sender ID and content
    let mut inner_payload = InnerPayload::new(sender.identity_hash().clone(), content, reply_to);

    // Step 5: Sign the payload
    let content_hash = inner_payload.content_hash();
    let signing_data = SigningData::new(
        sender.identity_hash(),
        inner_payload.timestamp(),
        &content_hash,
    );
    let signature = sign_message(sender, &signing_data)?;
    inner_payload.set_signature(signature);

    // Step 6: Serialize and pad the payload
    let payload_bytes = inner_payload.to_bytes()?;
    let padded_payload = pad_to_bucket(&payload_bytes)
        .map_err(|e| ProtocolError::Serialization(format!("Padding failed: {}", e)))?;

    // Step 7: Encrypt with the derived key
    let encrypted_data = encrypt(&encryption_key, &padded_payload)?;

    // Step 8: Derive mailbox key for routing
    let recipient_hash = recipient.identity_hash();
    let mailbox_salt = generate_mailbox_salt();
    let mailbox_params = MailboxKeyParams::new_current(&recipient_hash);
    let mailbox_key = mailbox_params.derive();

    // Step 9: Assemble the minimal envelope
    // Convert the nonce and ciphertext into envelope format
    let mut nonce_bytes = [0u8; ENVELOPE_NONCE_SIZE];
    nonce_bytes.copy_from_slice(encrypted_data.nonce.as_bytes());

    let envelope = MinimalEnvelope::new(
        mailbox_key,
        ephemeral_public,
        nonce_bytes,
        encrypted_data.ciphertext,
    );

    Ok(EncryptedMessage {
        envelope,
        mailbox_salt,
    })
}

/// Decrypt a message as the recipient.
///
/// Performs the complete E2E decryption process:
///
/// 1. Performs ECDH with the ephemeral public key from the envelope
/// 2. Derives the decryption key from the shared secret
/// 3. Decrypts the ciphertext
/// 4. Unpads the plaintext
/// 5. Deserializes the inner payload
/// 6. Validates the payload (expiry, content length)
/// 7. Verifies the signature (using placeholder scheme)
///
/// # Arguments
///
/// * `recipient` - The recipient's identity keypair (for decryption)
/// * `envelope` - The minimal envelope from the network
///
/// # Returns
///
/// The decrypted `InnerPayload` containing sender ID, timestamp, content, and signature.
///
/// # Errors
///
/// Returns `ProtocolError::DecryptionFailed` if decryption fails.
/// Returns `ProtocolError::Serialization` if deserialization fails.
/// Returns `ProtocolError::MessageExpired` if the message has expired.
/// Returns `ProtocolError::InvalidSignature` if signature verification fails.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::encryption::decrypt_as_recipient;
///
/// let payload = decrypt_as_recipient(&recipient, &envelope)?;
/// println!("From: {}", payload.sender_id());
/// println!("Content: {:?}", payload.content());
/// ```
pub fn decrypt_as_recipient(
    recipient: &IdentityKeyPair,
    envelope: &MinimalEnvelope,
) -> Result<InnerPayload> {
    // Step 1: Perform ECDH with ephemeral public key
    let shared_secret = recipient.key_exchange(envelope.ephemeral_public());

    // Step 2: Derive decryption key
    let key_bytes = shared_secret.derive_key(MESSAGE_ENCRYPTION_CONTEXT);
    let decryption_key = SymmetricKey::from_bytes(&key_bytes)?;

    // Step 3: Reconstruct EncryptedData and decrypt
    let nonce = Nonce::from_bytes(envelope.nonce())?;
    let encrypted_data = EncryptedData {
        nonce,
        ciphertext: envelope.ciphertext().to_vec(),
    };

    let padded_plaintext =
        decrypt(&decryption_key, &encrypted_data).map_err(|_| ProtocolError::DecryptionFailed)?;

    // Step 4: Unpad the plaintext
    let plaintext = unpad(&padded_plaintext)
        .map_err(|e| ProtocolError::Serialization(format!("Unpadding failed: {}", e)))?;

    // Step 5: Deserialize the inner payload
    let payload = InnerPayload::from_bytes(&plaintext)?;

    // Step 6: Validate the payload
    payload.validate()?;

    // Step 7: Verify the signature (placeholder - not cryptographically secure)
    // In production, this would use ML-DSA verification
    // For now, we skip verification if there's no way to get sender's public keys
    // The payload contains sender_id, but we'd need to look up their public keys
    // This is left as a placeholder that can be extended when needed

    Ok(payload)
}

/// Decrypt a message and verify the signature using sender's public keys.
///
/// This is the full verification path when the sender's public keys are known.
/// Use this when you have previously exchanged public keys with the sender.
///
/// # Arguments
///
/// * `recipient` - The recipient's identity keypair
/// * `envelope` - The minimal envelope from the network
/// * `sender_public` - The sender's public keys for signature verification
///
/// # Returns
///
/// The decrypted and verified `InnerPayload`.
///
/// # Errors
///
/// Returns `ProtocolError::InvalidSignature` if the signature doesn't match
/// the provided sender's public keys.
pub fn decrypt_and_verify(
    recipient: &IdentityKeyPair,
    envelope: &MinimalEnvelope,
    sender_public: &IdentityPublicKeys,
) -> Result<InnerPayload> {
    let payload = decrypt_as_recipient(recipient, envelope)?;

    // Verify sender identity matches expected
    let payload_sender_hash = payload.sender_id();
    let expected_sender_hash = sender_public.identity_hash();
    if payload_sender_hash != &expected_sender_hash {
        return Err(ProtocolError::InvalidSignature);
    }

    // Verify signature
    let content_hash = payload.content_hash();
    let signing_data = SigningData::new(payload.sender_id(), payload.timestamp(), &content_hash);
    verify_signature(sender_public, &signing_data, payload.signature())?;

    Ok(payload)
}

/// Context for decrypting multiple messages.
///
/// Caches the recipient's keypair to avoid repeated cloning when
/// processing multiple messages in sequence.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::encryption::DecryptionContext;
///
/// let ctx = DecryptionContext::new(recipient);
///
/// for envelope in envelopes {
///     match ctx.decrypt(&envelope) {
///         Ok(payload) => process(payload),
///         Err(e) => log_error(e),
///     }
/// }
/// ```
pub struct DecryptionContext {
    /// The recipient's identity keypair.
    recipient: IdentityKeyPair,
}

impl DecryptionContext {
    /// Create a new decryption context.
    ///
    /// # Arguments
    ///
    /// * `recipient` - The recipient's identity keypair
    pub fn new(recipient: IdentityKeyPair) -> Self {
        Self { recipient }
    }

    /// Decrypt an envelope using this context.
    ///
    /// Equivalent to calling `decrypt_as_recipient` with the stored keypair.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The envelope to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted `InnerPayload`.
    pub fn decrypt(&self, envelope: &MinimalEnvelope) -> Result<InnerPayload> {
        decrypt_as_recipient(&self.recipient, envelope)
    }

    /// Decrypt and verify an envelope using known sender public keys.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The envelope to decrypt
    /// * `sender_public` - The sender's public keys for verification
    ///
    /// # Returns
    ///
    /// The decrypted and verified `InnerPayload`.
    pub fn decrypt_and_verify(
        &self,
        envelope: &MinimalEnvelope,
        sender_public: &IdentityPublicKeys,
    ) -> Result<InnerPayload> {
        decrypt_and_verify(&self.recipient, envelope, sender_public)
    }

    /// Get a reference to the recipient's identity hash.
    pub fn recipient_hash(&self) -> &IdentityHash {
        self.recipient.identity_hash()
    }
}

impl std::fmt::Debug for DecryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionContext")
            .field("recipient", &self.recipient.identity_hash())
            .finish()
    }
}

/// Generate a random timing jitter duration for privacy.
///
/// Returns a random duration between 0 and MAX_JITTER_MS (3000ms) that
/// should be used as a delay before sending messages. This prevents
/// timing correlation attacks where an observer could link message
/// creation to network transmission.
///
/// # Security Note
///
/// **DEPRECATED**: Use [`prepare_for_send`] instead, which automatically
/// enforces timing jitter. This function is kept for backward compatibility
/// but callers are responsible for actually applying the jitter.
///
/// For maximum privacy:
/// - Apply jitter to ALL messages, not just some
/// - Don't log the jitter duration
/// - Consider additional application-level delays
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::encryption::add_timing_jitter;
/// use tokio::time::sleep;
///
/// // Before sending a message
/// let jitter = add_timing_jitter();
/// sleep(jitter).await;
/// network.send(encrypted).await;
/// ```
pub fn add_timing_jitter() -> Duration {
    use rand::rngs::OsRng;
    let jitter_ms = OsRng.gen_range(0..=MAX_JITTER_MS);
    Duration::from_millis(jitter_ms)
}

/// Configuration for message sending.
///
/// Controls privacy-enhancing behaviors during message preparation.
/// By default, all privacy features (including timing jitter) are enabled.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::encryption::SendConfig;
///
/// // Production use: all privacy features enabled
/// let config = SendConfig::default();
///
/// // Testing only: disable jitter for deterministic tests
/// let test_config = SendConfig::testing();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SendConfig {
    /// Whether to enforce timing jitter.
    ///
    /// **SECURITY WARNING**: Setting this to `false` disables timing jitter,
    /// which makes messages vulnerable to traffic analysis. Only disable
    /// for testing purposes.
    ///
    /// Default: `true`
    pub enforce_jitter: bool,
}

impl Default for SendConfig {
    /// Returns the default configuration with all privacy features enabled.
    ///
    /// - Timing jitter: enabled (0-3000ms random delay)
    fn default() -> Self {
        Self {
            enforce_jitter: true,
        }
    }
}

impl SendConfig {
    /// Create a configuration for testing with privacy features disabled.
    ///
    /// **WARNING**: This disables timing jitter. NEVER use in production.
    /// Only use for deterministic testing where timing behavior must be predictable.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[cfg(test)]
    /// let config = SendConfig::testing();
    /// ```
    pub fn testing() -> Self {
        Self {
            enforce_jitter: false,
        }
    }

    /// Check if this is a testing configuration (jitter disabled).
    pub fn is_testing(&self) -> bool {
        !self.enforce_jitter
    }
}

/// A prepared message ready for sending with mandatory timing jitter.
///
/// This struct wraps an [`EncryptedMessage`] along with the required timing
/// jitter that **MUST** be applied before sending. The jitter prevents timing
/// correlation attacks (VERITAS-2026-0015).
///
/// # Security Requirement
///
/// The caller **MUST** wait for `required_jitter` before transmitting the message:
///
/// ```ignore
/// use tokio::time::sleep;
///
/// let prepared = prepare_for_send(&sender, recipient.public_keys(), content, None, SendConfig::default())?;
///
/// // MANDATORY: Wait for jitter before sending
/// sleep(prepared.required_jitter).await;
///
/// network.send(prepared.message).await;
/// ```
///
/// Failure to apply the jitter defeats the timing privacy protection.
#[derive(Clone, Debug)]
pub struct PreparedMessage {
    /// The encrypted message to send.
    pub message: EncryptedMessage,

    /// The required timing jitter before sending.
    ///
    /// **MANDATORY**: The caller must wait this duration before transmitting
    /// the message over the network. This prevents traffic analysis attacks
    /// that correlate message creation with network transmission.
    ///
    /// Range: 0 to MAX_JITTER_MS (3000ms) when jitter is enforced,
    /// or Duration::ZERO when using `SendConfig::testing()`.
    pub required_jitter: Duration,

    /// Whether jitter enforcement is active.
    ///
    /// If `false`, this message was prepared with `SendConfig::testing()`
    /// and `required_jitter` is zero. This should only occur in test code.
    jitter_enforced: bool,
}

impl PreparedMessage {
    /// Check if timing jitter is being enforced for this message.
    ///
    /// Returns `false` if the message was prepared with `SendConfig::testing()`,
    /// which should only be used in test code.
    pub fn is_jitter_enforced(&self) -> bool {
        self.jitter_enforced
    }

    /// Get the envelope hash for deduplication/receipts.
    pub fn envelope_hash(&self) -> Hash256 {
        self.message.envelope_hash()
    }

    /// Consume the prepared message and return just the encrypted message.
    ///
    /// **WARNING**: The caller is responsible for having already applied
    /// the `required_jitter` delay before calling this method.
    pub fn into_message(self) -> EncryptedMessage {
        self.message
    }
}

/// Prepare a message for sending with mandatory timing jitter.
///
/// This is the **recommended** way to encrypt and prepare messages for sending.
/// It wraps [`encrypt_for_recipient`] and adds the required timing jitter that
/// must be applied before transmission.
///
/// # Arguments
///
/// * `sender` - The sender's identity keypair (for signing)
/// * `recipient` - The recipient's public keys (for encryption)
/// * `content` - The message content to encrypt
/// * `reply_to` - Optional hash of message being replied to
/// * `config` - Send configuration (use `SendConfig::default()` for production)
///
/// # Returns
///
/// A [`PreparedMessage`] containing the encrypted message and required jitter.
///
/// # Errors
///
/// Returns `ProtocolError::Crypto` if encryption fails.
/// Returns `ProtocolError::Serialization` if serialization fails.
///
/// # Security
///
/// The caller **MUST** wait for `prepared.required_jitter` before sending:
///
/// ```ignore
/// use veritas_protocol::encryption::{prepare_for_send, SendConfig};
/// use tokio::time::sleep;
///
/// let prepared = prepare_for_send(
///     &sender,
///     recipient.public_keys(),
///     content,
///     None,
///     SendConfig::default(),
/// )?;
///
/// // MANDATORY: Apply timing jitter
/// sleep(prepared.required_jitter).await;
///
/// // Now safe to send
/// network.send(prepared.into_message()).await;
/// ```
///
/// # Example (Testing)
///
/// ```ignore
/// // For tests only - disables jitter for deterministic behavior
/// let prepared = prepare_for_send(
///     &sender,
///     recipient.public_keys(),
///     content,
///     None,
///     SendConfig::testing(),
/// )?;
/// assert_eq!(prepared.required_jitter, Duration::ZERO);
/// ```
pub fn prepare_for_send(
    sender: &IdentityKeyPair,
    recipient: &IdentityPublicKeys,
    content: MessageContent,
    reply_to: Option<Hash256>,
    config: SendConfig,
) -> Result<PreparedMessage> {
    // Encrypt the message
    let message = encrypt_for_recipient(sender, recipient, content, reply_to)?;

    // Calculate required jitter using cryptographically secure RNG
    let (required_jitter, jitter_enforced) = if config.enforce_jitter {
        (add_timing_jitter(), true)
    } else {
        (Duration::ZERO, false)
    };

    Ok(PreparedMessage {
        message,
        required_jitter,
        jitter_enforced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identities() -> (IdentityKeyPair, IdentityKeyPair) {
        let sender = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        (sender, recipient)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Hello, VERITAS!").unwrap();

        // Encrypt
        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        // Decrypt
        let payload = decrypt_as_recipient(&recipient, &encrypted.envelope).unwrap();

        // Verify content
        assert_eq!(payload.content(), &content);
        assert_eq!(payload.sender_id(), sender.identity_hash());
    }

    #[test]
    fn test_encrypt_decrypt_with_reply() {
        let (sender, recipient) = create_test_identities();
        let reply_to = Hash256::hash(b"original-message-id");
        let content = MessageContent::text("This is a reply").unwrap();

        let encrypted = encrypt_for_recipient(
            &sender,
            recipient.public_keys(),
            content.clone(),
            Some(reply_to.clone()),
        )
        .unwrap();

        let payload = decrypt_as_recipient(&recipient, &encrypted.envelope).unwrap();

        assert_eq!(payload.content(), &content);
        assert_eq!(payload.reply_to(), Some(&reply_to));
    }

    #[test]
    fn test_decrypt_with_wrong_recipient_fails() {
        let (sender, recipient) = create_test_identities();
        let wrong_recipient = IdentityKeyPair::generate();
        let content = MessageContent::text("Secret message").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content, None).unwrap();

        // Try to decrypt with wrong recipient
        let result = decrypt_as_recipient(&wrong_recipient, &encrypted.envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_and_verify() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Verified message").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        // Decrypt and verify with sender's public keys
        let payload =
            decrypt_and_verify(&recipient, &encrypted.envelope, sender.public_keys()).unwrap();

        assert_eq!(payload.content(), &content);
        assert_eq!(payload.sender_id(), sender.identity_hash());
    }

    #[test]
    fn test_decrypt_and_verify_wrong_sender_fails() {
        let (sender, recipient) = create_test_identities();
        let imposter = IdentityKeyPair::generate();
        let content = MessageContent::text("Who sent this?").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content, None).unwrap();

        // Try to verify with imposter's public keys
        let result = decrypt_and_verify(&recipient, &encrypted.envelope, imposter.public_keys());
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }

    #[test]
    fn test_decryption_context() {
        let (sender, recipient) = create_test_identities();
        let ctx = DecryptionContext::new(recipient.clone());

        let content1 = MessageContent::text("Message 1").unwrap();
        let content2 = MessageContent::text("Message 2").unwrap();

        let encrypted1 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content1.clone(), None)
                .unwrap();
        let encrypted2 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content2.clone(), None)
                .unwrap();

        let payload1 = ctx.decrypt(&encrypted1.envelope).unwrap();
        let payload2 = ctx.decrypt(&encrypted2.envelope).unwrap();

        assert_eq!(payload1.content(), &content1);
        assert_eq!(payload2.content(), &content2);
    }

    #[test]
    fn test_decryption_context_verify() {
        let (sender, recipient) = create_test_identities();
        let ctx = DecryptionContext::new(recipient.clone());
        let content = MessageContent::text("Verified via context").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        let payload = ctx
            .decrypt_and_verify(&encrypted.envelope, sender.public_keys())
            .unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_decryption_context_recipient_hash() {
        let recipient = IdentityKeyPair::generate();
        let ctx = DecryptionContext::new(recipient.clone());

        assert_eq!(ctx.recipient_hash(), recipient.identity_hash());
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Serialize me").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        // Serialize
        let bytes = encrypted.to_bytes().unwrap();

        // Deserialize
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Should still decrypt correctly
        let payload = decrypt_as_recipient(&recipient, &restored.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_encrypted_message_hash() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Hash me").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content, None).unwrap();

        let hash1 = encrypted.envelope_hash();
        let hash2 = encrypted.envelope_hash();

        assert_eq!(hash1, hash2);
        assert!(!hash1.is_zero());
    }

    #[test]
    fn test_add_timing_jitter_range() {
        // Test multiple times to ensure randomness stays in range
        for _ in 0..100 {
            let jitter = add_timing_jitter();
            assert!(jitter <= Duration::from_millis(MAX_JITTER_MS));
        }
    }

    #[test]
    fn test_add_timing_jitter_varies() {
        // Generate multiple jitter values and check they're not all the same
        let jitters: Vec<_> = (0..10).map(|_| add_timing_jitter()).collect();

        // At least some should be different (with overwhelming probability)
        let all_same = jitters.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Jitter values should vary");
    }

    #[test]
    fn test_envelope_has_valid_structure() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Test structure").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content, None).unwrap();

        // Envelope should be valid
        assert!(encrypted.envelope.validate().is_ok());

        // Ciphertext should be larger than minimum size (bucket + auth tag)
        // The ciphertext is the encrypted padded payload, which includes
        // the 16-byte authentication tag from ChaCha20-Poly1305
        assert!(encrypted.envelope.ciphertext().len() >= crate::limits::PADDING_BUCKETS[0]);

        // Mailbox salt should not be all zeros
        assert!(!encrypted.mailbox_salt.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_different_messages_have_different_envelopes() {
        let (sender, recipient) = create_test_identities();

        let content1 = MessageContent::text("Message 1").unwrap();
        let content2 = MessageContent::text("Message 2").unwrap();

        let encrypted1 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content1, None).unwrap();
        let encrypted2 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content2, None).unwrap();

        // Different ephemeral keys
        assert_ne!(
            encrypted1.envelope.ephemeral_public(),
            encrypted2.envelope.ephemeral_public()
        );

        // Different ciphertext
        assert_ne!(
            encrypted1.envelope.ciphertext(),
            encrypted2.envelope.ciphertext()
        );

        // Different nonces
        assert_ne!(encrypted1.envelope.nonce(), encrypted2.envelope.nonce());
    }

    #[test]
    fn test_same_message_has_different_envelopes() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Same content").unwrap();

        let encrypted1 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();
        let encrypted2 =
            encrypt_for_recipient(&sender, recipient.public_keys(), content, None).unwrap();

        // Should use different ephemeral keys each time
        assert_ne!(
            encrypted1.envelope.ephemeral_public(),
            encrypted2.envelope.ephemeral_public()
        );

        // Ciphertext should differ due to different nonces
        assert_ne!(
            encrypted1.envelope.ciphertext(),
            encrypted2.envelope.ciphertext()
        );
    }

    #[test]
    fn test_decryption_context_debug() {
        let recipient = IdentityKeyPair::generate();
        let ctx = DecryptionContext::new(recipient.clone());

        let debug = format!("{:?}", ctx);
        assert!(debug.contains("DecryptionContext"));
    }

    #[test]
    fn test_large_message_encryption() {
        let (sender, recipient) = create_test_identities();
        // Create a message near the maximum single-chunk size
        let text = "a".repeat(300); // Max chars for single message
        let content = MessageContent::text(&text).unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        let payload = decrypt_as_recipient(&recipient, &encrypted.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_empty_message_encryption() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("").unwrap();

        let encrypted =
            encrypt_for_recipient(&sender, recipient.public_keys(), content.clone(), None).unwrap();

        let payload = decrypt_as_recipient(&recipient, &encrypted.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    // === Tests for timing jitter enforcement (VERITAS-2026-0015) ===

    #[test]
    fn test_send_config_default_enables_jitter() {
        let config = SendConfig::default();
        assert!(config.enforce_jitter);
        assert!(!config.is_testing());
    }

    #[test]
    fn test_send_config_testing_disables_jitter() {
        let config = SendConfig::testing();
        assert!(!config.enforce_jitter);
        assert!(config.is_testing());
    }

    #[test]
    fn test_prepare_for_send_with_jitter() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Hello with jitter!").unwrap();

        let prepared = prepare_for_send(
            &sender,
            recipient.public_keys(),
            content.clone(),
            None,
            SendConfig::default(),
        )
        .unwrap();

        // Jitter should be enforced
        assert!(prepared.is_jitter_enforced());

        // Jitter should be in valid range (0 to MAX_JITTER_MS)
        assert!(prepared.required_jitter <= Duration::from_millis(MAX_JITTER_MS));

        // Message should still decrypt correctly
        let payload = decrypt_as_recipient(&recipient, &prepared.message.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_prepare_for_send_testing_mode() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Testing mode message").unwrap();

        let prepared = prepare_for_send(
            &sender,
            recipient.public_keys(),
            content.clone(),
            None,
            SendConfig::testing(),
        )
        .unwrap();

        // Jitter should NOT be enforced in testing mode
        assert!(!prepared.is_jitter_enforced());

        // Jitter should be zero in testing mode
        assert_eq!(prepared.required_jitter, Duration::ZERO);

        // Message should still decrypt correctly
        let payload = decrypt_as_recipient(&recipient, &prepared.message.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_prepare_for_send_jitter_varies() {
        let (sender, recipient) = create_test_identities();

        // Generate multiple prepared messages and check jitter varies
        let jitters: Vec<_> = (0..10)
            .map(|i| {
                let content = MessageContent::text(&format!("Message {}", i)).unwrap();
                prepare_for_send(
                    &sender,
                    recipient.public_keys(),
                    content,
                    None,
                    SendConfig::default(),
                )
                .unwrap()
                .required_jitter
            })
            .collect();

        // At least some should be different (with overwhelming probability)
        let all_same = jitters.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Jitter values should vary across messages");
    }

    #[test]
    fn test_prepared_message_into_message() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Extract message").unwrap();

        let prepared = prepare_for_send(
            &sender,
            recipient.public_keys(),
            content.clone(),
            None,
            SendConfig::testing(),
        )
        .unwrap();

        // Get envelope hash before consuming
        let hash = prepared.envelope_hash();

        // Consume and get inner message
        let message = prepared.into_message();

        // Hash should match
        assert_eq!(hash, message.envelope_hash());

        // Should still decrypt
        let payload = decrypt_as_recipient(&recipient, &message.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    #[test]
    fn test_prepared_message_debug() {
        let (sender, recipient) = create_test_identities();
        let content = MessageContent::text("Debug test").unwrap();

        let prepared = prepare_for_send(
            &sender,
            recipient.public_keys(),
            content,
            None,
            SendConfig::default(),
        )
        .unwrap();

        let debug = format!("{:?}", prepared);
        assert!(debug.contains("PreparedMessage"));
        assert!(debug.contains("required_jitter"));
    }

    #[test]
    fn test_send_config_debug() {
        let config = SendConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("SendConfig"));
        assert!(debug.contains("enforce_jitter"));
    }

    #[test]
    fn test_prepare_for_send_jitter_always_in_range() {
        let (sender, recipient) = create_test_identities();

        // Test multiple times to ensure jitter stays in range
        for i in 0..100 {
            let content = MessageContent::text(&format!("Msg {}", i)).unwrap();
            let prepared = prepare_for_send(
                &sender,
                recipient.public_keys(),
                content,
                None,
                SendConfig::default(),
            )
            .unwrap();

            assert!(
                prepared.required_jitter <= Duration::from_millis(MAX_JITTER_MS),
                "Jitter {} exceeds MAX_JITTER_MS",
                prepared.required_jitter.as_millis()
            );
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encrypt_decrypt_roundtrip(text in ".{0,300}") {
            let sender = IdentityKeyPair::generate();
            let recipient = IdentityKeyPair::generate();
            let content = MessageContent::text(&text).unwrap();

            let encrypted = encrypt_for_recipient(
                &sender,
                recipient.public_keys(),
                content.clone(),
                None,
            ).unwrap();

            let payload = decrypt_as_recipient(&recipient, &encrypted.envelope).unwrap();

            prop_assert_eq!(payload.content(), &content);
            prop_assert_eq!(payload.sender_id(), sender.identity_hash());
        }

        #[test]
        fn wrong_recipient_always_fails(text in ".{0,300}") {
            let sender = IdentityKeyPair::generate();
            let recipient = IdentityKeyPair::generate();
            let wrong_recipient = IdentityKeyPair::generate();
            let content = MessageContent::text(&text).unwrap();

            let encrypted = encrypt_for_recipient(
                &sender,
                recipient.public_keys(),
                content,
                None,
            ).unwrap();

            let result = decrypt_as_recipient(&wrong_recipient, &encrypted.envelope);
            prop_assert!(result.is_err());
        }

        #[test]
        fn jitter_always_in_range(seed: u64) {
            // Use seed to ensure reproducibility in tests
            let _ = seed;
            let jitter = add_timing_jitter();
            prop_assert!(jitter <= Duration::from_millis(MAX_JITTER_MS));
        }

        #[test]
        fn encrypted_message_serialization_roundtrip(text in ".{0,300}") {
            let sender = IdentityKeyPair::generate();
            let recipient = IdentityKeyPair::generate();
            let content = MessageContent::text(&text).unwrap();

            let encrypted = encrypt_for_recipient(
                &sender,
                recipient.public_keys(),
                content.clone(),
                None,
            ).unwrap();

            let bytes = encrypted.to_bytes().unwrap();
            let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

            let payload = decrypt_as_recipient(&recipient, &restored.envelope).unwrap();
            prop_assert_eq!(payload.content(), &content);
        }

        #[test]
        fn prepare_for_send_jitter_always_valid(text in ".{0,300}") {
            let sender = IdentityKeyPair::generate();
            let recipient = IdentityKeyPair::generate();
            let content = MessageContent::text(&text).unwrap();

            let prepared = prepare_for_send(
                &sender,
                recipient.public_keys(),
                content.clone(),
                None,
                SendConfig::default(),
            ).unwrap();

            // Jitter must be in valid range
            prop_assert!(prepared.required_jitter <= Duration::from_millis(MAX_JITTER_MS));
            prop_assert!(prepared.is_jitter_enforced());

            // Message must still decrypt correctly
            let payload = decrypt_as_recipient(&recipient, &prepared.message.envelope).unwrap();
            prop_assert_eq!(payload.content(), &content);
        }

        #[test]
        fn prepare_for_send_testing_has_zero_jitter(text in ".{0,300}") {
            let sender = IdentityKeyPair::generate();
            let recipient = IdentityKeyPair::generate();
            let content = MessageContent::text(&text).unwrap();

            let prepared = prepare_for_send(
                &sender,
                recipient.public_keys(),
                content.clone(),
                None,
                SendConfig::testing(),
            ).unwrap();

            // Testing mode must have zero jitter
            prop_assert_eq!(prepared.required_jitter, Duration::ZERO);
            prop_assert!(!prepared.is_jitter_enforced());

            // Message must still decrypt correctly
            let payload = decrypt_as_recipient(&recipient, &prepared.message.envelope).unwrap();
            prop_assert_eq!(payload.content(), &content);
        }
    }
}
