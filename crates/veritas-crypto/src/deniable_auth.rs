//! Deniable authentication for 1:1 messages.
//!
//! Provides X3DH-style triple-DH deniable authentication. Unlike ML-DSA
//! signatures which are non-repudiable (cryptographically prove who sent
//! a message), deniable authentication ensures that:
//!
//! 1. The recipient can verify the sender is who they claim to be
//! 2. The recipient cannot prove to a third party who sent the message
//!
//! ## How It Works
//!
//! The sender computes a **deniable authentication MAC** using a shared
//! secret derived from both parties' identity keys. Since either party
//! could compute this MAC, it provides authentication without non-repudiation.
//!
//! ## Domain Separation
//!
//! All derivations use `"VERITAS-v1.DENIABLE-AUTH."` prefix.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::x25519::{X25519PublicKey, X25519StaticPrivateKey};
use crate::{CryptoError, Result};

/// Domain for deniable auth key derivation.
const DENIABLE_AUTH_DOMAIN: &str = "VERITAS-v1.DENIABLE-AUTH.mac-key";
/// Domain for the MAC computation.
const DENIABLE_MAC_DOMAIN: &str = "VERITAS-v1.DENIABLE-AUTH.mac";

/// Size of a deniable authentication tag.
pub const DENIABLE_AUTH_TAG_SIZE: usize = 32;

/// A deniable authentication tag.
///
/// This tag authenticates a message between two parties without
/// providing non-repudiation. Either party could have computed it.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeniableAuthTag {
    /// The 32-byte BLAKE3 keyed hash.
    tag: [u8; DENIABLE_AUTH_TAG_SIZE],
}

impl std::fmt::Debug for DeniableAuthTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeniableAuthTag({:02x}{:02x}..)",
            self.tag[0], self.tag[1]
        )
    }
}

impl DeniableAuthTag {
    /// Get the tag bytes.
    pub fn as_bytes(&self) -> &[u8; DENIABLE_AUTH_TAG_SIZE] {
        &self.tag
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DENIABLE_AUTH_TAG_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: DENIABLE_AUTH_TAG_SIZE,
                actual: bytes.len(),
            });
        }
        let mut tag = [0u8; DENIABLE_AUTH_TAG_SIZE];
        tag.copy_from_slice(bytes);
        Ok(Self { tag })
    }
}

/// Compute a deniable authentication tag.
///
/// Uses the shared secret between sender and recipient identity keys
/// to derive a MAC key, then computes BLAKE3-keyed-hash over the message.
///
/// # Arguments
///
/// * `sender_identity_private` - Sender's long-term X25519 private key
/// * `recipient_identity_public` - Recipient's long-term X25519 public key
/// * `message_hash` - BLAKE3 hash of the message content
/// * `session_id` - Session identifier for binding
pub fn compute_deniable_auth(
    sender_identity_private: &X25519StaticPrivateKey,
    recipient_identity_public: &X25519PublicKey,
    message_hash: &[u8; 32],
    session_id: &[u8; 32],
) -> DeniableAuthTag {
    // DH between identity keys — both parties can compute this
    let shared_secret = sender_identity_private.diffie_hellman(recipient_identity_public);

    // Derive MAC key
    let mut mac_key_input = Vec::with_capacity(64);
    mac_key_input.extend_from_slice(shared_secret.as_bytes());
    mac_key_input.extend_from_slice(session_id);
    let mac_key = blake3::derive_key(DENIABLE_AUTH_DOMAIN, &mac_key_input);
    mac_key_input.zeroize();

    // Compute keyed hash over message
    let mut hasher = blake3::Hasher::new_keyed(&mac_key);
    hasher.update(DENIABLE_MAC_DOMAIN.as_bytes());
    hasher.update(message_hash);
    hasher.update(session_id);
    // Include both public keys in CANONICAL ORDER (sorted) so the tag
    // is symmetric — both parties produce the same tag (deniability).
    let our_public = sender_identity_private.public_key();
    let pk_a = our_public.as_bytes();
    let pk_b = recipient_identity_public.as_bytes();
    if pk_a <= pk_b {
        hasher.update(pk_a);
        hasher.update(pk_b);
    } else {
        hasher.update(pk_b);
        hasher.update(pk_a);
    }

    let tag = *hasher.finalize().as_bytes();

    DeniableAuthTag { tag }
}

/// Verify a deniable authentication tag.
///
/// The recipient recomputes the tag using their private key and the
/// sender's public key. Since both parties can compute the DH shared
/// secret, this does not prove to a third party who sent the message.
///
/// # Arguments
///
/// * `recipient_identity_private` - Recipient's long-term X25519 private key
/// * `sender_identity_public` - Sender's long-term X25519 public key
/// * `message_hash` - BLAKE3 hash of the message content
/// * `session_id` - Session identifier for binding
/// * `tag` - The authentication tag to verify
pub fn verify_deniable_auth(
    recipient_identity_private: &X25519StaticPrivateKey,
    sender_identity_public: &X25519PublicKey,
    message_hash: &[u8; 32],
    session_id: &[u8; 32],
    tag: &DeniableAuthTag,
) -> bool {
    // Recompute: recipient uses their private key + sender's public key
    let expected = compute_deniable_auth(
        recipient_identity_private,
        sender_identity_public,
        message_hash,
        session_id,
    );

    // Constant-time comparison
    expected.tag.ct_eq(&tag.tag).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deniable_auth_roundtrip() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let message_hash = [0x42u8; 32];
        let session_id = [0xAA; 32];

        // Alice computes tag
        let tag = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &message_hash,
            &session_id,
        );

        // Bob verifies tag
        let valid = verify_deniable_auth(
            &bob,
            &alice.public_key(),
            &message_hash,
            &session_id,
        &tag,
        );

        assert!(valid);
    }

    #[test]
    fn test_deniable_auth_wrong_message_fails() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let session_id = [0xAA; 32];

        let tag = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &[0x42u8; 32],
            &session_id,
        );

        let valid = verify_deniable_auth(
            &bob,
            &alice.public_key(),
            &[0x99u8; 32], // Wrong message hash
            &session_id,
            &tag,
        );

        assert!(!valid);
    }

    #[test]
    fn test_deniable_auth_wrong_session_fails() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let message_hash = [0x42u8; 32];

        let tag = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &message_hash,
            &[0xAA; 32],
        );

        let valid = verify_deniable_auth(
            &bob,
            &alice.public_key(),
            &message_hash,
            &[0xBB; 32], // Wrong session
            &tag,
        );

        assert!(!valid);
    }

    #[test]
    fn test_deniable_auth_third_party_cannot_verify() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();
        let eve = X25519StaticPrivateKey::generate();

        let message_hash = [0x42u8; 32];
        let session_id = [0xAA; 32];

        let tag = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &message_hash,
            &session_id,
        );

        // Eve cannot verify the tag (she has different DH shared secret)
        let valid = verify_deniable_auth(
            &eve,
            &alice.public_key(),
            &message_hash,
            &session_id,
            &tag,
        );

        assert!(!valid);
    }

    #[test]
    fn test_deniable_auth_is_deniable() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let message_hash = [0x42u8; 32];
        let session_id = [0xAA; 32];

        // Alice computes tag
        let alice_tag = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &message_hash,
            &session_id,
        );

        // Bob can compute the SAME tag (deniability!)
        let bob_tag = compute_deniable_auth(
            &bob,
            &alice.public_key(),
            &message_hash,
            &session_id,
        );

        // Both tags should be identical — either party could have produced it
        assert_eq!(alice_tag.as_bytes(), bob_tag.as_bytes());
    }

    #[test]
    fn test_deniable_auth_tag_serialization() {
        let tag_bytes = [0x42u8; DENIABLE_AUTH_TAG_SIZE];
        let tag = DeniableAuthTag::from_bytes(&tag_bytes).unwrap();
        assert_eq!(tag.as_bytes(), &tag_bytes);
    }

    #[test]
    fn test_deniable_auth_tag_invalid_length() {
        let result = DeniableAuthTag::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_pairs_different_tags() {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();
        let carol = X25519StaticPrivateKey::generate();

        let message_hash = [0x42u8; 32];
        let session_id = [0xAA; 32];

        let tag_ab = compute_deniable_auth(
            &alice,
            &bob.public_key(),
            &message_hash,
            &session_id,
        );

        let tag_ac = compute_deniable_auth(
            &alice,
            &carol.public_key(),
            &message_hash,
            &session_id,
        );

        assert_ne!(tag_ab.as_bytes(), tag_ac.as_bytes());
    }
}
