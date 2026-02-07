//! Transcript binding for key derivation.
//!
//! Binds key derivation to the full communication context to prevent
//! key reuse across contexts and unknown key-share attacks.
//!
//! The transcript includes: sender_id || recipient_id || session_id || message_counter

use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

/// A transcript binding context for key derivation.
///
/// Includes all parties and session state to ensure derived keys
/// are unique to this specific communication context.
#[derive(Clone, Debug)]
pub struct TranscriptBinding {
    /// Sender's identity hash
    sender_id: IdentityHash,
    /// Recipient's identity hash
    recipient_id: IdentityHash,
    /// Session identifier (derived from initial key exchange)
    session_id: [u8; 32],
    /// Message counter within the session
    message_counter: u64,
}

impl TranscriptBinding {
    /// Create a new transcript binding.
    pub fn new(
        sender_id: IdentityHash,
        recipient_id: IdentityHash,
        session_id: [u8; 32],
        message_counter: u64,
    ) -> Self {
        Self {
            sender_id,
            recipient_id,
            session_id,
            message_counter,
        }
    }

    /// Serialize the transcript to bytes for use as HKDF context/info.
    ///
    /// Format: sender_id (32) || recipient_id (32) || session_id (32) || counter (8)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(104); // 32 + 32 + 32 + 8
        bytes.extend_from_slice(self.sender_id.as_bytes());
        bytes.extend_from_slice(self.recipient_id.as_bytes());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.message_counter.to_be_bytes());
        bytes
    }

    /// Compute a hash of this transcript for use as additional context.
    pub fn hash(&self) -> Hash256 {
        use crate::domain_separation::{domain_separator, purposes};
        let context = self.to_bytes();
        let domain = domain_separator(purposes::HKDF_EXPAND, &context);
        Hash256::hash(&domain)
    }

    /// Get the sender ID.
    pub fn sender_id(&self) -> &IdentityHash {
        &self.sender_id
    }

    /// Get the recipient ID.
    pub fn recipient_id(&self) -> &IdentityHash {
        &self.recipient_id
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get the message counter.
    pub fn message_counter(&self) -> u64 {
        self.message_counter
    }

    /// Create the next transcript binding (increment counter).
    pub fn next(&self) -> Self {
        Self {
            sender_id: self.sender_id.clone(),
            recipient_id: self.recipient_id.clone(),
            session_id: self.session_id,
            message_counter: self.message_counter.saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test IdentityHash from a byte value.
    fn test_identity(val: u8) -> IdentityHash {
        let key_bytes = [val; 32];
        IdentityHash::from_public_key(&key_bytes)
    }

    fn test_session_id() -> [u8; 32] {
        let mut sid = [0u8; 32];
        for (i, b) in sid.iter_mut().enumerate() {
            *b = i as u8;
        }
        sid
    }

    #[test]
    fn test_transcript_to_bytes_length() {
        let binding = TranscriptBinding::new(
            test_identity(1),
            test_identity(2),
            test_session_id(),
            0,
        );
        let bytes = binding.to_bytes();
        assert_eq!(bytes.len(), 104); // 32 + 32 + 32 + 8
    }

    #[test]
    fn test_transcript_to_bytes_contains_all_fields() {
        let sender = test_identity(1);
        let recipient = test_identity(2);
        let session_id = test_session_id();
        let counter: u64 = 42;

        let binding = TranscriptBinding::new(
            sender.clone(),
            recipient.clone(),
            session_id,
            counter,
        );
        let bytes = binding.to_bytes();

        // Verify sender_id is at the start
        assert_eq!(&bytes[0..32], sender.as_bytes());
        // Verify recipient_id follows
        assert_eq!(&bytes[32..64], recipient.as_bytes());
        // Verify session_id follows
        assert_eq!(&bytes[64..96], &session_id);
        // Verify counter at the end (big-endian)
        assert_eq!(&bytes[96..104], &counter.to_be_bytes());
    }

    #[test]
    fn test_transcript_different_senders_produce_different_bytes() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let b2 = TranscriptBinding::new(test_identity(3), test_identity(2), session_id, 0);
        assert_ne!(b1.to_bytes(), b2.to_bytes());
    }

    #[test]
    fn test_transcript_different_recipients_produce_different_bytes() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let b2 = TranscriptBinding::new(test_identity(1), test_identity(3), session_id, 0);
        assert_ne!(b1.to_bytes(), b2.to_bytes());
    }

    #[test]
    fn test_transcript_different_sessions_produce_different_bytes() {
        let sid1 = [0xAAu8; 32];
        let sid2 = [0xBBu8; 32];
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), sid1, 0);
        let b2 = TranscriptBinding::new(test_identity(1), test_identity(2), sid2, 0);
        assert_ne!(b1.to_bytes(), b2.to_bytes());
    }

    #[test]
    fn test_transcript_different_counters_produce_different_bytes() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let b2 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 1);
        assert_ne!(b1.to_bytes(), b2.to_bytes());
    }

    #[test]
    fn test_transcript_hash_is_deterministic() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 5);
        let b2 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 5);
        assert_eq!(b1.hash().as_bytes(), b2.hash().as_bytes());
    }

    #[test]
    fn test_transcript_hash_differs_for_different_bindings() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let b2 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 1);
        assert_ne!(b1.hash().as_bytes(), b2.hash().as_bytes());
    }

    #[test]
    fn test_transcript_next_increments_counter() {
        let session_id = test_session_id();
        let binding = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let next = binding.next();
        assert_eq!(next.message_counter(), 1);

        let next2 = next.next();
        assert_eq!(next2.message_counter(), 2);
    }

    #[test]
    fn test_transcript_next_preserves_other_fields() {
        let sender = test_identity(1);
        let recipient = test_identity(2);
        let session_id = test_session_id();
        let binding = TranscriptBinding::new(sender.clone(), recipient.clone(), session_id, 0);
        let next = binding.next();

        assert_eq!(next.sender_id().as_bytes(), sender.as_bytes());
        assert_eq!(next.recipient_id().as_bytes(), recipient.as_bytes());
        assert_eq!(next.session_id(), &session_id);
    }

    #[test]
    fn test_transcript_next_saturates_at_max() {
        let session_id = test_session_id();
        let binding = TranscriptBinding::new(
            test_identity(1),
            test_identity(2),
            session_id,
            u64::MAX,
        );
        let next = binding.next();
        assert_eq!(next.message_counter(), u64::MAX);
    }

    #[test]
    fn test_transcript_accessors() {
        let sender = test_identity(1);
        let recipient = test_identity(2);
        let session_id = test_session_id();
        let counter = 99u64;

        let binding = TranscriptBinding::new(
            sender.clone(),
            recipient.clone(),
            session_id,
            counter,
        );

        assert_eq!(binding.sender_id().as_bytes(), sender.as_bytes());
        assert_eq!(binding.recipient_id().as_bytes(), recipient.as_bytes());
        assert_eq!(binding.session_id(), &session_id);
        assert_eq!(binding.message_counter(), counter);
    }

    #[test]
    fn test_transcript_swapped_sender_recipient_differs() {
        let session_id = test_session_id();
        let b1 = TranscriptBinding::new(test_identity(1), test_identity(2), session_id, 0);
        let b2 = TranscriptBinding::new(test_identity(2), test_identity(1), session_id, 0);
        assert_ne!(b1.to_bytes(), b2.to_bytes());
        assert_ne!(b1.hash().as_bytes(), b2.hash().as_bytes());
    }
}
