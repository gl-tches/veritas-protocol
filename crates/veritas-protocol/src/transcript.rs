//! Transcript binding for key derivation.
//!
//! Ensures HKDF-derived keys are bound to the full communication context,
//! preventing key reuse across different sessions or parties.
//!
//! ## Binding Format
//!
//! `sender_id || recipient_id || session_id || counter`
//!
//! This is included as additional context in all key derivation operations.

use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

/// A transcript binding context for key derivation.
///
/// Binds derived keys to a specific communication session between two parties.
#[derive(Clone, Debug)]
pub struct TranscriptBinding {
    /// Sender's identity hash.
    pub sender_id: IdentityHash,
    /// Recipient's identity hash.
    pub recipient_id: IdentityHash,
    /// Session identifier (derived from key exchange).
    pub session_id: [u8; 32],
    /// Message counter within this session.
    pub counter: u64,
}

impl TranscriptBinding {
    /// Create a new transcript binding.
    pub fn new(
        sender_id: IdentityHash,
        recipient_id: IdentityHash,
        session_id: [u8; 32],
        counter: u64,
    ) -> Self {
        Self {
            sender_id,
            recipient_id,
            session_id,
            counter,
        }
    }

    /// Serialize the binding to bytes for use as HKDF context.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 32 + 32 + 8);
        bytes.extend_from_slice(self.sender_id.as_bytes());
        bytes.extend_from_slice(self.recipient_id.as_bytes());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.counter.to_be_bytes());
        bytes
    }

    /// Compute a domain-separated hash of this binding.
    ///
    /// Useful when the full binding bytes are too large for a context parameter.
    pub fn hash(&self) -> Hash256 {
        use crate::domain_separation::{build_domain_label, purposes};
        let label = build_domain_label(purposes::TRANSCRIPT, &self.to_bytes());
        Hash256::hash(&label)
    }

    /// Increment the counter and return the new value.
    pub fn next_counter(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        self.counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> IdentityHash {
        IdentityHash::from_bytes(&[0xAA; 32]).expect("valid 32-byte identity hash")
    }

    #[test]
    fn test_transcript_binding_serialization() {
        let binding = TranscriptBinding::new(test_identity(), test_identity(), [0xBB; 32], 42);
        let bytes = binding.to_bytes();
        assert_eq!(bytes.len(), 32 + 32 + 32 + 8); // 104 bytes
    }

    #[test]
    fn test_different_bindings_different_hashes() {
        let b1 = TranscriptBinding::new(test_identity(), test_identity(), [0xBB; 32], 1);
        let b2 = TranscriptBinding::new(test_identity(), test_identity(), [0xBB; 32], 2);
        assert_ne!(b1.hash(), b2.hash());
    }

    #[test]
    fn test_counter_increment() {
        let mut binding = TranscriptBinding::new(test_identity(), test_identity(), [0; 32], 0);
        assert_eq!(binding.next_counter(), 1);
        assert_eq!(binding.next_counter(), 2);
        assert_eq!(binding.counter, 2);
    }
}
