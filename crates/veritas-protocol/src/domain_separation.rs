//! Structured domain separation for VERITAS protocol.
//!
//! Provides a consistent domain separation format across all HKDF/hash operations:
//! `"VERITAS-v1." || purpose || "." || context_length || context`
//!
//! This prevents cross-protocol and cross-context attacks where a valid
//! output from one context could be reused in another.

/// Build a domain-separated label.
///
/// Format: `"VERITAS-v1." || purpose || "." || len(context) as 4-byte BE || context`
///
/// # Arguments
///
/// * `purpose` - Short string describing the cryptographic operation (e.g., "MESSAGE-SIG")
/// * `context` - Additional context bytes (e.g., sender_id || recipient_id)
///
/// # Example
///
/// ```ignore
/// let label = build_domain_label("MESSAGE-SIG", b"sender_hash||recipient_hash");
/// // Returns: b"VERITAS-v1.MESSAGE-SIG.00000026sender_hash||recipient_hash"
/// ```
pub fn build_domain_label(purpose: &str, context: &[u8]) -> Vec<u8> {
    let mut label = Vec::with_capacity(11 + purpose.len() + 1 + 4 + context.len());
    label.extend_from_slice(b"VERITAS-v1.");
    label.extend_from_slice(purpose.as_bytes());
    label.extend_from_slice(b".");
    label.extend_from_slice(&(context.len() as u32).to_be_bytes());
    label.extend_from_slice(context);
    label
}

/// Well-known domain separation purposes.
pub mod purposes {
    /// Message signature (inner payload signing).
    pub const MESSAGE_SIG: &str = "MESSAGE-SIG";
    /// Block signature (validator block signing).
    pub const BLOCK_SIG: &str = "BLOCK-SIG";
    /// Mailbox key derivation.
    pub const MAILBOX_KEY: &str = "MAILBOX-KEY";
    /// Envelope hash.
    pub const ENVELOPE_HASH: &str = "ENVELOPE-HASH";
    /// Chain entry hash.
    pub const CHAIN_ENTRY: &str = "CHAIN-ENTRY";
    /// Block hash.
    pub const BLOCK_HASH: &str = "BLOCK-HASH";
    /// Genesis block.
    pub const GENESIS: &str = "GENESIS";
    /// Receipt signature.
    pub const RECEIPT_SIG: &str = "RECEIPT-SIG";
    /// Key exchange derivation.
    pub const KEY_EXCHANGE: &str = "KEY-EXCHANGE";
    /// Interaction proof.
    pub const INTERACTION_PROOF: &str = "INTERACTION-PROOF";
    /// Identity hash derivation.
    pub const IDENTITY_HASH: &str = "IDENTITY-HASH";
    /// Transcript binding.
    pub const TRANSCRIPT: &str = "TRANSCRIPT";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_label_format() {
        let label = build_domain_label("MESSAGE-SIG", b"");
        assert_eq!(&label[..11], b"VERITAS-v1.");
        assert!(label.starts_with(b"VERITAS-v1.MESSAGE-SIG."));
    }

    #[test]
    fn test_domain_label_with_context() {
        let context = b"test-context";
        let label = build_domain_label("BLOCK-SIG", context);
        // Should contain prefix + purpose + separator + 4-byte length + context
        assert!(label.len() == 11 + 9 + 1 + 4 + 12);
        // Verify context length bytes
        let len_offset = 11 + 9 + 1;
        let len_bytes = &label[len_offset..len_offset + 4];
        assert_eq!(u32::from_be_bytes(len_bytes.try_into().unwrap()), 12);
    }

    #[test]
    fn test_different_purposes_produce_different_labels() {
        let label1 = build_domain_label("MESSAGE-SIG", b"ctx");
        let label2 = build_domain_label("BLOCK-SIG", b"ctx");
        assert_ne!(label1, label2);
    }

    #[test]
    fn test_different_contexts_produce_different_labels() {
        let label1 = build_domain_label("MESSAGE-SIG", b"context-a");
        let label2 = build_domain_label("MESSAGE-SIG", b"context-b");
        assert_ne!(label1, label2);
    }

    #[test]
    fn test_empty_context() {
        let label = build_domain_label("TEST", b"");
        let len_offset = 11 + 4 + 1; // "VERITAS-v1." + "TEST" + "."
        let len_bytes = &label[len_offset..len_offset + 4];
        assert_eq!(u32::from_be_bytes(len_bytes.try_into().unwrap()), 0);
    }
}
