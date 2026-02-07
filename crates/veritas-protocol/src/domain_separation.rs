//! Structured domain separation for VERITAS protocol.
//!
//! Format: "VERITAS-v1." || purpose || "." || context_length || context
//!
//! This ensures cryptographic operations in different contexts produce
//! different outputs even with identical inputs.

/// Build a domain separator following the VERITAS standard format.
///
/// Format: `"VERITAS-v1." || purpose || "." || context_length_as_decimal || context`
///
/// # Arguments
/// * `purpose` - The purpose string (e.g., "message-signing", "block-signing")
/// * `context` - Optional context bytes
///
/// # Example
/// ```ignore
/// let sep = domain_separator("message-signing", b"");
/// // Returns: b"VERITAS-v1.message-signing.0"
///
/// let sep = domain_separator("hkdf-expand", b"session123");
/// // Returns: b"VERITAS-v1.hkdf-expand.10session123"
/// ```
pub fn domain_separator(purpose: &str, context: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(b"VERITAS-v1.");
    result.extend_from_slice(purpose.as_bytes());
    result.push(b'.');
    // Encode context length as decimal string
    let len_str = context.len().to_string();
    result.extend_from_slice(len_str.as_bytes());
    result.extend_from_slice(context);
    result
}

/// Known domain separation purposes.
pub mod purposes {
    /// Domain separator purpose for message signing.
    pub const MESSAGE_SIGNING: &str = "message-signing";
    /// Domain separator purpose for block signing.
    pub const BLOCK_SIGNING: &str = "block-signing";
    /// Domain separator purpose for envelope hashing.
    pub const ENVELOPE_HASH: &str = "envelope-hash";
    /// Domain separator purpose for content hashing.
    pub const CONTENT_HASH: &str = "content-hash";
    /// Domain separator purpose for message ID derivation.
    pub const MESSAGE_ID: &str = "message-id";
    /// Domain separator purpose for chain entry hashing.
    pub const CHAIN_ENTRY: &str = "chain-entry";
    /// Domain separator purpose for genesis block.
    pub const GENESIS: &str = "genesis";
    /// Domain separator purpose for HKDF expansion.
    pub const HKDF_EXPAND: &str = "hkdf-expand";
    /// Domain separator purpose for mailbox key derivation.
    pub const MAILBOX_KEY: &str = "mailbox-key";
    /// Domain separator purpose for interaction proof generation.
    pub const INTERACTION_PROOF: &str = "interaction-proof";
    /// Domain separator purpose for receipt signing.
    pub const RECEIPT_SIGNING: &str = "receipt-signing";
    /// Domain separator purpose for transaction signing.
    pub const TRANSACTION: &str = "transaction";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separator_empty_context() {
        let sep = domain_separator("message-signing", b"");
        assert_eq!(sep, b"VERITAS-v1.message-signing.0");
    }

    #[test]
    fn test_domain_separator_with_context() {
        let sep = domain_separator("hkdf-expand", b"session123");
        assert_eq!(sep, b"VERITAS-v1.hkdf-expand.10session123");
    }

    #[test]
    fn test_domain_separator_different_purposes_differ() {
        let sep1 = domain_separator("message-signing", b"ctx");
        let sep2 = domain_separator("block-signing", b"ctx");
        assert_ne!(sep1, sep2);
    }

    #[test]
    fn test_domain_separator_different_contexts_differ() {
        let sep1 = domain_separator("hkdf-expand", b"context-a");
        let sep2 = domain_separator("hkdf-expand", b"context-b");
        assert_ne!(sep1, sep2);
    }

    #[test]
    fn test_domain_separator_context_length_prevents_ambiguity() {
        // "3abc" vs "1a" || "bc" -- the length prefix disambiguates
        let sep1 = domain_separator("test", b"abc");
        let sep2 = domain_separator("test", b"a");
        // sep1 = "VERITAS-v1.test.3abc"
        // sep2 = "VERITAS-v1.test.1a"
        assert_ne!(sep1, sep2);
    }

    #[test]
    fn test_domain_separator_starts_with_prefix() {
        let sep = domain_separator("anything", b"");
        assert!(sep.starts_with(b"VERITAS-v1."));
    }

    #[test]
    fn test_domain_separator_all_purposes() {
        // Verify all known purposes produce valid separators
        let all_purposes = [
            purposes::MESSAGE_SIGNING,
            purposes::BLOCK_SIGNING,
            purposes::ENVELOPE_HASH,
            purposes::CONTENT_HASH,
            purposes::MESSAGE_ID,
            purposes::CHAIN_ENTRY,
            purposes::GENESIS,
            purposes::HKDF_EXPAND,
            purposes::MAILBOX_KEY,
            purposes::INTERACTION_PROOF,
            purposes::RECEIPT_SIGNING,
            purposes::TRANSACTION,
        ];

        let mut separators = Vec::new();
        for purpose in &all_purposes {
            let sep = domain_separator(purpose, b"");
            // All should start with the standard prefix
            assert!(sep.starts_with(b"VERITAS-v1."));
            separators.push(sep);
        }

        // All purposes produce unique separators
        for i in 0..separators.len() {
            for j in (i + 1)..separators.len() {
                assert_ne!(
                    separators[i], separators[j],
                    "Purposes '{}' and '{}' produced the same separator",
                    all_purposes[i], all_purposes[j]
                );
            }
        }
    }

    #[test]
    fn test_domain_separator_binary_context() {
        let binary_ctx = &[0x00, 0x01, 0xFF, 0xFE];
        let sep = domain_separator("test", binary_ctx);
        // Should contain "VERITAS-v1.test.4" followed by the 4 binary bytes
        let expected_prefix = b"VERITAS-v1.test.4";
        assert!(sep.starts_with(expected_prefix));
        assert_eq!(sep.len(), expected_prefix.len() + 4);
        assert_eq!(&sep[expected_prefix.len()..], binary_ctx);
    }

    #[test]
    fn test_domain_separator_large_context() {
        let large_ctx = vec![0xABu8; 1000];
        let sep = domain_separator("test", &large_ctx);
        // Length "1000" is 4 digits
        let expected_prefix = b"VERITAS-v1.test.1000";
        assert!(sep.starts_with(expected_prefix));
        assert_eq!(sep.len(), expected_prefix.len() + 1000);
    }
}
