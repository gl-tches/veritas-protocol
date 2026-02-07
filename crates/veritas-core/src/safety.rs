//! Safety Numbers for Identity Verification.
//!
//! Safety numbers provide a way for users to verify they are communicating
//! with the intended party. They are derived from both parties' public keys
//! and can be compared out-of-band (e.g., in person, over a phone call, or
//! by scanning QR codes).
//!
//! # How Safety Numbers Work
//!
//! When two users want to verify their communication channel is secure:
//!
//! 1. Each user computes the safety number using both public keys
//! 2. The computation is symmetric - both users get the same result
//! 3. Users compare their safety numbers out-of-band
//! 4. If they match, users can be confident they have the correct keys
//!
//! # Why Safety Numbers Matter
//!
//! Safety numbers protect against man-in-the-middle (MITM) attacks:
//!
//! - An attacker who intercepts key exchange would have different keys
//! - The safety numbers would not match, alerting users to the attack
//! - This verification step ensures end-to-end encryption integrity
//!
//! # Display Formats
//!
//! Safety numbers can be displayed in two formats:
//!
//! - **Numeric**: 60 digits in 5-digit blocks for verbal comparison
//!   Example: `"12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"`
//!
//! - **QR/Hex**: 64-character hex string for QR code scanning
//!   Example: `"a1b2c3d4..."`
//!
//! # Example
//!
//! ```
//! use veritas_core::SafetyNumber;
//! use veritas_identity::IdentityKeyPair;
//!
//! let alice = IdentityKeyPair::generate();
//! let bob = IdentityKeyPair::generate();
//!
//! // Both compute the same safety number
//! let alice_sees = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
//! let bob_sees = SafetyNumber::compute(bob.public_keys(), alice.public_keys());
//!
//! // Safety numbers are identical regardless of computation order
//! assert_eq!(alice_sees, bob_sees);
//!
//! // Display for verbal verification
//! println!("Safety Number: {}", alice_sees);
//!
//! // Display for QR code
//! println!("QR Data: {}", alice_sees.to_qr_string());
//! ```
//!
//! # Security Notes
//!
//! - Safety numbers are computed using BLAKE3 with domain separation
//! - Keys are sorted lexicographically to ensure symmetric computation
//! - The domain prefix prevents cross-protocol attacks

use std::cmp::Ordering;
use std::fmt;

use veritas_crypto::Hash256;
use veritas_identity::IdentityPublicKeys;

/// Domain separation prefix for safety number computation.
///
/// This ensures safety numbers are distinct from other protocol hashes.
const DOMAIN: &[u8] = b"VERITAS-SAFETY-NUMBER-v1";

/// A safety number derived from two identities' public keys.
///
/// Safety numbers allow users to verify they are communicating with the
/// correct party by comparing these values out-of-band. Both parties
/// compute the same safety number from their combined public keys.
///
/// # Construction
///
/// Safety numbers are computed by:
/// 1. Sorting both identities' public keys by their identity hash
/// 2. Hashing with BLAKE3 using domain separation
/// 3. Including all public key components in the hash
///
/// # Comparison Methods
///
/// - [`to_numeric_string`](SafetyNumber::to_numeric_string): For verbal comparison (60 digits)
/// - [`to_qr_string`](SafetyNumber::to_qr_string): For QR code scanning (64 hex chars)
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// The 32-byte safety number value.
    bytes: [u8; 32],
}

impl SafetyNumber {
    /// Compute a safety number from two identities' public keys.
    ///
    /// The computation is symmetric: swapping the arguments produces
    /// the same result. This ensures both parties compute identical
    /// safety numbers.
    ///
    /// # Arguments
    ///
    /// * `our_keys` - Our identity's public keys
    /// * `their_keys` - The other party's public keys
    ///
    /// # Returns
    ///
    /// A safety number that both parties can compare.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_core::SafetyNumber;
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let alice = IdentityKeyPair::generate();
    /// let bob = IdentityKeyPair::generate();
    ///
    /// let safety_number = SafetyNumber::compute(
    ///     alice.public_keys(),
    ///     bob.public_keys(),
    /// );
    ///
    /// println!("Verify: {}", safety_number);
    /// ```
    pub fn compute(our_keys: &IdentityPublicKeys, their_keys: &IdentityPublicKeys) -> Self {
        // Get identity hashes for sorting
        let our_hash = our_keys.identity_hash();
        let their_hash = their_keys.identity_hash();

        // Sort keys lexicographically by identity hash to ensure symmetric computation
        let (first_keys, second_keys) = match our_hash.as_bytes().cmp(their_hash.as_bytes()) {
            Ordering::Less | Ordering::Equal => (our_keys, their_keys),
            Ordering::Greater => (their_keys, our_keys),
        };

        // Build inputs for hashing
        // Include: domain, first exchange key, first signing key, second exchange key, second signing key
        let first_exchange = first_keys.exchange.as_bytes();
        let first_signing_bytes = first_keys.signing.as_ref().map(|k| k.as_bytes());
        let first_signing: &[u8] = first_signing_bytes.as_deref().unwrap_or(&[]);

        let second_exchange = second_keys.exchange.as_bytes();
        let second_signing_bytes = second_keys.signing.as_ref().map(|k| k.as_bytes());
        let second_signing: &[u8] = second_signing_bytes.as_deref().unwrap_or(&[]);

        // Hash all components with domain separation
        let hash = Hash256::hash_many(&[
            DOMAIN,
            first_exchange,
            first_signing,
            second_exchange,
            second_signing,
        ]);

        Self {
            bytes: hash.to_bytes(),
        }
    }

    /// Format the safety number as a 60-digit numeric string.
    ///
    /// The output is formatted as 12 groups of 5 digits, separated by spaces.
    /// This format is ideal for verbal comparison between users.
    ///
    /// # Format
    ///
    /// Each byte is converted to a 2-digit number using `byte % 100`.
    /// The first 30 bytes are used to produce 60 digits, grouped as:
    /// `"XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"`
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_core::SafetyNumber;
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let alice = IdentityKeyPair::generate();
    /// let bob = IdentityKeyPair::generate();
    ///
    /// let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
    /// let numeric = safety.to_numeric_string();
    ///
    /// // Format: "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
    /// assert_eq!(numeric.len(), 71); // 60 digits + 11 spaces
    /// ```
    pub fn to_numeric_string(&self) -> String {
        // Convert first 30 bytes to 60 digits (each byte -> 2 digits via byte % 100)
        // First, generate all 60 digits
        let mut all_digits = String::with_capacity(60);
        for &byte in self.bytes.iter().take(30) {
            let two_digits = byte % 100;
            all_digits.push_str(&format!("{:02}", two_digits));
        }

        // Now format into 12 groups of 5 digits separated by spaces
        let mut result = String::with_capacity(71); // 60 digits + 11 spaces
        for (i, chunk) in all_digits.as_bytes().chunks(5).enumerate() {
            if i > 0 {
                result.push(' ');
            }
            // Safety: we know all_digits contains only ASCII digits
            result.push_str(std::str::from_utf8(chunk).unwrap());
        }

        result
    }

    /// Format the safety number as a hex string for QR codes.
    ///
    /// Returns a 64-character lowercase hex string representing
    /// all 32 bytes. This format is ideal for QR code generation
    /// and automated verification.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_core::SafetyNumber;
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let alice = IdentityKeyPair::generate();
    /// let bob = IdentityKeyPair::generate();
    ///
    /// let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
    /// let qr_data = safety.to_qr_string();
    ///
    /// assert_eq!(qr_data.len(), 64);
    /// ```
    pub fn to_qr_string(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in &self.bytes {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    /// Get the raw bytes of the safety number.
    ///
    /// Returns a reference to the underlying 32-byte array.
    /// This is useful for storage or custom formatting.
    ///
    /// # Example
    ///
    /// ```
    /// use veritas_core::SafetyNumber;
    /// use veritas_identity::IdentityKeyPair;
    ///
    /// let alice = IdentityKeyPair::generate();
    /// let bob = IdentityKeyPair::generate();
    ///
    /// let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
    /// let bytes = safety.as_bytes();
    ///
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({}...)", &self.to_qr_string()[..16])
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_numeric_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_identity::IdentityKeyPair;

    #[test]
    fn test_safety_number_symmetric() {
        // Safety numbers should be identical regardless of computation order
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_computes = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let bob_computes = SafetyNumber::compute(bob.public_keys(), alice.public_keys());

        assert_eq!(alice_computes, bob_computes);
    }

    #[test]
    fn test_safety_number_deterministic() {
        // Same keys should always produce the same safety number
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let first = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let second = SafetyNumber::compute(alice.public_keys(), bob.public_keys());

        assert_eq!(first, second);
    }

    #[test]
    fn test_safety_number_different_for_different_keys() {
        // Different key pairs should produce different safety numbers
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let charlie = IdentityKeyPair::generate();

        let alice_bob = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let alice_charlie = SafetyNumber::compute(alice.public_keys(), charlie.public_keys());

        assert_ne!(alice_bob, alice_charlie);
    }

    #[test]
    fn test_safety_number_same_identity() {
        // Computing with the same identity should still work
        let alice = IdentityKeyPair::generate();

        let result = SafetyNumber::compute(alice.public_keys(), alice.public_keys());

        // Should produce a valid safety number
        assert!(!result.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_numeric_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let numeric = safety.to_numeric_string();

        // Should be 60 digits + 11 spaces = 71 characters
        assert_eq!(numeric.len(), 71);

        // Should have 11 spaces (between 12 groups)
        assert_eq!(numeric.chars().filter(|&c| c == ' ').count(), 11);

        // Each group should be 5 digits
        let groups: Vec<&str> = numeric.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for group in groups {
            assert_eq!(group.len(), 5);
            assert!(group.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_qr_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let qr = safety.to_qr_string();

        // Should be 64 hex characters
        assert_eq!(qr.len(), 64);

        // Should be valid lowercase hex
        assert!(qr
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn test_as_bytes() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let bytes = safety.as_bytes();

        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_display_uses_numeric_string() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let display = format!("{}", safety);
        let numeric = safety.to_numeric_string();

        assert_eq!(display, numeric);
    }

    #[test]
    fn test_debug_shows_truncated_hex() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let debug = format!("{:?}", safety);

        assert!(debug.starts_with("SafetyNumber("));
        assert!(debug.ends_with("...)"));
        assert!(debug.contains(&safety.to_qr_string()[..16]));
    }

    #[test]
    fn test_clone() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let cloned = safety.clone();

        assert_eq!(safety, cloned);
        assert_eq!(safety.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_numeric_digits_bounded() {
        // Each byte % 100 should produce values 00-99
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let numeric = safety.to_numeric_string();

        // Remove spaces and check each 2-digit group
        let digits_only: String = numeric.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits_only.len(), 60);

        for chunk in digits_only.as_bytes().chunks(2) {
            let value: u32 = std::str::from_utf8(chunk).unwrap().parse().unwrap();
            assert!(value < 100);
        }
    }

    #[test]
    fn test_qr_string_matches_bytes() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let qr = safety.to_qr_string();
        let bytes = safety.as_bytes();

        // Verify QR string correctly encodes the bytes
        for (i, byte) in bytes.iter().enumerate() {
            let hex_pair = &qr[i * 2..i * 2 + 2];
            let parsed = u8::from_str_radix(hex_pair, 16).unwrap();
            assert_eq!(*byte, parsed);
        }
    }
}
