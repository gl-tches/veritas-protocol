//! Username validation and registration system.
//!
//! Usernames are optional identifiers that can be linked to identity hashes.
//! The identity hash remains the primary identifier; usernames provide
//! human-readable aliases that can be shared out-of-band.
//!
//! ## Validation Rules
//!
//! - Length: 3-32 characters
//! - Allowed characters: alphanumeric (a-z, A-Z, 0-9), underscore (_), hyphen (-)
//! - Case-insensitive for lookup (stored as provided)

use serde::{Deserialize, Serialize};

use crate::{IdentityError, IdentityHash, Result};

/// Minimum username length in characters.
pub const MIN_USERNAME_LEN: usize = 3;

/// Maximum username length in characters.
pub const MAX_USERNAME_LEN: usize = 32;

/// Reserved usernames that cannot be registered.
///
/// SECURITY (VERITAS-2026-0090): These usernames are reserved to prevent
/// impersonation of system accounts, administrators, or official channels.
pub const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "system",
    "veritas",
    "support",
    "help",
    "root",
    "moderator",
    "mod",
    "official",
    "verified",
    "security",
    "bot",
    "null",
    "undefined",
    "anonymous",
];

/// A validated username (3-32 characters).
///
/// Usernames provide human-readable aliases for identity hashes.
/// They are optional and must be registered on-chain to be resolvable.
///
/// ## Validation Rules
///
/// - Length: 3-32 characters
/// - Allowed characters: alphanumeric (a-z, A-Z, 0-9), underscore (_), hyphen (-)
/// - Cannot start or end with hyphen or underscore
/// - Cannot have consecutive hyphens or underscores
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Username(String);

impl Username {
    /// Create a new validated username.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::InvalidUsername` if:
    /// - Length is less than 3 or more than 32 characters
    /// - Contains invalid characters (only alphanumeric, underscore, hyphen allowed)
    /// - Starts or ends with hyphen or underscore
    /// - Contains consecutive special characters
    ///
    /// # Examples
    ///
    /// ```
    /// use veritas_identity::Username;
    ///
    /// // Valid usernames
    /// let valid = Username::new("alice").unwrap();
    /// let valid2 = Username::new("bob_smith").unwrap();
    /// let valid3 = Username::new("user-123").unwrap();
    ///
    /// // Invalid usernames
    /// assert!(Username::new("ab").is_err()); // Too short
    /// assert!(Username::new("_alice").is_err()); // Starts with underscore
    /// assert!(Username::new("bob@smith").is_err()); // Invalid character
    /// ```
    pub fn new(username: &str) -> Result<Self> {
        Self::validate(username)?;
        Self::check_reserved(username)?;
        Ok(Self(username.to_string()))
    }

    /// Check if a username is reserved.
    ///
    /// SECURITY (VERITAS-2026-0090): Reserved usernames cannot be registered
    /// to prevent impersonation of system accounts.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::InvalidUsername` if the username is reserved.
    pub fn check_reserved(username: &str) -> Result<()> {
        let normalized = username.to_ascii_lowercase();
        if RESERVED_USERNAMES.contains(&normalized.as_str()) {
            return Err(IdentityError::InvalidUsername {
                reason: format!("'{}' is a reserved username", username),
            });
        }
        Ok(())
    }

    /// Check if a username string is reserved (without other validation).
    ///
    /// Returns `true` if the username is in the reserved list.
    pub fn is_reserved(username: &str) -> bool {
        let normalized = username.to_ascii_lowercase();
        RESERVED_USERNAMES.contains(&normalized.as_str())
    }

    /// Validate a username string without creating a Username instance.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::InvalidUsername` with a reason if validation fails.
    pub fn validate(username: &str) -> Result<()> {
        let len = username.len();

        // Check length
        if len < MIN_USERNAME_LEN {
            return Err(IdentityError::InvalidUsername {
                reason: format!(
                    "username too short: minimum {} characters, got {}",
                    MIN_USERNAME_LEN, len
                ),
            });
        }

        if len > MAX_USERNAME_LEN {
            return Err(IdentityError::InvalidUsername {
                reason: format!(
                    "username too long: maximum {} characters, got {}",
                    MAX_USERNAME_LEN, len
                ),
            });
        }

        // Check for valid characters
        let chars: Vec<char> = username.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return Err(IdentityError::InvalidUsername {
                    reason: format!(
                        "invalid character '{}' at position {}: only alphanumeric, underscore, and hyphen allowed",
                        c, i
                    ),
                });
            }
        }

        // Check first character (must be alphanumeric)
        if let Some(&first) = chars.first() {
            if !first.is_ascii_alphanumeric() {
                return Err(IdentityError::InvalidUsername {
                    reason: "username must start with an alphanumeric character".to_string(),
                });
            }
        }

        // Check last character (must be alphanumeric)
        if let Some(&last) = chars.last() {
            if !last.is_ascii_alphanumeric() {
                return Err(IdentityError::InvalidUsername {
                    reason: "username must end with an alphanumeric character".to_string(),
                });
            }
        }

        // Check for consecutive special characters
        let mut prev_special = false;
        for c in &chars {
            let is_special = *c == '_' || *c == '-';
            if is_special && prev_special {
                return Err(IdentityError::InvalidUsername {
                    reason: "username cannot contain consecutive special characters".to_string(),
                });
            }
            prev_special = is_special;
        }

        Ok(())
    }

    /// Get the username as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get a normalized (lowercase) version for comparison.
    ///
    /// Usernames are case-insensitive for lookup purposes.
    pub fn normalized(&self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// Check if two usernames are equal (case-insensitive).
    pub fn eq_ignore_case(&self, other: &Username) -> bool {
        self.normalized() == other.normalized()
    }
}

impl std::fmt::Debug for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Username(\"{}\")", self.0)
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Registration linking a username to an identity.
///
/// A registration proves that the owner of an identity hash has claimed
/// a particular username. The registration is signed by the identity's
/// private key to prevent impersonation.
///
/// ## Verification
///
/// To verify a registration:
/// 1. Check the signature against the identity's public key
/// 2. Verify the timestamp is within acceptable bounds
/// 3. Check that no newer registration exists for the same username
#[derive(Clone, Serialize, Deserialize)]
pub struct UsernameRegistration {
    /// The username being registered.
    pub username: Username,
    /// The identity hash claiming this username.
    pub identity_hash: IdentityHash,
    /// Unix timestamp (seconds) when the registration was created.
    pub registered_at: u64,
    /// Signature over the registration data.
    ///
    /// Signs: username || identity_hash || registered_at
    pub signature: Vec<u8>,
}

impl UsernameRegistration {
    /// Create a new username registration.
    ///
    /// The caller is responsible for generating the signature using the
    /// identity's private signing key. Use `signing_payload()` to get
    /// the bytes that should be signed.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to register
    /// * `identity_hash` - The identity claiming this username
    /// * `registered_at` - Unix timestamp of registration
    /// * `signature` - Signature over the signing payload
    /// IDENT-FIX-8: Returns an error if signature is empty, since an unsigned
    /// registration should never be created.
    pub fn new(
        username: Username,
        identity_hash: IdentityHash,
        registered_at: u64,
        signature: Vec<u8>,
    ) -> Result<Self> {
        // IDENT-FIX-8: Validate signature is not empty
        if signature.is_empty() {
            return Err(IdentityError::InvalidUsername {
                reason: "registration signature must not be empty".to_string(),
            });
        }
        Ok(Self {
            username,
            identity_hash,
            registered_at,
            signature,
        })
    }

    /// Get the bytes that should be signed for this registration.
    ///
    /// The signing payload is: `username || identity_hash || registered_at`
    /// with length prefixes for domain separation.
    pub fn signing_payload(&self) -> Vec<u8> {
        Self::compute_signing_payload(&self.username, &self.identity_hash, self.registered_at)
    }

    /// Compute the signing payload for given registration parameters.
    ///
    /// This can be used to create the signature before constructing
    /// the full registration.
    pub fn compute_signing_payload(
        username: &Username,
        identity_hash: &IdentityHash,
        registered_at: u64,
    ) -> Vec<u8> {
        let username_bytes = username.as_str().as_bytes();
        let identity_bytes = identity_hash.as_bytes();
        let timestamp_bytes = registered_at.to_be_bytes();

        // Domain-separated concatenation with length prefixes
        let mut payload = Vec::with_capacity(
            8 + username_bytes.len() + 8 + identity_bytes.len() + 8 + timestamp_bytes.len(),
        );

        // Length-prefix each component
        payload.extend_from_slice(&(username_bytes.len() as u64).to_le_bytes());
        payload.extend_from_slice(username_bytes);
        payload.extend_from_slice(&(identity_bytes.len() as u64).to_le_bytes());
        payload.extend_from_slice(identity_bytes);
        payload.extend_from_slice(&(timestamp_bytes.len() as u64).to_le_bytes());
        payload.extend_from_slice(&timestamp_bytes);

        payload
    }

    /// Verify the registration signature.
    ///
    /// This method verifies that the signature was created by the holder
    /// of the private key corresponding to the registered identity.
    ///
    /// # Arguments
    ///
    /// * `verify_fn` - A closure that takes (message, signature) and returns
    ///   true if the signature is valid for the identity's public key
    ///
    /// # Returns
    ///
    /// `Ok(())` if signature verification succeeds, `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With ML-DSA verification
    /// registration.verify(|message, signature| {
    ///     public_key.verify(message, signature).is_ok()
    /// })?;
    /// ```
    pub fn verify<F>(&self, verify_fn: F) -> Result<()>
    where
        F: FnOnce(&[u8], &[u8]) -> bool,
    {
        let payload = self.signing_payload();
        if verify_fn(&payload, &self.signature) {
            Ok(())
        } else {
            Err(IdentityError::InvalidUsername {
                reason: "signature verification failed".to_string(),
            })
        }
    }

    /// Check if this registration has expired.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp in seconds
    /// * `max_age_secs` - Maximum age of registration in seconds
    pub fn is_expired(&self, current_time: u64, max_age_secs: u64) -> bool {
        current_time.saturating_sub(self.registered_at) > max_age_secs
    }
}

impl std::fmt::Debug for UsernameRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernameRegistration")
            .field("username", &self.username)
            .field("identity_hash", &self.identity_hash)
            .field("registered_at", &self.registered_at)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_crypto::Hash256;

    // ==================== Username Tests ====================

    #[test]
    fn test_valid_usernames() {
        // Simple alphanumeric
        assert!(Username::new("alice").is_ok());
        assert!(Username::new("Bob").is_ok());
        assert!(Username::new("user123").is_ok());

        // With underscores
        assert!(Username::new("alice_bob").is_ok());
        assert!(Username::new("user_name_123").is_ok());

        // With hyphens
        assert!(Username::new("alice-bob").is_ok());
        assert!(Username::new("user-name-123").is_ok());

        // Mixed
        assert!(Username::new("alice_bob-123").is_ok());
        assert!(Username::new("a1b2c3").is_ok());

        // Minimum length (3)
        assert!(Username::new("abc").is_ok());

        // Maximum length (32)
        assert!(Username::new("a".repeat(32).as_str()).is_ok());
    }

    #[test]
    fn test_username_too_short() {
        assert!(Username::new("").is_err());
        assert!(Username::new("a").is_err());
        assert!(Username::new("ab").is_err());

        let err = Username::new("ab").unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("too short"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_too_long() {
        let long_name = "a".repeat(33);
        assert!(Username::new(&long_name).is_err());

        let err = Username::new(&long_name).unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("too long"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_invalid_characters() {
        // Spaces
        assert!(Username::new("alice bob").is_err());

        // Special characters
        assert!(Username::new("alice@bob").is_err());
        assert!(Username::new("alice#123").is_err());
        assert!(Username::new("alice.bob").is_err());
        assert!(Username::new("alice!").is_err());

        // Unicode
        assert!(Username::new("alice\u{00e9}").is_err()); // é

        let err = Username::new("alice@bob").unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("invalid character"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_invalid_start() {
        assert!(Username::new("_alice").is_err());
        assert!(Username::new("-alice").is_err());

        let err = Username::new("_alice").unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("must start with"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_invalid_end() {
        assert!(Username::new("alice_").is_err());
        assert!(Username::new("alice-").is_err());

        let err = Username::new("alice_").unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("must end with"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_consecutive_special() {
        assert!(Username::new("alice__bob").is_err());
        assert!(Username::new("alice--bob").is_err());
        assert!(Username::new("alice_-bob").is_err());
        assert!(Username::new("alice-_bob").is_err());

        let err = Username::new("alice__bob").unwrap_err();
        match err {
            IdentityError::InvalidUsername { reason } => {
                assert!(reason.contains("consecutive"));
            }
            _ => panic!("Expected InvalidUsername error"),
        }
    }

    #[test]
    fn test_username_display() {
        let username = Username::new("alice").unwrap();
        assert_eq!(format!("{}", username), "alice");
    }

    #[test]
    fn test_username_normalized() {
        let username = Username::new("Alice_Bob").unwrap();
        assert_eq!(username.normalized(), "alice_bob");
    }

    #[test]
    fn test_username_case_insensitive_comparison() {
        let u1 = Username::new("Alice").unwrap();
        let u2 = Username::new("alice").unwrap();
        let u3 = Username::new("ALICE").unwrap();

        assert!(u1.eq_ignore_case(&u2));
        assert!(u2.eq_ignore_case(&u3));
        assert!(u1.eq_ignore_case(&u3));

        // Regular equality is case-sensitive
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_username_serialization() {
        let username = Username::new("alice").unwrap();
        let serialized = bincode::serialize(&username).unwrap();
        let deserialized: Username = bincode::deserialize(&serialized).unwrap();
        assert_eq!(username, deserialized);
    }

    // ==================== IdentityHash Tests ====================

    #[test]
    fn test_identity_hash_from_bytes() {
        let bytes = [42u8; 32];
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_identity_hash_from_bytes_invalid_length() {
        let bytes = [0u8; 16];
        assert!(IdentityHash::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_identity_hash_hex_roundtrip() {
        let bytes = [0xab; 32];
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        let hex = hash.to_hex();
        let recovered = IdentityHash::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_identity_hash_display() {
        let bytes = [0u8; 32];
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        let display = format!("{}", hash);
        assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_identity_hash_serialization() {
        let bytes = [123u8; 32];
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        let serialized = bincode::serialize(&hash).unwrap();
        let deserialized: IdentityHash = bincode::deserialize(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }

    // ==================== UsernameRegistration Tests ====================

    #[test]
    fn test_registration_creation() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;
        let signature = vec![0u8; 64];

        let reg =
            UsernameRegistration::new(username.clone(), identity.clone(), timestamp, signature).unwrap();

        assert_eq!(reg.username, username);
        assert_eq!(reg.identity_hash, identity);
        assert_eq!(reg.registered_at, timestamp);
    }

    #[test]
    fn test_registration_signing_payload() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;

        let payload1 =
            UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);

        let reg = UsernameRegistration::new(username, identity, timestamp, vec![0u8; 1]).unwrap();
        let payload2 = reg.signing_payload();

        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_registration_signing_payload_deterministic() {
        let username = Username::new("bob").unwrap();
        let identity = IdentityHash::from_bytes(&[2u8; 32]).unwrap();
        let timestamp = 1700000000u64;

        let payload1 =
            UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);
        let payload2 =
            UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);

        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_registration_signing_payload_different_inputs() {
        let username1 = Username::new("alice").unwrap();
        let username2 = Username::new("bob").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;

        let payload1 =
            UsernameRegistration::compute_signing_payload(&username1, &identity, timestamp);
        let payload2 =
            UsernameRegistration::compute_signing_payload(&username2, &identity, timestamp);

        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_registration_verify_success() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;

        // Create a mock signature (in real use, this would be a proper signature)
        let payload =
            UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);
        let mock_signature = Hash256::hash(&payload).to_bytes().to_vec();

        let reg = UsernameRegistration::new(username, identity, timestamp, mock_signature.clone()).unwrap();

        // Verify with a mock verifier that checks hash matches
        let result = reg.verify(|message, signature| {
            let expected = Hash256::hash(message).to_bytes();
            signature == expected
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_registration_verify_failure() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;
        let bad_signature = vec![0u8; 64];

        let reg = UsernameRegistration::new(username, identity, timestamp, bad_signature).unwrap();

        // Verify with a mock verifier that always fails
        let result = reg.verify(|_, _| false);

        assert!(result.is_err());
    }

    #[test]
    fn test_registration_expiry() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let registered_at = 1000u64;
        let signature = vec![0u8; 1];

        let reg = UsernameRegistration::new(username, identity, registered_at, signature).unwrap();

        // 30 day expiry
        let max_age = 30 * 24 * 60 * 60;

        // Just registered - not expired
        assert!(!reg.is_expired(1000, max_age));

        // Within expiry window
        assert!(!reg.is_expired(1000 + max_age - 1, max_age));

        // At expiry boundary
        assert!(!reg.is_expired(1000 + max_age, max_age));

        // Past expiry
        assert!(reg.is_expired(1000 + max_age + 1, max_age));
    }

    #[test]
    fn test_registration_serialization() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;
        let signature = vec![1, 2, 3, 4, 5];

        let reg = UsernameRegistration::new(username, identity, timestamp, signature).unwrap();

        let serialized = bincode::serialize(&reg).unwrap();
        let deserialized: UsernameRegistration = bincode::deserialize(&serialized).unwrap();

        assert_eq!(reg.username, deserialized.username);
        assert_eq!(reg.identity_hash, deserialized.identity_hash);
        assert_eq!(reg.registered_at, deserialized.registered_at);
        assert_eq!(reg.signature, deserialized.signature);
    }

    #[test]
    fn test_registration_debug() {
        let username = Username::new("alice").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let timestamp = 1700000000u64;
        let signature = vec![0u8; 64];

        let reg = UsernameRegistration::new(username, identity, timestamp, signature).unwrap();
        let debug = format!("{:?}", reg);

        assert!(debug.contains("UsernameRegistration"));
        assert!(debug.contains("alice"));
        assert!(debug.contains("64 bytes"));
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_valid_alphanumeric_usernames(s in "[a-zA-Z][a-zA-Z0-9]{2,30}[a-zA-Z0-9]") {
            // Pure alphanumeric usernames of valid length should always be valid
            prop_assert!(Username::new(&s).is_ok());
        }

        #[test]
        fn prop_username_normalized_is_lowercase(s in "[a-zA-Z][a-zA-Z0-9]{2,10}") {
            let result = Username::new(&s);
            prop_assume!(result.is_ok()); // Skip reserved usernames
            let username = result.unwrap();
            let normalized = username.normalized();
            let expected = normalized.to_ascii_lowercase();
            prop_assert_eq!(normalized, expected);
        }

        #[test]
        fn prop_username_roundtrip_serialization(s in "[a-zA-Z][a-zA-Z0-9]{2,10}") {
            let result = Username::new(&s);
            prop_assume!(result.is_ok()); // Skip reserved usernames
            let username = result.unwrap();
            let serialized = bincode::serialize(&username).unwrap();
            let deserialized: Username = bincode::deserialize(&serialized).unwrap();
            prop_assert_eq!(username, deserialized);
        }

        #[test]
        fn prop_identity_hash_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let hash = IdentityHash::from_bytes(&bytes).unwrap();
            prop_assert_eq!(hash.as_bytes(), &bytes);
        }

        #[test]
        fn prop_identity_hash_hex_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let hash = IdentityHash::from_bytes(&bytes).unwrap();
            let hex = hash.to_hex();
            let recovered = IdentityHash::from_hex(&hex).unwrap();
            prop_assert_eq!(hash, recovered);
        }

        #[test]
        fn prop_signing_payload_deterministic(
            username_str in "[a-zA-Z][a-zA-Z0-9]{2,10}",
            identity_bytes in prop::array::uniform32(any::<u8>()),
            timestamp in any::<u64>()
        ) {
            let result = Username::new(&username_str);
            prop_assume!(result.is_ok()); // Skip reserved usernames
            let username = result.unwrap();
            let identity = IdentityHash::from_bytes(&identity_bytes).unwrap();

            let payload1 = UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);
            let payload2 = UsernameRegistration::compute_signing_payload(&username, &identity, timestamp);

            prop_assert_eq!(payload1, payload2);
        }
    }
}
