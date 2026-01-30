//! Property-based tests for identity components.
//!
//! These tests verify identity system invariants:
//!
//! - Username validation accepts/rejects correctly
//! - Identity hashes are unique and deterministic
//! - Key generation produces unique identities
//! - Serialization roundtrips work correctly

use proptest::prelude::*;

use crate::{IdentityHash, IdentityKeyPair, Username, MAX_USERNAME_LEN, MIN_USERNAME_LEN};
use veritas_crypto::SymmetricKey;

// ==================== Username Validation Property Tests ====================

proptest! {
    /// Pure alphanumeric usernames of valid length should always be accepted.
    #[test]
    fn valid_alphanumeric_usernames(
        s in "[a-zA-Z][a-zA-Z0-9]{2,30}[a-zA-Z0-9]"
    ) {
        let result = Username::new(&s);
        prop_assert!(result.is_ok());
    }

    /// Usernames with underscores in valid positions should be accepted.
    #[test]
    fn valid_usernames_with_underscore(
        prefix in "[a-zA-Z][a-zA-Z0-9]{0,10}",
        suffix in "[a-zA-Z0-9]{1,10}"
    ) {
        let username = format!("{}_{}", prefix, suffix);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_ok());
        }
    }

    /// Usernames with hyphens in valid positions should be accepted.
    #[test]
    fn valid_usernames_with_hyphen(
        prefix in "[a-zA-Z][a-zA-Z0-9]{0,10}",
        suffix in "[a-zA-Z0-9]{1,10}"
    ) {
        let username = format!("{}-{}", prefix, suffix);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_ok());
        }
    }

    /// Usernames too short should be rejected.
    #[test]
    fn short_usernames_rejected(len in 0usize..MIN_USERNAME_LEN) {
        let username: String = (0..len).map(|_| 'a').collect();
        let result = Username::new(&username);
        prop_assert!(result.is_err());
    }

    /// Usernames too long should be rejected.
    #[test]
    fn long_usernames_rejected(extra in 1usize..100) {
        let len = MAX_USERNAME_LEN + extra;
        let username: String = (0..len).map(|_| 'a').collect();
        let result = Username::new(&username);
        prop_assert!(result.is_err());
    }

    /// Usernames with invalid characters should be rejected.
    #[test]
    fn invalid_chars_rejected(
        prefix in "[a-zA-Z]{3,10}",
        invalid_char in prop::char::range('!', '/')  // Special characters before '0'
    ) {
        // Skip hyphen which is valid
        prop_assume!(invalid_char != '-');

        let username = format!("{}{}", prefix, invalid_char);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_err());
        }
    }

    /// Usernames starting with special character should be rejected.
    #[test]
    fn start_with_special_rejected(suffix in "[a-zA-Z0-9]{2,10}") {
        let username = format!("_{}", suffix);
        let result = Username::new(&username);
        prop_assert!(result.is_err());

        let username = format!("-{}", suffix);
        let result = Username::new(&username);
        prop_assert!(result.is_err());
    }

    /// Usernames ending with special character should be rejected.
    #[test]
    fn end_with_special_rejected(prefix in "[a-zA-Z][a-zA-Z0-9]{1,10}") {
        let username = format!("{}_", prefix);
        let result = Username::new(&username);
        prop_assert!(result.is_err());

        let username = format!("{}-", prefix);
        let result = Username::new(&username);
        prop_assert!(result.is_err());
    }

    /// Usernames with consecutive special characters should be rejected.
    #[test]
    fn consecutive_special_rejected(
        prefix in "[a-zA-Z][a-zA-Z0-9]{0,5}",
        suffix in "[a-zA-Z0-9]{1,5}"
    ) {
        let username = format!("{}__{}", prefix, suffix);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_err());
        }

        let username = format!("{}--{}", prefix, suffix);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_err());
        }

        let username = format!("{}-_{}", prefix, suffix);
        if username.len() >= MIN_USERNAME_LEN && username.len() <= MAX_USERNAME_LEN {
            let result = Username::new(&username);
            prop_assert!(result.is_err());
        }
    }

    /// Username normalization produces lowercase.
    #[test]
    fn normalized_is_lowercase(s in "[a-zA-Z][a-zA-Z0-9]{2,10}") {
        let username = Username::new(&s).unwrap();
        let normalized = username.normalized();
        let lowercase = normalized.to_ascii_lowercase();
        prop_assert_eq!(normalized, lowercase);
    }

    /// Case-insensitive comparison works.
    #[test]
    fn case_insensitive_comparison(s in "[a-zA-Z][a-zA-Z0-9]{2,10}") {
        let lower = Username::new(&s.to_lowercase()).unwrap();
        let upper = Username::new(&s.to_uppercase()).unwrap();
        prop_assert!(lower.eq_ignore_case(&upper));
    }

    /// Username serialization roundtrip.
    #[test]
    fn username_serialization_roundtrip(s in "[a-zA-Z][a-zA-Z0-9]{2,10}") {
        let username = Username::new(&s).unwrap();
        let bytes = bincode::serialize(&username).unwrap();
        let restored: Username = bincode::deserialize(&bytes).unwrap();
        prop_assert_eq!(username, restored);
    }
}

// ==================== Identity Hash Property Tests ====================

proptest! {
    /// Hashing public key always produces 32-byte hash.
    #[test]
    fn identity_hash_size(key_bytes: Vec<u8>) {
        let hash = IdentityHash::from_public_key(&key_bytes);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }

    /// Same public key always produces same identity hash.
    #[test]
    fn identity_hash_deterministic(key_bytes: Vec<u8>) {
        let hash1 = IdentityHash::from_public_key(&key_bytes);
        let hash2 = IdentityHash::from_public_key(&key_bytes);
        prop_assert_eq!(hash1, hash2);
    }

    /// Different public keys produce different identity hashes.
    #[test]
    fn different_keys_different_hashes(
        key1 in prop::collection::vec(any::<u8>(), 0..100),
        key2 in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        prop_assume!(key1 != key2);

        let hash1 = IdentityHash::from_public_key(&key1);
        let hash2 = IdentityHash::from_public_key(&key2);

        prop_assert_ne!(hash1, hash2);
    }

    /// Hex roundtrip works.
    #[test]
    fn identity_hash_hex_roundtrip(key_bytes: Vec<u8>) {
        let hash = IdentityHash::from_public_key(&key_bytes);
        let hex = hash.to_hex();
        let restored = IdentityHash::from_hex(&hex).unwrap();
        prop_assert_eq!(hash, restored);
    }

    /// Bytes roundtrip works.
    #[test]
    fn identity_hash_bytes_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = IdentityHash::from_bytes(&bytes).unwrap();
        let restored = IdentityHash::from_bytes(hash.as_bytes()).unwrap();
        prop_assert_eq!(hash, restored);
    }

    /// Hex string is correct length.
    #[test]
    fn identity_hash_hex_length(key_bytes: Vec<u8>) {
        let hash = IdentityHash::from_public_key(&key_bytes);
        let hex = hash.to_hex();
        prop_assert_eq!(hex.len(), 64);  // 32 bytes = 64 hex chars
    }

    /// Short format is correct length.
    #[test]
    fn identity_hash_short_format(key_bytes: Vec<u8>) {
        let hash = IdentityHash::from_public_key(&key_bytes);
        let short = hash.short();
        prop_assert_eq!(short.len(), 19);  // 16 hex chars + "..."
        prop_assert!(short.ends_with("..."));
    }

    /// Invalid byte lengths for from_bytes should fail.
    #[test]
    fn identity_hash_invalid_length(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
        prop_assume!(bytes.len() != 32);

        let result = IdentityHash::from_bytes(&bytes);
        prop_assert!(result.is_err());
    }

    /// Invalid hex strings should fail.
    #[test]
    fn identity_hash_invalid_hex(s in "[^0-9a-fA-F]{1,64}") {
        // String with non-hex characters
        let result = IdentityHash::from_hex(&s);
        prop_assert!(result.is_err());
    }

    /// Constant-time equality matches regular equality.
    #[test]
    fn ct_eq_matches_eq(
        key1 in prop::collection::vec(any::<u8>(), 0..50),
        key2 in prop::collection::vec(any::<u8>(), 0..50)
    ) {
        let hash1 = IdentityHash::from_public_key(&key1);
        let hash2 = IdentityHash::from_public_key(&key2);

        prop_assert_eq!(hash1.ct_eq(&hash2), hash1 == hash2);
    }
}

// ==================== Identity KeyPair Property Tests ====================

proptest! {
    /// Generated identities have unique hashes.
    #[test]
    fn generated_identities_unique(_seed in any::<u64>()) {
        let id1 = IdentityKeyPair::generate();
        let id2 = IdentityKeyPair::generate();
        prop_assert_ne!(id1.identity_hash(), id2.identity_hash());
    }

    /// Identity hash derived from keypair matches hash from public keys.
    #[test]
    fn identity_hash_consistency(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let hash_from_keypair = identity.identity_hash();
        let hash_from_public = identity.public_keys().identity_hash();
        prop_assert_eq!(hash_from_keypair, &hash_from_public);
    }

    /// Key exchange produces symmetric shared secret.
    #[test]
    fn key_exchange_symmetric(_seed in any::<u64>()) {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_secret = alice.key_exchange(&bob.public_keys().exchange);
        let bob_secret = bob.key_exchange(&alice.public_keys().exchange);

        prop_assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    /// Encryption key derivation is symmetric.
    #[test]
    fn encryption_key_symmetric(_seed in any::<u64>()) {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_key = alice.derive_encryption_key(&bob.public_keys().exchange);
        let bob_key = bob.derive_encryption_key(&alice.public_keys().exchange);

        prop_assert_eq!(alice_key, bob_key);
    }

    /// Encrypted serialization roundtrip.
    #[test]
    fn encrypted_serialization_roundtrip(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();
        let restored = IdentityKeyPair::from_encrypted(&encrypted, &storage_key).unwrap();

        prop_assert_eq!(identity.identity_hash(), restored.identity_hash());
        prop_assert_eq!(
            identity.public_keys().exchange.to_bytes(),
            restored.public_keys().exchange.to_bytes()
        );
    }

    /// Encrypted serialization fails with wrong key.
    #[test]
    fn encrypted_serialization_wrong_key(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let correct_key = SymmetricKey::generate();
        let wrong_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&correct_key).unwrap();
        let result = IdentityKeyPair::from_encrypted(&encrypted, &wrong_key);

        prop_assert!(result.is_err());
    }

    /// Cloned identity has same hash and works identically.
    #[test]
    fn cloned_identity_works(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let cloned = identity.clone();
        let peer = IdentityKeyPair::generate();

        // Same identity hash
        prop_assert_eq!(identity.identity_hash(), cloned.identity_hash());

        // Same key exchange results
        let original_secret = identity.key_exchange(&peer.public_keys().exchange);
        let cloned_secret = cloned.key_exchange(&peer.public_keys().exchange);
        prop_assert_eq!(original_secret.as_bytes(), cloned_secret.as_bytes());
    }

    /// Different peers produce different shared secrets.
    #[test]
    fn different_peers_different_secrets(_seed in any::<u64>()) {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let carol = IdentityKeyPair::generate();

        let alice_bob = alice.key_exchange(&bob.public_keys().exchange);
        let alice_carol = alice.key_exchange(&carol.public_keys().exchange);

        prop_assert_ne!(alice_bob.as_bytes(), alice_carol.as_bytes());
    }

    /// Public keys serialization roundtrip.
    #[test]
    fn public_keys_serialization_roundtrip(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let public_keys = identity.public_keys();

        let bytes = public_keys.to_bytes();
        let restored = crate::IdentityPublicKeys::from_bytes(&bytes).unwrap();

        prop_assert_eq!(public_keys.exchange.to_bytes(), restored.exchange.to_bytes());
        prop_assert_eq!(public_keys.identity_hash(), restored.identity_hash());
    }

    /// Encrypted keypair can get identity hash without decrypting.
    #[test]
    fn encrypted_identity_hash_no_decrypt(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();

        // Can get identity hash without decrypting
        let hash = encrypted.identity_hash();
        prop_assert_eq!(identity.identity_hash(), &hash);
    }

    /// Encrypted keypair bytes roundtrip.
    #[test]
    fn encrypted_keypair_bytes_roundtrip(_seed in any::<u64>()) {
        let identity = IdentityKeyPair::generate();
        let storage_key = SymmetricKey::generate();

        let encrypted = identity.to_encrypted(&storage_key).unwrap();
        let bytes = encrypted.to_bytes();
        let restored_encrypted = crate::EncryptedIdentityKeyPair::from_bytes(&bytes).unwrap();

        // Can decrypt the restored version
        let restored = IdentityKeyPair::from_encrypted(&restored_encrypted, &storage_key).unwrap();
        prop_assert_eq!(identity.identity_hash(), restored.identity_hash());
    }
}

// ==================== Username Registration Property Tests ====================

proptest! {
    /// Signing payload is deterministic.
    #[test]
    fn signing_payload_deterministic(
        username_str in "[a-zA-Z][a-zA-Z0-9]{2,10}",
        identity_bytes in prop::array::uniform32(any::<u8>()),
        timestamp in any::<u64>()
    ) {
        let username = Username::new(&username_str).unwrap();
        let identity = IdentityHash::from_bytes(&identity_bytes).unwrap();

        let payload1 = crate::UsernameRegistration::compute_signing_payload(
            &username, &identity, timestamp
        );
        let payload2 = crate::UsernameRegistration::compute_signing_payload(
            &username, &identity, timestamp
        );

        prop_assert_eq!(payload1, payload2);
    }

    /// Different inputs produce different signing payloads.
    #[test]
    fn signing_payload_uniqueness(
        username_str in "[a-zA-Z][a-zA-Z0-9]{2,10}",
        identity_bytes in prop::array::uniform32(any::<u8>()),
        timestamp1 in any::<u64>(),
        timestamp2 in any::<u64>()
    ) {
        prop_assume!(timestamp1 != timestamp2);

        let username = Username::new(&username_str).unwrap();
        let identity = IdentityHash::from_bytes(&identity_bytes).unwrap();

        let payload1 = crate::UsernameRegistration::compute_signing_payload(
            &username, &identity, timestamp1
        );
        let payload2 = crate::UsernameRegistration::compute_signing_payload(
            &username, &identity, timestamp2
        );

        prop_assert_ne!(payload1, payload2);
    }

    /// Registration expiry calculation.
    #[test]
    fn registration_expiry(
        registered_at in any::<u64>(),
        max_age in 1u64..1_000_000,
        offset in 0u64..2_000_000
    ) {
        let username = Username::new("testuser").unwrap();
        let identity = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        let reg = crate::UsernameRegistration::new(
            username,
            identity,
            registered_at,
            vec![]
        );

        let current_time = registered_at.saturating_add(offset);
        let expected_expired = offset > max_age;

        prop_assert_eq!(reg.is_expired(current_time, max_age), expected_expired);
    }
}
