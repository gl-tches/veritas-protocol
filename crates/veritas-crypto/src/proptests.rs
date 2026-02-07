//! Property-based tests for cryptographic primitives.
//!
//! These tests use proptest to verify cryptographic properties hold
//! for arbitrary inputs. They focus on:
//!
//! - Roundtrip properties (encrypt/decrypt, serialize/deserialize)
//! - Uniqueness properties (keys, nonces)
//! - Consistency properties (same input produces same output)
//! - Error handling properties (invalid inputs are rejected)

use proptest::prelude::*;

use crate::{
    EncryptedData, Hash256, KEY_SIZE, NONCE_SIZE, Nonce, SymmetricKey, X25519EphemeralKeyPair,
    X25519PublicKey, X25519StaticPrivateKey, decrypt, decrypt_with_aad, encrypt, encrypt_with_aad,
};

// ==================== Symmetric Encryption Property Tests ====================

proptest! {
    /// Encryption followed by decryption should return the original plaintext.
    #[test]
    fn encrypt_decrypt_roundtrip(plaintext: Vec<u8>) {
        let key = SymmetricKey::generate();
        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    /// Empty plaintext should encrypt and decrypt correctly.
    #[test]
    fn encrypt_decrypt_empty_data(_seed in any::<u64>()) {
        let key = SymmetricKey::generate();
        let plaintext = vec![];
        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    /// Different keys should produce different ciphertexts for the same plaintext.
    #[test]
    fn different_keys_different_ciphertext(plaintext in prop::collection::vec(any::<u8>(), 1..100)) {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();

        let encrypted1 = encrypt(&key1, &plaintext).unwrap();
        let encrypted2 = encrypt(&key2, &plaintext).unwrap();

        // Ciphertexts should differ (overwhelmingly likely with different keys)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    /// Decryption with wrong key should fail.
    #[test]
    fn decrypt_wrong_key_fails(plaintext in prop::collection::vec(any::<u8>(), 1..100)) {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();

        let encrypted = encrypt(&key1, &plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);

        prop_assert!(result.is_err());
    }

    /// Multiple encryptions of the same plaintext should produce different ciphertexts
    /// (due to random nonces).
    #[test]
    fn same_plaintext_different_ciphertext(plaintext in prop::collection::vec(any::<u8>(), 1..100)) {
        let key = SymmetricKey::generate();

        let encrypted1 = encrypt(&key, &plaintext).unwrap();
        let encrypted2 = encrypt(&key, &plaintext).unwrap();

        // Nonces should be different (random)
        prop_assert_ne!(encrypted1.nonce.as_bytes(), encrypted2.nonce.as_bytes());
        // Ciphertexts should be different (due to different nonces)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    /// EncryptedData serialization/deserialization roundtrip.
    #[test]
    fn encrypted_data_bytes_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..1000)) {
        let key = SymmetricKey::generate();
        let encrypted = encrypt(&key, &plaintext).unwrap();

        let bytes = encrypted.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        prop_assert_eq!(encrypted.nonce.as_bytes(), restored.nonce.as_bytes());
        prop_assert_eq!(&encrypted.ciphertext, &restored.ciphertext);

        // Should still decrypt correctly
        let decrypted = decrypt(&key, &restored).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    /// Encrypt with AAD roundtrip.
    #[test]
    fn encrypt_with_aad_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..500),
        aad in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let key = SymmetricKey::generate();
        let encrypted = encrypt_with_aad(&key, &plaintext, &aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &encrypted, &aad).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    /// Wrong AAD should fail decryption.
    #[test]
    fn wrong_aad_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
        aad1 in prop::collection::vec(any::<u8>(), 1..50),
        aad2 in prop::collection::vec(any::<u8>(), 1..50)
    ) {
        prop_assume!(aad1 != aad2);

        let key = SymmetricKey::generate();
        let encrypted = encrypt_with_aad(&key, &plaintext, &aad1).unwrap();
        let result = decrypt_with_aad(&key, &encrypted, &aad2);

        prop_assert!(result.is_err());
    }

    /// SymmetricKey from_bytes/as_bytes roundtrip.
    #[test]
    fn symmetric_key_bytes_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let key = SymmetricKey::from_bytes(&bytes).unwrap();
        prop_assert_eq!(key.as_bytes(), &bytes);
    }

    /// Invalid key length should fail.
    #[test]
    fn symmetric_key_invalid_length(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
        prop_assume!(bytes.len() != KEY_SIZE);

        let result = SymmetricKey::from_bytes(&bytes);
        prop_assert!(result.is_err());
    }

    /// Nonce from_bytes/as_bytes roundtrip.
    #[test]
    fn nonce_bytes_roundtrip(bytes in prop::collection::vec(any::<u8>(), NONCE_SIZE..=NONCE_SIZE)) {
        let nonce = Nonce::from_bytes(&bytes).unwrap();
        prop_assert_eq!(nonce.as_bytes().as_slice(), bytes.as_slice());
    }

    /// Invalid nonce length should fail.
    #[test]
    fn nonce_invalid_length(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
        prop_assume!(bytes.len() != NONCE_SIZE);

        let result = Nonce::from_bytes(&bytes);
        prop_assert!(result.is_err());
    }
}

// ==================== Hash Property Tests ====================

proptest! {
    /// Hashing the same input should always produce the same output.
    #[test]
    fn hash_deterministic(data: Vec<u8>) {
        let h1 = Hash256::hash(&data);
        let h2 = Hash256::hash(&data);
        prop_assert_eq!(h1, h2);
    }

    /// Different inputs should produce different hashes (with overwhelming probability).
    #[test]
    fn different_inputs_different_hashes(
        data1 in prop::collection::vec(any::<u8>(), 0..1000),
        data2 in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        prop_assume!(data1 != data2);

        let h1 = Hash256::hash(&data1);
        let h2 = Hash256::hash(&data2);

        prop_assert_ne!(h1, h2);
    }

    /// Hash output is always 32 bytes.
    #[test]
    fn hash_output_size(data: Vec<u8>) {
        let hash = Hash256::hash(&data);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }

    /// hash_many with length prefixing should prevent ambiguity.
    #[test]
    fn hash_many_prevents_ambiguity(
        a in prop::collection::vec(any::<u8>(), 1..50),
        b in prop::collection::vec(any::<u8>(), 1..50)
    ) {
        // Hash of [a, b] should differ from hash of [a || b]
        let h1 = Hash256::hash_many(&[&a, &b]);

        let mut combined = a.clone();
        combined.extend(&b);
        let h2 = Hash256::hash(&combined);

        prop_assert_ne!(h1, h2);
    }

    /// Hash hex roundtrip.
    #[test]
    fn hash_hex_roundtrip(data: Vec<u8>) {
        let hash = Hash256::hash(&data);
        let hex = hash.to_hex();
        let restored = Hash256::from_hex(&hex).unwrap();
        prop_assert_eq!(hash, restored);
    }

    /// Hash bytes roundtrip.
    #[test]
    fn hash_bytes_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash256::from_bytes(&bytes).unwrap();
        prop_assert_eq!(hash.to_bytes(), bytes);
        prop_assert_eq!(hash.as_bytes(), &bytes);
    }

    /// Keyed hash with different keys produces different outputs.
    #[test]
    fn keyed_hash_different_keys(
        data in prop::collection::vec(any::<u8>(), 1..100),
        key1 in prop::array::uniform32(any::<u8>()),
        key2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(key1 != key2);

        let h1 = Hash256::keyed_hash(&key1, &data);
        let h2 = Hash256::keyed_hash(&key2, &data);

        prop_assert_ne!(h1, h2);
    }

    /// Key derivation with different contexts produces different outputs.
    #[test]
    fn derive_key_different_contexts(data: Vec<u8>) {
        let hash = Hash256::hash(&data);

        let k1 = hash.derive_key("context1");
        let k2 = hash.derive_key("context2");

        prop_assert_ne!(k1, k2);
    }
}

// ==================== X25519 Key Exchange Property Tests ====================

proptest! {
    /// Key exchange produces the same shared secret for both parties.
    #[test]
    fn x25519_key_exchange_symmetric(_seed in any::<u64>()) {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        prop_assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    /// Different key pairs produce different shared secrets.
    #[test]
    fn different_peers_different_secrets(_seed in any::<u64>()) {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();
        let carol = X25519StaticPrivateKey::generate();

        let alice_bob = alice.diffie_hellman(&bob.public_key());
        let alice_carol = alice.diffie_hellman(&carol.public_key());

        prop_assert_ne!(alice_bob.as_bytes(), alice_carol.as_bytes());
    }

    /// Static private key bytes roundtrip.
    #[test]
    fn x25519_private_key_roundtrip(_seed in any::<u64>()) {
        let original = X25519StaticPrivateKey::generate();
        let bytes = original.as_bytes();
        let restored = X25519StaticPrivateKey::from_bytes(bytes).unwrap();

        // Same public key means same private key
        prop_assert_eq!(original.public_key(), restored.public_key());
    }

    /// Public key bytes roundtrip.
    #[test]
    fn x25519_public_key_roundtrip(_seed in any::<u64>()) {
        let private = X25519StaticPrivateKey::generate();
        let public = private.public_key();

        let bytes = public.to_bytes();
        let restored = X25519PublicKey::from_bytes(&bytes).unwrap();

        prop_assert_eq!(public, restored);
    }

    /// Ephemeral and static keys can exchange with each other.
    #[test]
    fn ephemeral_static_exchange(_seed in any::<u64>()) {
        let static_key = X25519StaticPrivateKey::generate();
        let static_public = static_key.public_key();

        let ephemeral = X25519EphemeralKeyPair::generate();
        let ephemeral_public = ephemeral.public_key().clone();

        let static_shared = static_key.diffie_hellman(&ephemeral_public);
        let ephemeral_shared = ephemeral.diffie_hellman(&static_public);

        prop_assert_eq!(static_shared.as_bytes(), ephemeral_shared.as_bytes());
    }

    /// Key derivation from shared secret produces consistent results.
    #[test]
    fn shared_secret_derive_deterministic(_seed in any::<u64>()) {
        let alice = X25519StaticPrivateKey::generate();
        let bob = X25519StaticPrivateKey::generate();

        let shared = alice.diffie_hellman(&bob.public_key());

        let k1 = shared.derive_key("test context");
        let k2 = shared.derive_key("test context");

        prop_assert_eq!(k1, k2);
    }
}

// ==================== Key Uniqueness Property Tests ====================

proptest! {
    /// Generated symmetric keys should be unique (with overwhelming probability).
    #[test]
    fn symmetric_keys_unique(_seed in any::<u64>()) {
        let k1 = SymmetricKey::generate();
        let k2 = SymmetricKey::generate();
        prop_assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// Generated nonces should be unique (with overwhelming probability).
    #[test]
    fn nonces_unique(_seed in any::<u64>()) {
        let n1 = Nonce::generate();
        let n2 = Nonce::generate();
        prop_assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    /// Generated X25519 keys should be unique.
    #[test]
    fn x25519_keys_unique(_seed in any::<u64>()) {
        let k1 = X25519StaticPrivateKey::generate();
        let k2 = X25519StaticPrivateKey::generate();
        prop_assert_ne!(k1.public_key(), k2.public_key());
    }
}

// ==================== Ciphertext Tamper Detection Tests ====================

proptest! {
    /// Tampering with any byte of the ciphertext should cause decryption to fail.
    #[test]
    fn tampered_ciphertext_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
        tamper_index in any::<usize>()
    ) {
        let key = SymmetricKey::generate();
        let mut encrypted = encrypt(&key, &plaintext).unwrap();

        // Only tamper if there are bytes to tamper with
        if !encrypted.ciphertext.is_empty() {
            let idx = tamper_index % encrypted.ciphertext.len();
            encrypted.ciphertext[idx] ^= 0xFF;

            let result = decrypt(&key, &encrypted);
            prop_assert!(result.is_err());
        }
    }
}
