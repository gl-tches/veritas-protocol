//! Group key management.
//!
//! Provides group key generation, encryption for members, and message encryption.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use veritas_crypto::{EncryptedData, Hash256, SymmetricKey, decrypt, encrypt};
use veritas_identity::{IdentityHash, IdentityKeyPair, IdentityPublicKeys};

use crate::error::{ProtocolError, Result};
use crate::groups::metadata::GroupId;

/// Domain separation context for group key derivation.
const GROUP_KEY_CONTEXT: &str = "VERITAS group key v1";

/// Domain separation context for group message encryption.
const GROUP_MESSAGE_CONTEXT: &str = "VERITAS group message v1";

/// A symmetric key for group encryption.
///
/// The key is automatically zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GroupKey {
    /// The underlying symmetric key.
    key: SymmetricKey,
    /// Key generation number for tracking rotation.
    #[zeroize(skip)]
    generation: u32,
}

impl GroupKey {
    /// Generate a new random group key.
    ///
    /// # Arguments
    ///
    /// * `generation` - The key generation number (starts at 0, increments on rotation)
    pub fn generate(generation: u32) -> Self {
        Self {
            key: SymmetricKey::generate(),
            generation,
        }
    }

    /// Create a group key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte key material
    /// * `generation` - The key generation number
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8], generation: u32) -> Result<Self> {
        let key = SymmetricKey::from_bytes(bytes)?;
        Ok(Self { key, generation })
    }

    /// Get the underlying symmetric key.
    pub fn symmetric_key(&self) -> &SymmetricKey {
        &self.key
    }

    /// Get the raw key bytes.
    ///
    /// # Security
    ///
    /// Handle with care - this exposes the raw key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }

    /// Get the key generation number.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Compute a hash of this key for verification.
    ///
    /// Used to verify key integrity without exposing the key.
    pub fn hash(&self) -> Hash256 {
        Hash256::hash_many(&[GROUP_KEY_CONTEXT.as_bytes(), self.key.as_bytes()])
    }
}

impl std::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupKey(gen={}, [REDACTED])", self.generation)
    }
}

/// A group key encrypted for a specific member.
///
/// Each member receives their own encrypted copy of the group key.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedGroupKey {
    /// The member this key is encrypted for.
    pub member_id: IdentityHash,
    /// The key generation number.
    pub generation: u32,
    /// The encrypted key data.
    pub encrypted_key: EncryptedData,
}

impl std::fmt::Debug for EncryptedGroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedGroupKey")
            .field("member_id", &self.member_id)
            .field("generation", &self.generation)
            .field(
                "encrypted_key",
                &format!("[{} bytes]", self.encrypted_key.len()),
            )
            .finish()
    }
}

/// Manager for group key operations.
///
/// Stateless utility for encrypting and decrypting group keys.
pub struct GroupKeyManager;

impl GroupKeyManager {
    /// Encrypt a group key for multiple members.
    ///
    /// For each member, derives an encryption key via ECDH between the
    /// sender and member, then encrypts the group key.
    ///
    /// # Arguments
    ///
    /// * `group_key` - The group key to encrypt
    /// * `sender` - The identity encrypting the key (usually an admin)
    /// * `members` - List of (identity hash, public keys) for each member
    ///
    /// # Returns
    ///
    /// A list of encrypted keys, one per member.
    pub fn encrypt_for_members(
        group_key: &GroupKey,
        sender: &IdentityKeyPair,
        members: &[(IdentityHash, IdentityPublicKeys)],
    ) -> Result<Vec<EncryptedGroupKey>> {
        let mut encrypted_keys = Vec::with_capacity(members.len());

        for (member_id, member_public_keys) in members {
            // Derive shared encryption key via ECDH
            let encryption_key_bytes = sender.derive_encryption_key(&member_public_keys.exchange);
            let encryption_key = SymmetricKey::from_bytes(&encryption_key_bytes)?;

            // Encrypt the group key
            let encrypted_key = encrypt(&encryption_key, group_key.as_bytes())?;

            encrypted_keys.push(EncryptedGroupKey {
                member_id: member_id.clone(),
                generation: group_key.generation(),
                encrypted_key,
            });
        }

        Ok(encrypted_keys)
    }

    /// Decrypt a group key received from another member.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted group key
    /// * `member` - The receiving member's identity keypair
    /// * `sender_public` - The sender's public keys
    ///
    /// # Returns
    ///
    /// The decrypted group key.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decrypt_for_member(
        encrypted: &EncryptedGroupKey,
        member: &IdentityKeyPair,
        sender_public: &IdentityPublicKeys,
    ) -> Result<GroupKey> {
        // Derive shared decryption key via ECDH
        let decryption_key_bytes = member.derive_encryption_key(&sender_public.exchange);
        let decryption_key = SymmetricKey::from_bytes(&decryption_key_bytes)?;

        // Decrypt the group key
        let key_bytes = decrypt(&decryption_key, &encrypted.encrypted_key)?;

        GroupKey::from_bytes(&key_bytes, encrypted.generation)
    }
}

/// Encrypted group message data.
///
/// Contains all information needed to decrypt a group message.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMessageData {
    /// The group this message belongs to.
    pub group_id: GroupId,
    /// The key generation used to encrypt this message.
    pub key_generation: u32,
    /// The encrypted message content.
    pub encrypted_content: EncryptedData,
}

impl std::fmt::Debug for GroupMessageData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupMessageData")
            .field("group_id", &self.group_id)
            .field("key_generation", &self.key_generation)
            .field(
                "encrypted_content",
                &format!("[{} bytes]", self.encrypted_content.len()),
            )
            .finish()
    }
}

impl GroupMessageData {
    /// Encrypt content for a group.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group identifier
    /// * `group_key` - The current group key
    /// * `content` - The message content to encrypt
    ///
    /// # Returns
    ///
    /// Encrypted group message data.
    pub fn encrypt(group_id: &GroupId, group_key: &GroupKey, content: &str) -> Result<Self> {
        let encrypted_content = encrypt(group_key.symmetric_key(), content.as_bytes())?;

        Ok(Self {
            group_id: group_id.clone(),
            key_generation: group_key.generation(),
            encrypted_content,
        })
    }

    /// Decrypt the message content.
    ///
    /// # Arguments
    ///
    /// * `group_key` - The group key matching this message's generation
    ///
    /// # Returns
    ///
    /// The decrypted message content.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key generation doesn't match
    /// - Decryption fails
    pub fn decrypt(&self, group_key: &GroupKey) -> Result<String> {
        // Verify key generation matches
        if self.key_generation != group_key.generation() {
            return Err(ProtocolError::InvalidKeyGeneration {
                expected: self.key_generation,
                actual: group_key.generation(),
            });
        }

        let plaintext = decrypt(group_key.symmetric_key(), &self.encrypted_content)?;

        String::from_utf8(plaintext).map_err(|_| {
            ProtocolError::Serialization("Invalid UTF-8 in decrypted content".to_string())
        })
    }

    /// Compute a hash of this message data.
    ///
    /// Useful for message identification and deduplication.
    pub fn hash(&self) -> Hash256 {
        let group_id_bytes = self.group_id.as_bytes();
        // PROTO-FIX-10: Use big-endian for consistency with protocol wire format.
        let generation_bytes = self.key_generation.to_be_bytes();
        let ciphertext_bytes = self.encrypted_content.to_bytes();

        Hash256::hash_many(&[
            GROUP_MESSAGE_CONTEXT.as_bytes(),
            group_id_bytes,
            &generation_bytes,
            &ciphertext_bytes,
        ])
    }

    /// Get the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the key generation.
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_key_generation() {
        let key1 = GroupKey::generate(0);
        let key2 = GroupKey::generate(0);

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.generation(), 0);
    }

    #[test]
    fn test_group_key_from_bytes() {
        let key = GroupKey::generate(5);
        let bytes = *key.as_bytes();

        let restored = GroupKey::from_bytes(&bytes, 5).unwrap();
        assert_eq!(key.as_bytes(), restored.as_bytes());
        assert_eq!(restored.generation(), 5);
    }

    #[test]
    fn test_group_key_hash() {
        let key1 = GroupKey::generate(0);
        let key2 = GroupKey::generate(0);

        // Same key should produce same hash
        let hash1 = key1.hash();
        let hash2 = key1.hash();
        assert_eq!(hash1, hash2);

        // Different keys should produce different hashes
        let hash3 = key2.hash();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_encrypt_decrypt_for_members() {
        let group_key = GroupKey::generate(0);
        let admin = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();

        let members = vec![(member.identity_hash().clone(), member.public_keys().clone())];

        // Encrypt for members
        let encrypted_keys =
            GroupKeyManager::encrypt_for_members(&group_key, &admin, &members).unwrap();

        assert_eq!(encrypted_keys.len(), 1);
        assert_eq!(&encrypted_keys[0].member_id, member.identity_hash());
        assert_eq!(encrypted_keys[0].generation, 0);

        // Decrypt for member
        let decrypted =
            GroupKeyManager::decrypt_for_member(&encrypted_keys[0], &member, admin.public_keys())
                .unwrap();

        assert_eq!(decrypted.as_bytes(), group_key.as_bytes());
        assert_eq!(decrypted.generation(), group_key.generation());
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let group_id = GroupId::generate();
        let group_key = GroupKey::generate(0);
        let content = "Hello, group!";

        // Encrypt
        let encrypted = GroupMessageData::encrypt(&group_id, &group_key, content).unwrap();

        assert_eq!(encrypted.group_id(), &group_id);
        assert_eq!(encrypted.key_generation(), 0);

        // Decrypt
        let decrypted = encrypted.decrypt(&group_key).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_decrypt_wrong_generation_fails() {
        let group_id = GroupId::generate();
        let key_gen0 = GroupKey::generate(0);
        let key_gen1 = GroupKey::generate(1);

        let encrypted = GroupMessageData::encrypt(&group_id, &key_gen0, "test").unwrap();

        // Try to decrypt with wrong generation
        let result = encrypted.decrypt(&key_gen1);
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidKeyGeneration {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let group_id = GroupId::generate();
        let key1 = GroupKey::generate(0);
        let key2 = GroupKey::from_bytes(&[42u8; 32], 0).unwrap();

        let encrypted = GroupMessageData::encrypt(&group_id, &key1, "test").unwrap();

        // Try to decrypt with wrong key (same generation)
        let result = encrypted.decrypt(&key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_hash_deterministic() {
        let group_id = GroupId::generate();
        let group_key = GroupKey::generate(0);

        let encrypted = GroupMessageData::encrypt(&group_id, &group_key, "test").unwrap();

        let hash1 = encrypted.hash();
        let hash2 = encrypted.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_message_hash_different_content() {
        let group_id = GroupId::generate();
        let group_key = GroupKey::generate(0);

        let encrypted1 = GroupMessageData::encrypt(&group_id, &group_key, "test1").unwrap();
        let encrypted2 = GroupMessageData::encrypt(&group_id, &group_key, "test2").unwrap();

        // Different content should produce different hashes (due to different ciphertext)
        assert_ne!(encrypted1.hash(), encrypted2.hash());
    }

    #[test]
    fn test_encrypt_empty_content() {
        let group_id = GroupId::generate();
        let group_key = GroupKey::generate(0);

        let encrypted = GroupMessageData::encrypt(&group_id, &group_key, "").unwrap();
        let decrypted = encrypted.decrypt(&group_key).unwrap();

        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_unicode_content() {
        let group_id = GroupId::generate();
        let group_key = GroupKey::generate(0);
        let content = "Hello, world! \u{1F389}";

        let encrypted = GroupMessageData::encrypt(&group_id, &group_key, content).unwrap();
        let decrypted = encrypted.decrypt(&group_key).unwrap();

        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_group_key_debug_redacted() {
        let key = GroupKey::generate(5);
        let debug = format!("{:?}", key);

        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("gen=5"));
    }

    #[test]
    fn test_multiple_members_encryption() {
        let group_key = GroupKey::generate(0);
        let admin = IdentityKeyPair::generate();

        // Create multiple members with their keypairs so we can decrypt later
        let member_keypairs: Vec<_> = (0..5).map(|_| IdentityKeyPair::generate()).collect();

        let members_with_keys: Vec<_> = member_keypairs
            .iter()
            .map(|m| (m.identity_hash().clone(), m.public_keys().clone()))
            .collect();

        let encrypted_keys =
            GroupKeyManager::encrypt_for_members(&group_key, &admin, &members_with_keys).unwrap();

        assert_eq!(encrypted_keys.len(), 5);

        // Each member should be able to decrypt their key
        for (i, member) in member_keypairs.iter().enumerate() {
            let decrypted = GroupKeyManager::decrypt_for_member(
                &encrypted_keys[i],
                member,
                admin.public_keys(),
            )
            .unwrap();
            assert_eq!(decrypted.as_bytes(), group_key.as_bytes());
        }
    }
}
