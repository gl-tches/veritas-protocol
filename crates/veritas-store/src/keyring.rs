//! Identity keyring for secure storage and management of identity keys.
//!
//! The keyring provides:
//! - Secure storage of identity keypairs protected by a password
//! - Primary identity selection
//! - Export/import of identities for backup and transfer
//! - Metadata tracking (creation time, last used, labels)
//!
//! ## Security
//!
//! - Password-derived keys use Argon2id with hardened parameters
//! - All stored keypairs are encrypted with ChaCha20-Poly1305
//! - Password key is zeroized on drop
//! - Verification hash allows password checking without full decryption
//!
//! ## Example
//!
//! ```ignore
//! use veritas_store::keyring::Keyring;
//! use veritas_identity::IdentityKeyPair;
//!
//! // Open or create a keyring
//! let keyring = Keyring::open(&db, b"my-secure-password")?;
//!
//! // Add a new identity
//! let keypair = IdentityKeyPair::generate();
//! keyring.add_identity(&keypair, Some("My main identity"))?;
//!
//! // Set as primary
//! keyring.set_primary(keypair.identity_hash().as_bytes())?;
//!
//! // Later, get the primary identity
//! let primary = keyring.get_primary()?;
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use veritas_crypto::{decrypt, encrypt, SymmetricKey};
use veritas_identity::{EncryptedIdentityKeyPair, IdentityKeyPair};

use crate::{Result, StoreError};

/// Tree name for keyring entries.
const KEYRING_TREE: &str = "veritas_keyring";

/// Tree name for keyring metadata.
const KEYRING_META_TREE: &str = "veritas_keyring_meta";

/// Key for storing keyring metadata.
const META_KEY: &[u8] = b"keyring_meta";

/// Key for storing password verification data.
const VERIFICATION_KEY: &[u8] = b"password_verification";

/// Current schema version.
const SCHEMA_VERSION: u32 = 1;

/// Maximum size of a serialized `ExportedIdentity` in bytes.
///
/// SECURITY: Pre-deserialization size validation prevents crafted input from
/// causing excessive memory allocation during bincode deserialization (VERITAS-2026-0003).
/// Exported identities include an encrypted keypair, so the limit is generous.
pub const MAX_EXPORTED_IDENTITY_SIZE: usize = 16384;

/// Domain separation for password key derivation.
const PASSWORD_KEY_CONTEXT: &str = "VERITAS keyring password key v1";

/// Domain separation for export key derivation.
const EXPORT_KEY_CONTEXT: &str = "VERITAS identity export key v1";

/// Domain separation for verification hash.
const VERIFICATION_CONTEXT: &str = "VERITAS password verification v1";

// Argon2id parameters (hardened for key derivation)
// Memory: 64 MiB, Iterations: 3, Parallelism: 4
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MiB in KiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

/// A keyring entry containing an encrypted identity and metadata.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyringEntry {
    /// The identity hash (32 bytes).
    pub identity_hash: [u8; 32],
    /// The encrypted keypair.
    pub encrypted_keypair: EncryptedIdentityKeyPair,
    /// User-friendly label for this identity.
    pub label: Option<String>,
    /// Unix timestamp when the identity was created.
    pub created_at: i64,
    /// Unix timestamp when the identity was last used.
    pub last_used_at: i64,
    /// Whether this is the primary identity.
    pub is_primary: bool,
}

impl std::fmt::Debug for KeyringEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringEntry")
            .field("identity_hash", &hex::encode(&self.identity_hash[..8]))
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("is_primary", &self.is_primary)
            .finish()
    }
}

/// Metadata about the keyring.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyringMetadata {
    /// Schema version for migration support.
    pub version: u32,
    /// Unix timestamp when the keyring was created.
    pub created_at: i64,
    /// The identity hash of the primary identity, if set.
    pub primary_identity: Option<[u8; 32]>,
    /// Total number of stored identities.
    pub identity_count: u32,
}

impl Default for KeyringMetadata {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            created_at: Utc::now().timestamp(),
            primary_identity: None,
            identity_count: 0,
        }
    }
}

/// Password verification data stored in the database.
#[derive(Serialize, Deserialize)]
struct PasswordVerification {
    /// Salt used for key derivation.
    salt: [u8; 32],
    /// Hash of the derived key for verification.
    verification_hash: [u8; 32],
}

/// An exported identity in portable format.
///
/// This format is used for backing up and transferring identities
/// between devices. It uses a separate password from the keyring.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExportedIdentity {
    /// Format version.
    pub version: u32,
    /// Salt for key derivation.
    pub salt: [u8; 32],
    /// Encrypted identity keypair data.
    pub encrypted_data: Vec<u8>,
    /// Identity hash for verification.
    pub identity_hash: [u8; 32],
}

impl ExportedIdentity {
    /// Serialize to bytes for file export.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    ///
    /// # Security
    ///
    /// Validates input size BEFORE deserialization to prevent crafted input
    /// from causing excessive memory allocation (VERITAS-2026-0003).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SECURITY: Pre-deserialization size check (VERITAS-2026-0003)
        if bytes.len() > MAX_EXPORTED_IDENTITY_SIZE {
            return Err(StoreError::Serialization(format!(
                "ExportedIdentity data too large: {} bytes (max: {})",
                bytes.len(),
                MAX_EXPORTED_IDENTITY_SIZE
            )));
        }
        bincode::deserialize(bytes).map_err(|e| StoreError::Serialization(e.to_string()))
    }
}

impl std::fmt::Debug for ExportedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedIdentity")
            .field("version", &self.version)
            .field("identity_hash", &hex::encode(&self.identity_hash[..8]))
            .field("encrypted_data_len", &self.encrypted_data.len())
            .finish()
    }
}

/// Wrapper for the password-derived key that ensures zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
struct PasswordKey {
    bytes: [u8; 32],
}

impl PasswordKey {
    /// Create from raw bytes.
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get as SymmetricKey for encryption operations.
    ///
    /// STORE-FIX-1: This creates a new SymmetricKey each call (copies the bytes).
    /// This is intentional: SymmetricKey is a lightweight wrapper, and caching it
    /// would require managing an additional zeroizable field. The performance
    /// impact is negligible compared to the Argon2 derivation.
    fn as_symmetric_key(&self) -> SymmetricKey {
        SymmetricKey::from_bytes(&self.bytes).expect("PasswordKey is always 32 bytes")
    }
}

/// Secure keyring for storing and managing identity keypairs.
///
/// The keyring encrypts all stored identities using a password-derived key.
/// Password verification is done using a stored hash to avoid full decryption
/// for simple password checks.
pub struct Keyring {
    /// Tree storing KeyringEntry by identity_hash.
    tree: sled::Tree,
    /// Tree storing KeyringMetadata and password verification.
    meta_tree: sled::Tree,
    /// Password-derived key for encryption/decryption.
    password_key: PasswordKey,
}

impl Keyring {
    /// Create or open a keyring with the given password.
    ///
    /// If the keyring doesn't exist, it will be created with the given password.
    /// If it exists, the password will be verified before opening.
    ///
    /// # Arguments
    ///
    /// * `db` - The sled database instance
    /// * `password` - Password to protect the keyring
    ///
    /// # Errors
    ///
    /// Returns `StoreError::InvalidPassword` if the password is incorrect.
    /// Returns `StoreError::Database` if database operations fail.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let db = sled::open("my_data")?;
    /// let keyring = Keyring::open(&db, b"my-password")?;
    /// ```
    pub fn open(db: &sled::Db, password: &[u8]) -> Result<Self> {
        let tree = db
            .open_tree(KEYRING_TREE)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let meta_tree = db
            .open_tree(KEYRING_META_TREE)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Check if keyring exists (has password verification)
        match meta_tree
            .get(VERIFICATION_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
        { Some(verification_bytes) => {
            // Existing keyring - verify password
            let verification: PasswordVerification = bincode::deserialize(&verification_bytes)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            let password_key = derive_password_key(password, &verification.salt)?;
            let computed_hash = compute_verification_hash(&password_key.bytes);

            // Constant-time comparison
            if bool::from(computed_hash.ct_eq(&verification.verification_hash)) {
                Ok(Self {
                    tree,
                    meta_tree,
                    password_key,
                })
            } else {
                Err(StoreError::InvalidPassword)
            }
        } _ => {
            // New keyring - create with password
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);

            let password_key = derive_password_key(password, &salt)?;
            let verification_hash = compute_verification_hash(&password_key.bytes);

            let verification = PasswordVerification {
                salt,
                verification_hash,
            };

            let verification_bytes = bincode::serialize(&verification)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            meta_tree
                .insert(VERIFICATION_KEY, verification_bytes)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            // Initialize metadata
            let metadata = KeyringMetadata::default();
            let metadata_bytes = bincode::serialize(&metadata)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            meta_tree
                .insert(META_KEY, metadata_bytes)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            meta_tree
                .flush()
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(Self {
                tree,
                meta_tree,
                password_key,
            })
        }}
    }

    /// Change the keyring password.
    ///
    /// Re-encrypts all stored identities with the new password-derived key.
    ///
    /// # Arguments
    ///
    /// * `old_password` - Current password
    /// * `new_password` - New password to set
    ///
    /// # Errors
    ///
    /// Returns `StoreError::InvalidPassword` if the old password is incorrect.
    pub fn change_password(&mut self, old_password: &[u8], new_password: &[u8]) -> Result<()> {
        // Verify old password
        let verification_bytes = self
            .meta_tree
            .get(VERIFICATION_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or(StoreError::Corruption(
                "Missing password verification".into(),
            ))?;

        let old_verification: PasswordVerification = bincode::deserialize(&verification_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let old_key = derive_password_key(old_password, &old_verification.salt)?;
        let old_hash = compute_verification_hash(&old_key.bytes);

        if !bool::from(old_hash.ct_eq(&old_verification.verification_hash)) {
            return Err(StoreError::InvalidPassword);
        }

        // Generate new salt and key
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);
        let new_key = derive_password_key(new_password, &new_salt)?;
        let new_hash = compute_verification_hash(&new_key.bytes);

        // Re-encrypt all identities
        let entries: Vec<_> = self.tree.iter().filter_map(|r| r.ok()).collect();

        for (key, value) in entries {
            let entry: KeyringEntry = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            // Decrypt with old key
            let keypair = IdentityKeyPair::from_encrypted(
                &entry.encrypted_keypair,
                &self.password_key.as_symmetric_key(),
            )
            .map_err(|_| StoreError::Corruption("Failed to decrypt identity".into()))?;

            // Re-encrypt with new key
            let new_encrypted = keypair.to_encrypted(&new_key.as_symmetric_key())?;

            let new_entry = KeyringEntry {
                encrypted_keypair: new_encrypted,
                ..entry
            };

            let entry_bytes = bincode::serialize(&new_entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            self.tree
                .insert(key, entry_bytes)
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        // Store new verification data
        let new_verification = PasswordVerification {
            salt: new_salt,
            verification_hash: new_hash,
        };

        let verification_bytes = bincode::serialize(&new_verification)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.meta_tree
            .insert(VERIFICATION_KEY, verification_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Flush changes
        self.tree
            .flush()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        self.meta_tree
            .flush()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Update stored key
        self.password_key = new_key;

        Ok(())
    }

    /// Check if a password is correct without fully opening the keyring.
    ///
    /// # Arguments
    ///
    /// * `db` - The sled database instance
    /// * `password` - Password to verify
    ///
    /// # Returns
    ///
    /// `true` if the password is correct, `false` otherwise.
    /// Returns an error if the keyring doesn't exist or is corrupted.
    pub fn verify_password(db: &sled::Db, password: &[u8]) -> Result<bool> {
        let meta_tree = db
            .open_tree(KEYRING_META_TREE)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let verification_bytes = meta_tree
            .get(VERIFICATION_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or(StoreError::KeyNotFound("Keyring not initialized".into()))?;

        let verification: PasswordVerification = bincode::deserialize(&verification_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let password_key = derive_password_key(password, &verification.salt)?;
        let computed_hash = compute_verification_hash(&password_key.bytes);

        Ok(bool::from(
            computed_hash.ct_eq(&verification.verification_hash),
        ))
    }

    // --- Identity Management ---

    /// Store a new identity keypair in the keyring.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The identity keypair to store
    /// * `label` - Optional user-friendly label
    ///
    /// # Errors
    ///
    /// Returns an error if the identity already exists or encryption fails.
    pub fn add_identity(&self, keypair: &IdentityKeyPair, label: Option<&str>) -> Result<()> {
        let identity_hash = keypair.identity_hash().to_bytes();

        // Check if identity already exists
        if self
            .tree
            .contains_key(identity_hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            return Err(StoreError::Database(format!(
                "Identity {} already exists",
                hex::encode(&identity_hash[..8])
            )));
        }

        // Encrypt the keypair
        let encrypted = keypair.to_encrypted(&self.password_key.as_symmetric_key())?;

        let now = Utc::now().timestamp();
        let entry = KeyringEntry {
            identity_hash,
            encrypted_keypair: encrypted,
            label: label.map(String::from),
            created_at: now,
            last_used_at: now,
            is_primary: false,
        };

        let entry_bytes =
            bincode::serialize(&entry).map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.tree
            .insert(identity_hash, entry_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Update metadata
        self.update_metadata(|meta| {
            meta.identity_count += 1;
        })?;

        self.tree
            .flush()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get an identity by its hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash
    ///
    /// # Returns
    ///
    /// The decrypted identity keypair, or `None` if not found.
    pub fn get_identity(&self, hash: &[u8; 32]) -> Result<Option<IdentityKeyPair>> {
        let entry_bytes = match self
            .tree
            .get(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let entry: KeyringEntry = bincode::deserialize(&entry_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let keypair = IdentityKeyPair::from_encrypted(
            &entry.encrypted_keypair,
            &self.password_key.as_symmetric_key(),
        )
        .map_err(|_| StoreError::Corruption("Failed to decrypt identity".into()))?;

        Ok(Some(keypair))
    }

    /// List all stored identities (metadata only, not keys).
    ///
    /// # Returns
    ///
    /// A vector of `KeyringEntry` with metadata for all stored identities.
    pub fn list_identities(&self) -> Result<Vec<KeyringEntry>> {
        let mut entries = Vec::new();

        for result in self.tree.iter() {
            let (_, value) = result.map_err(|e| StoreError::Database(e.to_string()))?;
            let entry: KeyringEntry = bincode::deserialize(&value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Remove an identity from the keyring.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash
    ///
    /// # Returns
    ///
    /// `true` if the identity was removed, `false` if it didn't exist.
    pub fn remove_identity(&self, hash: &[u8; 32]) -> Result<bool> {
        // Check if this is the primary identity
        let metadata = self.metadata()?;
        let was_primary = metadata
            .primary_identity
            .as_ref()
            .map(|p| p == hash)
            .unwrap_or(false);

        let removed = self
            .tree
            .remove(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .is_some();

        if removed {
            self.update_metadata(|meta| {
                meta.identity_count = meta.identity_count.saturating_sub(1);
                if was_primary {
                    meta.primary_identity = None;
                }
            })?;

            self.tree
                .flush()
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        Ok(removed)
    }

    /// Update the last used timestamp for an identity.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash
    pub fn touch_identity(&self, hash: &[u8; 32]) -> Result<()> {
        let entry_bytes = self
            .tree
            .get(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or_else(|| {
                StoreError::KeyNotFound(format!("Identity {}", hex::encode(&hash[..8])))
            })?;

        let mut entry: KeyringEntry = bincode::deserialize(&entry_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        entry.last_used_at = Utc::now().timestamp();

        let updated_bytes =
            bincode::serialize(&entry).map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.tree
            .insert(hash, updated_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    /// Set the label for an identity.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash
    /// * `label` - The new label, or `None` to remove the label
    pub fn set_label(&self, hash: &[u8; 32], label: Option<&str>) -> Result<()> {
        let entry_bytes = self
            .tree
            .get(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or_else(|| {
                StoreError::KeyNotFound(format!("Identity {}", hex::encode(&hash[..8])))
            })?;

        let mut entry: KeyringEntry = bincode::deserialize(&entry_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        entry.label = label.map(String::from);

        let updated_bytes =
            bincode::serialize(&entry).map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.tree
            .insert(hash, updated_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    // --- Primary Identity ---

    /// Set which identity is the primary one.
    ///
    /// Only one identity can be primary at a time.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash to set as primary
    pub fn set_primary(&self, hash: &[u8; 32]) -> Result<()> {
        // Verify identity exists
        if !self
            .tree
            .contains_key(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            return Err(StoreError::KeyNotFound(format!(
                "Identity {}",
                hex::encode(&hash[..8])
            )));
        }

        // Get current primary and unset it
        let metadata = self.metadata()?;
        if let Some(old_primary) = metadata.primary_identity {
            if old_primary != *hash {
                self.update_entry(&old_primary, |entry| {
                    entry.is_primary = false;
                })?;
            }
        }

        // Set new primary
        self.update_entry(hash, |entry| {
            entry.is_primary = true;
        })?;

        // Update metadata
        self.update_metadata(|meta| {
            meta.primary_identity = Some(*hash);
        })?;

        Ok(())
    }

    /// Get the primary identity.
    ///
    /// # Returns
    ///
    /// The decrypted primary identity keypair, or `None` if no primary is set.
    pub fn get_primary(&self) -> Result<Option<IdentityKeyPair>> {
        let metadata = self.metadata()?;

        match metadata.primary_identity {
            Some(hash) => self.get_identity(&hash),
            None => Ok(None),
        }
    }

    /// Get the primary identity hash without decrypting.
    ///
    /// # Returns
    ///
    /// The primary identity hash, or `None` if no primary is set.
    pub fn get_primary_hash(&self) -> Result<Option<[u8; 32]>> {
        let metadata = self.metadata()?;
        Ok(metadata.primary_identity)
    }

    // --- Export/Import ---

    /// Export an identity to portable format.
    ///
    /// The exported identity is encrypted with a separate password,
    /// allowing it to be backed up or transferred to another device.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte identity hash to export
    /// * `export_password` - Password to protect the exported identity
    ///
    /// # Returns
    ///
    /// An `ExportedIdentity` that can be serialized to bytes.
    pub fn export_identity(
        &self,
        hash: &[u8; 32],
        export_password: &[u8],
    ) -> Result<ExportedIdentity> {
        // Get and decrypt the identity
        let keypair = self.get_identity(hash)?.ok_or_else(|| {
            StoreError::KeyNotFound(format!("Identity {}", hex::encode(&hash[..8])))
        })?;

        // Generate salt for export encryption
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Derive export key
        let export_key = derive_export_key(export_password, &salt)?;

        // Encrypt the keypair for export
        let encrypted_keypair = keypair.to_encrypted(&export_key)?;

        let keypair_bytes = bincode::serialize(&encrypted_keypair)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        // Encrypt the serialized keypair
        let encrypted_data = encrypt(&export_key, &keypair_bytes)?;

        let encrypted_bytes = bincode::serialize(&encrypted_data)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        Ok(ExportedIdentity {
            version: 1,
            salt,
            encrypted_data: encrypted_bytes,
            identity_hash: *hash,
        })
    }

    /// Import an identity from portable format.
    ///
    /// # Arguments
    ///
    /// * `exported` - The exported identity data
    /// * `export_password` - Password used when exporting
    /// * `label` - Optional label for the imported identity
    ///
    /// # Returns
    ///
    /// The identity hash of the imported identity.
    pub fn import_identity(
        &self,
        exported: &ExportedIdentity,
        export_password: &[u8],
        label: Option<&str>,
    ) -> Result<[u8; 32]> {
        if exported.version != 1 {
            return Err(StoreError::Corruption(format!(
                "Unsupported export version: {}",
                exported.version
            )));
        }

        // Derive export key
        let export_key = derive_export_key(export_password, &exported.salt)?;

        // Decrypt the outer layer
        let encrypted_data: veritas_crypto::EncryptedData =
            bincode::deserialize(&exported.encrypted_data)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

        let keypair_bytes =
            decrypt(&export_key, &encrypted_data).map_err(|_| StoreError::InvalidPassword)?;

        // Deserialize the encrypted keypair
        let encrypted_keypair: EncryptedIdentityKeyPair = bincode::deserialize(&keypair_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        // Decrypt the keypair
        let keypair = IdentityKeyPair::from_encrypted(&encrypted_keypair, &export_key)
            .map_err(|_| StoreError::InvalidPassword)?;

        // Verify identity hash matches
        let computed_hash = keypair.identity_hash().to_bytes();
        let hash_matches: bool = computed_hash.ct_eq(&exported.identity_hash).into();
        if !hash_matches {
            return Err(StoreError::Corruption(
                "Identity hash mismatch in import".into(),
            ));
        }

        // Store in keyring
        self.add_identity(&keypair, label)?;

        Ok(computed_hash)
    }

    // --- Metadata ---

    /// Get keyring metadata.
    pub fn metadata(&self) -> Result<KeyringMetadata> {
        let meta_bytes = self
            .meta_tree
            .get(META_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or(StoreError::Corruption("Missing keyring metadata".into()))?;

        bincode::deserialize(&meta_bytes).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    /// Get the number of stored identities.
    pub fn count(&self) -> Result<u32> {
        Ok(self.metadata()?.identity_count)
    }

    // --- Private Helpers ---

    /// Update metadata with a closure.
    ///
    /// STORE-FIX-4: Flushes metadata to disk on every update. This prioritizes
    /// durability over throughput. For batch operations (e.g., importing many
    /// identities), consider a batch API that flushes once at the end.
    fn update_metadata<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut KeyringMetadata),
    {
        let mut metadata = self.metadata()?;
        f(&mut metadata);

        let meta_bytes =
            bincode::serialize(&metadata).map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.meta_tree
            .insert(META_KEY, meta_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        self.meta_tree
            .flush()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update a keyring entry with a closure.
    fn update_entry<F>(&self, hash: &[u8; 32], f: F) -> Result<()>
    where
        F: FnOnce(&mut KeyringEntry),
    {
        let entry_bytes = self
            .tree
            .get(hash)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or_else(|| {
                StoreError::KeyNotFound(format!("Identity {}", hex::encode(&hash[..8])))
            })?;

        let mut entry: KeyringEntry = bincode::deserialize(&entry_bytes)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        f(&mut entry);

        let updated_bytes =
            bincode::serialize(&entry).map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.tree
            .insert(hash, updated_bytes)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        self.tree
            .flush()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// --- Helper Functions ---

/// Derive a password key using Argon2id.
fn derive_password_key(password: &[u8], salt: &[u8; 32]) -> Result<PasswordKey> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| StoreError::Crypto(veritas_crypto::CryptoError::KeyGeneration(e.to_string())))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| {
            StoreError::Crypto(veritas_crypto::CryptoError::KeyGeneration(e.to_string()))
        })?;

    // Apply context for domain separation
    let contextualized = blake3::derive_key(PASSWORD_KEY_CONTEXT, &output);
    output.zeroize();

    Ok(PasswordKey::from_bytes(contextualized))
}

/// Derive an export key using Argon2id.
fn derive_export_key(password: &[u8], salt: &[u8; 32]) -> Result<SymmetricKey> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| StoreError::Crypto(veritas_crypto::CryptoError::KeyGeneration(e.to_string())))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| {
            StoreError::Crypto(veritas_crypto::CryptoError::KeyGeneration(e.to_string()))
        })?;

    // Apply context for domain separation
    let contextualized = blake3::derive_key(EXPORT_KEY_CONTEXT, &output);
    output.zeroize();

    Ok(SymmetricKey::from_bytes(&contextualized)?)
}

/// Compute verification hash for password checking.
fn compute_verification_hash(key_bytes: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(VERIFICATION_CONTEXT, key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_db() -> (tempfile::TempDir, sled::Db) {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn test_create_and_open_keyring() {
        let (_dir, db) = create_test_db();
        let password = b"test-password-123";

        // Create new keyring
        let keyring = Keyring::open(&db, password).unwrap();
        assert_eq!(keyring.count().unwrap(), 0);

        drop(keyring);

        // Reopen with same password
        let keyring2 = Keyring::open(&db, password).unwrap();
        assert_eq!(keyring2.count().unwrap(), 0);
    }

    #[test]
    fn test_wrong_password_fails() {
        let (_dir, db) = create_test_db();
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        // Create keyring
        let _keyring = Keyring::open(&db, password).unwrap();
        drop(_keyring);

        // Try to open with wrong password
        let result = Keyring::open(&db, wrong_password);
        assert!(matches!(result, Err(StoreError::InvalidPassword)));
    }

    #[test]
    fn test_verify_password() {
        let (_dir, db) = create_test_db();
        let password = b"my-password";

        // Create keyring
        let _keyring = Keyring::open(&db, password).unwrap();
        drop(_keyring);

        // Verify correct password
        assert!(Keyring::verify_password(&db, password).unwrap());

        // Verify wrong password
        assert!(!Keyring::verify_password(&db, b"wrong").unwrap());
    }

    #[test]
    fn test_add_and_get_identity() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        // Add identity
        keyring
            .add_identity(&keypair, Some("Test identity"))
            .unwrap();
        assert_eq!(keyring.count().unwrap(), 1);

        // Get identity
        let retrieved = keyring.get_identity(&hash).unwrap().unwrap();
        assert_eq!(retrieved.identity_hash().to_bytes(), hash);

        // List identities
        let entries = keyring.list_identities().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, Some("Test identity".into()));
        assert!(!entries[0].is_primary);
    }

    #[test]
    fn test_add_duplicate_fails() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();

        keyring.add_identity(&keypair, None).unwrap();
        let result = keyring.add_identity(&keypair, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_remove_identity() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring.add_identity(&keypair, None).unwrap();
        assert_eq!(keyring.count().unwrap(), 1);

        // Remove
        assert!(keyring.remove_identity(&hash).unwrap());
        assert_eq!(keyring.count().unwrap(), 0);

        // Remove non-existent
        assert!(!keyring.remove_identity(&hash).unwrap());
    }

    #[test]
    fn test_primary_identity() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair1 = IdentityKeyPair::generate();
        let keypair2 = IdentityKeyPair::generate();
        let hash1 = keypair1.identity_hash().to_bytes();
        let hash2 = keypair2.identity_hash().to_bytes();

        keyring.add_identity(&keypair1, Some("First")).unwrap();
        keyring.add_identity(&keypair2, Some("Second")).unwrap();

        // No primary initially
        assert!(keyring.get_primary_hash().unwrap().is_none());

        // Set primary
        keyring.set_primary(&hash1).unwrap();
        assert_eq!(keyring.get_primary_hash().unwrap(), Some(hash1));

        let primary = keyring.get_primary().unwrap().unwrap();
        assert_eq!(primary.identity_hash().to_bytes(), hash1);

        // Change primary
        keyring.set_primary(&hash2).unwrap();
        assert_eq!(keyring.get_primary_hash().unwrap(), Some(hash2));

        // Check entries
        let entries = keyring.list_identities().unwrap();
        let entry1 = entries.iter().find(|e| e.identity_hash == hash1).unwrap();
        let entry2 = entries.iter().find(|e| e.identity_hash == hash2).unwrap();
        assert!(!entry1.is_primary);
        assert!(entry2.is_primary);
    }

    #[test]
    fn test_set_primary_nonexistent_fails() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let fake_hash = [0u8; 32];
        let result = keyring.set_primary(&fake_hash);

        assert!(matches!(result, Err(StoreError::KeyNotFound(_))));
    }

    #[test]
    fn test_remove_primary_clears_metadata() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring.add_identity(&keypair, None).unwrap();
        keyring.set_primary(&hash).unwrap();

        assert!(keyring.get_primary_hash().unwrap().is_some());

        keyring.remove_identity(&hash).unwrap();

        assert!(keyring.get_primary_hash().unwrap().is_none());
    }

    #[test]
    fn test_touch_identity() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring.add_identity(&keypair, None).unwrap();

        let entries1 = keyring.list_identities().unwrap();
        let last_used1 = entries1[0].last_used_at;

        // Sleep briefly to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        keyring.touch_identity(&hash).unwrap();

        let entries2 = keyring.list_identities().unwrap();
        let last_used2 = entries2[0].last_used_at;

        assert!(last_used2 >= last_used1);
    }

    #[test]
    fn test_set_label() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring.add_identity(&keypair, Some("Original")).unwrap();

        // Change label
        keyring.set_label(&hash, Some("Updated")).unwrap();

        let entries = keyring.list_identities().unwrap();
        assert_eq!(entries[0].label, Some("Updated".into()));

        // Remove label
        keyring.set_label(&hash, None).unwrap();

        let entries = keyring.list_identities().unwrap();
        assert_eq!(entries[0].label, None);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let (_dir1, db1) = create_test_db();
        let (_dir2, db2) = create_test_db();

        let keyring1 = Keyring::open(&db1, b"keyring-password").unwrap();
        let keyring2 = Keyring::open(&db2, b"other-keyring-password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring1
            .add_identity(&keypair, Some("Export test"))
            .unwrap();

        // Export
        let export_password = b"export-secret";
        let exported = keyring1.export_identity(&hash, export_password).unwrap();

        // Serialize and deserialize
        let bytes = exported.to_bytes().unwrap();
        let restored_export = ExportedIdentity::from_bytes(&bytes).unwrap();

        // Import into different keyring
        let imported_hash = keyring2
            .import_identity(&restored_export, export_password, Some("Imported"))
            .unwrap();

        assert_eq!(imported_hash, hash);
        assert_eq!(keyring2.count().unwrap(), 1);

        // Verify the imported identity works
        let imported_keypair = keyring2.get_identity(&hash).unwrap().unwrap();
        assert_eq!(imported_keypair.identity_hash().to_bytes(), hash);
    }

    #[test]
    fn test_import_wrong_password_fails() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();

        keyring.add_identity(&keypair, None).unwrap();

        let exported = keyring.export_identity(&hash, b"correct").unwrap();

        // Create new keyring for import
        let (_dir2, db2) = create_test_db();
        let keyring2 = Keyring::open(&db2, b"password").unwrap();

        let result = keyring2.import_identity(&exported, b"wrong", None);
        assert!(matches!(result, Err(StoreError::InvalidPassword)));
    }

    #[test]
    fn test_change_password() {
        let (_dir, db) = create_test_db();
        let old_password = b"old-password";
        let new_password = b"new-password";

        // Create keyring with identity
        let mut keyring = Keyring::open(&db, old_password).unwrap();
        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();
        keyring.add_identity(&keypair, Some("Test")).unwrap();

        // Change password
        keyring.change_password(old_password, new_password).unwrap();

        // Drop and verify old password fails
        drop(keyring);
        let result = Keyring::open(&db, old_password);
        assert!(matches!(result, Err(StoreError::InvalidPassword)));

        // Verify new password works
        let keyring2 = Keyring::open(&db, new_password).unwrap();
        let retrieved = keyring2.get_identity(&hash).unwrap().unwrap();
        assert_eq!(retrieved.identity_hash().to_bytes(), hash);
    }

    #[test]
    fn test_change_password_wrong_old_fails() {
        let (_dir, db) = create_test_db();
        let mut keyring = Keyring::open(&db, b"correct").unwrap();

        let result = keyring.change_password(b"wrong", b"new");
        assert!(matches!(result, Err(StoreError::InvalidPassword)));
    }

    #[test]
    fn test_metadata() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let metadata = keyring.metadata().unwrap();
        assert_eq!(metadata.version, SCHEMA_VERSION);
        assert_eq!(metadata.identity_count, 0);
        assert!(metadata.primary_identity.is_none());

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();
        keyring.add_identity(&keypair, None).unwrap();
        keyring.set_primary(&hash).unwrap();

        let metadata = keyring.metadata().unwrap();
        assert_eq!(metadata.identity_count, 1);
        assert_eq!(metadata.primary_identity, Some(hash));
    }

    #[test]
    fn test_multiple_identities() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypairs: Vec<_> = (0..5).map(|_| IdentityKeyPair::generate()).collect();

        for (i, kp) in keypairs.iter().enumerate() {
            keyring
                .add_identity(kp, Some(&format!("Identity {}", i)))
                .unwrap();
        }

        assert_eq!(keyring.count().unwrap(), 5);

        let entries = keyring.list_identities().unwrap();
        assert_eq!(entries.len(), 5);

        // All should be retrievable
        for kp in &keypairs {
            let hash = kp.identity_hash().to_bytes();
            let retrieved = keyring.get_identity(&hash).unwrap().unwrap();
            assert_eq!(retrieved.identity_hash().to_bytes(), hash);
        }
    }

    #[test]
    fn test_keyring_debug_redacted() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let debug = format!("{:?}", keyring);
        assert!(debug.contains("REDACTED"));
        // Ensure the actual key bytes don't leak (password_key field name is ok)
        assert!(!debug.contains("[0x"));
    }

    #[test]
    fn test_exported_identity_debug() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();
        keyring.add_identity(&keypair, None).unwrap();

        let exported = keyring.export_identity(&hash, b"export").unwrap();
        let debug = format!("{:?}", exported);

        assert!(debug.contains("ExportedIdentity"));
        assert!(debug.contains("version"));
    }

    // ========================================================================
    // Pre-deserialization size check tests (VERITAS-2026-0003)
    // ========================================================================

    #[test]
    fn test_exported_identity_from_bytes_rejects_oversized() {
        let oversized = vec![0u8; MAX_EXPORTED_IDENTITY_SIZE + 1];
        let result = ExportedIdentity::from_bytes(&oversized);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_exported_identity_from_bytes_accepts_at_limit() {
        // Data at exactly the limit should pass the size check.
        // Bincode may or may not succeed deserializing depending on
        // the data, but the size check must NOT reject it.
        let at_limit = vec![0u8; MAX_EXPORTED_IDENTITY_SIZE];
        let result = ExportedIdentity::from_bytes(&at_limit);
        // If it fails, it should NOT be because of the size check
        if let Err(ref e) = result {
            let err_msg = format!("{}", e);
            assert!(
                !err_msg.contains("too large"),
                "Should not be a size error at the limit, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_exported_identity_roundtrip_within_limit() {
        let (_dir, db) = create_test_db();
        let keyring = Keyring::open(&db, b"password").unwrap();

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().to_bytes();
        keyring.add_identity(&keypair, None).unwrap();

        let exported = keyring.export_identity(&hash, b"export-pass").unwrap();
        let bytes = exported.to_bytes().unwrap();

        assert!(
            bytes.len() <= MAX_EXPORTED_IDENTITY_SIZE,
            "Serialized ExportedIdentity ({} bytes) exceeds MAX_EXPORTED_IDENTITY_SIZE ({})",
            bytes.len(),
            MAX_EXPORTED_IDENTITY_SIZE
        );

        let restored = ExportedIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(restored.identity_hash, hash);
        assert_eq!(restored.version, exported.version);
    }
}
