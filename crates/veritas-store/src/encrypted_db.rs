//! Encrypted database wrapper using sled + ChaCha20-Poly1305.
//!
//! Provides a secure key-value store with password-based encryption.
//! All values are encrypted at rest using keys derived from a password
//! via Argon2id.
//!
//! ## Security
//!
//! - Password is NEVER stored
//! - Encryption key is derived using Argon2id (memory-hard)
//! - Each value encrypted with unique nonce (XChaCha20-Poly1305)
//! - Salt stored in database for key derivation consistency
//! - Key is zeroized on drop
//!
//! ## Example
//!
//! ```no_run
//! use veritas_store::encrypted_db::EncryptedDb;
//! use std::path::Path;
//!
//! let db = EncryptedDb::open(Path::new("/tmp/test-db"), b"password").unwrap();
//! db.put(b"key", b"secret value").unwrap();
//! let value = db.get(b"key").unwrap();
//! assert_eq!(value, Some(b"secret value".to_vec()));
//! ```

use std::path::Path;
use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use veritas_crypto::symmetric::{decrypt, encrypt, EncryptedData, SymmetricKey};

use crate::{Result, StoreError};

/// Salt size in bytes.
const SALT_SIZE: usize = 32;

/// Key for storing salt in the meta tree.
const SALT_KEY: &[u8] = b"salt";

/// Name of the meta tree for internal storage.
const META_TREE_NAME: &str = "__meta__";

/// Argon2id parameters for key derivation.
///
/// These parameters are chosen to provide strong security while maintaining
/// reasonable performance on typical hardware:
/// - Memory: 64 MiB (provides resistance to GPU/ASIC attacks)
/// - Iterations: 3 (balances security and performance)
/// - Parallelism: 4 (utilizes multi-core CPUs)
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

/// A database encryption key derived from a password.
///
/// The key is automatically zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DbKey {
    key: SymmetricKey,
}

impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbKey([REDACTED])")
    }
}

impl DbKey {
    /// Derive a database encryption key from a password using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from
    /// * `salt` - A 32-byte salt value (must be consistent across opens)
    ///
    /// # Security
    ///
    /// Uses Argon2id with:
    /// - 64 MiB memory
    /// - 3 iterations
    /// - 4 parallelism lanes
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails (should not happen with valid inputs).
    pub fn derive_from_password(password: &[u8], salt: &[u8; SALT_SIZE]) -> Result<Self> {
        // Configure Argon2id with recommended parameters
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|e| StoreError::Database(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Derive the key
        let mut key_bytes = [0u8; ARGON2_OUTPUT_LEN];
        argon2
            .hash_password_into(password, salt, &mut key_bytes)
            .map_err(|e| StoreError::Database(format!("Argon2 key derivation failed: {}", e)))?;

        let key = SymmetricKey::from_bytes(&key_bytes).map_err(StoreError::Crypto)?;

        // Zeroize the intermediate buffer
        key_bytes.zeroize();

        Ok(Self { key })
    }

    /// Get the underlying symmetric key.
    fn symmetric_key(&self) -> &SymmetricKey {
        &self.key
    }
}

/// An encrypted sled database.
///
/// All values stored in this database are encrypted using ChaCha20-Poly1305.
/// The encryption key is derived from a password using Argon2id.
pub struct EncryptedDb {
    /// The underlying sled database.
    db: sled::Db,
    /// The encryption key (derived from password).
    key: Arc<DbKey>,
    /// The path to the database directory.
    path: std::path::PathBuf,
}

impl std::fmt::Debug for EncryptedDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl EncryptedDb {
    /// Open or create an encrypted database.
    ///
    /// If the database exists, the password must match the one used to create it.
    /// If the database is new, a random salt is generated and stored.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory
    /// * `password` - Password for encryption/decryption
    ///
    /// # Errors
    ///
    /// Returns `StoreError::InvalidPassword` if the password is incorrect.
    /// Returns `StoreError::Database` if the database cannot be opened.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        // Open the underlying sled database
        let db = sled::open(path)
            .map_err(|e| StoreError::Database(format!("Failed to open database: {}", e)))?;

        // Get or create the meta tree
        let meta_tree = db
            .open_tree(META_TREE_NAME)
            .map_err(|e| StoreError::Database(format!("Failed to open meta tree: {}", e)))?;

        // Get or generate the salt
        let salt = match meta_tree
            .get(SALT_KEY)
            .map_err(|e| StoreError::Database(format!("Failed to read salt: {}", e)))?
        {
            Some(salt_bytes) => {
                // Existing database - use stored salt
                if salt_bytes.len() != SALT_SIZE {
                    return Err(StoreError::Corruption(format!(
                        "Invalid salt length: expected {}, got {}",
                        SALT_SIZE,
                        salt_bytes.len()
                    )));
                }
                let mut salt = [0u8; SALT_SIZE];
                salt.copy_from_slice(&salt_bytes);
                salt
            }
            None => {
                // New database - generate random salt
                let mut salt = [0u8; SALT_SIZE];
                OsRng.fill_bytes(&mut salt);

                // Store the salt
                meta_tree
                    .insert(SALT_KEY, &salt[..])
                    .map_err(|e| StoreError::Database(format!("Failed to store salt: {}", e)))?;

                salt
            }
        };

        // Derive the encryption key
        let key = DbKey::derive_from_password(password, &salt)?;

        // Verify the password by checking a known value
        let verification_key = b"__verify__";
        let verification_value = b"VERITAS_ENCRYPTED_DB_v1";

        match meta_tree
            .get(verification_key)
            .map_err(|e| StoreError::Database(format!("Failed to read verification: {}", e)))?
        {
            Some(encrypted_verify) => {
                // Existing database - verify password
                let encrypted = EncryptedData::from_bytes(&encrypted_verify)
                    .map_err(|_| StoreError::InvalidPassword)?;

                let decrypted = decrypt(key.symmetric_key(), &encrypted)
                    .map_err(|_| StoreError::InvalidPassword)?;

                if decrypted != verification_value {
                    return Err(StoreError::InvalidPassword);
                }
            }
            None => {
                // New database - store verification value
                let encrypted =
                    encrypt(key.symmetric_key(), verification_value).map_err(StoreError::Crypto)?;

                meta_tree
                    .insert(verification_key, encrypted.to_bytes())
                    .map_err(|e| {
                        StoreError::Database(format!("Failed to store verification: {}", e))
                    })?;
            }
        }

        Ok(Self {
            db,
            key: Arc::new(key),
            path: path.to_path_buf(),
        })
    }

    /// Store an encrypted key-value pair.
    ///
    /// The value is encrypted before being stored. Keys are stored in plaintext.
    ///
    /// # Arguments
    ///
    /// * `key` - The key (stored in plaintext)
    /// * `value` - The value (encrypted before storage)
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or storage fails.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let encrypted = encrypt(self.key.symmetric_key(), value).map_err(StoreError::Crypto)?;

        self.db
            .insert(key, encrypted.to_bytes())
            .map_err(|e| StoreError::Database(format!("Failed to insert: {}", e)))?;

        Ok(())
    }

    /// Get and decrypt a value by key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(value))` if the key exists and decryption succeeds.
    /// Returns `Ok(None)` if the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (indicates corruption).
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self
            .db
            .get(key)
            .map_err(|e| StoreError::Database(format!("Failed to get: {}", e)))?
        {
            Some(encrypted_bytes) => {
                let encrypted =
                    EncryptedData::from_bytes(&encrypted_bytes).map_err(StoreError::Crypto)?;

                let decrypted =
                    decrypt(self.key.symmetric_key(), &encrypted).map_err(StoreError::Crypto)?;

                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }

    /// Delete a key from the database.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.db
            .remove(key)
            .map_err(|e| StoreError::Database(format!("Failed to delete: {}", e)))?;
        Ok(())
    }

    /// Check if a key exists in the database.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the key exists, `false` otherwise.
    pub fn contains(&self, key: &[u8]) -> Result<bool> {
        self.db
            .contains_key(key)
            .map_err(|e| StoreError::Database(format!("Failed to check key: {}", e)))
    }

    /// Iterate over all key-value pairs (decrypted).
    ///
    /// # Returns
    ///
    /// Returns an iterator over `(key, decrypted_value)` pairs.
    ///
    /// # Note
    ///
    /// This includes all keys in the default tree. Keys from named trees
    /// are not included.
    pub fn iter(&self) -> EncryptedIterator {
        EncryptedIterator {
            inner: self.db.iter(),
            key: Arc::clone(&self.key),
        }
    }

    /// Flush all pending writes to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush operation fails.
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| StoreError::Database(format!("Failed to flush: {}", e)))?;
        Ok(())
    }

    /// Open a named tree (namespace) within the database.
    ///
    /// Trees provide isolated namespaces within the same database file.
    /// All operations on a tree use the same encryption key as the parent.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tree to open
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be opened.
    pub fn open_tree(&self, name: &str) -> Result<EncryptedTree> {
        // Prevent access to the internal meta tree
        if name == META_TREE_NAME {
            return Err(StoreError::Database(
                "Cannot open reserved tree name".to_string(),
            ));
        }

        let tree = self
            .db
            .open_tree(name)
            .map_err(|e| StoreError::Database(format!("Failed to open tree: {}", e)))?;

        Ok(EncryptedTree {
            tree,
            key: Arc::clone(&self.key),
        })
    }

    /// Get the path to the database directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An encrypted tree (namespace) within the database.
///
/// Provides the same encrypted operations as `EncryptedDb` but scoped to
/// a specific namespace.
pub struct EncryptedTree {
    /// The underlying sled tree.
    tree: sled::Tree,
    /// The encryption key (shared with parent database).
    key: Arc<DbKey>,
}

impl std::fmt::Debug for EncryptedTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedTree")
            .field("name", &String::from_utf8_lossy(&self.tree.name()))
            .finish_non_exhaustive()
    }
}

impl EncryptedTree {
    /// Store an encrypted key-value pair in this tree.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let encrypted = encrypt(self.key.symmetric_key(), value).map_err(StoreError::Crypto)?;

        self.tree
            .insert(key, encrypted.to_bytes())
            .map_err(|e| StoreError::Database(format!("Failed to insert: {}", e)))?;

        Ok(())
    }

    /// Get and decrypt a value by key from this tree.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self
            .tree
            .get(key)
            .map_err(|e| StoreError::Database(format!("Failed to get: {}", e)))?
        {
            Some(encrypted_bytes) => {
                let encrypted =
                    EncryptedData::from_bytes(&encrypted_bytes).map_err(StoreError::Crypto)?;

                let decrypted =
                    decrypt(self.key.symmetric_key(), &encrypted).map_err(StoreError::Crypto)?;

                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }

    /// Delete a key from this tree.
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.tree
            .remove(key)
            .map_err(|e| StoreError::Database(format!("Failed to delete: {}", e)))?;
        Ok(())
    }

    /// Check if a key exists in this tree.
    pub fn contains(&self, key: &[u8]) -> Result<bool> {
        self.tree
            .contains_key(key)
            .map_err(|e| StoreError::Database(format!("Failed to check key: {}", e)))
    }

    /// Iterate over all key-value pairs in this tree (decrypted).
    pub fn iter(&self) -> EncryptedTreeIterator {
        EncryptedTreeIterator {
            inner: self.tree.iter(),
            key: Arc::clone(&self.key),
        }
    }

    /// Flush all pending writes for this tree to disk.
    pub fn flush(&self) -> Result<()> {
        self.tree
            .flush()
            .map_err(|e| StoreError::Database(format!("Failed to flush: {}", e)))?;
        Ok(())
    }

    /// Get the name of this tree.
    pub fn name(&self) -> Vec<u8> {
        self.tree.name().to_vec()
    }

    /// Clear all entries in this tree.
    pub fn clear(&self) -> Result<()> {
        self.tree
            .clear()
            .map_err(|e| StoreError::Database(format!("Failed to clear tree: {}", e)))?;
        Ok(())
    }

    /// Get the number of entries in this tree.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Check if this tree is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
}

/// Iterator over encrypted database entries.
pub struct EncryptedIterator {
    inner: sled::Iter,
    key: Arc<DbKey>,
}

impl Iterator for EncryptedIterator {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            Some(Ok((key, encrypted_bytes))) => {
                let result = (|| {
                    let encrypted =
                        EncryptedData::from_bytes(&encrypted_bytes).map_err(StoreError::Crypto)?;

                    let decrypted = decrypt(self.key.symmetric_key(), &encrypted)
                        .map_err(StoreError::Crypto)?;

                    Ok((key.to_vec(), decrypted))
                })();
                Some(result)
            }
            Some(Err(e)) => Some(Err(StoreError::Database(format!("Iterator error: {}", e)))),
            None => None,
        }
    }
}

/// Iterator over encrypted tree entries.
pub struct EncryptedTreeIterator {
    inner: sled::Iter,
    key: Arc<DbKey>,
}

impl Iterator for EncryptedTreeIterator {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            Some(Ok((key, encrypted_bytes))) => {
                let result = (|| {
                    let encrypted =
                        EncryptedData::from_bytes(&encrypted_bytes).map_err(StoreError::Crypto)?;

                    let decrypted = decrypt(self.key.symmetric_key(), &encrypted)
                        .map_err(StoreError::Crypto)?;

                    Ok((key.to_vec(), decrypted))
                })();
                Some(result)
            }
            Some(Err(e)) => Some(Err(StoreError::Database(format!("Iterator error: {}", e)))),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db(password: &[u8]) -> (TempDir, EncryptedDb) {
        let dir = TempDir::new().unwrap();
        let db = EncryptedDb::open(dir.path(), password).unwrap();
        (dir, db)
    }

    #[test]
    fn test_open_new_database() {
        let dir = TempDir::new().unwrap();
        let db = EncryptedDb::open(dir.path(), b"password");
        assert!(db.is_ok());
    }

    #[test]
    fn test_reopen_with_same_password() {
        let dir = TempDir::new().unwrap();

        // Create database with password
        {
            let db = EncryptedDb::open(dir.path(), b"password").unwrap();
            db.put(b"key", b"value").unwrap();
            db.flush().unwrap();
        }

        // Reopen with same password
        {
            let db = EncryptedDb::open(dir.path(), b"password").unwrap();
            let value = db.get(b"key").unwrap();
            assert_eq!(value, Some(b"value".to_vec()));
        }
    }

    #[test]
    fn test_reopen_with_wrong_password() {
        let dir = TempDir::new().unwrap();

        // Create database with password
        {
            let db = EncryptedDb::open(dir.path(), b"password").unwrap();
            db.put(b"key", b"value").unwrap();
            db.flush().unwrap();
        }

        // Try to reopen with wrong password
        let result = EncryptedDb::open(dir.path(), b"wrong-password");
        assert!(matches!(result, Err(StoreError::InvalidPassword)));
    }

    #[test]
    fn test_put_get_roundtrip() {
        let (_dir, db) = temp_db(b"password");

        db.put(b"key1", b"value1").unwrap();
        db.put(b"key2", b"value2").unwrap();

        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_get_nonexistent_key() {
        let (_dir, db) = temp_db(b"password");

        let value = db.get(b"nonexistent").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_delete() {
        let (_dir, db) = temp_db(b"password");

        db.put(b"key", b"value").unwrap();
        assert!(db.contains(b"key").unwrap());

        db.delete(b"key").unwrap();
        assert!(!db.contains(b"key").unwrap());
        assert_eq!(db.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_contains() {
        let (_dir, db) = temp_db(b"password");

        assert!(!db.contains(b"key").unwrap());

        db.put(b"key", b"value").unwrap();
        assert!(db.contains(b"key").unwrap());
    }

    #[test]
    fn test_update_value() {
        let (_dir, db) = temp_db(b"password");

        db.put(b"key", b"value1").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value1".to_vec()));

        db.put(b"key", b"value2").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_empty_value() {
        let (_dir, db) = temp_db(b"password");

        db.put(b"key", b"").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"".to_vec()));
    }

    #[test]
    fn test_large_value() {
        let (_dir, db) = temp_db(b"password");

        let large_value = vec![0x42u8; 1024 * 1024]; // 1 MiB
        db.put(b"key", &large_value).unwrap();

        let retrieved = db.get(b"key").unwrap().unwrap();
        assert_eq!(retrieved, large_value);
    }

    #[test]
    fn test_iter() {
        let (_dir, db) = temp_db(b"password");

        db.put(b"key1", b"value1").unwrap();
        db.put(b"key2", b"value2").unwrap();
        db.put(b"key3", b"value3").unwrap();

        let mut entries: Vec<_> = db.iter().map(|r| r.unwrap()).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (b"key1".to_vec(), b"value1".to_vec()));
        assert_eq!(entries[1], (b"key2".to_vec(), b"value2".to_vec()));
        assert_eq!(entries[2], (b"key3".to_vec(), b"value3".to_vec()));
    }

    #[test]
    fn test_tree_isolation() {
        let (_dir, db) = temp_db(b"password");

        // Put in default tree
        db.put(b"key", b"default-value").unwrap();

        // Put in named tree
        let tree = db.open_tree("my-tree").unwrap();
        tree.put(b"key", b"tree-value").unwrap();

        // Values should be isolated
        assert_eq!(db.get(b"key").unwrap(), Some(b"default-value".to_vec()));
        assert_eq!(tree.get(b"key").unwrap(), Some(b"tree-value".to_vec()));

        // Delete from one shouldn't affect the other
        db.delete(b"key").unwrap();
        assert_eq!(db.get(b"key").unwrap(), None);
        assert_eq!(tree.get(b"key").unwrap(), Some(b"tree-value".to_vec()));
    }

    #[test]
    fn test_tree_operations() {
        let (_dir, db) = temp_db(b"password");
        let tree = db.open_tree("test-tree").unwrap();

        // Put/Get
        tree.put(b"key", b"value").unwrap();
        assert_eq!(tree.get(b"key").unwrap(), Some(b"value".to_vec()));

        // Contains
        assert!(tree.contains(b"key").unwrap());
        assert!(!tree.contains(b"nonexistent").unwrap());

        // Delete
        tree.delete(b"key").unwrap();
        assert_eq!(tree.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_tree_iter() {
        let (_dir, db) = temp_db(b"password");
        let tree = db.open_tree("test-tree").unwrap();

        tree.put(b"a", b"1").unwrap();
        tree.put(b"b", b"2").unwrap();

        let entries: Vec<_> = tree.iter().map(|r| r.unwrap()).collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_tree_clear() {
        let (_dir, db) = temp_db(b"password");
        let tree = db.open_tree("test-tree").unwrap();

        tree.put(b"a", b"1").unwrap();
        tree.put(b"b", b"2").unwrap();
        assert_eq!(tree.len(), 2);

        tree.clear().unwrap();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_multiple_trees() {
        let (_dir, db) = temp_db(b"password");

        let tree1 = db.open_tree("tree1").unwrap();
        let tree2 = db.open_tree("tree2").unwrap();

        tree1.put(b"key", b"value1").unwrap();
        tree2.put(b"key", b"value2").unwrap();

        assert_eq!(tree1.get(b"key").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(tree2.get(b"key").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_cannot_open_meta_tree() {
        let (_dir, db) = temp_db(b"password");

        let result = db.open_tree(META_TREE_NAME);
        assert!(matches!(result, Err(StoreError::Database(_))));
    }

    #[test]
    fn test_flush() {
        let dir = TempDir::new().unwrap();

        {
            let db = EncryptedDb::open(dir.path(), b"password").unwrap();
            db.put(b"key", b"value").unwrap();
            db.flush().unwrap();
        }

        // Verify data persisted
        let db = EncryptedDb::open(dir.path(), b"password").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_tree_flush() {
        let dir = TempDir::new().unwrap();

        {
            let db = EncryptedDb::open(dir.path(), b"password").unwrap();
            let tree = db.open_tree("test-tree").unwrap();
            tree.put(b"key", b"value").unwrap();
            tree.flush().unwrap();
        }

        // Verify data persisted
        let db = EncryptedDb::open(dir.path(), b"password").unwrap();
        let tree = db.open_tree("test-tree").unwrap();
        assert_eq!(tree.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_binary_key_and_value() {
        let (_dir, db) = temp_db(b"password");

        let key = vec![0x00, 0xFF, 0x01, 0xFE];
        let value = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        db.put(&key, &value).unwrap();
        assert_eq!(db.get(&key).unwrap(), Some(value));
    }

    #[test]
    fn test_db_key_derive() {
        let salt = [0x42u8; SALT_SIZE];
        let password = b"test-password";

        // Same password and salt should produce same key
        let key1 = DbKey::derive_from_password(password, &salt).unwrap();
        let key2 = DbKey::derive_from_password(password, &salt).unwrap();

        // We can't directly compare keys, but we can encrypt/decrypt
        let test_data = b"test";
        let encrypted = encrypt(key1.symmetric_key(), test_data).unwrap();
        let decrypted = decrypt(key2.symmetric_key(), &encrypted).unwrap();
        assert_eq!(test_data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0x42u8; SALT_SIZE];

        let key1 = DbKey::derive_from_password(b"password1", &salt).unwrap();
        let key2 = DbKey::derive_from_password(b"password2", &salt).unwrap();

        // Different passwords should produce different keys
        let test_data = b"test";
        let encrypted = encrypt(key1.symmetric_key(), test_data).unwrap();
        let result = decrypt(key2.symmetric_key(), &encrypted);

        // Decryption should fail with wrong key
        assert!(result.is_err());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let salt1 = [0x42u8; SALT_SIZE];
        let salt2 = [0x43u8; SALT_SIZE];
        let password = b"password";

        let key1 = DbKey::derive_from_password(password, &salt1).unwrap();
        let key2 = DbKey::derive_from_password(password, &salt2).unwrap();

        // Different salts should produce different keys
        let test_data = b"test";
        let encrypted = encrypt(key1.symmetric_key(), test_data).unwrap();
        let result = decrypt(key2.symmetric_key(), &encrypted);

        // Decryption should fail with wrong key
        assert!(result.is_err());
    }

    #[test]
    fn test_tree_name() {
        let (_dir, db) = temp_db(b"password");
        let tree = db.open_tree("my-named-tree").unwrap();

        assert_eq!(tree.name(), b"my-named-tree".to_vec());
    }

    #[test]
    fn test_empty_password() {
        let dir = TempDir::new().unwrap();

        // Empty password should work (not recommended but valid)
        let db = EncryptedDb::open(dir.path(), b"").unwrap();
        db.put(b"key", b"value").unwrap();
        db.flush().unwrap();
        drop(db);

        // Should be able to reopen with empty password
        let db = EncryptedDb::open(dir.path(), b"").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_unicode_values() {
        let (_dir, db) = temp_db(b"password");

        let value = "Hello, world!";
        db.put(b"key", value.as_bytes()).unwrap();

        let retrieved = db.get(b"key").unwrap().unwrap();
        let retrieved_str = std::str::from_utf8(&retrieved).unwrap();
        assert_eq!(retrieved_str, value);
    }
}
