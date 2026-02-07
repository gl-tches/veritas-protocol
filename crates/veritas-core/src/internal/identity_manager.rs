//! Identity management service for VERITAS protocol.
//!
//! The `IdentityManager` coordinates identity keypair storage, slot management,
//! and lifecycle tracking. It provides a unified interface for:
//!
//! - Creating and storing identity keypairs
//! - Managing primary identity selection
//! - Tracking identity slot limits (max 3 per device)
//! - Handling key lifecycle (expiry, rotation)
//!
//! ## Security
//!
//! - All keypairs are stored encrypted using a password-derived key
//! - Private keys implement Zeroize for secure memory cleanup
//! - Cached primary keypair is zeroized on drop
//!
//! ## Example
//!
//! ```ignore
//! use veritas_core::internal::IdentityManager;
//! use std::path::Path;
//!
//! let mut manager = IdentityManager::open(Path::new("/tmp/db"), b"password")?;
//!
//! // Create a new identity
//! let hash = manager.create_identity(Some("My main identity"))?;
//!
//! // Set as primary
//! manager.set_primary(&hash)?;
//!
//! // Use the primary keypair
//! let keypair = manager.primary_keypair()?;
//! ```

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use veritas_identity::{
    HardwareAttestation, IdentityHash, IdentityKeyPair, IdentityLimiter, IdentityPublicKeys,
    IdentitySlotInfo, KeyLifecycle, KeyState, MAX_IDENTITIES_PER_ORIGIN, OriginFingerprint,
};
use veritas_store::{Keyring, KeyringEntry};

use crate::config::ClientConfig;
use crate::error::{CoreError, Result};

/// Information about an identity in the manager.
///
/// This is a user-friendly view of an identity that combines information
/// from both the keyring storage and the lifecycle tracker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// The identity hash (unique identifier).
    pub hash: IdentityHash,
    /// User-friendly label for this identity.
    pub label: Option<String>,
    /// Whether this is the primary identity.
    pub is_primary: bool,
    /// Unix timestamp when the identity was created.
    pub created_at: u64,
    /// Key lifecycle information.
    pub lifecycle: KeyLifecycle,
}

impl IdentityInfo {
    /// Check if this identity can be used for operations.
    pub fn is_usable(&self) -> bool {
        self.lifecycle.state.is_usable()
    }

    /// Check if this identity is in the expiring warning period.
    pub fn is_expiring(&self) -> bool {
        matches!(self.lifecycle.state, KeyState::Expiring)
    }

    /// Get the key state.
    pub fn key_state(&self) -> KeyState {
        self.lifecycle.state
    }

    /// Get days until expiry.
    pub fn days_until_expiry(&self, current_time: u64) -> Option<u32> {
        let seconds = self.lifecycle.seconds_until_expiry(current_time);
        if seconds > 0 {
            Some((seconds / (24 * 60 * 60)) as u32)
        } else {
            None
        }
    }
}

/// Manages identity keypairs and slot limits for VERITAS protocol.
///
/// The `IdentityManager` is the central coordinator for identity management.
/// It combines:
/// - Encrypted keyring storage (from veritas-store)
/// - Identity slot limits (from veritas-identity)
/// - Key lifecycle tracking
///
/// ## Thread Safety
///
/// The manager is NOT thread-safe. Use external synchronization if accessed
/// from multiple threads (e.g., wrap in `Arc<Mutex<IdentityManager>>`).
///
/// ## Memory Safety
///
/// The cached primary keypair is zeroized when:
/// - The manager is dropped
/// - `zeroize()` is called explicitly
/// - A new primary is set (old keypair is zeroized)
pub struct IdentityManager {
    /// Client configuration (used for in-memory mode).
    #[allow(dead_code)]
    config: ClientConfig,
    /// The primary identity keypair (if set).
    primary_identity: Option<IdentityKeyPair>,
    /// All stored keypairs, indexed by identity hash.
    /// This ensures non-primary keypairs are not lost.
    keypairs: HashMap<IdentityHash, IdentityKeyPair>,
    /// List of all identity info (metadata only).
    identities: Vec<IdentityInfo>,
}

impl IdentityManager {
    /// Create a new identity manager with the given configuration.
    ///
    /// This creates an in-memory identity manager suitable for testing
    /// or when persistent storage is not needed.
    ///
    /// # Arguments
    ///
    /// * `config` - Client configuration
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            primary_identity: None,
            keypairs: HashMap::new(),
            identities: Vec::new(),
        }
    }

    /// Get the primary identity hash.
    pub fn primary_identity_hash(&self) -> Option<&IdentityHash> {
        self.primary_identity.as_ref().map(|k| k.identity_hash())
    }

    /// Get the primary identity's public keys.
    pub fn primary_public_keys(&self) -> Option<&IdentityPublicKeys> {
        self.primary_identity.as_ref().map(|k| k.public_keys())
    }

    /// List all identities.
    pub fn list_identities(&self) -> &[IdentityInfo] {
        &self.identities
    }

    /// Create a new identity.
    ///
    /// # Arguments
    ///
    /// * `label` - Optional user-defined label
    ///
    /// # Returns
    ///
    /// The hash of the newly created identity.
    pub fn create_identity(&mut self, label: Option<&str>) -> Result<IdentityHash> {
        // Enforce the 3-identity slot limit
        if self.identities.len() >= MAX_IDENTITIES_PER_ORIGIN as usize {
            return Err(CoreError::Identity(
                veritas_identity::IdentityError::MaxIdentitiesReached {
                    max: MAX_IDENTITIES_PER_ORIGIN,
                },
            ));
        }

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().clone();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let is_primary = self.primary_identity.is_none();

        let info = IdentityInfo {
            hash: hash.clone(),
            label: label.map(String::from),
            is_primary,
            created_at: current_time,
            lifecycle: KeyLifecycle::new(current_time),
        };

        self.identities.push(info);

        // Store the keypair so it is not lost
        self.keypairs.insert(hash.clone(), keypair.clone());

        if is_primary {
            self.primary_identity = Some(keypair);
        }

        Ok(hash)
    }

    /// Set the primary identity.
    ///
    /// # Arguments
    ///
    /// * `hash` - The identity hash to set as primary
    ///
    /// # Errors
    ///
    /// Returns an error if the identity is not found.
    pub fn set_primary_identity(&mut self, hash: &IdentityHash) -> Result<()> {
        // Check if identity exists
        let exists = self.identities.iter().any(|info| &info.hash == hash);
        if !exists {
            return Err(CoreError::IdentityNotFound(hash.to_hex()));
        }

        // Look up the keypair from the stored keypairs
        let keypair = self
            .keypairs
            .get(hash)
            .ok_or_else(|| CoreError::IdentityNotFound(hash.to_hex()))?
            .clone();

        // Update is_primary flags
        for info in &mut self.identities {
            info.is_primary = &info.hash == hash;
        }

        // Update the cached primary identity keypair
        self.primary_identity = Some(keypair);

        Ok(())
    }

    /// Check if there is a primary identity.
    pub fn has_primary_identity(&self) -> bool {
        self.primary_identity.is_some()
    }

    /// Get slot information.
    ///
    /// Returns identity slot usage info. For in-memory mode,
    /// this returns a mock slot info.
    pub fn slot_info(&self) -> IdentitySlotInfo {
        IdentitySlotInfo {
            used: self.identities.len() as u32,
            max: 3,
            available: 3u32.saturating_sub(self.identities.len() as u32),
            next_slot_available: None,
        }
    }

    /// Zeroize sensitive data in memory.
    pub fn zeroize(&mut self) {
        if let Some(primary) = self.primary_identity.take() {
            // IdentityKeyPair implements ZeroizeOnDrop
            drop(primary);
        }
        // Zeroize all stored keypairs (ZeroizeOnDrop handles cleanup)
        let keypairs = std::mem::take(&mut self.keypairs);
        drop(keypairs);
    }

    // ========================================================================
    // Compatibility Methods
    // ========================================================================
    // These methods provide API compatibility with client.rs expectations

    /// Open an identity manager from the given path.
    ///
    /// For in-memory mode, this creates a new empty manager.
    /// Password is ignored for in-memory mode.
    pub fn open(_db_path: &Path, _password: &[u8]) -> Result<Self> {
        // For now, return an in-memory manager
        // Full persistent storage will be added in a future phase
        Ok(Self::new(ClientConfig::in_memory()))
    }

    /// Flush pending changes to disk.
    ///
    /// No-op for in-memory mode.
    pub fn flush(&self) -> Result<()> {
        // No-op for in-memory mode
        Ok(())
    }

    /// Get the primary identity hash.
    ///
    /// Alias for compatibility with client.rs.
    pub fn primary_hash(&self) -> Result<IdentityHash> {
        self.primary_identity_hash()
            .cloned()
            .ok_or_else(|| CoreError::IdentityNotFound("No primary identity set".to_string()))
    }

    /// Get a reference to the primary keypair.
    ///
    /// Note: For in-memory mode, this returns a reference to the cached keypair.
    pub fn primary_keypair(&self) -> Result<&IdentityKeyPair> {
        self.primary_identity
            .as_ref()
            .ok_or_else(|| CoreError::IdentityNotFound("No primary identity set".to_string()))
    }

    /// Set the primary identity.
    ///
    /// Alias for set_primary_identity for compatibility.
    pub fn set_primary(&mut self, hash: &IdentityHash) -> Result<()> {
        self.set_primary_identity(hash)
    }
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field(
                "primary_identity",
                &self.primary_identity.as_ref().map(|k| k.identity_hash()),
            )
            .field("identity_count", &self.identities.len())
            .field("stored_keypairs", &self.keypairs.len())
            .finish()
    }
}

// ============================================================================
// Persistent Identity Manager (for future use)
// ============================================================================

/// Persistent identity manager with encrypted keyring storage.
///
/// This provides full identity management with:
/// - Encrypted keypair storage
/// - Identity slot limits (max 3 per device)
/// - Key lifecycle tracking
///
/// ## Example
///
/// ```ignore
/// use veritas_core::internal::PersistentIdentityManager;
/// use std::path::Path;
///
/// let mut manager = PersistentIdentityManager::open(Path::new("/tmp/db"), b"password")?;
/// let hash = manager.create_identity(Some("Main"))?;
/// ```
pub struct PersistentIdentityManager {
    /// The sled database instance.
    db: sled::Db,
    /// Encrypted keyring for identity storage.
    keyring: Keyring,
    /// Identity slot limiter for this device.
    limiter: IdentityLimiter,
    /// Cached primary identity keypair.
    cached_primary: Option<IdentityKeyPair>,
}

impl PersistentIdentityManager {
    /// Open or create a persistent identity manager.
    ///
    /// If the database doesn't exist, it will be created with the given password.
    /// If it exists, the password will be verified before opening.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the sled database directory
    /// * `password` - Password to protect the keyring
    pub fn open(db_path: &Path, password: &[u8]) -> Result<Self> {
        // Open or create the sled database
        let db = sled::open(db_path).map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to open database: {}",
                e
            )))
        })?;

        // Open the keyring with password verification
        let keyring = Keyring::open(&db, password)?;

        // Load or create identity limiter
        let limiter = Self::load_or_create_limiter(&db)?;

        Ok(Self {
            db,
            keyring,
            limiter,
            cached_primary: None,
        })
    }

    /// Load or create the identity limiter from the database.
    fn load_or_create_limiter(db: &sled::Db) -> Result<IdentityLimiter> {
        let limiter_tree = db.open_tree("veritas_identity_limiter").map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to open limiter tree: {}",
                e
            )))
        })?;

        let key = b"limiter";

        match limiter_tree.get(key).map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to get limiter: {}",
                e
            )))
        })? {
            Some(bytes) => bincode::deserialize(&bytes).map_err(|e| {
                CoreError::Store(veritas_store::StoreError::Serialization(format!(
                    "Failed to deserialize limiter: {}",
                    e
                )))
            }),
            _ => {
                // Create origin fingerprint from hardware attestation
                let attestation = HardwareAttestation::collect().map_err(CoreError::Identity)?;
                let origin =
                    OriginFingerprint::from_hardware(&attestation).map_err(CoreError::Identity)?;
                let limiter = IdentityLimiter::new(origin);

                let bytes = bincode::serialize(&limiter).map_err(|e| {
                    CoreError::Store(veritas_store::StoreError::Serialization(format!(
                        "Failed to serialize limiter: {}",
                        e
                    )))
                })?;

                limiter_tree.insert(key, bytes).map_err(|e| {
                    CoreError::Store(veritas_store::StoreError::Database(format!(
                        "Failed to save limiter: {}",
                        e
                    )))
                })?;

                limiter_tree.flush().map_err(|e| {
                    CoreError::Store(veritas_store::StoreError::Database(format!(
                        "Failed to flush limiter: {}",
                        e
                    )))
                })?;

                Ok(limiter)
            }
        }
    }

    /// Save the identity limiter to the database.
    fn save_limiter(&self) -> Result<()> {
        let limiter_tree = self.db.open_tree("veritas_identity_limiter").map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to open limiter tree: {}",
                e
            )))
        })?;

        let bytes = bincode::serialize(&self.limiter).map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Serialization(format!(
                "Failed to serialize limiter: {}",
                e
            )))
        })?;

        limiter_tree.insert(b"limiter", bytes).map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to save limiter: {}",
                e
            )))
        })?;

        limiter_tree.flush().map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to flush limiter: {}",
                e
            )))
        })?;

        Ok(())
    }

    /// Get the primary identity keypair.
    pub fn primary_keypair(&mut self) -> Result<&IdentityKeyPair> {
        if let Some(ref primary) = self.cached_primary {
            return Ok(primary);
        }

        let keypair = self.keyring.get_primary()?.ok_or_else(|| {
            CoreError::Identity(veritas_identity::IdentityError::NotFound(
                "No primary identity set".to_string(),
            ))
        })?;

        self.cached_primary = Some(keypair);
        Ok(self.cached_primary.as_ref().unwrap())
    }

    /// Get the primary identity hash.
    pub fn primary_hash(&self) -> Result<IdentityHash> {
        if let Some(ref keypair) = self.cached_primary {
            return Ok(keypair.identity_hash().clone());
        }

        let hash_bytes = self.keyring.get_primary_hash()?.ok_or_else(|| {
            CoreError::Identity(veritas_identity::IdentityError::NotFound(
                "No primary identity set".to_string(),
            ))
        })?;

        IdentityHash::from_bytes(&hash_bytes).map_err(CoreError::Identity)
    }

    /// Create a new identity.
    pub fn create_identity(&mut self, label: Option<&str>) -> Result<IdentityHash> {
        let current_time = Utc::now().timestamp() as u64;

        if !self.limiter.can_register(current_time) {
            return Err(CoreError::Identity(
                veritas_identity::IdentityError::MaxIdentitiesReached { max: 3 },
            ));
        }

        let keypair = IdentityKeyPair::generate();
        let hash = keypair.identity_hash().clone();

        self.limiter.register(hash.clone(), current_time)?;
        self.save_limiter()?;
        self.keyring.add_identity(&keypair, label)?;

        Ok(hash)
    }

    /// Set the primary identity.
    pub fn set_primary(&mut self, hash: &IdentityHash) -> Result<()> {
        let current_time = Utc::now().timestamp() as u64;

        if let Some(lifecycle) = self.limiter.get(hash) {
            lifecycle.can_use(current_time)?;
        } else {
            return Err(CoreError::Identity(
                veritas_identity::IdentityError::NotFound(hash.to_hex()),
            ));
        }

        if let Some(old_primary) = self.cached_primary.take() {
            drop(old_primary);
        }

        let hash_bytes = hash.to_bytes();
        self.keyring.set_primary(&hash_bytes)?;

        Ok(())
    }

    /// List all identities.
    pub fn list_identities(&self) -> Vec<IdentityInfo> {
        let current_time = Utc::now().timestamp() as u64;
        let entries = self.keyring.list_identities().unwrap_or_default();

        entries
            .into_iter()
            .filter_map(|entry| self.entry_to_info(entry, current_time))
            .collect()
    }

    fn entry_to_info(&self, entry: KeyringEntry, _current_time: u64) -> Option<IdentityInfo> {
        let hash = IdentityHash::from_bytes(&entry.identity_hash).ok()?;

        let lifecycle = if let Some(lc) = self.limiter.get(&hash) {
            lc.clone()
        } else {
            KeyLifecycle::new(entry.created_at as u64)
        };

        Some(IdentityInfo {
            hash,
            label: entry.label,
            is_primary: entry.is_primary,
            created_at: entry.created_at as u64,
            lifecycle,
        })
    }

    /// Get slot information.
    pub fn slot_info(&self) -> IdentitySlotInfo {
        let current_time = Utc::now().timestamp() as u64;
        self.limiter.slot_info(current_time)
    }

    /// Get an identity keypair by hash.
    pub fn get_identity(&self, hash: &IdentityHash) -> Result<Option<IdentityKeyPair>> {
        let hash_bytes = hash.to_bytes();
        Ok(self.keyring.get_identity(&hash_bytes)?)
    }

    /// Touch an identity (update last used time).
    pub fn touch(&mut self, hash: &IdentityHash) -> Result<()> {
        let current_time = Utc::now().timestamp() as u64;
        self.limiter.touch(hash, current_time)?;
        self.save_limiter()?;

        let hash_bytes = hash.to_bytes();
        self.keyring.touch_identity(&hash_bytes)?;

        Ok(())
    }

    /// Revoke an identity.
    pub fn revoke(&mut self, hash: &IdentityHash) -> Result<()> {
        self.limiter.revoke(hash)?;
        self.save_limiter()?;

        if let Some(ref primary) = self.cached_primary {
            if primary.identity_hash() == hash {
                self.cached_primary = None;
            }
        }

        Ok(())
    }

    /// Remove an identity completely.
    pub fn remove_identity(&mut self, hash: &IdentityHash) -> Result<bool> {
        let hash_bytes = hash.to_bytes();
        let removed = self.keyring.remove_identity(&hash_bytes)?;

        if let Some(ref primary) = self.cached_primary {
            if primary.identity_hash() == hash {
                self.cached_primary = None;
            }
        }

        Ok(removed)
    }

    /// Check if an identity exists and is usable.
    pub fn is_usable(&self, hash: &IdentityHash) -> bool {
        let current_time = Utc::now().timestamp() as u64;

        if let Some(lifecycle) = self.limiter.get(hash) {
            lifecycle.can_use(current_time).is_ok()
        } else {
            false
        }
    }

    /// Flush all pending changes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().map_err(|e| {
            CoreError::Store(veritas_store::StoreError::Database(format!(
                "Failed to flush database: {}",
                e
            )))
        })?;
        Ok(())
    }

    /// Zeroize sensitive data in memory.
    pub fn zeroize(&mut self) {
        if let Some(primary) = self.cached_primary.take() {
            drop(primary);
        }
    }
}

impl Drop for PersistentIdentityManager {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for PersistentIdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentIdentityManager")
            .field("keyring", &"[REDACTED]")
            .field("limiter", &self.limiter)
            .field("cached_primary", &self.cached_primary.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ClientConfig {
        ClientConfig::in_memory()
    }

    #[test]
    fn test_identity_manager_new() {
        let manager = IdentityManager::new(test_config());
        assert!(manager.primary_identity_hash().is_none());
        assert!(manager.list_identities().is_empty());
    }

    #[test]
    fn test_identity_manager_create_identity() {
        let mut manager = IdentityManager::new(test_config());

        let hash1 = manager.create_identity(Some("Test Identity")).unwrap();

        assert_eq!(manager.primary_identity_hash(), Some(&hash1));
        assert_eq!(manager.list_identities().len(), 1);

        let info = &manager.list_identities()[0];
        assert_eq!(info.hash, hash1);
        assert_eq!(info.label, Some("Test Identity".to_string()));
        assert!(info.is_primary);
    }

    #[test]
    fn test_identity_manager_multiple_identities() {
        let mut manager = IdentityManager::new(test_config());

        let hash1 = manager.create_identity(Some("First")).unwrap();
        let hash2 = manager.create_identity(Some("Second")).unwrap();

        assert_eq!(manager.list_identities().len(), 2);
        assert_eq!(manager.primary_identity_hash(), Some(&hash1));

        let second = manager
            .list_identities()
            .iter()
            .find(|i| i.hash == hash2)
            .unwrap();
        assert!(!second.is_primary);
    }

    #[test]
    fn test_identity_manager_set_primary() {
        let mut manager = IdentityManager::new(test_config());

        let hash1 = manager.create_identity(Some("First")).unwrap();
        let hash2 = manager.create_identity(Some("Second")).unwrap();

        assert!(
            manager
                .list_identities()
                .iter()
                .find(|i| i.hash == hash1)
                .unwrap()
                .is_primary
        );

        manager.set_primary_identity(&hash2).unwrap();

        let first = manager
            .list_identities()
            .iter()
            .find(|i| i.hash == hash1)
            .unwrap();
        let second = manager
            .list_identities()
            .iter()
            .find(|i| i.hash == hash2)
            .unwrap();

        assert!(!first.is_primary);
        assert!(second.is_primary);
    }

    #[test]
    fn test_identity_manager_set_primary_not_found() {
        let mut manager = IdentityManager::new(test_config());

        let fake_hash = IdentityHash::from_public_key(b"nonexistent");
        let result = manager.set_primary_identity(&fake_hash);

        assert!(result.is_err());
    }

    #[test]
    fn test_slot_info() {
        let mut manager = IdentityManager::new(test_config());

        let info = manager.slot_info();
        assert_eq!(info.used, 0);
        assert_eq!(info.max, 3);
        assert_eq!(info.available, 3);

        manager.create_identity(None).unwrap();
        let info = manager.slot_info();
        assert_eq!(info.used, 1);
        assert_eq!(info.available, 2);
    }

    #[test]
    fn test_identity_info_serialization() {
        let hash = IdentityHash::from_public_key(b"test");
        let lifecycle = KeyLifecycle::new(1700000000);

        let info = IdentityInfo {
            hash,
            label: Some("Test".to_string()),
            is_primary: true,
            created_at: 1700000000,
            lifecycle,
        };

        let json = serde_json::to_string(&info).unwrap();
        let restored: IdentityInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.label, Some("Test".to_string()));
        assert!(restored.is_primary);
        assert_eq!(restored.created_at, 1700000000);
    }

    #[test]
    fn test_identity_info_is_usable() {
        let hash = IdentityHash::from_public_key(b"test");
        let lifecycle = KeyLifecycle::new(1700000000);

        let info = IdentityInfo {
            hash,
            label: None,
            is_primary: false,
            created_at: 1700000000,
            lifecycle,
        };

        assert!(info.is_usable());
        assert!(!info.is_expiring());
    }

    #[test]
    fn test_create_three_identities_and_switch_primary() {
        let mut manager = IdentityManager::new(test_config());

        // Create 3 identities (the maximum allowed)
        let hash1 = manager.create_identity(Some("First")).unwrap();
        let hash2 = manager.create_identity(Some("Second")).unwrap();
        let hash3 = manager.create_identity(Some("Third")).unwrap();

        assert_eq!(manager.list_identities().len(), 3);

        // First identity should be primary
        assert_eq!(manager.primary_identity_hash(), Some(&hash1));

        // All keypairs should be accessible
        assert!(manager.keypairs.contains_key(&hash1));
        assert!(manager.keypairs.contains_key(&hash2));
        assert!(manager.keypairs.contains_key(&hash3));

        // Switch primary to second identity
        manager.set_primary_identity(&hash2).unwrap();
        assert_eq!(manager.primary_identity_hash(), Some(&hash2));

        // Verify the primary keypair was updated
        let primary_kp = manager.primary_keypair().unwrap();
        assert_eq!(primary_kp.identity_hash(), &hash2);

        // Switch primary to third identity
        manager.set_primary_identity(&hash3).unwrap();
        assert_eq!(manager.primary_identity_hash(), Some(&hash3));
        let primary_kp = manager.primary_keypair().unwrap();
        assert_eq!(primary_kp.identity_hash(), &hash3);

        // Switch back to first identity
        manager.set_primary_identity(&hash1).unwrap();
        assert_eq!(manager.primary_identity_hash(), Some(&hash1));
        let primary_kp = manager.primary_keypair().unwrap();
        assert_eq!(primary_kp.identity_hash(), &hash1);
    }

    #[test]
    fn test_fourth_identity_creation_fails() {
        let mut manager = IdentityManager::new(test_config());

        // Create 3 identities successfully
        manager.create_identity(Some("First")).unwrap();
        manager.create_identity(Some("Second")).unwrap();
        manager.create_identity(Some("Third")).unwrap();

        // Fourth identity should fail
        let result = manager.create_identity(Some("Fourth"));
        assert!(result.is_err());

        // Verify the error is MaxIdentitiesReached
        match result.unwrap_err() {
            CoreError::Identity(veritas_identity::IdentityError::MaxIdentitiesReached { max }) => {
                assert_eq!(max, 3);
            }
            other => panic!("Expected MaxIdentitiesReached, got: {:?}", other),
        }

        // Should still have exactly 3 identities
        assert_eq!(manager.list_identities().len(), 3);
    }

    #[test]
    fn test_all_keypairs_accessible_after_creation() {
        let mut manager = IdentityManager::new(test_config());

        let hash1 = manager.create_identity(Some("First")).unwrap();
        let hash2 = manager.create_identity(Some("Second")).unwrap();

        // Both keypairs should be in the keypairs map
        let kp1 = manager.keypairs.get(&hash1).unwrap();
        let kp2 = manager.keypairs.get(&hash2).unwrap();

        // Verify they have the correct identity hashes
        assert_eq!(kp1.identity_hash(), &hash1);
        assert_eq!(kp2.identity_hash(), &hash2);

        // Verify they are different keypairs
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_set_primary_updates_primary_keypair() {
        let mut manager = IdentityManager::new(test_config());

        let hash1 = manager.create_identity(Some("First")).unwrap();
        let hash2 = manager.create_identity(Some("Second")).unwrap();

        // Initially first is primary
        let primary_kp = manager.primary_keypair().unwrap();
        assert_eq!(primary_kp.identity_hash(), &hash1);

        // Switch to second
        manager.set_primary_identity(&hash2).unwrap();

        // Primary keypair should now return the second identity's keypair
        let primary_kp = manager.primary_keypair().unwrap();
        assert_eq!(primary_kp.identity_hash(), &hash2);
    }
}
