//! WASM client implementation.
//!
//! Provides a browser-compatible API for VERITAS protocol operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use wasm_bindgen::prelude::*;

use veritas_crypto::SymmetricKey;
use veritas_identity::{
    EncryptedIdentityKeyPair, IdentityKeyPair, IdentityLimiter, OriginFingerprint,
};

use crate::error::{WasmError, WasmResult};
use crate::identity::{WasmIdentityInfo, WasmIdentitySlotInfo};

/// Get current Unix timestamp in seconds.
///
/// In WASM, uses js_sys::Date::now(). In tests, uses SystemTime.
fn current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// In-memory storage for identities.
#[derive(Clone)]
struct IdentityStore {
    /// Encrypted identity keypairs.
    identities: HashMap<String, EncryptedIdentityKeyPair>,
    /// Optional labels for identities.
    labels: HashMap<String, String>,
    /// Identity limiter for this origin.
    limiter: IdentityLimiter,
}

impl IdentityStore {
    fn new(origin: OriginFingerprint) -> Self {
        Self {
            identities: HashMap::new(),
            labels: HashMap::new(),
            limiter: IdentityLimiter::new(origin),
        }
    }
}

/// Internal state that gets locked/unlocked.
struct UnlockedState {
    /// The password-derived storage key.
    storage_key: SymmetricKey,
    /// Current active identity (if any).
    current_identity: Option<IdentityKeyPair>,
}

/// WASM client for VERITAS protocol.
///
/// Provides identity management and cryptographic operations in the browser.
#[wasm_bindgen]
pub struct WasmClient {
    /// In-memory identity storage.
    store: Arc<Mutex<IdentityStore>>,
    /// Unlocked state (None when locked).
    unlocked: Arc<Mutex<Option<UnlockedState>>>,
    /// Random Argon2 salt for key derivation (B64-encoded string).
    /// Generated per client instance using cryptographic randomness to prevent
    /// pre-computed rainbow table attacks against the hardcoded salt.
    argon2_salt: String,
}

#[wasm_bindgen]
impl WasmClient {
    /// Create a new WASM client with in-memory storage.
    ///
    /// In browser environments, uses browser-derived fingerprint for identity limiting.
    /// This provides Sybil resistance within the browser context.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // For WASM/browser, derive fingerprint from browser-available data
        // This includes: origin URL, user agent, and crypto-random installation ID
        let origin = Self::derive_browser_fingerprint();
        Self::new_with_origin(origin)
    }

    /// Check if the client is currently unlocked.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.lock().unwrap().is_some()
    }

    /// Unlock the client with a password.
    ///
    /// This derives the storage key from the password and makes identities accessible.
    pub fn unlock(&self, password: &str) -> Result<(), JsValue> {
        self.unlock_internal(password).map_err(|e| e.into())
    }

    /// Lock the client.
    ///
    /// Clears the storage key and active identity from memory.
    pub fn lock(&self) -> Result<(), JsValue> {
        self.lock_internal().map_err(|e| e.into())
    }

    /// Shutdown the client and clear all state.
    pub fn shutdown(&self) -> Result<(), JsValue> {
        self.shutdown_internal().map_err(|e| e.into())
    }

    /// Get the current identity hash (if any identity is active).
    ///
    /// Returns hex-encoded hash or None.
    #[wasm_bindgen(js_name = identityHash)]
    pub fn identity_hash(&self) -> Option<String> {
        let unlocked = self.unlocked.lock().unwrap();
        unlocked
            .as_ref()
            .and_then(|state| state.current_identity.as_ref())
            .map(|id| id.identity_hash().to_hex())
    }

    /// Create a new identity with an optional label.
    ///
    /// Returns the identity hash as a hex string.
    #[wasm_bindgen(js_name = createIdentity)]
    pub fn create_identity(&self, label: Option<String>) -> Result<String, JsValue> {
        self.create_identity_internal(label).map_err(|e| e.into())
    }

    /// List all identities.
    ///
    /// Returns a JSON array of identity info objects.
    #[wasm_bindgen(js_name = listIdentities)]
    pub fn list_identities(&self) -> Result<JsValue, JsValue> {
        self.list_identities_internal()
            // WASM-FIX-6: Replace .unwrap() with proper error handling
            .and_then(|v| {
                serde_wasm_bindgen::to_value(&v)
                    .map_err(|e| WasmError::new(format!("Serialization failed: {}", e)))
            })
            .map_err(|e| e.into())
    }

    /// Get identity slot information.
    ///
    /// Returns a JSON object with used/max/available counts.
    #[wasm_bindgen(js_name = identitySlots)]
    pub fn identity_slots(&self) -> Result<JsValue, JsValue> {
        self.identity_slots_internal()
            // WASM-FIX-6: Replace .unwrap() with proper error handling
            .and_then(|v| {
                serde_wasm_bindgen::to_value(&v)
                    .map_err(|e| WasmError::new(format!("Serialization failed: {}", e)))
            })
            .map_err(|e| e.into())
    }

    /// Switch to a different identity by hash.
    #[wasm_bindgen(js_name = switchIdentity)]
    pub fn switch_identity(&self, hash_hex: &str) -> Result<(), JsValue> {
        self.switch_identity_internal(hash_hex)
            .map_err(|e| e.into())
    }

    /// Get public keys for the current identity.
    ///
    /// Returns serialized public keys as bytes.
    #[wasm_bindgen(js_name = getPublicKeys)]
    pub fn get_public_keys(&self) -> Result<Vec<u8>, JsValue> {
        self.get_public_keys_internal().map_err(|e| e.into())
    }
}

impl WasmClient {
    /// Create a client with a specific origin.
    fn new_with_origin(origin: OriginFingerprint) -> Self {
        // Generate a random 16-byte salt for Argon2 key derivation.
        // Each client instance gets a unique salt, preventing pre-computed
        // rainbow table attacks that the previous hardcoded salt allowed.
        let mut salt_bytes = [0u8; 16];
        getrandom::getrandom(&mut salt_bytes).expect("getrandom failed");
        let salt = SaltString::encode_b64(&salt_bytes).expect("Failed to encode Argon2 salt");

        Self {
            store: Arc::new(Mutex::new(IdentityStore::new(origin))),
            unlocked: Arc::new(Mutex::new(None)),
            argon2_salt: salt.to_string(),
        }
    }

    /// Derive a browser fingerprint for identity limiting.
    ///
    /// This collects browser-available data to create a semi-stable fingerprint.
    /// While not as strong as hardware attestation, it provides Sybil resistance
    /// within browser contexts.
    ///
    /// The installation ID is persisted to localStorage so that it survives page
    /// refreshes and browser restarts, providing consistent Sybil resistance.
    fn derive_browser_fingerprint() -> OriginFingerprint {
        use veritas_crypto::Hash256;

        // Collect browser fingerprint components
        let mut fingerprint_data = Vec::new();

        #[cfg(target_arch = "wasm32")]
        {
            // In WASM context, collect browser data
            if let Some(window) = web_sys::window() {
                // Origin URL (e.g., "https://example.com")
                if let Ok(origin) = window.location().origin() {
                    fingerprint_data.extend_from_slice(origin.as_bytes());
                }

                // User agent
                if let Ok(navigator) = window.navigator().user_agent() {
                    fingerprint_data.extend_from_slice(navigator.as_bytes());
                }
            }
        }

        // Add domain separator
        fingerprint_data.extend_from_slice(b"VERITAS-BROWSER-FINGERPRINT-v1");

        // Hash the collected data to create hardware_id equivalent
        let hardware_id = Hash256::hash(&fingerprint_data);

        // Load or create a persistent installation ID.
        // On WASM, this is stored in localStorage so it survives page refreshes.
        // On native (tests), a fresh random ID is generated each time.
        let installation_id = Self::load_or_create_installation_id();

        OriginFingerprint::new(hardware_id.as_bytes(), None, &installation_id)
    }

    /// Load an existing installation ID from persistent storage, or create and
    /// persist a new one if none exists.
    ///
    /// On WASM targets, localStorage is used for persistence. On native targets
    /// (used in tests), a fresh random ID is generated each time.
    fn load_or_create_installation_id() -> [u8; 32] {
        #[cfg(target_arch = "wasm32")]
        {
            const STORAGE_KEY: &str = "veritas-installation-id";

            // Try to load existing installation ID from localStorage
            if let Some(hex_str) = Self::get_local_storage_item(STORAGE_KEY) {
                if let Some(bytes) = Self::hex_decode_32(&hex_str) {
                    return bytes;
                }
                // If decoding fails, fall through to generate a new one
            }

            // Generate a new installation ID using cryptographic randomness
            let mut installation_id = [0u8; 32];
            getrandom::getrandom(&mut installation_id).expect("getrandom failed");

            // Persist to localStorage for future sessions
            let hex_str = Self::hex_encode(&installation_id);
            Self::set_local_storage_item(STORAGE_KEY, &hex_str);

            installation_id
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut installation_id = [0u8; 32];
            getrandom::getrandom(&mut installation_id).expect("getrandom failed");
            installation_id
        }
    }

    /// Retrieve a value from browser localStorage.
    #[cfg(target_arch = "wasm32")]
    fn get_local_storage_item(key: &str) -> Option<String> {
        let window = web_sys::window()?;
        let storage = window.local_storage().ok()??;
        storage.get_item(key).ok()?
    }

    /// Store a value in browser localStorage.
    #[cfg(target_arch = "wasm32")]
    fn set_local_storage_item(key: &str, value: &str) {
        if let Some(window) = web_sys::window() {
            if let Ok(Some(storage)) = window.local_storage() {
                let _ = storage.set_item(key, value);
            }
        }
    }

    /// Encode a byte slice as a lowercase hex string.
    #[cfg(target_arch = "wasm32")]
    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode a 64-character hex string into a 32-byte array.
    /// Returns None if the string is not valid hex or wrong length.
    #[cfg(target_arch = "wasm32")]
    fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(bytes)
    }

    fn unlock_internal(&self, password: &str) -> WasmResult<()> {
        // Derive storage key from password using Argon2 with a per-instance random salt.
        // The salt is generated at client creation time using cryptographic randomness,
        // preventing pre-computed rainbow table attacks.
        let salt = SaltString::from_b64(&self.argon2_salt)
            .map_err(|_| WasmError::new("Failed to create salt"))?;

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| WasmError::new("Failed to derive key from password"))?;

        // Extract the first 32 bytes of the hash as the storage key
        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| WasmError::new("No hash produced"))?;
        let key_bytes = hash_bytes.as_bytes();
        if key_bytes.len() < 32 {
            return Err(WasmError::new("Derived key too short"));
        }

        let storage_key = SymmetricKey::from_bytes(&key_bytes[..32])?;

        let mut unlocked = self.unlocked.lock().unwrap();
        *unlocked = Some(UnlockedState {
            storage_key,
            current_identity: None,
        });

        Ok(())
    }

    fn lock_internal(&self) -> WasmResult<()> {
        let mut unlocked = self.unlocked.lock().unwrap();
        *unlocked = None;
        Ok(())
    }

    fn shutdown_internal(&self) -> WasmResult<()> {
        // Lock first
        self.lock_internal()?;

        // Clear store
        let mut store = self.store.lock().unwrap();
        store.identities.clear();
        store.labels.clear();

        Ok(())
    }

    fn create_identity_internal(&self, label: Option<String>) -> WasmResult<String> {
        // Check unlocked
        let mut unlocked = self.unlocked.lock().unwrap();
        let unlocked_state = unlocked
            .as_mut()
            .ok_or_else(|| WasmError::new("Client is locked"))?;

        // Generate new identity
        let identity = IdentityKeyPair::generate();
        let hash = identity.identity_hash().clone();
        let hash_hex = hash.to_hex();

        // Get current time
        let current_time = current_timestamp();

        // Register with limiter
        let mut store = self.store.lock().unwrap();
        store.limiter.register(hash.clone(), current_time)?;

        // Encrypt and store
        let encrypted = identity.to_encrypted(&unlocked_state.storage_key)?;
        store.identities.insert(hash_hex.clone(), encrypted);

        // Store label if provided
        if let Some(label) = label {
            store.labels.insert(hash_hex.clone(), label);
        }

        // Set as current identity
        unlocked_state.current_identity = Some(identity);

        Ok(hash_hex)
    }

    fn list_identities_internal(&self) -> WasmResult<Vec<WasmIdentityInfo>> {
        // Check unlocked
        let _unlocked = self.unlocked.lock().unwrap();
        if _unlocked.is_none() {
            return Err(WasmError::new("Client is locked"));
        }

        let store = self.store.lock().unwrap();
        let current_time = current_timestamp();

        let mut infos = Vec::new();
        for (hash, lifecycle) in store.limiter.list() {
            let label = store.labels.get(&hash.to_hex()).cloned();
            let info = WasmIdentityInfo::from_internal(hash, label, lifecycle, current_time);
            infos.push(info);
        }

        Ok(infos)
    }

    fn identity_slots_internal(&self) -> WasmResult<WasmIdentitySlotInfo> {
        let store = self.store.lock().unwrap();
        let current_time = current_timestamp();
        let info = store.limiter.slot_info(current_time);
        Ok(info.into())
    }

    fn switch_identity_internal(&self, hash_hex: &str) -> WasmResult<()> {
        // Check unlocked
        let mut unlocked = self.unlocked.lock().unwrap();
        let unlocked_state = unlocked
            .as_mut()
            .ok_or_else(|| WasmError::new("Client is locked"))?;

        // Find encrypted identity
        let store = self.store.lock().unwrap();
        let encrypted = store
            .identities
            .get(hash_hex)
            .ok_or_else(|| WasmError::new("Identity not found"))?;

        // Decrypt
        let identity = IdentityKeyPair::from_encrypted(encrypted, &unlocked_state.storage_key)?;

        // Set as current
        unlocked_state.current_identity = Some(identity);

        Ok(())
    }

    fn get_public_keys_internal(&self) -> WasmResult<Vec<u8>> {
        let unlocked = self.unlocked.lock().unwrap();
        let identity = unlocked
            .as_ref()
            .and_then(|state| state.current_identity.as_ref())
            .ok_or_else(|| WasmError::new("No identity active"))?;

        Ok(identity.public_keys().to_bytes())
    }
}

impl Default for WasmClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test client with a random fingerprint (test-only)
    fn create_test_client() -> WasmClient {
        // Create a random origin fingerprint for testing
        let mut hardware_id = [0u8; 32];
        let mut installation_id = [0u8; 32];
        getrandom::getrandom(&mut hardware_id).expect("getrandom failed");
        getrandom::getrandom(&mut installation_id).expect("getrandom failed");
        let origin = OriginFingerprint::new(&hardware_id, None, &installation_id);
        WasmClient::new_with_origin(origin)
    }

    #[test]
    fn test_client_lifecycle() {
        let client = create_test_client();

        // Initially locked
        assert!(!client.is_unlocked());

        // Unlock
        client.unlock_internal("test-password").unwrap();
        assert!(client.is_unlocked());

        // Lock
        client.lock_internal().unwrap();
        assert!(!client.is_unlocked());
    }

    #[test]
    fn test_create_identity_when_locked() {
        let client = create_test_client();
        let result = client.create_identity_internal(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_identity_when_unlocked() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();

        let hash = client
            .create_identity_internal(Some("Test Identity".to_string()))
            .unwrap();
        assert_eq!(hash.len(), 64); // Hex hash

        // Should be current identity
        assert_eq!(client.identity_hash(), Some(hash));
    }

    #[test]
    fn test_list_identities() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();

        client
            .create_identity_internal(Some("Alice".to_string()))
            .unwrap();
        client
            .create_identity_internal(Some("Bob".to_string()))
            .unwrap();

        let identities = client.list_identities_internal().unwrap();
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn test_identity_slots() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();

        let slots = client.identity_slots_internal().unwrap();
        assert_eq!(slots.max(), 3);
        assert_eq!(slots.used(), 0);
        assert_eq!(slots.available(), 3);

        // Create one
        client.create_identity_internal(None).unwrap();
        let slots = client.identity_slots_internal().unwrap();
        assert_eq!(slots.used(), 1);
        assert_eq!(slots.available(), 2);
    }

    #[test]
    fn test_switch_identity() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();

        let hash1 = client.create_identity_internal(None).unwrap();
        let hash2 = client.create_identity_internal(None).unwrap();

        // Currently hash2
        assert_eq!(client.identity_hash(), Some(hash2.clone()));

        // Switch to hash1
        client.switch_identity_internal(&hash1).unwrap();
        assert_eq!(client.identity_hash(), Some(hash1));
    }

    #[test]
    fn test_get_public_keys() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();
        client.create_identity_internal(None).unwrap();

        let public_keys = client.get_public_keys_internal().unwrap();
        assert!(!public_keys.is_empty());
    }

    #[test]
    fn test_shutdown() {
        let client = create_test_client();
        client.unlock_internal("test-password").unwrap();
        client.create_identity_internal(None).unwrap();

        client.shutdown_internal().unwrap();

        // Should be locked
        assert!(!client.is_unlocked());

        // Store should be empty
        let store = client.store.lock().unwrap();
        assert_eq!(store.identities.len(), 0);
    }
}
