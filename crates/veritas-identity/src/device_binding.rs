//! Device-binding for interim Sybil resistance.
//!
//! Provides a cryptographic mechanism to bind identities to devices
//! without requiring hardware attestation (which is deferred to v2.0).
//!
//! A device binding creates a persistent, hard-to-forge token that:
//! 1. Ties identities to a specific installation
//! 2. Makes multi-device Sybil attacks detectable
//! 3. Limits identity creation rate per device
//!
//! ## Security Model
//!
//! This is NOT a strong Sybil resistance mechanism — determined attackers
//! can create multiple bindings. It raises the bar for casual Sybil attacks
//! and provides a foundation for hardware attestation in v2.0.

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{IdentityError, Result};
use crate::identity_hash::IdentityHash;

/// Maximum number of identities per device binding.
pub const MAX_IDENTITIES_PER_DEVICE: u32 = 3;

/// Device binding token validity (90 days).
pub const DEVICE_BINDING_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;

/// Maximum number of device bindings tracked per registry.
pub const MAX_DEVICE_BINDINGS: usize = 100_000;

/// Minimum installation ID length in bytes.
pub const MIN_INSTALLATION_ID_LEN: usize = 16;

/// Maximum installation ID length in bytes.
pub const MAX_INSTALLATION_ID_LEN: usize = 64;

/// A device-bound installation secret.
///
/// This is generated once per device installation and persisted.
/// It serves as the root of trust for device binding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret {
    /// 32-byte random secret generated at installation time.
    bytes: [u8; 32],
}

impl DeviceSecret {
    /// Generate a new device secret using OsRng.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        Self { bytes }
    }

    /// Restore from persisted bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Derive the device fingerprint from this secret.
    ///
    /// The fingerprint is a non-reversible hash that can be shared publicly.
    pub fn fingerprint(&self) -> DeviceFingerprint {
        let hash = Hash256::hash_many(&[
            b"VERITAS-v1.DEVICE-BINDING.fingerprint",
            &self.bytes,
        ]);
        DeviceFingerprint(hash)
    }

    /// Sign a device binding token.
    ///
    /// Uses BLAKE3 keyed hash (not ML-DSA) since this is a symmetric binding.
    pub fn sign_binding(&self, payload: &[u8]) -> [u8; 32] {
        Hash256::hash_many(&[
            b"VERITAS-v1.DEVICE-BINDING.sign",
            &self.bytes,
            payload,
        ])
        .to_bytes()
    }

    /// Verify a device binding signature.
    pub fn verify_binding(&self, payload: &[u8], signature: &[u8; 32]) -> bool {
        let expected = self.sign_binding(payload);
        // Constant-time comparison
        subtle::ConstantTimeEq::ct_eq(&expected[..], &signature[..]).into()
    }
}

impl std::fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A non-reversible fingerprint derived from a DeviceSecret.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceFingerprint(Hash256);

impl DeviceFingerprint {
    /// Create from raw hash.
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Get the fingerprint as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get hex representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Short display (first 16 hex chars).
    pub fn short(&self) -> String {
        let hex = self.to_hex();
        format!("{}...", &hex[..16])
    }
}

/// A device binding token that ties an identity to a device.
///
/// This token is presented at identity registration time and stored on-chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceBindingToken {
    /// Device fingerprint (derived from device secret).
    pub device_fingerprint: DeviceFingerprint,
    /// Identity hash being bound.
    pub identity_hash: IdentityHash,
    /// Platform identifier (e.g., "android", "ios", "desktop-linux").
    pub platform: String,
    /// Timestamp when binding was created.
    pub created_at: u64,
    /// BLAKE3 keyed hash proving device possession.
    pub binding_proof: [u8; 32],
    /// Installation ID (persistent per app install).
    pub installation_id: Vec<u8>,
}

impl DeviceBindingToken {
    /// Create a new device binding token.
    pub fn create(
        device_secret: &DeviceSecret,
        identity_hash: IdentityHash,
        platform: String,
        timestamp: u64,
        installation_id: Vec<u8>,
    ) -> Result<Self> {
        // Validate installation ID
        if installation_id.len() < MIN_INSTALLATION_ID_LEN {
            return Err(IdentityError::Validation(format!(
                "installation ID too short: {} < {}",
                installation_id.len(),
                MIN_INSTALLATION_ID_LEN
            )));
        }
        if installation_id.len() > MAX_INSTALLATION_ID_LEN {
            return Err(IdentityError::Validation(format!(
                "installation ID too long: {} > {}",
                installation_id.len(),
                MAX_INSTALLATION_ID_LEN
            )));
        }
        // Validate platform
        if platform.is_empty() || platform.len() > 32 {
            return Err(IdentityError::Validation(
                "platform identifier must be 1-32 characters".into(),
            ));
        }
        // Validate timestamp (reject before 2024-01-01 or after 2100-01-01)
        if timestamp < 1704067200 || timestamp > 4102444800 {
            return Err(IdentityError::Validation(
                "invalid binding timestamp".into(),
            ));
        }

        let device_fingerprint = device_secret.fingerprint();
        let payload = Self::compute_binding_payload(
            &device_fingerprint,
            &identity_hash,
            &platform,
            timestamp,
            &installation_id,
        );
        let binding_proof = device_secret.sign_binding(&payload);

        Ok(Self {
            device_fingerprint,
            identity_hash,
            platform,
            created_at: timestamp,
            binding_proof,
            installation_id,
        })
    }

    /// Compute the binding payload that is signed.
    fn compute_binding_payload(
        device_fingerprint: &DeviceFingerprint,
        identity_hash: &IdentityHash,
        platform: &str,
        timestamp: u64,
        installation_id: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(b"VERITAS-v1.DEVICE-BINDING.token");
        payload.extend_from_slice(device_fingerprint.as_bytes());
        payload.extend_from_slice(identity_hash.as_bytes());
        payload.extend_from_slice(&(platform.len() as u16).to_be_bytes());
        payload.extend_from_slice(platform.as_bytes());
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(installation_id);
        payload
    }

    /// Verify this token's binding proof using the device secret.
    pub fn verify(&self, device_secret: &DeviceSecret) -> bool {
        let expected_fingerprint = device_secret.fingerprint();
        if self.device_fingerprint != expected_fingerprint {
            return false;
        }
        let payload = Self::compute_binding_payload(
            &self.device_fingerprint,
            &self.identity_hash,
            &self.platform,
            self.created_at,
            &self.installation_id,
        );
        device_secret.verify_binding(&payload, &self.binding_proof)
    }

    /// Check if this binding has expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.created_at + DEVICE_BINDING_VALIDITY_SECS
    }

    /// Get the hash of this binding token (for on-chain reference).
    pub fn hash(&self) -> Hash256 {
        let serialized = bincode::serialize(self).unwrap_or_default();
        Hash256::hash_many(&[b"VERITAS-DEVICE-BINDING-v1", &serialized])
    }
}

/// Registry for tracking device bindings and enforcing per-device limits.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceBindingRegistry {
    /// Bindings indexed by device fingerprint.
    bindings: std::collections::HashMap<[u8; 32], Vec<DeviceBindingToken>>,
    /// Quick lookup: identity -> device fingerprint.
    identity_to_device: std::collections::HashMap<IdentityHash, [u8; 32]>,
}

impl DeviceBindingRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device binding.
    pub fn register_binding(&mut self, token: DeviceBindingToken) -> Result<()> {
        // Check total registry size
        let total: usize = self.bindings.values().map(|v| v.len()).sum();
        if total >= MAX_DEVICE_BINDINGS {
            return Err(IdentityError::Validation(
                "device binding registry full".into(),
            ));
        }

        let fp_bytes = *token.device_fingerprint.as_bytes();

        // Check per-device limit
        let existing = self.bindings.entry(fp_bytes).or_default();
        let active_count = existing
            .iter()
            .filter(|b| !b.is_expired(token.created_at))
            .count() as u32;
        if active_count >= MAX_IDENTITIES_PER_DEVICE {
            return Err(IdentityError::MaxIdentitiesReached {
                max: MAX_IDENTITIES_PER_DEVICE,
            });
        }

        // Check for duplicate identity binding
        if self.identity_to_device.contains_key(&token.identity_hash) {
            return Err(IdentityError::AlreadyExists);
        }

        self.identity_to_device
            .insert(token.identity_hash.clone(), fp_bytes);
        existing.push(token);
        Ok(())
    }

    /// Check if a device can register more identities.
    pub fn can_register(
        &self,
        device_fingerprint: &DeviceFingerprint,
        current_time: u64,
    ) -> bool {
        let fp_bytes = device_fingerprint.as_bytes();
        self.bindings
            .get(fp_bytes)
            .map(|bindings| {
                let active = bindings
                    .iter()
                    .filter(|b| !b.is_expired(current_time))
                    .count();
                (active as u32) < MAX_IDENTITIES_PER_DEVICE
            })
            .unwrap_or(true)
    }

    /// Check if an identity is bound to a device.
    pub fn is_bound(&self, identity: &IdentityHash) -> bool {
        self.identity_to_device.contains_key(identity)
    }

    /// Get the device fingerprint for an identity.
    pub fn get_device_for_identity(
        &self,
        identity: &IdentityHash,
    ) -> Option<DeviceFingerprint> {
        self.identity_to_device.get(identity).map(|bytes| {
            // bytes is &[u8; 32], which is always valid for Hash256
            DeviceFingerprint::from_hash(
                Hash256::from_bytes(bytes).expect("stored fingerprint is always 32 bytes"),
            )
        })
    }

    /// Detect cross-device collusion: identities from the same device.
    pub fn get_identities_for_device(
        &self,
        device_fingerprint: &DeviceFingerprint,
    ) -> Vec<IdentityHash> {
        let fp_bytes = device_fingerprint.as_bytes();
        self.bindings
            .get(fp_bytes)
            .map(|bindings| {
                bindings
                    .iter()
                    .map(|b| b.identity_hash.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get total number of tracked bindings.
    pub fn total_bindings(&self) -> usize {
        self.bindings.values().map(|v| v.len()).sum()
    }

    /// Clean up expired bindings.
    pub fn cleanup_expired(&mut self, current_time: u64) {
        for bindings in self.bindings.values_mut() {
            bindings.retain(|b| !b.is_expired(current_time));
        }
        // Remove empty entries
        self.bindings.retain(|_, v| !v.is_empty());
        // Rebuild identity lookup
        self.identity_to_device.clear();
        for (fp, bindings) in &self.bindings {
            for b in bindings {
                self.identity_to_device
                    .insert(b.identity_hash.clone(), *fp);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test identity hash from a label.
    fn test_identity(label: &str) -> IdentityHash {
        IdentityHash::from_public_key(label.as_bytes())
    }

    /// Helper to create a valid installation ID.
    fn test_installation_id() -> Vec<u8> {
        vec![0xAB; 32]
    }

    /// Helper to get a valid test timestamp (2025-06-01).
    fn test_timestamp() -> u64 {
        1748736000
    }

    // ======================================================================
    // DeviceSecret tests
    // ======================================================================

    #[test]
    fn test_device_secret_generate() {
        let secret1 = DeviceSecret::generate();
        let secret2 = DeviceSecret::generate();
        // Two generated secrets should be different (with overwhelming probability)
        assert_ne!(secret1.bytes, secret2.bytes);
    }

    #[test]
    fn test_device_secret_from_bytes() {
        let bytes = [42u8; 32];
        let secret = DeviceSecret::from_bytes(bytes);
        assert_eq!(secret.bytes, bytes);
    }

    #[test]
    fn test_device_secret_fingerprint_deterministic() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let fp1 = secret.fingerprint();
        let fp2 = secret.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_device_secret_fingerprint_different_secrets() {
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);
        assert_ne!(secret1.fingerprint(), secret2.fingerprint());
    }

    #[test]
    fn test_device_secret_sign_verify() {
        let secret = DeviceSecret::from_bytes([7u8; 32]);
        let payload = b"test payload data";
        let signature = secret.sign_binding(payload);
        assert!(secret.verify_binding(payload, &signature));
    }

    #[test]
    fn test_device_secret_verify_wrong_payload() {
        let secret = DeviceSecret::from_bytes([7u8; 32]);
        let signature = secret.sign_binding(b"correct payload");
        assert!(!secret.verify_binding(b"wrong payload", &signature));
    }

    #[test]
    fn test_device_secret_verify_wrong_secret() {
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);
        let payload = b"test payload";
        let signature = secret1.sign_binding(payload);
        assert!(!secret2.verify_binding(payload, &signature));
    }

    #[test]
    fn test_device_secret_verify_tampered_signature() {
        let secret = DeviceSecret::from_bytes([7u8; 32]);
        let payload = b"test payload";
        let mut signature = secret.sign_binding(payload);
        signature[0] ^= 0xFF; // Tamper with one byte
        assert!(!secret.verify_binding(payload, &signature));
    }

    #[test]
    fn test_device_secret_sign_deterministic() {
        let secret = DeviceSecret::from_bytes([3u8; 32]);
        let payload = b"deterministic test";
        let sig1 = secret.sign_binding(payload);
        let sig2 = secret.sign_binding(payload);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_device_secret_debug_redacted() {
        let secret = DeviceSecret::from_bytes([99u8; 32]);
        let debug = format!("{:?}", secret);
        assert!(debug.contains("[REDACTED]"));
        // Ensure the actual bytes are NOT in the debug output
        assert!(!debug.contains("99"));
    }

    // ======================================================================
    // DeviceFingerprint tests
    // ======================================================================

    #[test]
    fn test_device_fingerprint_from_hash() {
        let hash = Hash256::hash(b"test fingerprint data");
        let fp = DeviceFingerprint::from_hash(hash.clone());
        assert_eq!(fp.as_bytes(), hash.as_bytes());
    }

    #[test]
    fn test_device_fingerprint_to_hex() {
        let secret = DeviceSecret::from_bytes([5u8; 32]);
        let fp = secret.fingerprint();
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_device_fingerprint_short() {
        let secret = DeviceSecret::from_bytes([5u8; 32]);
        let fp = secret.fingerprint();
        let short = fp.short();
        assert_eq!(short.len(), 19); // 16 hex chars + "..."
        assert!(short.ends_with("..."));
    }

    #[test]
    fn test_device_fingerprint_eq() {
        let hash = Hash256::hash(b"same data");
        let fp1 = DeviceFingerprint::from_hash(hash.clone());
        let fp2 = DeviceFingerprint::from_hash(hash);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_device_fingerprint_ne() {
        let fp1 = DeviceFingerprint::from_hash(Hash256::hash(b"data1"));
        let fp2 = DeviceFingerprint::from_hash(Hash256::hash(b"data2"));
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_device_fingerprint_serialization_roundtrip() {
        let secret = DeviceSecret::from_bytes([10u8; 32]);
        let fp = secret.fingerprint();
        let serialized = bincode::serialize(&fp).unwrap();
        let deserialized: DeviceFingerprint = bincode::deserialize(&serialized).unwrap();
        assert_eq!(fp, deserialized);
    }

    // ======================================================================
    // DeviceBindingToken creation and validation tests
    // ======================================================================

    #[test]
    fn test_token_create_valid() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");
        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        assert_eq!(token.device_fingerprint, secret.fingerprint());
        assert_eq!(token.identity_hash, identity);
        assert_eq!(token.platform, "desktop-linux");
        assert_eq!(token.created_at, test_timestamp());
        assert_eq!(token.installation_id, test_installation_id());
    }

    #[test]
    fn test_token_create_installation_id_too_short() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            vec![0u8; MIN_INSTALLATION_ID_LEN - 1],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("too short")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_installation_id_too_long() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            vec![0u8; MAX_INSTALLATION_ID_LEN + 1],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("too long")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_installation_id_min_length() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            vec![0xAB; MIN_INSTALLATION_ID_LEN],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_create_installation_id_max_length() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            vec![0xAB; MAX_INSTALLATION_ID_LEN],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_create_empty_platform() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "".to_string(),
            test_timestamp(),
            test_installation_id(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("platform")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_platform_too_long() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "a".repeat(33),
            test_timestamp(),
            test_installation_id(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("platform")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_platform_max_length() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "a".repeat(32),
            test_timestamp(),
            test_installation_id(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_create_timestamp_too_old() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            1704067199, // Just before 2024-01-01
            test_installation_id(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("timestamp")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_timestamp_too_far_future() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            4102444801, // Just after 2100-01-01
            test_installation_id(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::Validation(msg) => assert!(msg.contains("timestamp")),
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_token_create_timestamp_boundary_valid() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        // Exactly 2024-01-01 00:00:00 UTC
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            1704067200,
            test_installation_id(),
        );
        assert!(result.is_ok());

        // Exactly 2100-01-01 00:00:00 UTC
        let result = DeviceBindingToken::create(
            &secret,
            test_identity("bob"),
            "android".to_string(),
            4102444800,
            test_installation_id(),
        );
        assert!(result.is_ok());
    }

    // ======================================================================
    // Token verification tests
    // ======================================================================

    #[test]
    fn test_token_verify_valid() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        assert!(token.verify(&secret));
    }

    #[test]
    fn test_token_verify_wrong_secret() {
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);
        let token = DeviceBindingToken::create(
            &secret1,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        assert!(!token.verify(&secret2));
    }

    #[test]
    fn test_token_verify_tampered_identity() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let mut token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        // Tamper with the identity hash
        token.identity_hash = test_identity("eve");
        assert!(!token.verify(&secret));
    }

    #[test]
    fn test_token_verify_tampered_platform() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let mut token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        token.platform = "android".to_string();
        assert!(!token.verify(&secret));
    }

    #[test]
    fn test_token_verify_tampered_timestamp() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let mut token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        token.created_at += 1;
        assert!(!token.verify(&secret));
    }

    #[test]
    fn test_token_verify_tampered_installation_id() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let mut token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        token.installation_id = vec![0xCD; 32];
        assert!(!token.verify(&secret));
    }

    #[test]
    fn test_token_verify_tampered_proof() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let mut token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        token.binding_proof[0] ^= 0xFF;
        assert!(!token.verify(&secret));
    }

    // ======================================================================
    // Token expiry tests
    // ======================================================================

    #[test]
    fn test_token_not_expired() {
        let token_time = test_timestamp();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            token_time,
            test_installation_id(),
        )
        .unwrap();

        // Right at creation time
        assert!(!token.is_expired(token_time));
        // One second before expiry
        assert!(!token.is_expired(token_time + DEVICE_BINDING_VALIDITY_SECS));
    }

    #[test]
    fn test_token_expired() {
        let token_time = test_timestamp();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            token_time,
            test_installation_id(),
        )
        .unwrap();

        // One second past expiry
        assert!(token.is_expired(token_time + DEVICE_BINDING_VALIDITY_SECS + 1));
        // Well past expiry
        assert!(token.is_expired(token_time + 365 * 24 * 60 * 60));
    }

    // ======================================================================
    // Token hash test
    // ======================================================================

    #[test]
    fn test_token_hash_deterministic() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        let hash1 = token.hash();
        let hash2 = token.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_token_hash_different_tokens() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token1 = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        let token2 = DeviceBindingToken::create(
            &secret,
            test_identity("bob"),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        assert_ne!(token1.hash(), token2.hash());
    }

    // ======================================================================
    // DeviceBindingRegistry tests
    // ======================================================================

    #[test]
    fn test_registry_new_empty() {
        let registry = DeviceBindingRegistry::new();
        assert_eq!(registry.total_bindings(), 0);
    }

    #[test]
    fn test_registry_register_single() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");
        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        registry.register_binding(token).unwrap();
        assert_eq!(registry.total_bindings(), 1);
        assert!(registry.is_bound(&identity));
    }

    #[test]
    fn test_registry_register_up_to_limit() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let identity = test_identity(&format!("user_{}", i));
            let token = DeviceBindingToken::create(
                &secret,
                identity,
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        assert_eq!(registry.total_bindings(), MAX_IDENTITIES_PER_DEVICE as usize);
    }

    #[test]
    fn test_registry_register_exceeds_limit() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        // Fill up to the limit
        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let identity = test_identity(&format!("user_{}", i));
            let token = DeviceBindingToken::create(
                &secret,
                identity,
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        // One more should fail
        let extra_identity = test_identity("extra_user");
        let extra_token = DeviceBindingToken::create(
            &secret,
            extra_identity,
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        let result = registry.register_binding(extra_token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::MaxIdentitiesReached { max: 3 }
        ));
    }

    #[test]
    fn test_registry_different_devices_independent_limits() {
        let mut registry = DeviceBindingRegistry::new();
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);

        // Fill device 1 to the limit
        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let identity = test_identity(&format!("dev1_user_{}", i));
            let token = DeviceBindingToken::create(
                &secret1,
                identity,
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        // Device 2 should still be able to register
        let identity = test_identity("dev2_user_0");
        let token = DeviceBindingToken::create(
            &secret2,
            identity,
            "ios".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        assert!(registry.register_binding(token).is_ok());

        assert_eq!(
            registry.total_bindings(),
            MAX_IDENTITIES_PER_DEVICE as usize + 1
        );
    }

    #[test]
    fn test_registry_reject_duplicate_identity() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");

        let token1 = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token1).unwrap();

        // Try to register the same identity again (even from same device)
        let token2 = DeviceBindingToken::create(
            &secret,
            identity,
            "android".to_string(),
            test_timestamp() + 1,
            test_installation_id(),
        )
        .unwrap();
        let result = registry.register_binding(token2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdentityError::AlreadyExists));
    }

    #[test]
    fn test_registry_reject_duplicate_identity_different_device() {
        let mut registry = DeviceBindingRegistry::new();
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);
        let identity = test_identity("alice");

        let token1 = DeviceBindingToken::create(
            &secret1,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token1).unwrap();

        // Same identity on different device should also fail
        let token2 = DeviceBindingToken::create(
            &secret2,
            identity,
            "ios".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        let result = registry.register_binding(token2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdentityError::AlreadyExists));
    }

    // ======================================================================
    // can_register tests
    // ======================================================================

    #[test]
    fn test_registry_can_register_empty() {
        let registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        assert!(registry.can_register(&secret.fingerprint(), test_timestamp()));
    }

    #[test]
    fn test_registry_can_register_below_limit() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token).unwrap();

        assert!(registry.can_register(&secret.fingerprint(), test_timestamp()));
    }

    #[test]
    fn test_registry_can_register_at_limit() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let token = DeviceBindingToken::create(
                &secret,
                test_identity(&format!("user_{}", i)),
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        assert!(!registry.can_register(&secret.fingerprint(), test_timestamp()));
    }

    #[test]
    fn test_registry_can_register_after_expiry() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let token = DeviceBindingToken::create(
                &secret,
                test_identity(&format!("user_{}", i)),
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        // After expiry, should be able to register again
        let future_time = test_timestamp() + DEVICE_BINDING_VALIDITY_SECS + 1;
        assert!(registry.can_register(&secret.fingerprint(), future_time));
    }

    // ======================================================================
    // is_bound tests
    // ======================================================================

    #[test]
    fn test_registry_is_bound_registered() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");
        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token).unwrap();

        assert!(registry.is_bound(&identity));
    }

    #[test]
    fn test_registry_is_bound_not_registered() {
        let registry = DeviceBindingRegistry::new();
        assert!(!registry.is_bound(&test_identity("unknown")));
    }

    // ======================================================================
    // get_device_for_identity tests
    // ======================================================================

    #[test]
    fn test_registry_get_device_for_identity() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");
        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token).unwrap();

        let fp = registry.get_device_for_identity(&identity);
        assert!(fp.is_some());
        assert_eq!(fp.unwrap(), secret.fingerprint());
    }

    #[test]
    fn test_registry_get_device_for_identity_not_found() {
        let registry = DeviceBindingRegistry::new();
        assert!(registry
            .get_device_for_identity(&test_identity("unknown"))
            .is_none());
    }

    // ======================================================================
    // Cross-device identity detection tests
    // ======================================================================

    #[test]
    fn test_registry_get_identities_for_device() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let id1 = test_identity("alice");
        let id2 = test_identity("bob");

        let token1 = DeviceBindingToken::create(
            &secret,
            id1.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        let token2 = DeviceBindingToken::create(
            &secret,
            id2.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        registry.register_binding(token1).unwrap();
        registry.register_binding(token2).unwrap();

        let identities = registry.get_identities_for_device(&secret.fingerprint());
        assert_eq!(identities.len(), 2);
        assert!(identities.contains(&id1));
        assert!(identities.contains(&id2));
    }

    #[test]
    fn test_registry_get_identities_for_unknown_device() {
        let registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([99u8; 32]);
        let identities = registry.get_identities_for_device(&secret.fingerprint());
        assert!(identities.is_empty());
    }

    #[test]
    fn test_registry_cross_device_detection_separate() {
        let mut registry = DeviceBindingRegistry::new();
        let secret1 = DeviceSecret::from_bytes([1u8; 32]);
        let secret2 = DeviceSecret::from_bytes([2u8; 32]);

        let token1 = DeviceBindingToken::create(
            &secret1,
            test_identity("alice_dev1"),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        let token2 = DeviceBindingToken::create(
            &secret2,
            test_identity("alice_dev2"),
            "ios".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        registry.register_binding(token1).unwrap();
        registry.register_binding(token2).unwrap();

        // Each device should only show its own identity
        let dev1_ids = registry.get_identities_for_device(&secret1.fingerprint());
        let dev2_ids = registry.get_identities_for_device(&secret2.fingerprint());
        assert_eq!(dev1_ids.len(), 1);
        assert_eq!(dev2_ids.len(), 1);
        assert_ne!(dev1_ids[0], dev2_ids[0]);
    }

    // ======================================================================
    // Cleanup expired bindings tests
    // ======================================================================

    #[test]
    fn test_registry_cleanup_expired_removes_old() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");

        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token).unwrap();
        assert_eq!(registry.total_bindings(), 1);
        assert!(registry.is_bound(&identity));

        // Cleanup well past expiry
        let future = test_timestamp() + DEVICE_BINDING_VALIDITY_SECS + 1;
        registry.cleanup_expired(future);
        assert_eq!(registry.total_bindings(), 0);
        assert!(!registry.is_bound(&identity));
    }

    #[test]
    fn test_registry_cleanup_expired_keeps_valid() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let identity = test_identity("alice");

        let token = DeviceBindingToken::create(
            &secret,
            identity.clone(),
            "android".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(token).unwrap();

        // Cleanup before expiry should keep the binding
        registry.cleanup_expired(test_timestamp() + 1000);
        assert_eq!(registry.total_bindings(), 1);
        assert!(registry.is_bound(&identity));
    }

    #[test]
    fn test_registry_cleanup_mixed_expired_and_valid() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        // Create an old binding
        let old_identity = test_identity("old_user");
        let old_time = test_timestamp();
        let old_token = DeviceBindingToken::create(
            &secret,
            old_identity.clone(),
            "android".to_string(),
            old_time,
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(old_token).unwrap();

        // Create a newer binding
        let new_identity = test_identity("new_user");
        let new_time = old_time + DEVICE_BINDING_VALIDITY_SECS; // Created right at old expiry
        let new_token = DeviceBindingToken::create(
            &secret,
            new_identity.clone(),
            "android".to_string(),
            new_time,
            test_installation_id(),
        )
        .unwrap();
        registry.register_binding(new_token).unwrap();

        assert_eq!(registry.total_bindings(), 2);

        // Cleanup at a time when old is expired but new is not
        let cleanup_time = old_time + DEVICE_BINDING_VALIDITY_SECS + 1;
        registry.cleanup_expired(cleanup_time);

        assert_eq!(registry.total_bindings(), 1);
        assert!(!registry.is_bound(&old_identity));
        assert!(registry.is_bound(&new_identity));
    }

    #[test]
    fn test_registry_cleanup_allows_reregistration() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        // Fill up to limit
        for i in 0..MAX_IDENTITIES_PER_DEVICE {
            let token = DeviceBindingToken::create(
                &secret,
                test_identity(&format!("user_{}", i)),
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        // Cannot register more
        assert!(!registry.can_register(&secret.fingerprint(), test_timestamp()));

        // After cleanup of expired, can register again
        let future = test_timestamp() + DEVICE_BINDING_VALIDITY_SECS + 1;
        registry.cleanup_expired(future);
        assert!(registry.can_register(&secret.fingerprint(), future));
    }

    // ======================================================================
    // Registry bounds enforcement tests
    // ======================================================================

    #[test]
    fn test_registry_bounds_constants() {
        assert_eq!(MAX_IDENTITIES_PER_DEVICE, 3);
        assert_eq!(DEVICE_BINDING_VALIDITY_SECS, 90 * 24 * 60 * 60);
        assert_eq!(MAX_DEVICE_BINDINGS, 100_000);
        assert_eq!(MIN_INSTALLATION_ID_LEN, 16);
        assert_eq!(MAX_INSTALLATION_ID_LEN, 64);
    }

    // ======================================================================
    // Serialization roundtrip tests
    // ======================================================================

    #[test]
    fn test_token_serialization_roundtrip() {
        let secret = DeviceSecret::from_bytes([1u8; 32]);
        let token = DeviceBindingToken::create(
            &secret,
            test_identity("alice"),
            "desktop-linux".to_string(),
            test_timestamp(),
            test_installation_id(),
        )
        .unwrap();

        let serialized = bincode::serialize(&token).unwrap();
        let deserialized: DeviceBindingToken = bincode::deserialize(&serialized).unwrap();
        assert_eq!(token, deserialized);
    }

    #[test]
    fn test_registry_serialization_roundtrip() {
        let mut registry = DeviceBindingRegistry::new();
        let secret = DeviceSecret::from_bytes([1u8; 32]);

        for i in 0..2 {
            let token = DeviceBindingToken::create(
                &secret,
                test_identity(&format!("user_{}", i)),
                "android".to_string(),
                test_timestamp(),
                test_installation_id(),
            )
            .unwrap();
            registry.register_binding(token).unwrap();
        }

        let serialized = bincode::serialize(&registry).unwrap();
        let deserialized: DeviceBindingRegistry = bincode::deserialize(&serialized).unwrap();

        assert_eq!(registry.total_bindings(), deserialized.total_bindings());
        assert!(deserialized.is_bound(&test_identity("user_0")));
        assert!(deserialized.is_bound(&test_identity("user_1")));
    }

    // ======================================================================
    // Domain separation tests
    // ======================================================================

    #[test]
    fn test_fingerprint_uses_domain_separation() {
        // Fingerprint should be different from a plain hash of the same bytes
        let secret_bytes = [42u8; 32];
        let secret = DeviceSecret::from_bytes(secret_bytes);
        let fingerprint = secret.fingerprint();
        let plain_hash = Hash256::hash(&secret_bytes);

        assert_ne!(fingerprint.as_bytes(), plain_hash.as_bytes());
    }

    #[test]
    fn test_sign_uses_domain_separation() {
        // Signing should be different from a plain hash of the same data
        let secret = DeviceSecret::from_bytes([42u8; 32]);
        let payload = b"test payload";
        let signature = secret.sign_binding(payload);
        let plain_hash = Hash256::hash(payload);

        assert_ne!(&signature, plain_hash.as_bytes());
    }
}
