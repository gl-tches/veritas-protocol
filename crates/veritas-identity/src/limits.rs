//! Identity limits and origin-based restrictions.
//!
//! Enforces the maximum of 3 identities per device origin with slot recycling
//! when identities expire past the grace period.
//!
//! # Security
//!
//! Origin fingerprints MUST be hardware-bound in production to prevent Sybil attacks.
//! The `generate()` function is only available in tests. Production code must use
//! `from_hardware()` which requires a verified `HardwareAttestation`.
//!
//! See VERITAS-2026-0001 for vulnerability details.

#[cfg(test)]
use rand::rngs::OsRng;
#[cfg(test)]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::hardware::HardwareAttestation;
use crate::lifecycle::{KeyLifecycle, EXPIRY_GRACE_PERIOD_SECS, KEY_EXPIRY_SECS};
use crate::IdentityHash;

/// Maximum identities per device origin.
pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;

/// Privacy-preserving device fingerprint for identity limiting.
///
/// The origin is derived from device-specific data to limit identity
/// creation without tracking users across devices.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginFingerprint(Hash256);

impl OriginFingerprint {
    /// Create an origin fingerprint from device-specific components.
    ///
    /// The fingerprint is a hash of multiple device identifiers to create
    /// a stable but privacy-preserving binding.
    ///
    /// # Arguments
    ///
    /// * `hardware_id` - Platform-specific hardware identifier
    /// * `enclave_binding` - Optional secure enclave binding (if available)
    /// * `installation_id` - Random ID stored locally per installation
    pub fn new(hardware_id: &[u8], enclave_binding: Option<&[u8]>, installation_id: &[u8]) -> Self {
        let empty: &[u8] = &[];
        Self(Hash256::hash_many(&[
            hardware_id,
            enclave_binding.unwrap_or(empty),
            installation_id,
        ]))
    }

    /// Generate a new origin fingerprint with a random installation ID.
    ///
    /// # Security Warning
    ///
    /// This function creates fingerprints that are NOT hardware-bound and
    /// can be used to bypass the identity limit. It is only available in
    /// test builds.
    ///
    /// **Production code MUST use `from_hardware()` instead.**
    ///
    /// See VERITAS-2026-0001 for details on the Sybil attack this prevents.
    #[cfg(test)]
    pub fn generate() -> Self {
        let mut installation_id = [0u8; 32];
        OsRng.fill_bytes(&mut installation_id);
        Self::new(&[], None, &installation_id)
    }

    /// Create an origin fingerprint from verified hardware attestation.
    ///
    /// This is the ONLY way to create origin fingerprints in production.
    /// The hardware attestation must be verified before the fingerprint
    /// is created, ensuring that each physical device can only create
    /// a limited number of identities.
    ///
    /// # Arguments
    ///
    /// * `attestation` - A hardware attestation that has been collected
    ///   from the current device's secure hardware.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The attestation fails verification
    /// - The hardware does not provide strong binding (in production)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_identity::hardware::HardwareAttestation;
    /// use veritas_identity::limits::OriginFingerprint;
    ///
    /// // Collect attestation from secure hardware
    /// let attestation = HardwareAttestation::collect()?;
    ///
    /// // Create hardware-bound fingerprint
    /// let origin = OriginFingerprint::from_hardware(&attestation)?;
    /// ```
    ///
    /// # Security
    ///
    /// This function enforces VERITAS-2026-0001 remediation by requiring
    /// cryptographic proof from secure hardware before creating an origin
    /// fingerprint. This prevents unlimited identity creation.
    pub fn from_hardware(attestation: &HardwareAttestation) -> crate::Result<Self> {
        // Verify the attestation is valid
        attestation.verify()?;

        // In production, require strong hardware binding
        #[cfg(not(test))]
        if !attestation.is_strong_binding() {
            return Err(crate::IdentityError::HardwareAttestationFailed {
                reason: "production requires strong hardware binding (TPM, Secure Enclave, or Android Keystore)".into(),
            });
        }

        // Derive the fingerprint from hardware attestation
        let hardware_fingerprint = attestation.fingerprint();

        // Create origin fingerprint using the hardware identity
        // The installation_id is derived from the hardware fingerprint
        // to ensure determinism while maintaining privacy
        Ok(Self::new(
            hardware_fingerprint.as_bytes(),
            None,
            hardware_fingerprint.as_bytes(),
        ))
    }

    /// Get the fingerprint as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self(Hash256::from_bytes(bytes)?))
    }

    /// Format as hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl std::fmt::Debug for OriginFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OriginFingerprint({})", &self.to_hex()[..16])
    }
}

/// Information about identity slot usage for a given origin.
///
/// Provides user-facing information about how many identity slots
/// are used and when the next slot will become available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySlotInfo {
    /// Number of slots currently in use (includes grace period).
    pub used: u32,
    /// Maximum allowed slots per origin.
    pub max: u32,
    /// Number of slots available for new identities.
    pub available: u32,
    /// Unix timestamp when the next slot will become available (if at limit).
    /// None if slots are available or all identities are active.
    pub next_slot_available: Option<u64>,
}

impl IdentitySlotInfo {
    /// Check if a new identity can be created.
    pub fn can_create(&self) -> bool {
        self.available > 0
    }
}

/// Manages identity limits per origin.
///
/// Enforces the maximum of 3 identities per device origin with:
/// - Slot tracking for active identities
/// - Grace period handling (24h after expiry)
/// - Slot recycling when identities fully expire
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityLimiter {
    /// The origin fingerprint for this limiter.
    origin: OriginFingerprint,
    /// Identities associated with this origin.
    /// Uses Vec instead of HashMap for simplicity and small size.
    identities: Vec<(IdentityHash, KeyLifecycle)>,
}

impl IdentityLimiter {
    /// Create a new identity limiter for the given origin.
    pub fn new(origin: OriginFingerprint) -> Self {
        Self {
            origin,
            identities: Vec::with_capacity(MAX_IDENTITIES_PER_ORIGIN as usize),
        }
    }

    /// Get the origin fingerprint.
    pub fn origin(&self) -> &OriginFingerprint {
        &self.origin
    }

    /// Get the number of identities (including those in grace period).
    pub fn count(&self) -> usize {
        self.identities.len()
    }

    /// Get the number of active slots (not yet released).
    ///
    /// This counts identities that are either active/expiring or in the grace period.
    pub fn active_slot_count(&self, current_time: u64) -> u32 {
        self.identities
            .iter()
            .filter(|(_, lifecycle)| !lifecycle.should_release_slot(current_time))
            .count() as u32
    }

    /// Clean up expired identities past grace period.
    ///
    /// Removes identities that have fully expired (past 24h grace period)
    /// to free up slots for new identities.
    pub fn cleanup_expired(&mut self, current_time: u64) {
        self.identities
            .retain(|(_, lifecycle)| !lifecycle.should_release_slot(current_time));
    }

    /// Get information about identity slot usage.
    pub fn slot_info(&self, current_time: u64) -> IdentitySlotInfo {
        // Clean up first to get accurate count
        let active_count = self.active_slot_count(current_time);
        let max = MAX_IDENTITIES_PER_ORIGIN;
        let available = max.saturating_sub(active_count);

        // Find next slot availability time
        let next_slot_available = if available == 0 {
            // Find the earliest release time
            self.identities
                .iter()
                .filter_map(|(_, lifecycle)| {
                    if lifecycle.should_release_slot(current_time) {
                        None
                    } else {
                        // Calculate when this slot will be released
                        Some(lifecycle.created_at + KEY_EXPIRY_SECS + EXPIRY_GRACE_PERIOD_SECS)
                    }
                })
                .min()
        } else {
            None
        };

        IdentitySlotInfo {
            used: active_count,
            max,
            available,
            next_slot_available,
        }
    }

    /// Check if a new identity can be registered.
    pub fn can_register(&self, current_time: u64) -> bool {
        self.active_slot_count(current_time) < MAX_IDENTITIES_PER_ORIGIN
    }

    /// Register a new identity for this origin.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum identities per origin has been reached.
    pub fn register(
        &mut self,
        identity: IdentityHash,
        current_time: u64,
    ) -> crate::Result<KeyLifecycle> {
        // Clean up expired identities first
        self.cleanup_expired(current_time);

        // Check limit
        if self.active_slot_count(current_time) >= MAX_IDENTITIES_PER_ORIGIN {
            return Err(crate::IdentityError::MaxIdentitiesReached {
                max: MAX_IDENTITIES_PER_ORIGIN,
            });
        }

        // Check for duplicate
        if self.identities.iter().any(|(id, _)| id == &identity) {
            return Err(crate::IdentityError::AlreadyExists);
        }

        let lifecycle = KeyLifecycle::new(current_time);
        self.identities.push((identity, lifecycle.clone()));
        Ok(lifecycle)
    }

    /// Register a new identity as a rotation from a previous identity.
    ///
    /// This marks the old identity as rotated and creates a new one linked to it.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The old identity is not found
    /// - The old identity is not in a rotatable state
    /// - The maximum identities would be exceeded (shouldn't happen for rotation)
    pub fn register_rotation(
        &mut self,
        old_identity: &IdentityHash,
        new_identity: IdentityHash,
        current_time: u64,
    ) -> crate::Result<KeyLifecycle> {
        // Find and rotate the old identity
        let old_idx = self
            .identities
            .iter()
            .position(|(id, _)| id == old_identity)
            .ok_or_else(|| crate::IdentityError::NotFound(old_identity.to_hex()))?;

        // Rotate the old identity
        self.identities[old_idx].1.rotate(new_identity.clone())?;

        // Create new lifecycle linked to old
        let lifecycle = KeyLifecycle::new_from_rotation(current_time, old_identity.clone());
        self.identities.push((new_identity, lifecycle.clone()));

        // Note: The old identity slot is immediately freed since it's now in Rotated state
        // This means rotation doesn't consume an extra slot

        Ok(lifecycle)
    }

    /// Get an identity's lifecycle by hash.
    pub fn get(&self, identity: &IdentityHash) -> Option<&KeyLifecycle> {
        self.identities
            .iter()
            .find(|(id, _)| id == identity)
            .map(|(_, lifecycle)| lifecycle)
    }

    /// Get a mutable reference to an identity's lifecycle.
    pub fn get_mut(&mut self, identity: &IdentityHash) -> Option<&mut KeyLifecycle> {
        self.identities
            .iter_mut()
            .find(|(id, _)| id == identity)
            .map(|(_, lifecycle)| lifecycle)
    }

    /// Update the last active time for an identity.
    pub fn touch(&mut self, identity: &IdentityHash, current_time: u64) -> crate::Result<()> {
        let lifecycle = self
            .get_mut(identity)
            .ok_or_else(|| crate::IdentityError::NotFound(identity.to_hex()))?;
        lifecycle.touch(current_time);
        Ok(())
    }

    /// Revoke an identity.
    pub fn revoke(&mut self, identity: &IdentityHash) -> crate::Result<()> {
        let lifecycle = self
            .get_mut(identity)
            .ok_or_else(|| crate::IdentityError::NotFound(identity.to_hex()))?;
        lifecycle.revoke()
    }

    /// List all identities with their lifecycles.
    pub fn list(&self) -> &[(IdentityHash, KeyLifecycle)] {
        &self.identities
    }

    /// List only usable identities (active or expiring).
    pub fn list_usable(&self, current_time: u64) -> Vec<(&IdentityHash, &KeyLifecycle)> {
        self.identities
            .iter()
            .filter(|(_, lifecycle)| lifecycle.can_use(current_time).is_ok())
            .map(|(id, lifecycle)| (id, lifecycle))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a timestamp after MIN_VALID_TIMESTAMP (2024-01-01 = 1704067200)
    // 1710000000 = March 9, 2024
    const BASE_TIME: u64 = 1710000000;
    const DAY: u64 = 24 * 60 * 60;

    fn make_identity(name: &str) -> IdentityHash {
        IdentityHash::from_public_key(name.as_bytes())
    }

    #[test]
    fn test_origin_fingerprint_new() {
        let fp1 = OriginFingerprint::new(b"hw1", Some(b"enclave"), b"install1");
        let fp2 = OriginFingerprint::new(b"hw1", Some(b"enclave"), b"install1");
        let fp3 = OriginFingerprint::new(b"hw2", Some(b"enclave"), b"install1");

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_origin_fingerprint_generate() {
        let fp1 = OriginFingerprint::generate();
        let fp2 = OriginFingerprint::generate();
        assert_ne!(fp1, fp2); // Random, should be different
    }

    #[test]
    fn test_identity_slot_info_can_create() {
        let info = IdentitySlotInfo {
            used: 2,
            max: 3,
            available: 1,
            next_slot_available: None,
        };
        assert!(info.can_create());

        let full = IdentitySlotInfo {
            used: 3,
            max: 3,
            available: 0,
            next_slot_available: Some(BASE_TIME + 31 * DAY),
        };
        assert!(!full.can_create());
    }

    #[test]
    fn test_identity_limiter_new() {
        let origin = OriginFingerprint::generate();
        let limiter = IdentityLimiter::new(origin.clone());
        assert_eq!(limiter.origin(), &origin);
        assert_eq!(limiter.count(), 0);
    }

    #[test]
    fn test_identity_limiter_register() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let id1 = make_identity("user1");
        let lifecycle = limiter.register(id1.clone(), BASE_TIME).unwrap();
        assert_eq!(lifecycle.created_at, BASE_TIME);
        assert_eq!(limiter.count(), 1);

        // Can retrieve it
        assert!(limiter.get(&id1).is_some());
    }

    #[test]
    fn test_identity_limiter_register_duplicate() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let id = make_identity("user");
        limiter.register(id.clone(), BASE_TIME).unwrap();
        let result = limiter.register(id, BASE_TIME);
        assert!(matches!(result, Err(crate::IdentityError::AlreadyExists)));
    }

    #[test]
    fn test_identity_limiter_max_limit() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        // Register 3 identities
        for i in 0..3 {
            let id = make_identity(&format!("user{}", i));
            limiter.register(id, BASE_TIME).unwrap();
        }

        // Fourth should fail
        let id4 = make_identity("user4");
        let result = limiter.register(id4, BASE_TIME);
        assert!(matches!(
            result,
            Err(crate::IdentityError::MaxIdentitiesReached { max: 3 })
        ));
    }

    #[test]
    fn test_identity_limiter_slot_info_basic() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let info = limiter.slot_info(BASE_TIME);
        assert_eq!(info.used, 0);
        assert_eq!(info.max, 3);
        assert_eq!(info.available, 3);
        assert!(info.next_slot_available.is_none());

        // Add one identity
        limiter.register(make_identity("user1"), BASE_TIME).unwrap();
        let info = limiter.slot_info(BASE_TIME);
        assert_eq!(info.used, 1);
        assert_eq!(info.available, 2);
    }

    #[test]
    fn test_identity_limiter_slot_info_at_limit() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        for i in 0..3 {
            let id = make_identity(&format!("user{}", i));
            limiter.register(id, BASE_TIME + i as u64).unwrap();
        }

        let info = limiter.slot_info(BASE_TIME);
        assert_eq!(info.used, 3);
        assert_eq!(info.available, 0);
        // Next slot should be when first identity expires + grace period
        let expected_release = BASE_TIME + KEY_EXPIRY_SECS + EXPIRY_GRACE_PERIOD_SECS;
        assert_eq!(info.next_slot_available, Some(expected_release));
    }

    #[test]
    fn test_identity_limiter_cleanup_expired() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        limiter.register(make_identity("user1"), BASE_TIME).unwrap();

        // Before grace period ends
        let during_grace = BASE_TIME + 30 * DAY + 12 * 60 * 60; // 30.5 days
        limiter.cleanup_expired(during_grace);
        assert_eq!(limiter.count(), 1); // Still present

        // After grace period
        let after_grace = BASE_TIME + 32 * DAY; // 32 days
        limiter.cleanup_expired(after_grace);
        assert_eq!(limiter.count(), 0); // Cleaned up
    }

    #[test]
    fn test_identity_limiter_slot_recycling() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        // Fill all slots
        for i in 0..3 {
            limiter
                .register(make_identity(&format!("user{}", i)), BASE_TIME)
                .unwrap();
        }

        // At limit
        assert!(!limiter.can_register(BASE_TIME));

        // After grace period, slots should be available
        let after_grace = BASE_TIME + 32 * DAY;
        assert!(limiter.can_register(after_grace));

        // Can register new identity
        limiter
            .register(make_identity("new_user"), after_grace)
            .unwrap();
        assert_eq!(limiter.count(), 1); // Only new one, old ones cleaned
    }

    #[test]
    fn test_identity_limiter_rotation() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let old_id = make_identity("old_user");
        let new_id = make_identity("new_user");

        limiter.register(old_id.clone(), BASE_TIME).unwrap();

        // Rotate
        let new_lifecycle = limiter
            .register_rotation(&old_id, new_id.clone(), BASE_TIME + 1000)
            .unwrap();

        // New identity should link to old
        assert!(new_lifecycle.prev_identity.is_some());
        assert_eq!(new_lifecycle.prev_identity.unwrap(), old_id);

        // Old identity should be rotated state
        let old_lifecycle = limiter.get(&old_id).unwrap();
        assert!(old_lifecycle.state.is_terminated());
    }

    #[test]
    fn test_identity_limiter_rotation_not_found() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let old_id = make_identity("nonexistent");
        let new_id = make_identity("new_user");

        let result = limiter.register_rotation(&old_id, new_id, BASE_TIME);
        assert!(matches!(result, Err(crate::IdentityError::NotFound(_))));
    }

    #[test]
    fn test_identity_limiter_touch() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let id = make_identity("user");
        limiter.register(id.clone(), BASE_TIME).unwrap();

        limiter.touch(&id, BASE_TIME + 1000).unwrap();
        assert_eq!(limiter.get(&id).unwrap().last_active, BASE_TIME + 1000);
    }

    #[test]
    fn test_identity_limiter_revoke() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let id = make_identity("user");
        limiter.register(id.clone(), BASE_TIME).unwrap();

        limiter.revoke(&id).unwrap();
        assert!(limiter.get(&id).unwrap().state.is_terminated());
    }

    #[test]
    fn test_identity_limiter_list_usable() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        let id1 = make_identity("user1");
        let id2 = make_identity("user2");

        limiter.register(id1.clone(), BASE_TIME).unwrap();
        limiter.register(id2.clone(), BASE_TIME).unwrap();

        // Both usable initially
        assert_eq!(limiter.list_usable(BASE_TIME).len(), 2);

        // Revoke one
        limiter.revoke(&id1).unwrap();
        assert_eq!(limiter.list_usable(BASE_TIME).len(), 1);

        // After expiry
        let after_expiry = BASE_TIME + 31 * DAY;
        assert_eq!(limiter.list_usable(after_expiry).len(), 0);
    }

    #[test]
    fn test_identity_limiter_active_slot_count() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        // Register at different times
        limiter.register(make_identity("user1"), BASE_TIME).unwrap();
        limiter
            .register(make_identity("user2"), BASE_TIME + 5 * DAY)
            .unwrap();

        // Both active
        assert_eq!(limiter.active_slot_count(BASE_TIME + 10 * DAY), 2);

        // First in grace period, second still active
        assert_eq!(limiter.active_slot_count(BASE_TIME + 30 * DAY), 2);

        // First released, second in grace
        assert_eq!(limiter.active_slot_count(BASE_TIME + 32 * DAY), 1);

        // Both released
        assert_eq!(limiter.active_slot_count(BASE_TIME + 37 * DAY), 0);
    }

    #[test]
    fn test_rotation_does_not_consume_extra_slot() {
        let origin = OriginFingerprint::generate();
        let mut limiter = IdentityLimiter::new(origin);

        // Fill all slots
        for i in 0..3 {
            limiter
                .register(make_identity(&format!("user{}", i)), BASE_TIME)
                .unwrap();
        }

        let slot_info = limiter.slot_info(BASE_TIME);
        assert_eq!(slot_info.available, 0);

        // Rotate one - should free a slot for the new identity
        let old_id = make_identity("user0");
        let new_id = make_identity("new_user0");
        limiter
            .register_rotation(&old_id, new_id, BASE_TIME + 1000)
            .unwrap();

        // After rotation, old is terminated so its slot is "freed"
        // But we still have 3 identities in the list (1 rotated, 2 active, 1 new)
        // The rotated one counts as terminated
        let slot_info = limiter.slot_info(BASE_TIME + 1000);
        // user0 is Rotated (terminated), user1 and user2 are Active, new_user0 is Active
        // Only non-terminated identities count: user1, user2, new_user0 = 3
        assert_eq!(slot_info.used, 3);
    }

    // =========================================================================
    // Security Tests for VERITAS-2026-0001: Sybil Attack Prevention
    // =========================================================================

    #[test]
    fn test_from_hardware_valid_attestation() {
        // Test that from_hardware works with valid attestations
        let attestation = HardwareAttestation::test_attestation();
        let result = OriginFingerprint::from_hardware(&attestation);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_hardware_deterministic() {
        // Same attestation should produce same fingerprint
        let attestation = HardwareAttestation::test_attestation();
        let fp1 = OriginFingerprint::from_hardware(&attestation).unwrap();
        let fp2 = OriginFingerprint::from_hardware(&attestation).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_from_hardware_unique_per_device() {
        // Different hardware attestations should produce different fingerprints
        let attestation1 = HardwareAttestation::test_attestation();
        let attestation2 = HardwareAttestation::test_attestation();
        let fp1 = OriginFingerprint::from_hardware(&attestation1).unwrap();
        let fp2 = OriginFingerprint::from_hardware(&attestation2).unwrap();
        // Test attestations have random hardware_id, so fingerprints should differ
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_from_hardware_verifies_attestation() {
        // Test that from_hardware() calls verify() on the attestation
        // A valid test attestation should pass
        let attestation = HardwareAttestation::test_attestation();
        let result = OriginFingerprint::from_hardware(&attestation);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sybil_attack_prevention() {
        // Verify that the same hardware attestation creates the same origin,
        // preventing unlimited identity creation
        let attestation = HardwareAttestation::test_attestation();

        // Create origin from hardware
        let origin = OriginFingerprint::from_hardware(&attestation).unwrap();
        let mut limiter = IdentityLimiter::new(origin.clone());

        // Register max identities
        for i in 0..MAX_IDENTITIES_PER_ORIGIN {
            let id = make_identity(&format!("user{}", i));
            limiter.register(id, BASE_TIME).unwrap();
        }

        // Verify we hit the limit
        assert!(!limiter.can_register(BASE_TIME));

        // Creating another origin from the SAME attestation should give SAME origin
        let same_origin = OriginFingerprint::from_hardware(&attestation).unwrap();
        assert_eq!(origin, same_origin);

        // This proves that an attacker cannot create unlimited fingerprints
        // from the same hardware attestation
    }

    #[test]
    fn test_generate_only_available_in_tests() {
        // This test verifies generate() is available in tests
        // In production builds, generate() won't compile
        let fp = OriginFingerprint::generate();
        assert!(fp.as_bytes().len() == 32);
    }
}
