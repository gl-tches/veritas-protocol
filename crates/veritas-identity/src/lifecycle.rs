//! Key lifecycle management.
//!
//! Provides key state tracking, expiry detection, and rotation support.
//! Keys have a 30-day lifecycle with a 5-day warning period before expiry.
//!
//! ## Security: Time Validation (VERITAS-2026-0008)
//!
//! All time-based operations validate timestamps to prevent manipulation:
//! - Future timestamps (beyond allowed clock skew) are treated as expired
//! - Ancient timestamps (before protocol inception) are treated as expired
//! - This prevents attackers from bypassing expiry checks with invalid times

use serde::{Deserialize, Serialize};

use crate::IdentityHash;

// === Identity Lifecycle Constants ===
// Note: These are duplicated from veritas-protocol::limits to avoid circular dependency.
// veritas-protocol depends on veritas-identity for IdentityHash, so we can't depend on it.

/// Key expiry time in seconds (30 days).
pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;

/// Warning period before key expiry (5 days).
pub const KEY_WARNING_SECS: u64 = 5 * 24 * 60 * 60;

/// Grace period after key expiry (24 hours).
pub const EXPIRY_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60;

// === Rotation Grace Period (VERITAS-2026-0091) ===

/// Grace period after key rotation before old key is destroyed (1 hour).
///
/// SECURITY (VERITAS-2026-0091): This grace period allows pending messages encrypted
/// with the old key to be decrypted before the key is permanently destroyed.
/// After this period, the old key MUST be removed from storage to enforce
/// Perfect Forward Secrecy (PFS).
///
/// **Important**: The old key WILL be destroyed after this period. Any messages
/// encrypted with the old key that are not received within this window will be
/// permanently unreadable.
pub const ROTATION_GRACE_PERIOD_SECS: u64 = 60 * 60; // 1 hour

// === Time Validation Constants (VERITAS-2026-0008) ===
// Duplicated from veritas-core::time to avoid circular dependency.

/// Maximum allowed clock skew in seconds (5 minutes).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC).
pub const MIN_VALID_TIMESTAMP: u64 = 1704067200;

/// Maximum valid timestamp (2100-01-01 00:00:00 UTC).
pub const MAX_VALID_TIMESTAMP: u64 = 4102444800;

/// State of an identity key.
///
/// Keys progress through states: Active -> Expiring -> Expired.
/// Keys can also be manually Rotated or Revoked.
///
/// ## Security (VERITAS-2026-0091)
///
/// When a key is rotated, it enters the `Rotated` state with a timestamp.
/// After `ROTATION_GRACE_PERIOD_SECS` (1 hour), the old key should be
/// destroyed from storage to enforce Perfect Forward Secrecy (PFS).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is active and valid for use.
    Active,
    /// Key is within 5 days of expiry (warning period).
    Expiring,
    /// Key has expired and cannot be used for new operations.
    Expired,
    /// Key has been rotated to a new identity.
    ///
    /// SECURITY (VERITAS-2026-0091): After `ROTATION_GRACE_PERIOD_SECS`,
    /// the old key material should be destroyed from storage.
    Rotated {
        /// The new identity that this key was rotated to.
        new_identity: [u8; 32],
        /// Unix timestamp when the rotation occurred (for PFS grace period).
        #[serde(default)]
        rotated_at: u64,
    },
    /// Key has been manually revoked.
    Revoked,
}

impl KeyState {
    /// Check if the key is usable for operations.
    pub fn is_usable(&self) -> bool {
        matches!(self, KeyState::Active | KeyState::Expiring)
    }

    /// Check if the key has been terminated (expired, rotated, or revoked).
    pub fn is_terminated(&self) -> bool {
        matches!(
            self,
            KeyState::Expired | KeyState::Rotated { .. } | KeyState::Revoked
        )
    }

    /// Get a string representation for error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyState::Active => "Active",
            KeyState::Expiring => "Expiring",
            KeyState::Expired => "Expired",
            KeyState::Rotated { .. } => "Rotated",
            KeyState::Revoked => "Revoked",
        }
    }
}

impl KeyState {
    /// Check if this rotated key's grace period has expired.
    ///
    /// SECURITY (VERITAS-2026-0091): After the rotation grace period expires,
    /// the old key material should be destroyed from storage to enforce PFS.
    ///
    /// Returns `None` if the key is not in Rotated state, otherwise returns
    /// `Some(true)` if the grace period has expired.
    pub fn rotation_grace_expired(&self, current_time: u64) -> Option<bool> {
        if let KeyState::Rotated { rotated_at, .. } = self {
            let elapsed = current_time.saturating_sub(*rotated_at);
            Some(elapsed >= ROTATION_GRACE_PERIOD_SECS)
        } else {
            None
        }
    }

    /// Get the rotation timestamp if this key is in Rotated state.
    pub fn rotation_time(&self) -> Option<u64> {
        if let KeyState::Rotated { rotated_at, .. } = self {
            Some(*rotated_at)
        } else {
            None
        }
    }

    /// Check if decryption with this key should still be allowed.
    ///
    /// SECURITY (VERITAS-2026-0091): For rotated keys, decryption is only
    /// allowed during the grace period. After that, decryption fails even
    /// if the key material still exists (defensive check).
    ///
    /// For other terminated states (Expired, Revoked), decryption is never allowed.
    pub fn allows_decryption(&self, current_time: u64) -> bool {
        match self {
            KeyState::Active | KeyState::Expiring => true,
            KeyState::Rotated { rotated_at, .. } => {
                // Allow decryption only during grace period
                let elapsed = current_time.saturating_sub(*rotated_at);
                elapsed < ROTATION_GRACE_PERIOD_SECS
            }
            KeyState::Expired | KeyState::Revoked => false,
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Active => write!(f, "Active"),
            KeyState::Expiring => write!(f, "Expiring"),
            KeyState::Expired => write!(f, "Expired"),
            KeyState::Rotated { new_identity, rotated_at } => {
                write!(f, "Rotated({}... at {})", hex::encode(&new_identity[..8]), rotated_at)
            }
            KeyState::Revoked => write!(f, "Revoked"),
        }
    }
}

/// Key lifecycle management.
///
/// Tracks the creation, last activity, and state of an identity key.
/// Provides methods to check expiry status and perform key rotation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyLifecycle {
    /// Unix timestamp when the key was created.
    pub created_at: u64,
    /// Unix timestamp of last activity (message sent/received).
    pub last_active: u64,
    /// Current state of the key.
    pub state: KeyState,
    /// Previous identity if this was created via rotation.
    pub prev_identity: Option<IdentityHash>,
}

impl KeyLifecycle {
    /// Create a new key lifecycle starting in Active state.
    pub fn new(current_time: u64) -> Self {
        Self {
            created_at: current_time,
            last_active: current_time,
            state: KeyState::Active,
            prev_identity: None,
        }
    }

    /// Create a new key lifecycle as a rotation from a previous identity.
    pub fn new_from_rotation(current_time: u64, prev_identity: IdentityHash) -> Self {
        Self {
            created_at: current_time,
            last_active: current_time,
            state: KeyState::Active,
            prev_identity: Some(prev_identity),
        }
    }

    /// Update the last active timestamp.
    ///
    /// IDENT-FIX-7: Only updates if the timestamp is valid and not in the past
    /// relative to the current last_active time.
    pub fn touch(&mut self, current_time: u64) {
        // IDENT-FIX-7: Validate timestamp before updating
        if Self::is_valid_timestamp(current_time) && current_time >= self.last_active {
            self.last_active = current_time;
        }
    }

    /// Calculate the current state based on time.
    ///
    /// This updates the state field if the key has moved to Expiring or Expired.
    ///
    /// IDENT-FIX-6: Validates timestamps before updating state. Invalid timestamps
    /// cause the key to be marked as Expired for safety.
    pub fn update_state(&mut self, current_time: u64) {
        // Don't change state if already terminated
        if self.state.is_terminated() {
            return;
        }

        // IDENT-FIX-6: Validate timestamps before computing state
        if !Self::is_valid_timestamp(current_time) || !Self::is_valid_timestamp(self.created_at) {
            self.state = KeyState::Expired;
            return;
        }

        let elapsed = current_time.saturating_sub(self.created_at);

        if elapsed >= KEY_EXPIRY_SECS {
            self.state = KeyState::Expired;
        } else if elapsed >= KEY_EXPIRY_SECS - KEY_WARNING_SECS {
            self.state = KeyState::Expiring;
        }
    }

    /// Get the current state, updating it based on time if needed.
    pub fn current_state(&mut self, current_time: u64) -> KeyState {
        self.update_state(current_time);
        self.state
    }

    /// Get seconds until expiry.
    ///
    /// Returns 0 if already expired.
    pub fn seconds_until_expiry(&self, current_time: u64) -> u64 {
        let expiry_time = self.created_at.saturating_add(KEY_EXPIRY_SECS);
        expiry_time.saturating_sub(current_time)
    }

    /// Get the expiry timestamp.
    pub fn expiry_time(&self) -> u64 {
        self.created_at.saturating_add(KEY_EXPIRY_SECS)
    }

    /// Check if the key is within the warning period (5 days before expiry).
    pub fn is_expiring(&self, current_time: u64) -> bool {
        let elapsed = current_time.saturating_sub(self.created_at);
        let warning_start = KEY_EXPIRY_SECS - KEY_WARNING_SECS;
        (warning_start..KEY_EXPIRY_SECS).contains(&elapsed)
    }

    /// Check if the key has expired.
    ///
    /// ## Security (VERITAS-2026-0008)
    ///
    /// This method validates timestamps before use:
    /// - Invalid timestamps (too old, too far in future, or malformed) are treated as expired
    /// - This prevents attackers from manipulating time to bypass expiry checks
    ///
    /// # Arguments
    ///
    /// * `current_time` - The current Unix timestamp in seconds
    ///
    /// # Returns
    ///
    /// `true` if the key has expired or if timestamps are invalid, `false` otherwise.
    pub fn is_expired(&self, current_time: u64) -> bool {
        // SECURITY: Validate created_at timestamp is reasonable
        // Invalid created_at means the key data is corrupted or manipulated
        if !Self::is_valid_timestamp(self.created_at) {
            return true; // Treat as expired for safety
        }

        // SECURITY: Validate current_time is reasonable
        // Future current_time beyond skew indicates time manipulation
        if !Self::is_valid_timestamp(current_time) {
            return true; // Treat as expired for safety
        }

        // SECURITY: Check if created_at is in the future (impossible for legitimate keys)
        // Allow small clock skew between creation and checking
        if self.created_at > current_time.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return true; // Future creation date is suspicious, treat as expired
        }

        let elapsed = current_time.saturating_sub(self.created_at);
        elapsed >= KEY_EXPIRY_SECS
    }

    /// Validate that a timestamp is within acceptable bounds.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The Unix timestamp to validate
    ///
    /// # Returns
    ///
    /// `true` if the timestamp is valid, `false` otherwise.
    fn is_valid_timestamp(timestamp: u64) -> bool {
        (MIN_VALID_TIMESTAMP..=MAX_VALID_TIMESTAMP).contains(&timestamp)
    }

    /// Check if the key is in the grace period after expiry.
    ///
    /// During the grace period, the slot is not yet released for reuse.
    pub fn is_in_grace_period(&self, current_time: u64) -> bool {
        let elapsed = current_time.saturating_sub(self.created_at);
        let expiry_with_grace = KEY_EXPIRY_SECS + EXPIRY_GRACE_PERIOD_SECS;
        elapsed >= KEY_EXPIRY_SECS && elapsed < expiry_with_grace
    }

    /// Check if the slot should be released (expired + past grace period, or rotated).
    ///
    /// Rotated identities immediately release their slot because a new identity
    /// has taken over. Expired and revoked identities retain their slot during
    /// the grace period to prevent rapid slot recycling attacks.
    pub fn should_release_slot(&self, current_time: u64) -> bool {
        // Rotated identities immediately release their slot
        if matches!(self.state, KeyState::Rotated { .. }) {
            return true;
        }

        // Time-based release for expired identities past grace period
        let elapsed = current_time.saturating_sub(self.created_at);
        let expiry_with_grace = KEY_EXPIRY_SECS + EXPIRY_GRACE_PERIOD_SECS;
        elapsed >= expiry_with_grace
    }

    /// Rotate this key to a new identity.
    ///
    /// SECURITY (VERITAS-2026-0091): This method now records the rotation timestamp
    /// for PFS enforcement. After `ROTATION_GRACE_PERIOD_SECS`, the old key material
    /// should be destroyed from storage.
    ///
    /// # Arguments
    ///
    /// * `new_identity` - The identity hash of the new key
    /// * `current_time` - The current Unix timestamp (for PFS tracking)
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not in a rotatable state.
    pub fn rotate(&mut self, new_identity: IdentityHash, current_time: u64) -> crate::Result<()> {
        if !self.state.is_usable() {
            return Err(crate::IdentityError::InvalidStateTransition {
                from: self.state.as_str().to_string(),
                to: "Rotated".to_string(),
            });
        }

        self.state = KeyState::Rotated {
            new_identity: new_identity.to_bytes(),
            rotated_at: current_time,
        };
        Ok(())
    }

    /// Check if the rotation grace period has expired and the key should be destroyed.
    ///
    /// SECURITY (VERITAS-2026-0091): This method should be called periodically
    /// to check if rotated keys should be purged from storage.
    ///
    /// # Returns
    ///
    /// `true` if the key is in Rotated state and the grace period has expired,
    /// `false` otherwise.
    pub fn should_destroy_for_pfs(&self, current_time: u64) -> bool {
        self.state.rotation_grace_expired(current_time).unwrap_or(false)
    }

    /// Check if decryption is allowed based on key state and PFS grace period.
    ///
    /// SECURITY (VERITAS-2026-0091): Decryption is only allowed for:
    /// - Active or Expiring keys
    /// - Rotated keys within the grace period
    ///
    /// This is a defensive check to prevent decryption even if the key
    /// material hasn't been destroyed yet.
    pub fn can_decrypt(&self, current_time: u64) -> bool {
        self.state.allows_decryption(current_time)
    }

    /// Revoke this key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is already rotated or revoked.
    pub fn revoke(&mut self) -> crate::Result<()> {
        match self.state {
            KeyState::Rotated { .. } => {
                return Err(crate::IdentityError::InvalidStateTransition {
                    from: self.state.as_str().to_string(),
                    to: "Revoked".to_string(),
                });
            }
            KeyState::Revoked => {
                // Already revoked, idempotent
                return Ok(());
            }
            _ => {}
        }

        self.state = KeyState::Revoked;
        Ok(())
    }

    /// Check if this identity can be used for sending/receiving messages.
    pub fn can_use(&self, current_time: u64) -> crate::Result<()> {
        match self.state {
            KeyState::Revoked => Err(crate::IdentityError::Revoked),
            KeyState::Expired => Err(crate::IdentityError::Expired),
            KeyState::Rotated { .. } => Err(crate::IdentityError::Expired),
            KeyState::Active | KeyState::Expiring => {
                // Check time-based expiry
                if self.is_expired(current_time) {
                    Err(crate::IdentityError::Expired)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a timestamp after MIN_VALID_TIMESTAMP (2024-01-01)
    // 1710000000 = March 2024
    const BASE_TIME: u64 = 1710000000;

    #[test]
    fn test_identity_hash_from_public_key() {
        let pubkey = b"test_public_key_data";
        let hash1 = IdentityHash::from_public_key(pubkey);
        let hash2 = IdentityHash::from_public_key(pubkey);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_identity_hash_hex_roundtrip() {
        let pubkey = b"test_key";
        let hash = IdentityHash::from_public_key(pubkey);
        let hex = hash.to_hex();
        let recovered = IdentityHash::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_key_state_is_usable() {
        assert!(KeyState::Active.is_usable());
        assert!(KeyState::Expiring.is_usable());
        assert!(!KeyState::Expired.is_usable());
        assert!(!KeyState::Revoked.is_usable());
        assert!(!KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        }
        .is_usable());
    }

    #[test]
    fn test_key_state_is_terminated() {
        assert!(!KeyState::Active.is_terminated());
        assert!(!KeyState::Expiring.is_terminated());
        assert!(KeyState::Expired.is_terminated());
        assert!(KeyState::Revoked.is_terminated());
        assert!(KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        }
        .is_terminated());
    }

    #[test]
    fn test_key_lifecycle_new() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        assert_eq!(lifecycle.created_at, BASE_TIME);
        assert_eq!(lifecycle.last_active, BASE_TIME);
        assert_eq!(lifecycle.state, KeyState::Active);
        assert!(lifecycle.prev_identity.is_none());
    }

    #[test]
    fn test_key_lifecycle_from_rotation() {
        let prev = IdentityHash::from_public_key(b"old_key");
        let lifecycle = KeyLifecycle::new_from_rotation(BASE_TIME, prev.clone());
        assert_eq!(lifecycle.state, KeyState::Active);
        assert_eq!(lifecycle.prev_identity.unwrap(), prev);
    }

    #[test]
    fn test_key_lifecycle_touch() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let new_time = BASE_TIME + 1000;
        lifecycle.touch(new_time);
        assert_eq!(lifecycle.last_active, new_time);
    }

    #[test]
    fn test_key_lifecycle_update_state_active() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let one_day_later = BASE_TIME + 24 * 60 * 60;
        lifecycle.update_state(one_day_later);
        assert_eq!(lifecycle.state, KeyState::Active);
    }

    #[test]
    fn test_key_lifecycle_update_state_expiring() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        // 26 days later (within 5 days of 30-day expiry)
        let time = BASE_TIME + 26 * 24 * 60 * 60;
        lifecycle.update_state(time);
        assert_eq!(lifecycle.state, KeyState::Expiring);
    }

    #[test]
    fn test_key_lifecycle_update_state_expired() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        // 31 days later (past 30-day expiry)
        let time = BASE_TIME + 31 * 24 * 60 * 60;
        lifecycle.update_state(time);
        assert_eq!(lifecycle.state, KeyState::Expired);
    }

    #[test]
    fn test_key_lifecycle_update_state_does_not_change_terminated() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.state = KeyState::Revoked;
        let time = BASE_TIME + 100 * 24 * 60 * 60;
        lifecycle.update_state(time);
        assert_eq!(lifecycle.state, KeyState::Revoked);
    }

    #[test]
    fn test_key_lifecycle_seconds_until_expiry() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        let seconds = lifecycle.seconds_until_expiry(BASE_TIME);
        assert_eq!(seconds, KEY_EXPIRY_SECS);
    }

    #[test]
    fn test_key_lifecycle_is_expiring() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);

        // Active period
        assert!(!lifecycle.is_expiring(BASE_TIME));
        assert!(!lifecycle.is_expiring(BASE_TIME + 24 * 24 * 60 * 60));

        // Expiring period (day 26-30)
        assert!(lifecycle.is_expiring(BASE_TIME + 26 * 24 * 60 * 60));
        assert!(lifecycle.is_expiring(BASE_TIME + 29 * 24 * 60 * 60));

        // Expired
        assert!(!lifecycle.is_expiring(BASE_TIME + 31 * 24 * 60 * 60));
    }

    #[test]
    fn test_key_lifecycle_is_expired() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        assert!(!lifecycle.is_expired(BASE_TIME));
        assert!(!lifecycle.is_expired(BASE_TIME + 29 * 24 * 60 * 60));
        assert!(lifecycle.is_expired(BASE_TIME + 30 * 24 * 60 * 60));
        assert!(lifecycle.is_expired(BASE_TIME + 31 * 24 * 60 * 60));
    }

    #[test]
    fn test_key_lifecycle_is_in_grace_period() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        // Day 30: expired but in grace
        assert!(lifecycle.is_in_grace_period(BASE_TIME + 30 * 24 * 60 * 60));
        // Day 30.5: still in grace
        assert!(lifecycle.is_in_grace_period(BASE_TIME + 30 * 24 * 60 * 60 + 12 * 60 * 60));
        // Day 32: past grace
        assert!(!lifecycle.is_in_grace_period(BASE_TIME + 32 * 24 * 60 * 60));
    }

    #[test]
    fn test_key_lifecycle_should_release_slot() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        // Day 30: still in grace
        assert!(!lifecycle.should_release_slot(BASE_TIME + 30 * 24 * 60 * 60));
        // Day 31: just past grace
        assert!(lifecycle.should_release_slot(BASE_TIME + 31 * 24 * 60 * 60));
        // Day 32: well past grace
        assert!(lifecycle.should_release_slot(BASE_TIME + 32 * 24 * 60 * 60));
    }

    #[test]
    fn test_key_lifecycle_rotate() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let new_id = IdentityHash::from_public_key(b"new_key");
        let rotation_time = BASE_TIME + 1000;
        lifecycle.rotate(new_id.clone(), rotation_time).unwrap();

        match lifecycle.state {
            KeyState::Rotated { new_identity, rotated_at } => {
                assert_eq!(new_identity, new_id.to_bytes());
                assert_eq!(rotated_at, rotation_time);
            }
            _ => panic!("Expected Rotated state"),
        }
    }

    #[test]
    fn test_key_lifecycle_rotate_fails_when_expired() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.state = KeyState::Expired;
        let new_id = IdentityHash::from_public_key(b"new_key");
        assert!(lifecycle.rotate(new_id, BASE_TIME).is_err());
    }

    #[test]
    fn test_key_lifecycle_rotate_fails_when_revoked() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.state = KeyState::Revoked;
        let new_id = IdentityHash::from_public_key(b"new_key");
        assert!(lifecycle.rotate(new_id, BASE_TIME).is_err());
    }

    #[test]
    fn test_key_lifecycle_revoke() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.revoke().unwrap();
        assert_eq!(lifecycle.state, KeyState::Revoked);
    }

    #[test]
    fn test_key_lifecycle_revoke_idempotent() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.revoke().unwrap();
        lifecycle.revoke().unwrap(); // Should not error
        assert_eq!(lifecycle.state, KeyState::Revoked);
    }

    #[test]
    fn test_key_lifecycle_revoke_fails_when_rotated() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let new_id = IdentityHash::from_public_key(b"new_key");
        lifecycle.rotate(new_id, BASE_TIME).unwrap();
        assert!(lifecycle.revoke().is_err());
    }

    #[test]
    fn test_key_lifecycle_can_use_active() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        assert!(lifecycle.can_use(BASE_TIME).is_ok());
    }

    #[test]
    fn test_key_lifecycle_can_use_expiring() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        // Day 26: expiring but usable
        assert!(lifecycle.can_use(BASE_TIME + 26 * 24 * 60 * 60).is_ok());
    }

    #[test]
    fn test_key_lifecycle_can_use_expired() {
        let lifecycle = KeyLifecycle::new(BASE_TIME);
        // Day 31: expired
        assert!(lifecycle.can_use(BASE_TIME + 31 * 24 * 60 * 60).is_err());
    }

    #[test]
    fn test_key_lifecycle_can_use_revoked() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.revoke().unwrap();
        assert!(lifecycle.can_use(BASE_TIME).is_err());
    }

    #[test]
    fn test_key_lifecycle_can_use_rotated() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle
            .rotate(IdentityHash::from_public_key(b"new"), BASE_TIME)
            .unwrap();
        assert!(lifecycle.can_use(BASE_TIME).is_err());
    }

    // === Security Tests for VERITAS-2026-0008 ===

    #[test]
    fn test_is_valid_timestamp() {
        // Valid timestamps
        assert!(KeyLifecycle::is_valid_timestamp(MIN_VALID_TIMESTAMP));
        assert!(KeyLifecycle::is_valid_timestamp(MAX_VALID_TIMESTAMP));
        assert!(KeyLifecycle::is_valid_timestamp(BASE_TIME));

        // Invalid timestamps - too old
        assert!(!KeyLifecycle::is_valid_timestamp(MIN_VALID_TIMESTAMP - 1));
        assert!(!KeyLifecycle::is_valid_timestamp(0));
        assert!(!KeyLifecycle::is_valid_timestamp(1000000000)); // 2001

        // Invalid timestamps - too large
        assert!(!KeyLifecycle::is_valid_timestamp(MAX_VALID_TIMESTAMP + 1));
        assert!(!KeyLifecycle::is_valid_timestamp(u64::MAX));
    }

    #[test]
    fn test_is_expired_rejects_ancient_created_at() {
        // SECURITY: Keys with ancient created_at should be treated as expired
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.created_at = 1000000000; // 2001 - before MIN_VALID_TIMESTAMP

        // Even with valid current_time, should be treated as expired
        assert!(lifecycle.is_expired(BASE_TIME));
    }

    #[test]
    fn test_is_expired_rejects_ancient_current_time() {
        // SECURITY: Ancient current_time indicates time manipulation
        let lifecycle = KeyLifecycle::new(BASE_TIME);

        // Passing ancient current_time should treat key as expired
        assert!(lifecycle.is_expired(1000000000)); // 2001
    }

    #[test]
    fn test_is_expired_rejects_far_future_current_time() {
        // SECURITY: Far future current_time beyond MAX_VALID_TIMESTAMP
        let lifecycle = KeyLifecycle::new(BASE_TIME);

        // Passing far future time should treat key as expired
        assert!(lifecycle.is_expired(MAX_VALID_TIMESTAMP + 1));
        assert!(lifecycle.is_expired(u64::MAX));
    }

    #[test]
    fn test_is_expired_rejects_future_created_at() {
        // SECURITY: Keys created in the future are suspicious
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        // Set created_at far in the future (beyond clock skew)
        lifecycle.created_at = BASE_TIME + MAX_CLOCK_SKEW_SECS + 1000;

        // Should be treated as expired (suspicious)
        assert!(lifecycle.is_expired(BASE_TIME));
    }

    #[test]
    fn test_is_expired_allows_small_clock_skew() {
        // SECURITY: Small clock skew should be allowed
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        // Set created_at slightly in the future (within clock skew)
        lifecycle.created_at = BASE_TIME + MAX_CLOCK_SKEW_SECS - 10;

        // Should NOT be treated as expired (within acceptable skew)
        assert!(!lifecycle.is_expired(BASE_TIME));
    }

    #[test]
    fn test_is_expired_zero_timestamp() {
        // SECURITY: Zero timestamp should be rejected
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.created_at = 0;

        assert!(lifecycle.is_expired(BASE_TIME));

        // Also check zero current_time
        let lifecycle2 = KeyLifecycle::new(BASE_TIME);
        assert!(lifecycle2.is_expired(0));
    }

    #[test]
    fn test_is_expired_boundary_conditions() {
        // Test at exact MIN_VALID_TIMESTAMP boundary
        let lifecycle = KeyLifecycle::new(MIN_VALID_TIMESTAMP);
        assert!(!lifecycle.is_expired(MIN_VALID_TIMESTAMP + 1000));

        // Test at exact MAX_VALID_TIMESTAMP boundary
        let mut lifecycle2 = KeyLifecycle::new(BASE_TIME);
        lifecycle2.created_at = MAX_VALID_TIMESTAMP;
        // This should fail because created_at > current_time + skew
        assert!(lifecycle2.is_expired(BASE_TIME));
    }

    #[test]
    fn test_time_constants_consistent() {
        // Verify constants are in correct order
        const { assert!(MIN_VALID_TIMESTAMP < MAX_VALID_TIMESTAMP) }
        const { assert!(MAX_CLOCK_SKEW_SECS < KEY_EXPIRY_SECS) }

        // Verify MIN_VALID_TIMESTAMP is 2024-01-01
        assert_eq!(MIN_VALID_TIMESTAMP, 1704067200);

        // Verify MAX_VALID_TIMESTAMP is 2100-01-01
        assert_eq!(MAX_VALID_TIMESTAMP, 4102444800);

        // Verify MAX_CLOCK_SKEW_SECS is 5 minutes
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300);
    }

    // === Security Tests for VERITAS-2026-0091 (PFS) ===

    #[test]
    fn test_rotation_grace_period_constant() {
        // Verify rotation grace period is 1 hour
        assert_eq!(ROTATION_GRACE_PERIOD_SECS, 3600);
    }

    #[test]
    fn test_rotation_grace_expired_during_grace_period() {
        let state = KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        };

        // Immediately after rotation: not expired
        assert_eq!(state.rotation_grace_expired(BASE_TIME), Some(false));

        // 30 minutes after rotation: not expired
        assert_eq!(state.rotation_grace_expired(BASE_TIME + 30 * 60), Some(false));

        // 59 minutes after rotation: not expired
        assert_eq!(state.rotation_grace_expired(BASE_TIME + 59 * 60), Some(false));
    }

    #[test]
    fn test_rotation_grace_expired_after_grace_period() {
        let state = KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        };

        // Exactly 1 hour after rotation: expired
        assert_eq!(state.rotation_grace_expired(BASE_TIME + ROTATION_GRACE_PERIOD_SECS), Some(true));

        // 2 hours after rotation: expired
        assert_eq!(state.rotation_grace_expired(BASE_TIME + 2 * ROTATION_GRACE_PERIOD_SECS), Some(true));
    }

    #[test]
    fn test_rotation_grace_expired_non_rotated_state() {
        // Non-rotated states return None
        assert_eq!(KeyState::Active.rotation_grace_expired(BASE_TIME), None);
        assert_eq!(KeyState::Expiring.rotation_grace_expired(BASE_TIME), None);
        assert_eq!(KeyState::Expired.rotation_grace_expired(BASE_TIME), None);
        assert_eq!(KeyState::Revoked.rotation_grace_expired(BASE_TIME), None);
    }

    #[test]
    fn test_allows_decryption_during_grace_period() {
        let state = KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        };

        // During grace period: decryption allowed
        assert!(state.allows_decryption(BASE_TIME));
        assert!(state.allows_decryption(BASE_TIME + 30 * 60));
        assert!(state.allows_decryption(BASE_TIME + ROTATION_GRACE_PERIOD_SECS - 1));
    }

    #[test]
    fn test_denies_decryption_after_grace_period() {
        let state = KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME,
        };

        // After grace period: decryption denied
        assert!(!state.allows_decryption(BASE_TIME + ROTATION_GRACE_PERIOD_SECS));
        assert!(!state.allows_decryption(BASE_TIME + 2 * ROTATION_GRACE_PERIOD_SECS));
    }

    #[test]
    fn test_allows_decryption_active_expiring() {
        assert!(KeyState::Active.allows_decryption(BASE_TIME));
        assert!(KeyState::Expiring.allows_decryption(BASE_TIME));
    }

    #[test]
    fn test_denies_decryption_expired_revoked() {
        assert!(!KeyState::Expired.allows_decryption(BASE_TIME));
        assert!(!KeyState::Revoked.allows_decryption(BASE_TIME));
    }

    #[test]
    fn test_should_destroy_for_pfs() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let new_id = IdentityHash::from_public_key(b"new_key");
        let rotation_time = BASE_TIME + 1000;

        // Before rotation: should not destroy
        assert!(!lifecycle.should_destroy_for_pfs(BASE_TIME));

        // Rotate the key
        lifecycle.rotate(new_id, rotation_time).unwrap();

        // During grace period: should not destroy
        assert!(!lifecycle.should_destroy_for_pfs(rotation_time));
        assert!(!lifecycle.should_destroy_for_pfs(rotation_time + 30 * 60));

        // After grace period: should destroy
        assert!(lifecycle.should_destroy_for_pfs(rotation_time + ROTATION_GRACE_PERIOD_SECS));
        assert!(lifecycle.should_destroy_for_pfs(rotation_time + 2 * ROTATION_GRACE_PERIOD_SECS));
    }

    #[test]
    fn test_can_decrypt_follows_pfs_rules() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        let new_id = IdentityHash::from_public_key(b"new_key");
        let rotation_time = BASE_TIME + 1000;

        // Active key: can decrypt
        assert!(lifecycle.can_decrypt(BASE_TIME));

        // Rotate the key
        lifecycle.rotate(new_id, rotation_time).unwrap();

        // During grace period: can decrypt
        assert!(lifecycle.can_decrypt(rotation_time + 30 * 60));

        // After grace period: cannot decrypt
        assert!(!lifecycle.can_decrypt(rotation_time + ROTATION_GRACE_PERIOD_SECS));
    }

    #[test]
    fn test_rotation_time_accessor() {
        let state = KeyState::Rotated {
            new_identity: [0; 32],
            rotated_at: BASE_TIME + 5000,
        };
        assert_eq!(state.rotation_time(), Some(BASE_TIME + 5000));

        assert_eq!(KeyState::Active.rotation_time(), None);
        assert_eq!(KeyState::Expired.rotation_time(), None);
    }
}
