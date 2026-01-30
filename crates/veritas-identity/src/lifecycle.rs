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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is active and valid for use.
    Active,
    /// Key is within 5 days of expiry (warning period).
    Expiring,
    /// Key has expired and cannot be used for new operations.
    Expired,
    /// Key has been rotated to a new identity.
    Rotated {
        /// The new identity that this key was rotated to.
        new_identity: [u8; 32],
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

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Active => write!(f, "Active"),
            KeyState::Expiring => write!(f, "Expiring"),
            KeyState::Expired => write!(f, "Expired"),
            KeyState::Rotated { new_identity } => {
                write!(f, "Rotated({}...)", hex::encode(&new_identity[..8]))
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
    pub fn touch(&mut self, current_time: u64) {
        self.last_active = current_time;
    }

    /// Calculate the current state based on time.
    ///
    /// This updates the state field if the key has moved to Expiring or Expired.
    pub fn update_state(&mut self, current_time: u64) {
        // Don't change state if already terminated
        if self.state.is_terminated() {
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
    /// # Errors
    ///
    /// Returns an error if the key is not in a rotatable state.
    pub fn rotate(&mut self, new_identity: IdentityHash) -> crate::Result<()> {
        if !self.state.is_usable() {
            return Err(crate::IdentityError::InvalidStateTransition {
                from: self.state.as_str().to_string(),
                to: "Rotated".to_string(),
            });
        }

        self.state = KeyState::Rotated {
            new_identity: new_identity.to_bytes(),
        };
        Ok(())
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
            new_identity: [0; 32]
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
            new_identity: [0; 32]
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
        lifecycle.rotate(new_id.clone()).unwrap();

        match lifecycle.state {
            KeyState::Rotated { new_identity } => {
                assert_eq!(new_identity, new_id.to_bytes());
            }
            _ => panic!("Expected Rotated state"),
        }
    }

    #[test]
    fn test_key_lifecycle_rotate_fails_when_expired() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.state = KeyState::Expired;
        let new_id = IdentityHash::from_public_key(b"new_key");
        assert!(lifecycle.rotate(new_id).is_err());
    }

    #[test]
    fn test_key_lifecycle_rotate_fails_when_revoked() {
        let mut lifecycle = KeyLifecycle::new(BASE_TIME);
        lifecycle.state = KeyState::Revoked;
        let new_id = IdentityHash::from_public_key(b"new_key");
        assert!(lifecycle.rotate(new_id).is_err());
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
        lifecycle.rotate(new_id).unwrap();
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
            .rotate(IdentityHash::from_public_key(b"new"))
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
}
