//! Key rotation contact notification system.
//!
//! When a key rotates, this module provides the mechanism to create
//! on-chain notifications that contacts can discover and verify.
//! Notifications are signed by BOTH the old and new keys to prove
//! legitimate rotation (not impersonation).

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::error::{IdentityError, Result};
use crate::identity_hash::IdentityHash;

/// Maximum number of contacts to notify per rotation.
pub const MAX_NOTIFICATION_CONTACTS: usize = 1_000;

/// Notification expiry time (30 days, same as epoch).
pub const NOTIFICATION_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum allowed clock skew for notification timestamps (5 minutes).
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Maximum allowed signature size in bytes (accommodates ML-DSA-65 at 3,309 bytes).
const MAX_SIGNATURE_SIZE: usize = 4096;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC).
const MIN_VALID_TIMESTAMP: u64 = 1704067200;

/// Maximum valid timestamp (2100-01-01 00:00:00 UTC).
const MAX_VALID_TIMESTAMP: u64 = 4102444800;

/// Domain separation prefix for key rotation notification signing payloads.
const SIGNING_DOMAIN: &[u8] = b"VERITAS-v1.KEY-ROTATION-NOTIFY.";

/// A key rotation notification destined for contacts.
///
/// This is signed by BOTH the old key and the new key to prove:
/// 1. The old key owner authorized the rotation
/// 2. The new key owner is the legitimate successor
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationNotification {
    /// The old identity being rotated away from.
    pub old_identity: IdentityHash,
    /// The new identity being rotated to.
    pub new_identity: IdentityHash,
    /// Serialized new public keys (for contact to update records).
    pub new_public_keys: Vec<u8>,
    /// Rotation timestamp (Unix seconds).
    pub timestamp: u64,
    /// Signature from the OLD key (proving authorization).
    pub old_key_signature: Vec<u8>,
    /// Signature from the NEW key (proving possession).
    pub new_key_signature: Vec<u8>,
    /// Optional list of mailbox keys for targeted notification.
    /// Contacts can check if their mailbox key is included.
    pub notification_mailbox_keys: Vec<[u8; 32]>,
}

impl KeyRotationNotification {
    /// Create a new rotation notification.
    ///
    /// # Arguments
    ///
    /// * `old_identity` - The identity being rotated away from
    /// * `new_identity` - The identity being rotated to
    /// * `new_public_keys` - Serialized new public keys
    /// * `timestamp` - Rotation timestamp (Unix seconds)
    /// * `old_key_signature` - Signature from the old key over the signing payload
    /// * `new_key_signature` - Signature from the new key over the signing payload
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `old_identity` equals `new_identity` (rotation to self)
    /// - Either signature is empty or exceeds 4096 bytes
    /// - `new_public_keys` is empty
    /// - `timestamp` is outside valid range
    pub fn new(
        old_identity: IdentityHash,
        new_identity: IdentityHash,
        new_public_keys: Vec<u8>,
        timestamp: u64,
        old_key_signature: Vec<u8>,
        new_key_signature: Vec<u8>,
    ) -> Result<Self> {
        // Prevent rotation to self
        if old_identity == new_identity {
            return Err(IdentityError::InvalidStateTransition {
                from: "active".to_string(),
                to: "same identity".to_string(),
            });
        }

        // Validate signatures are not empty
        if old_key_signature.is_empty() || new_key_signature.is_empty() {
            return Err(IdentityError::Validation(
                "rotation notification signatures cannot be empty".into(),
            ));
        }

        // Validate signature sizes
        if old_key_signature.len() > MAX_SIGNATURE_SIZE
            || new_key_signature.len() > MAX_SIGNATURE_SIZE
        {
            return Err(IdentityError::Validation(
                "rotation notification signature too large".into(),
            ));
        }

        // Validate public keys not empty
        if new_public_keys.is_empty() {
            return Err(IdentityError::Validation(
                "new public keys cannot be empty".into(),
            ));
        }

        // Validate timestamp
        if timestamp < MIN_VALID_TIMESTAMP || timestamp > MAX_VALID_TIMESTAMP {
            return Err(IdentityError::Validation(
                "invalid rotation notification timestamp".into(),
            ));
        }

        Ok(Self {
            old_identity,
            new_identity,
            new_public_keys,
            timestamp,
            old_key_signature,
            new_key_signature,
            notification_mailbox_keys: Vec::new(),
        })
    }

    /// Add mailbox keys for targeted notification.
    ///
    /// If mailbox keys are set, only contacts whose mailbox key appears in the
    /// list will consider the notification relevant. If no mailbox keys are set,
    /// the notification is treated as a broadcast to all contacts.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of keys exceeds [`MAX_NOTIFICATION_CONTACTS`].
    pub fn with_mailbox_keys(mut self, keys: Vec<[u8; 32]>) -> Result<Self> {
        if keys.len() > MAX_NOTIFICATION_CONTACTS {
            return Err(IdentityError::Validation(format!(
                "too many notification contacts: {} > {}",
                keys.len(),
                MAX_NOTIFICATION_CONTACTS
            )));
        }
        self.notification_mailbox_keys = keys;
        Ok(self)
    }

    /// Compute the signing payload for this notification.
    ///
    /// Both the old and new keys sign the same payload.
    /// Format: `domain || old_identity || new_identity || new_public_keys_hash || timestamp`
    pub fn signing_payload(&self) -> Vec<u8> {
        Self::compute_signing_payload(
            &self.old_identity,
            &self.new_identity,
            &self.new_public_keys,
            self.timestamp,
        )
    }

    /// Static method to compute signing payload from components.
    ///
    /// This can be used by the signing side to compute the payload before
    /// creating the notification, and by the verifying side to check it.
    ///
    /// Format: `"VERITAS-v1.KEY-ROTATION-NOTIFY." || old_identity || new_identity || BLAKE3(new_public_keys) || timestamp_be`
    pub fn compute_signing_payload(
        old_identity: &IdentityHash,
        new_identity: &IdentityHash,
        new_public_keys: &[u8],
        timestamp: u64,
    ) -> Vec<u8> {
        let keys_hash = Hash256::hash(new_public_keys);
        let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + 32 + 32 + 8);
        payload.extend_from_slice(SIGNING_DOMAIN);
        payload.extend_from_slice(old_identity.as_bytes());
        payload.extend_from_slice(new_identity.as_bytes());
        payload.extend_from_slice(keys_hash.as_bytes());
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload
    }

    /// Verify both signatures on this notification.
    ///
    /// The provided `verify_fn` is called with `(identity, payload, signature)` and
    /// must return `true` if the signature is valid for the given identity and payload.
    ///
    /// # Errors
    ///
    /// Returns an error if either the old or new key signature verification fails.
    pub fn verify<F>(&self, verify_fn: F) -> Result<()>
    where
        F: Fn(&IdentityHash, &[u8], &[u8]) -> bool,
    {
        let payload = self.signing_payload();

        // Verify old key signature
        if !verify_fn(&self.old_identity, &payload, &self.old_key_signature) {
            return Err(IdentityError::Validation(
                "old key signature verification failed".into(),
            ));
        }

        // Verify new key signature
        if !verify_fn(&self.new_identity, &payload, &self.new_key_signature) {
            return Err(IdentityError::Validation(
                "new key signature verification failed".into(),
            ));
        }

        Ok(())
    }

    /// Check if a mailbox key is in the notification target list.
    ///
    /// If `notification_mailbox_keys` is empty, the notification is broadcast
    /// (visible to all contacts). If populated, only matching contacts see it.
    pub fn is_targeted_to(&self, mailbox_key: &[u8; 32]) -> bool {
        self.notification_mailbox_keys.is_empty()
            || self.notification_mailbox_keys.iter().any(|k| k == mailbox_key)
    }

    /// Validate the notification timestamp against the current time.
    ///
    /// Rejects notifications that are:
    /// - More than 300 seconds in the future (clock skew protection)
    /// - Older than [`NOTIFICATION_EXPIRY_SECS`] (30 days)
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp is in the future or expired.
    pub fn validate_timestamp(&self, current_time: u64) -> Result<()> {
        if self.timestamp > current_time + MAX_CLOCK_SKEW_SECS {
            return Err(IdentityError::Validation(
                "rotation notification timestamp in future".into(),
            ));
        }
        if current_time > self.timestamp + NOTIFICATION_EXPIRY_SECS {
            return Err(IdentityError::Validation(
                "rotation notification expired".into(),
            ));
        }
        Ok(())
    }

    /// Check if this notification has expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.timestamp + NOTIFICATION_EXPIRY_SECS
    }
}

/// Manages rotation notifications for an identity's contacts.
///
/// Provides storage, lookup, and identity chain resolution for
/// key rotation notifications. Notifications are indexed by the
/// old identity hash for efficient lookup.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RotationNotificationManager {
    /// Pending notifications indexed by old identity.
    pending: std::collections::HashMap<IdentityHash, Vec<KeyRotationNotification>>,
    /// Maximum tracked notifications (bounded to prevent unbounded growth).
    max_notifications: usize,
}

impl RotationNotificationManager {
    /// Create a new notification manager.
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            max_notifications: 10_000,
        }
    }

    /// Create a new notification manager with a custom capacity limit.
    pub fn with_capacity(max_notifications: usize) -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            max_notifications,
        }
    }

    /// Store a rotation notification.
    ///
    /// # Errors
    ///
    /// Returns an error if the total notification count would exceed the
    /// configured maximum.
    pub fn add_notification(&mut self, notification: KeyRotationNotification) -> Result<()> {
        let total: usize = self.pending.values().map(|v| v.len()).sum();
        if total >= self.max_notifications {
            return Err(IdentityError::Validation(
                "notification manager full".into(),
            ));
        }
        self.pending
            .entry(notification.old_identity.clone())
            .or_default()
            .push(notification);
        Ok(())
    }

    /// Look up rotation notifications for an old identity.
    pub fn get_notifications(
        &self,
        old_identity: &IdentityHash,
    ) -> Option<&Vec<KeyRotationNotification>> {
        self.pending.get(old_identity)
    }

    /// Get the latest new identity for an old identity (chain of rotations).
    ///
    /// Follows the chain of rotations from the given old identity until no
    /// further rotations are found. Includes cycle detection to prevent
    /// infinite loops in case of malicious circular rotation chains.
    pub fn resolve_identity(&self, old_identity: &IdentityHash) -> IdentityHash {
        let mut current = old_identity.clone();
        let mut visited = std::collections::HashSet::new();

        while let Some(notifications) = self.pending.get(&current) {
            if let Some(latest) = notifications.last() {
                if visited.contains(&latest.new_identity) {
                    break; // Cycle detection
                }
                visited.insert(current);
                current = latest.new_identity.clone();
            } else {
                break;
            }
        }
        current
    }

    /// Clean up expired notifications.
    ///
    /// Removes all notifications whose timestamp is older than
    /// [`NOTIFICATION_EXPIRY_SECS`] relative to `current_time`.
    /// Also removes empty entries from the map.
    pub fn cleanup_expired(&mut self, current_time: u64) {
        for notifications in self.pending.values_mut() {
            notifications.retain(|n| !n.is_expired(current_time));
        }
        self.pending.retain(|_, v| !v.is_empty());
    }

    /// Total notification count across all identities.
    pub fn total_notifications(&self) -> usize {
        self.pending.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a timestamp after MIN_VALID_TIMESTAMP (2024-01-01)
    // 1710000000 = March 2024
    const BASE_TIME: u64 = 1710000000;

    fn make_identity(name: &[u8]) -> IdentityHash {
        IdentityHash::from_public_key(name)
    }

    fn make_notification(
        old_name: &[u8],
        new_name: &[u8],
    ) -> KeyRotationNotification {
        let old_identity = make_identity(old_name);
        let new_identity = make_identity(new_name);
        KeyRotationNotification::new(
            old_identity,
            new_identity,
            vec![1, 2, 3, 4], // dummy public keys
            BASE_TIME,
            vec![0xAA; 64], // dummy old signature
            vec![0xBB; 64], // dummy new signature
        )
        .unwrap()
    }

    // ===== KeyRotationNotification::new tests =====

    #[test]
    fn test_new_valid_notification() {
        let notification = make_notification(b"old_key", b"new_key");
        assert_eq!(notification.old_identity, make_identity(b"old_key"));
        assert_eq!(notification.new_identity, make_identity(b"new_key"));
        assert_eq!(notification.new_public_keys, vec![1, 2, 3, 4]);
        assert_eq!(notification.timestamp, BASE_TIME);
        assert_eq!(notification.old_key_signature, vec![0xAA; 64]);
        assert_eq!(notification.new_key_signature, vec![0xBB; 64]);
        assert!(notification.notification_mailbox_keys.is_empty());
    }

    #[test]
    fn test_new_rejects_same_identity() {
        let identity = make_identity(b"same_key");
        let result = KeyRotationNotification::new(
            identity.clone(),
            identity,
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("same identity"));
    }

    #[test]
    fn test_new_rejects_empty_old_signature() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            BASE_TIME,
            vec![],       // empty old signature
            vec![0xBB],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signatures cannot be empty"));
    }

    #[test]
    fn test_new_rejects_empty_new_signature() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA],
            vec![],       // empty new signature
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signatures cannot be empty"));
    }

    #[test]
    fn test_new_rejects_oversized_old_signature() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA; MAX_SIGNATURE_SIZE + 1],
            vec![0xBB; 64],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signature too large"));
    }

    #[test]
    fn test_new_rejects_oversized_new_signature() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA; 64],
            vec![0xBB; MAX_SIGNATURE_SIZE + 1],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signature too large"));
    }

    #[test]
    fn test_new_accepts_max_size_signature() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA; MAX_SIGNATURE_SIZE],
            vec![0xBB; MAX_SIGNATURE_SIZE],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_rejects_empty_public_keys() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![],       // empty public keys
            BASE_TIME,
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("new public keys cannot be empty"));
    }

    #[test]
    fn test_new_rejects_timestamp_too_old() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            MIN_VALID_TIMESTAMP - 1, // too old
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid rotation notification timestamp"));
    }

    #[test]
    fn test_new_rejects_timestamp_too_far_future() {
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            MAX_VALID_TIMESTAMP + 1, // too far future
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid rotation notification timestamp"));
    }

    #[test]
    fn test_new_accepts_boundary_timestamps() {
        // Minimum valid timestamp
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            MIN_VALID_TIMESTAMP,
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_ok());

        // Maximum valid timestamp
        let result = KeyRotationNotification::new(
            make_identity(b"old"),
            make_identity(b"new"),
            vec![1, 2, 3],
            MAX_VALID_TIMESTAMP,
            vec![0xAA],
            vec![0xBB],
        );
        assert!(result.is_ok());
    }

    // ===== Signing payload tests =====

    #[test]
    fn test_signing_payload_deterministic() {
        let notification = make_notification(b"old_key", b"new_key");
        let payload1 = notification.signing_payload();
        let payload2 = notification.signing_payload();
        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_signing_payload_starts_with_domain() {
        let notification = make_notification(b"old_key", b"new_key");
        let payload = notification.signing_payload();
        assert!(payload.starts_with(SIGNING_DOMAIN));
    }

    #[test]
    fn test_signing_payload_matches_static_method() {
        let notification = make_notification(b"old_key", b"new_key");
        let payload_instance = notification.signing_payload();
        let payload_static = KeyRotationNotification::compute_signing_payload(
            &notification.old_identity,
            &notification.new_identity,
            &notification.new_public_keys,
            notification.timestamp,
        );
        assert_eq!(payload_instance, payload_static);
    }

    #[test]
    fn test_signing_payload_different_identities_produce_different_payloads() {
        let payload1 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old_a"),
            &make_identity(b"new_a"),
            &[1, 2, 3],
            BASE_TIME,
        );
        let payload2 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old_b"),
            &make_identity(b"new_b"),
            &[1, 2, 3],
            BASE_TIME,
        );
        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_signing_payload_different_keys_produce_different_payloads() {
        let payload1 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old"),
            &make_identity(b"new"),
            &[1, 2, 3],
            BASE_TIME,
        );
        let payload2 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old"),
            &make_identity(b"new"),
            &[4, 5, 6],
            BASE_TIME,
        );
        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_signing_payload_different_timestamps_produce_different_payloads() {
        let payload1 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old"),
            &make_identity(b"new"),
            &[1, 2, 3],
            BASE_TIME,
        );
        let payload2 = KeyRotationNotification::compute_signing_payload(
            &make_identity(b"old"),
            &make_identity(b"new"),
            &[1, 2, 3],
            BASE_TIME + 1,
        );
        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_signing_payload_expected_length() {
        let notification = make_notification(b"old_key", b"new_key");
        let payload = notification.signing_payload();
        // domain (31 bytes) + old_identity (32) + new_identity (32) + keys_hash (32) + timestamp (8) = 135
        assert_eq!(payload.len(), SIGNING_DOMAIN.len() + 32 + 32 + 32 + 8);
    }

    // ===== Dual signature verification tests =====

    #[test]
    fn test_verify_both_signatures_valid() {
        let notification = make_notification(b"old_key", b"new_key");
        // Verify function that always returns true
        let result = notification.verify(|_identity, _payload, _sig| true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_old_signature_invalid() {
        let notification = make_notification(b"old_key", b"new_key");
        let old_id = notification.old_identity.clone();
        let result = notification.verify(|identity, _payload, _sig| {
            // Old key fails, new key passes
            identity != &old_id
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("old key signature verification failed"));
    }

    #[test]
    fn test_verify_new_signature_invalid() {
        let notification = make_notification(b"old_key", b"new_key");
        let new_id = notification.new_identity.clone();
        let result = notification.verify(|identity, _payload, _sig| {
            // Old key passes, new key fails
            identity != &new_id
        });
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("new key signature verification failed"));
    }

    #[test]
    fn test_verify_both_signatures_invalid() {
        let notification = make_notification(b"old_key", b"new_key");
        // Both fail - should report old key failure first
        let result = notification.verify(|_identity, _payload, _sig| false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("old key signature verification failed"));
    }

    #[test]
    fn test_verify_receives_correct_payload() {
        let notification = make_notification(b"old_key", b"new_key");
        let expected_payload = notification.signing_payload();
        let result = notification.verify(|_identity, payload, _sig| {
            payload == expected_payload.as_slice()
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_receives_correct_signatures() {
        let notification = make_notification(b"old_key", b"new_key");
        let old_id = notification.old_identity.clone();
        let result = notification.verify(|identity, _payload, sig| {
            if identity == &old_id {
                sig == vec![0xAA; 64].as_slice()
            } else {
                sig == vec![0xBB; 64].as_slice()
            }
        });
        assert!(result.is_ok());
    }

    // ===== Mailbox key targeting tests =====

    #[test]
    fn test_with_mailbox_keys_valid() {
        let notification = make_notification(b"old", b"new");
        let keys = vec![[1u8; 32], [2u8; 32]];
        let notification = notification.with_mailbox_keys(keys.clone()).unwrap();
        assert_eq!(notification.notification_mailbox_keys, keys);
    }

    #[test]
    fn test_with_mailbox_keys_too_many() {
        let notification = make_notification(b"old", b"new");
        let keys = vec![[0u8; 32]; MAX_NOTIFICATION_CONTACTS + 1];
        let result = notification.with_mailbox_keys(keys);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too many notification contacts"));
    }

    #[test]
    fn test_with_mailbox_keys_exact_max() {
        let notification = make_notification(b"old", b"new");
        let keys = vec![[0u8; 32]; MAX_NOTIFICATION_CONTACTS];
        let result = notification.with_mailbox_keys(keys);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_targeted_to_broadcast() {
        // Empty mailbox keys = broadcast to all
        let notification = make_notification(b"old", b"new");
        assert!(notification.is_targeted_to(&[0u8; 32]));
        assert!(notification.is_targeted_to(&[1u8; 32]));
        assert!(notification.is_targeted_to(&[255u8; 32]));
    }

    #[test]
    fn test_is_targeted_to_specific_contacts() {
        let notification = make_notification(b"old", b"new");
        let target_key = [42u8; 32];
        let notification = notification
            .with_mailbox_keys(vec![target_key, [99u8; 32]])
            .unwrap();

        assert!(notification.is_targeted_to(&target_key));
        assert!(notification.is_targeted_to(&[99u8; 32]));
        assert!(!notification.is_targeted_to(&[0u8; 32]));
        assert!(!notification.is_targeted_to(&[1u8; 32]));
    }

    // ===== Timestamp validation tests =====

    #[test]
    fn test_validate_timestamp_valid() {
        let notification = make_notification(b"old", b"new");
        assert!(notification.validate_timestamp(BASE_TIME).is_ok());
        assert!(notification.validate_timestamp(BASE_TIME + 1000).is_ok());
    }

    #[test]
    fn test_validate_timestamp_within_clock_skew() {
        // Notification timestamp is slightly in the future (within skew)
        let notification = make_notification(b"old", b"new");
        let current_time = BASE_TIME - MAX_CLOCK_SKEW_SECS;
        assert!(notification.validate_timestamp(current_time).is_ok());
    }

    #[test]
    fn test_validate_timestamp_in_future() {
        let notification = make_notification(b"old", b"new");
        let current_time = BASE_TIME - MAX_CLOCK_SKEW_SECS - 1;
        let result = notification.validate_timestamp(current_time);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timestamp in future"));
    }

    #[test]
    fn test_validate_timestamp_expired() {
        let notification = make_notification(b"old", b"new");
        let current_time = BASE_TIME + NOTIFICATION_EXPIRY_SECS + 1;
        let result = notification.validate_timestamp(current_time);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expired"));
    }

    #[test]
    fn test_validate_timestamp_just_before_expiry() {
        let notification = make_notification(b"old", b"new");
        let current_time = BASE_TIME + NOTIFICATION_EXPIRY_SECS;
        // Exactly at boundary: current_time == timestamp + NOTIFICATION_EXPIRY_SECS
        // The condition is current_time > self.timestamp + NOTIFICATION_EXPIRY_SECS
        // So this should be OK (not expired yet).
        assert!(notification.validate_timestamp(current_time).is_ok());
    }

    // ===== is_expired tests =====

    #[test]
    fn test_is_expired_false_when_fresh() {
        let notification = make_notification(b"old", b"new");
        assert!(!notification.is_expired(BASE_TIME));
        assert!(!notification.is_expired(BASE_TIME + 1000));
    }

    #[test]
    fn test_is_expired_false_at_boundary() {
        let notification = make_notification(b"old", b"new");
        // Exactly at expiry boundary
        assert!(!notification.is_expired(BASE_TIME + NOTIFICATION_EXPIRY_SECS));
    }

    #[test]
    fn test_is_expired_true_after_expiry() {
        let notification = make_notification(b"old", b"new");
        assert!(notification.is_expired(BASE_TIME + NOTIFICATION_EXPIRY_SECS + 1));
    }

    // ===== Serialization roundtrip =====

    #[test]
    fn test_serialization_roundtrip() {
        let notification = make_notification(b"old", b"new");
        let notification = notification
            .with_mailbox_keys(vec![[1u8; 32], [2u8; 32]])
            .unwrap();

        let serialized = bincode::serialize(&notification).unwrap();
        let deserialized: KeyRotationNotification =
            bincode::deserialize(&serialized).unwrap();

        assert_eq!(notification, deserialized);
    }

    // ===== RotationNotificationManager tests =====

    #[test]
    fn test_manager_new() {
        let manager = RotationNotificationManager::new();
        assert_eq!(manager.total_notifications(), 0);
    }

    #[test]
    fn test_manager_with_capacity() {
        let manager = RotationNotificationManager::with_capacity(100);
        assert_eq!(manager.total_notifications(), 0);
        assert_eq!(manager.max_notifications, 100);
    }

    #[test]
    fn test_manager_add_notification() {
        let mut manager = RotationNotificationManager::new();
        let notification = make_notification(b"old", b"new");
        manager.add_notification(notification).unwrap();
        assert_eq!(manager.total_notifications(), 1);
    }

    #[test]
    fn test_manager_add_multiple_notifications() {
        let mut manager = RotationNotificationManager::new();
        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();
        manager
            .add_notification(make_notification(b"old2", b"new2"))
            .unwrap();
        assert_eq!(manager.total_notifications(), 2);
    }

    #[test]
    fn test_manager_add_notification_full() {
        let mut manager = RotationNotificationManager::with_capacity(2);
        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();
        manager
            .add_notification(make_notification(b"old2", b"new2"))
            .unwrap();

        let result = manager.add_notification(make_notification(b"old3", b"new3"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("notification manager full"));
    }

    #[test]
    fn test_manager_get_notifications() {
        let mut manager = RotationNotificationManager::new();
        let old_identity = make_identity(b"old");
        let notification = make_notification(b"old", b"new");
        manager.add_notification(notification.clone()).unwrap();

        let notifications = manager.get_notifications(&old_identity).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0], notification);
    }

    #[test]
    fn test_manager_get_notifications_not_found() {
        let manager = RotationNotificationManager::new();
        let unknown = make_identity(b"unknown");
        assert!(manager.get_notifications(&unknown).is_none());
    }

    #[test]
    fn test_manager_resolve_identity_no_rotation() {
        let manager = RotationNotificationManager::new();
        let identity = make_identity(b"key");
        let resolved = manager.resolve_identity(&identity);
        assert_eq!(resolved, identity);
    }

    #[test]
    fn test_manager_resolve_identity_single_rotation() {
        let mut manager = RotationNotificationManager::new();
        let notification = make_notification(b"old", b"new");
        manager.add_notification(notification).unwrap();

        let old_identity = make_identity(b"old");
        let new_identity = make_identity(b"new");
        let resolved = manager.resolve_identity(&old_identity);
        assert_eq!(resolved, new_identity);
    }

    #[test]
    fn test_manager_resolve_identity_chain() {
        let mut manager = RotationNotificationManager::new();
        // old -> mid -> new
        manager
            .add_notification(make_notification(b"old", b"mid"))
            .unwrap();
        manager
            .add_notification(make_notification(b"mid", b"new"))
            .unwrap();

        let old_identity = make_identity(b"old");
        let new_identity = make_identity(b"new");
        let resolved = manager.resolve_identity(&old_identity);
        assert_eq!(resolved, new_identity);
    }

    #[test]
    fn test_manager_resolve_identity_cycle_detection() {
        let mut manager = RotationNotificationManager::new();

        // Create a cycle: A -> B -> C -> A
        // We need to manually construct this since the identities need to form a cycle.
        let id_a = make_identity(b"key_a");
        let id_b = make_identity(b"key_b");
        let id_c = make_identity(b"key_c");

        // A -> B
        let notif_ab = KeyRotationNotification::new(
            id_a.clone(),
            id_b.clone(),
            vec![1, 2, 3],
            BASE_TIME,
            vec![0xAA],
            vec![0xBB],
        )
        .unwrap();
        manager.add_notification(notif_ab).unwrap();

        // B -> C
        let notif_bc = KeyRotationNotification::new(
            id_b.clone(),
            id_c.clone(),
            vec![4, 5, 6],
            BASE_TIME + 1,
            vec![0xAA],
            vec![0xBB],
        )
        .unwrap();
        manager.add_notification(notif_bc).unwrap();

        // C -> A (creates cycle)
        let notif_ca = KeyRotationNotification::new(
            id_c.clone(),
            id_a.clone(),
            vec![7, 8, 9],
            BASE_TIME + 2,
            vec![0xAA],
            vec![0xBB],
        )
        .unwrap();
        manager.add_notification(notif_ca).unwrap();

        // Resolution from A should not loop forever.
        // The chain is A -> B -> C -> A(cycle detected).
        // When we reach C and see its successor A is already visited, we stop.
        // So resolved = C (the last identity before the cycle was detected).
        let resolved = manager.resolve_identity(&id_a);
        assert_eq!(resolved, id_c);
    }

    #[test]
    fn test_manager_cleanup_expired() {
        let mut manager = RotationNotificationManager::new();
        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();
        manager
            .add_notification(make_notification(b"old2", b"new2"))
            .unwrap();
        assert_eq!(manager.total_notifications(), 2);

        // Not expired yet
        manager.cleanup_expired(BASE_TIME + 1000);
        assert_eq!(manager.total_notifications(), 2);

        // All expired
        manager.cleanup_expired(BASE_TIME + NOTIFICATION_EXPIRY_SECS + 1);
        assert_eq!(manager.total_notifications(), 0);
    }

    #[test]
    fn test_manager_cleanup_expired_partial() {
        let mut manager = RotationNotificationManager::new();

        // First notification at BASE_TIME
        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();

        // Second notification at BASE_TIME + 15 days
        let later_notification = KeyRotationNotification::new(
            make_identity(b"old2"),
            make_identity(b"new2"),
            vec![1, 2, 3],
            BASE_TIME + 15 * 24 * 60 * 60,
            vec![0xAA],
            vec![0xBB],
        )
        .unwrap();
        manager.add_notification(later_notification).unwrap();

        assert_eq!(manager.total_notifications(), 2);

        // Clean up at BASE_TIME + 31 days: first notification expired, second still valid
        let cleanup_time = BASE_TIME + 31 * 24 * 60 * 60;
        manager.cleanup_expired(cleanup_time);
        assert_eq!(manager.total_notifications(), 1);

        // The remaining notification should be the later one
        assert!(manager.get_notifications(&make_identity(b"old1")).is_none());
        assert!(manager.get_notifications(&make_identity(b"old2")).is_some());
    }

    #[test]
    fn test_manager_total_notifications() {
        let mut manager = RotationNotificationManager::new();
        assert_eq!(manager.total_notifications(), 0);

        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();
        assert_eq!(manager.total_notifications(), 1);

        // Add another notification for the same old identity
        let second_notification = KeyRotationNotification::new(
            make_identity(b"old1"),
            make_identity(b"new2"),
            vec![4, 5, 6],
            BASE_TIME + 100,
            vec![0xCC],
            vec![0xDD],
        )
        .unwrap();
        manager.add_notification(second_notification).unwrap();
        assert_eq!(manager.total_notifications(), 2);
    }

    #[test]
    fn test_manager_serialization_roundtrip() {
        let mut manager = RotationNotificationManager::new();
        manager
            .add_notification(make_notification(b"old1", b"new1"))
            .unwrap();
        manager
            .add_notification(make_notification(b"old2", b"new2"))
            .unwrap();

        let serialized = bincode::serialize(&manager).unwrap();
        let deserialized: RotationNotificationManager =
            bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.total_notifications(), 2);
        assert!(deserialized
            .get_notifications(&make_identity(b"old1"))
            .is_some());
        assert!(deserialized
            .get_notifications(&make_identity(b"old2"))
            .is_some());
    }

    #[test]
    fn test_manager_default() {
        let manager = RotationNotificationManager::default();
        assert_eq!(manager.total_notifications(), 0);
    }

    // ===== Constants tests =====

    #[test]
    fn test_constants() {
        assert_eq!(MAX_NOTIFICATION_CONTACTS, 1_000);
        assert_eq!(NOTIFICATION_EXPIRY_SECS, 30 * 24 * 60 * 60);
        assert_eq!(NOTIFICATION_EXPIRY_SECS, 2_592_000);
    }
}
