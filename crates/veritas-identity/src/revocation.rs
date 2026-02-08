//! Key revocation system for VERITAS identities.
//!
//! Provides cryptographic key revocation with on-chain tracking.
//! Revocation is irreversible — once a key is revoked, it cannot be reactivated.
//!
//! ## Revocation Flow
//!
//! 1. Owner (or admin) creates a [`KeyRevocationRequest`] with the key hash and reason.
//! 2. The request is signed with ML-DSA-65 using the owner's signing key.
//! 3. The signed request is submitted as a `Transaction::KeyRevocation` on-chain.
//! 4. Validators verify the signature and timestamp, then record the revocation.
//! 5. The [`RevocationRegistry`] tracks all revoked keys for efficient lookup.
//!
//! ## Security Properties
//!
//! - **Irreversibility**: Once revoked, a key cannot be reactivated.
//! - **Authorization**: Only the key owner (or an admin for `AdminAction`) can revoke.
//! - **Timestamp validation**: Requests must be fresh (within 24 hours) and not in the future.
//! - **Domain separation**: Signing payload uses `"VERITAS-v1.KEY-REVOCATION."` prefix.
//! - **Bounded collections**: Registry limited to [`MAX_REVOCATIONS`] entries.
//! - **Duplicate rejection**: Revoking the same key twice is an error.

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::error::{IdentityError, Result};
use crate::identity_hash::IdentityHash;

/// Maximum number of revocations tracked per registry.
pub const MAX_REVOCATIONS: usize = 10_000;

/// Maximum age of a revocation request in seconds (24 hours).
pub const MAX_REVOCATION_REQUEST_AGE_SECS: u64 = 86_400;

/// Reasons for key revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key material has been compromised.
    KeyCompromise,
    /// Key has expired and owner is cleaning up.
    KeyExpired,
    /// User initiated revocation (no longer needs this key).
    UserInitiated,
    /// Administrative action (abuse, policy violation).
    AdminAction,
    /// Key has been superseded by a rotated key.
    Superseded {
        /// The new identity that replaces the revoked one.
        new_identity: IdentityHash,
    },
}

impl RevocationReason {
    /// Get a byte representation for signing.
    ///
    /// Each reason maps to a unique byte value used in the signing payload
    /// to ensure different reasons produce different signatures.
    pub fn as_byte(&self) -> u8 {
        match self {
            RevocationReason::KeyCompromise => 0,
            RevocationReason::KeyExpired => 1,
            RevocationReason::UserInitiated => 2,
            RevocationReason::AdminAction => 3,
            RevocationReason::Superseded { .. } => 4,
        }
    }

    /// Check if this reason allows the key to still decrypt old messages.
    ///
    /// Some revocation reasons (like key compromise or admin action) require
    /// immediate full revocation with no grace period for decryption.
    /// Others (like expiry or user-initiated) allow a grace period where
    /// the key can still be used to decrypt previously-received messages.
    pub fn allows_decryption_grace(&self) -> bool {
        match self {
            RevocationReason::KeyCompromise => false, // Immediate full revocation
            RevocationReason::KeyExpired => true,
            RevocationReason::UserInitiated => true,
            RevocationReason::AdminAction => false,
            RevocationReason::Superseded { .. } => true,
        }
    }
}

/// A request to revoke a key, signed by the key owner.
///
/// The request includes:
/// - The identity and key being revoked
/// - A reason for revocation
/// - A timestamp for freshness validation
/// - An ML-DSA-65 signature proving authorization
/// - An optional revoker identity (for admin actions)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRevocationRequest {
    /// Identity hash of the key being revoked.
    pub identity_hash: IdentityHash,
    /// Hash of the specific public key being revoked.
    pub revoked_key_hash: Hash256,
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Timestamp of the revocation request (Unix seconds).
    pub timestamp: u64,
    /// ML-DSA-65 signature proving authorization.
    pub signature: Vec<u8>,
    /// Optional: Hash of the revoking authority (for admin actions).
    pub revoker: Option<IdentityHash>,
}

impl KeyRevocationRequest {
    /// Create a new revocation request.
    ///
    /// # Arguments
    ///
    /// * `identity_hash` - Identity hash of the key being revoked.
    /// * `revoked_key_hash` - Hash of the specific public key to revoke.
    /// * `reason` - Reason for revocation.
    /// * `timestamp` - Unix timestamp in seconds.
    /// * `signature` - ML-DSA-65 signature over the signing payload.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Validation` if:
    /// - The signature is empty
    /// - The signature exceeds 4096 bytes
    /// - The timestamp is before 2024-01-01 (1704067200)
    /// - The timestamp is after 2100-01-01 (4102444800)
    pub fn new(
        identity_hash: IdentityHash,
        revoked_key_hash: Hash256,
        reason: RevocationReason,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Result<Self> {
        // Validate signature is not empty
        if signature.is_empty() {
            return Err(IdentityError::Validation(
                "revocation signature cannot be empty".into(),
            ));
        }
        // Validate signature size (ML-DSA-65 = 3309 bytes, allow some margin)
        if signature.len() > 4096 {
            return Err(IdentityError::Validation(
                "revocation signature too large".into(),
            ));
        }
        // Validate timestamp is not absurdly old (before 2024-01-01)
        if timestamp < 1704067200 {
            return Err(IdentityError::Validation("timestamp too old".into()));
        }
        // Validate timestamp is not absurdly far in future (after 2100-01-01)
        if timestamp > 4102444800 {
            return Err(IdentityError::Validation(
                "timestamp too far in future".into(),
            ));
        }
        Ok(Self {
            identity_hash,
            revoked_key_hash,
            reason,
            timestamp,
            signature,
            revoker: None,
        })
    }

    /// Create a revocation request with a revoker (for admin actions).
    ///
    /// The revoker identity is used for signature verification instead of
    /// the identity being revoked, allowing authorized administrators to
    /// revoke keys on behalf of users.
    pub fn with_revoker(mut self, revoker: IdentityHash) -> Self {
        self.revoker = Some(revoker);
        self
    }

    /// Compute the signing payload for this revocation request.
    ///
    /// Format: `"VERITAS-v1.KEY-REVOCATION." || identity_hash || revoked_key_hash || reason_byte || timestamp`
    pub fn signing_payload(&self) -> Vec<u8> {
        Self::compute_signing_payload(
            &self.identity_hash,
            &self.revoked_key_hash,
            &self.reason,
            self.timestamp,
        )
    }

    /// Static method to compute signing payload without requiring a full request.
    ///
    /// This is useful for constructing the payload before signing.
    ///
    /// Format: `"VERITAS-v1.KEY-REVOCATION." || identity_hash (32B) || revoked_key_hash (32B) || reason_byte (1B) || timestamp (8B BE)`
    pub fn compute_signing_payload(
        identity_hash: &IdentityHash,
        revoked_key_hash: &Hash256,
        reason: &RevocationReason,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(b"VERITAS-v1.KEY-REVOCATION.");
        payload.extend_from_slice(identity_hash.as_bytes());
        payload.extend_from_slice(revoked_key_hash.as_bytes());
        payload.push(reason.as_byte());
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload
    }

    /// Validate the revocation request timestamp against the current time.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Validation` if:
    /// - The timestamp is more than 300 seconds in the future (clock skew)
    /// - The request is older than [`MAX_REVOCATION_REQUEST_AGE_SECS`] (24 hours)
    pub fn validate_timestamp(&self, current_time: u64) -> Result<()> {
        if self.timestamp > current_time + 300 {
            return Err(IdentityError::Validation(
                "revocation timestamp in future".into(),
            ));
        }
        if current_time > self.timestamp + MAX_REVOCATION_REQUEST_AGE_SECS {
            return Err(IdentityError::Validation(
                "revocation request expired".into(),
            ));
        }
        Ok(())
    }

    /// Verify the request signature using a verification function.
    ///
    /// The verification function is called with:
    /// - The identity to verify against (revoker if set, otherwise the identity being revoked)
    /// - The signing payload bytes
    /// - The signature bytes
    ///
    /// # Arguments
    ///
    /// * `verify_fn` - A function that verifies an ML-DSA-65 signature.
    ///   Takes `(identity, payload, signature)` and returns `true` if valid.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Validation` if signature verification fails.
    pub fn verify<F>(&self, verify_fn: F) -> Result<()>
    where
        F: Fn(&IdentityHash, &[u8], &[u8]) -> bool,
    {
        let payload = self.signing_payload();
        let verifier = self.revoker.as_ref().unwrap_or(&self.identity_hash);
        if !verify_fn(verifier, &payload, &self.signature) {
            return Err(IdentityError::Validation(
                "revocation signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// A record of a revoked key, stored in the registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Identity hash of the revoked key.
    pub identity_hash: IdentityHash,
    /// Hash of the revoked public key.
    pub revoked_key_hash: Hash256,
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// When the revocation occurred (Unix seconds).
    pub revoked_at: u64,
    /// Block height where the revocation was recorded (0 if not yet on-chain).
    pub block_height: u64,
}

/// Registry for tracking revoked keys.
///
/// The registry maintains:
/// - A mapping from identity hash to revocation records (for querying by identity)
/// - A set of revoked key hashes (for fast revocation checks)
///
/// The registry is bounded to [`MAX_REVOCATIONS`] total entries to prevent
/// unbounded memory growth.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevocationRegistry {
    /// Revoked keys indexed by identity hash.
    records: std::collections::HashMap<IdentityHash, Vec<RevocationRecord>>,
    /// Quick lookup set for checking if a key hash is revoked.
    revoked_key_hashes: std::collections::HashSet<[u8; 32]>,
}

impl RevocationRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a key revocation.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Validation` if:
    /// - The registry is full ([`MAX_REVOCATIONS`] reached)
    /// - The key has already been revoked (duplicate)
    pub fn record_revocation(&mut self, record: RevocationRecord) -> Result<()> {
        // Check bounds
        let total: usize = self.records.values().map(|v| v.len()).sum();
        if total >= MAX_REVOCATIONS {
            return Err(IdentityError::Validation(
                "revocation registry full".into(),
            ));
        }

        // Check for duplicate revocation
        if self
            .revoked_key_hashes
            .contains(record.revoked_key_hash.as_bytes())
        {
            return Err(IdentityError::Validation("key already revoked".into()));
        }

        self.revoked_key_hashes
            .insert(*record.revoked_key_hash.as_bytes());
        self.records
            .entry(record.identity_hash.clone())
            .or_default()
            .push(record);
        Ok(())
    }

    /// Check if a key hash has been revoked.
    pub fn is_revoked(&self, key_hash: &Hash256) -> bool {
        self.revoked_key_hashes.contains(key_hash.as_bytes())
    }

    /// Check if an identity has any revoked keys.
    pub fn has_revoked_keys(&self, identity: &IdentityHash) -> bool {
        self.records.get(identity).is_some_and(|r| !r.is_empty())
    }

    /// Get all revocation records for an identity.
    pub fn get_revocations(&self, identity: &IdentityHash) -> Option<&Vec<RevocationRecord>> {
        self.records.get(identity)
    }

    /// Get total number of revocations tracked.
    pub fn total_revocations(&self) -> usize {
        self.revoked_key_hashes.len()
    }

    /// Process a revocation request and record it.
    ///
    /// Creates a [`RevocationRecord`] from the request and adds it to the registry.
    ///
    /// # Arguments
    ///
    /// * `request` - The verified revocation request.
    /// * `block_height` - The block height at which the revocation is recorded.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Validation` if the key is already revoked or
    /// the registry is full.
    pub fn process_request(
        &mut self,
        request: &KeyRevocationRequest,
        block_height: u64,
    ) -> Result<RevocationRecord> {
        let record = RevocationRecord {
            identity_hash: request.identity_hash.clone(),
            revoked_key_hash: request.revoked_key_hash.clone(),
            reason: request.reason.clone(),
            revoked_at: request.timestamp,
            block_height,
        };
        self.record_revocation(record.clone())?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> IdentityHash {
        IdentityHash::from_bytes(&[0xAA; 32]).unwrap()
    }

    fn test_identity_2() -> IdentityHash {
        IdentityHash::from_bytes(&[0xBB; 32]).unwrap()
    }

    fn test_key_hash() -> Hash256 {
        Hash256::hash(b"test-public-key")
    }

    fn test_key_hash_2() -> Hash256 {
        Hash256::hash(b"test-public-key-2")
    }

    fn test_signature() -> Vec<u8> {
        vec![0xDD; 3309] // ML-DSA-65 signature size
    }

    fn test_timestamp() -> u64 {
        1710000000 // March 2024
    }

    // --- RevocationReason tests ---

    #[test]
    fn test_revocation_reason_byte_encoding() {
        assert_eq!(RevocationReason::KeyCompromise.as_byte(), 0);
        assert_eq!(RevocationReason::KeyExpired.as_byte(), 1);
        assert_eq!(RevocationReason::UserInitiated.as_byte(), 2);
        assert_eq!(RevocationReason::AdminAction.as_byte(), 3);
        assert_eq!(
            RevocationReason::Superseded {
                new_identity: test_identity()
            }
            .as_byte(),
            4
        );
    }

    #[test]
    fn test_revocation_reason_byte_uniqueness() {
        let reasons = [
            RevocationReason::KeyCompromise,
            RevocationReason::KeyExpired,
            RevocationReason::UserInitiated,
            RevocationReason::AdminAction,
            RevocationReason::Superseded {
                new_identity: test_identity(),
            },
        ];
        let bytes: Vec<u8> = reasons.iter().map(|r| r.as_byte()).collect();
        let mut unique = bytes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(bytes.len(), unique.len(), "reason bytes must be unique");
    }

    #[test]
    fn test_decryption_grace_key_compromise() {
        assert!(!RevocationReason::KeyCompromise.allows_decryption_grace());
    }

    #[test]
    fn test_decryption_grace_key_expired() {
        assert!(RevocationReason::KeyExpired.allows_decryption_grace());
    }

    #[test]
    fn test_decryption_grace_user_initiated() {
        assert!(RevocationReason::UserInitiated.allows_decryption_grace());
    }

    #[test]
    fn test_decryption_grace_admin_action() {
        assert!(!RevocationReason::AdminAction.allows_decryption_grace());
    }

    #[test]
    fn test_decryption_grace_superseded() {
        let reason = RevocationReason::Superseded {
            new_identity: test_identity(),
        };
        assert!(reason.allows_decryption_grace());
    }

    #[test]
    fn test_revocation_reason_serialization_roundtrip() {
        let reasons = vec![
            RevocationReason::KeyCompromise,
            RevocationReason::KeyExpired,
            RevocationReason::UserInitiated,
            RevocationReason::AdminAction,
            RevocationReason::Superseded {
                new_identity: test_identity(),
            },
        ];
        for reason in reasons {
            let serialized = bincode::serialize(&reason).unwrap();
            let deserialized: RevocationReason = bincode::deserialize(&serialized).unwrap();
            assert_eq!(reason, deserialized);
        }
    }

    // --- KeyRevocationRequest creation tests ---

    #[test]
    fn test_request_creation_valid() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        );
        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.identity_hash, test_identity());
        assert_eq!(req.revoked_key_hash, test_key_hash());
        assert_eq!(req.reason, RevocationReason::UserInitiated);
        assert_eq!(req.timestamp, test_timestamp());
        assert!(req.revoker.is_none());
    }

    #[test]
    fn test_request_creation_empty_signature() {
        let result = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            vec![], // empty signature
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn test_request_creation_oversized_signature() {
        let result = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            vec![0; 4097], // over 4096 bytes
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"));
    }

    #[test]
    fn test_request_creation_timestamp_too_old() {
        let result = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            1000000000, // year 2001
            test_signature(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too old"));
    }

    #[test]
    fn test_request_creation_timestamp_too_far_future() {
        let result = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            4102444801, // after 2100
            test_signature(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too far in future"));
    }

    #[test]
    fn test_request_with_revoker() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::AdminAction,
            test_timestamp(),
            test_signature(),
        )
        .unwrap()
        .with_revoker(test_identity_2());

        assert!(req.revoker.is_some());
        assert_eq!(req.revoker.unwrap(), test_identity_2());
    }

    // --- Signing payload tests ---

    #[test]
    fn test_signing_payload_deterministic() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        let p1 = req.signing_payload();
        let p2 = req.signing_payload();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_signing_payload_starts_with_domain() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        let payload = req.signing_payload();
        assert!(payload.starts_with(b"VERITAS-v1.KEY-REVOCATION."));
    }

    #[test]
    fn test_signing_payload_static_matches_instance() {
        let identity = test_identity();
        let key_hash = test_key_hash();
        let reason = RevocationReason::KeyExpired;
        let timestamp = test_timestamp();

        let req = KeyRevocationRequest::new(
            identity.clone(),
            key_hash.clone(),
            reason.clone(),
            timestamp,
            test_signature(),
        )
        .unwrap();

        let instance_payload = req.signing_payload();
        let static_payload = KeyRevocationRequest::compute_signing_payload(
            &identity, &key_hash, &reason, timestamp,
        );

        assert_eq!(instance_payload, static_payload);
    }

    #[test]
    fn test_signing_payload_different_reasons_differ() {
        let p1 = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp(),
        );
        let p2 = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::UserInitiated,
            test_timestamp(),
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_signing_payload_different_timestamps_differ() {
        let p1 = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp(),
        );
        let p2 = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp() + 1,
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_signing_payload_different_identities_differ() {
        let p1 = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp(),
        );
        let p2 = KeyRevocationRequest::compute_signing_payload(
            &test_identity_2(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp(),
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_signing_payload_expected_length() {
        let payload = KeyRevocationRequest::compute_signing_payload(
            &test_identity(),
            &test_key_hash(),
            &RevocationReason::KeyCompromise,
            test_timestamp(),
        );
        // "VERITAS-v1.KEY-REVOCATION." = 26 bytes
        // identity_hash = 32 bytes
        // revoked_key_hash = 32 bytes
        // reason_byte = 1 byte
        // timestamp = 8 bytes
        assert_eq!(payload.len(), 26 + 32 + 32 + 1 + 8);
    }

    // --- Timestamp validation tests ---

    #[test]
    fn test_timestamp_validation_valid() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Current time = timestamp + 1 hour (well within 24h window)
        assert!(req.validate_timestamp(test_timestamp() + 3600).is_ok());
    }

    #[test]
    fn test_timestamp_validation_same_time() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        assert!(req.validate_timestamp(test_timestamp()).is_ok());
    }

    #[test]
    fn test_timestamp_validation_in_future() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp() + 500, // 500 seconds in future
            test_signature(),
        )
        .unwrap();

        // Current time is 500 seconds before the request timestamp
        // That's > 300s clock skew tolerance
        let result = req.validate_timestamp(test_timestamp());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("future"));
    }

    #[test]
    fn test_timestamp_validation_within_clock_skew() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp() + 200, // 200 seconds in future
            test_signature(),
        )
        .unwrap();

        // 200s < 300s clock skew, should be OK
        assert!(req.validate_timestamp(test_timestamp()).is_ok());
    }

    #[test]
    fn test_timestamp_validation_expired() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Current time = timestamp + 25 hours (past 24h window)
        let result = req.validate_timestamp(test_timestamp() + 90_000);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expired"));
    }

    #[test]
    fn test_timestamp_validation_at_boundary() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Exactly at the 24h boundary
        assert!(req
            .validate_timestamp(test_timestamp() + MAX_REVOCATION_REQUEST_AGE_SECS)
            .is_ok());

        // One second past the boundary
        let result =
            req.validate_timestamp(test_timestamp() + MAX_REVOCATION_REQUEST_AGE_SECS + 1);
        assert!(result.is_err());
    }

    // --- Signature verification tests ---

    #[test]
    fn test_verify_signature_valid() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Verifier that always succeeds
        let result = req.verify(|_id, _payload, _sig| true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Verifier that always fails
        let result = req.verify(|_id, _payload, _sig| false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("verification failed"));
    }

    #[test]
    fn test_verify_uses_identity_when_no_revoker() {
        let identity = test_identity();
        let req = KeyRevocationRequest::new(
            identity.clone(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // Verify that the identity (not revoker) is used for verification
        let result = req.verify(|id, _payload, _sig| *id == identity);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_uses_revoker_when_present() {
        let revoker = test_identity_2();
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::AdminAction,
            test_timestamp(),
            test_signature(),
        )
        .unwrap()
        .with_revoker(revoker.clone());

        // Verify that the revoker identity is used for verification
        let result = req.verify(|id, _payload, _sig| *id == revoker);
        assert!(result.is_ok());

        // If we check against the original identity, it should fail
        let identity = test_identity();
        let result = req.verify(|id, _payload, _sig| *id == identity);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_receives_correct_payload() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        let expected_payload = req.signing_payload();
        let result = req.verify(|_id, payload, _sig| payload == expected_payload);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_receives_correct_signature() {
        let sig = test_signature();
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            sig.clone(),
        )
        .unwrap();

        let result = req.verify(|_id, _payload, received_sig| received_sig == sig);
        assert!(result.is_ok());
    }

    // --- RevocationRegistry tests ---

    #[test]
    fn test_registry_new_is_empty() {
        let registry = RevocationRegistry::new();
        assert_eq!(registry.total_revocations(), 0);
    }

    #[test]
    fn test_registry_record_revocation() {
        let mut registry = RevocationRegistry::new();
        let record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp(),
            block_height: 100,
        };
        assert!(registry.record_revocation(record).is_ok());
        assert_eq!(registry.total_revocations(), 1);
    }

    #[test]
    fn test_registry_is_revoked() {
        let mut registry = RevocationRegistry::new();
        let key_hash = test_key_hash();

        assert!(!registry.is_revoked(&key_hash));

        let record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: key_hash.clone(),
            reason: RevocationReason::KeyCompromise,
            revoked_at: test_timestamp(),
            block_height: 50,
        };
        registry.record_revocation(record).unwrap();

        assert!(registry.is_revoked(&key_hash));
    }

    #[test]
    fn test_registry_not_revoked_different_key() {
        let mut registry = RevocationRegistry::new();
        let record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::KeyCompromise,
            revoked_at: test_timestamp(),
            block_height: 50,
        };
        registry.record_revocation(record).unwrap();

        // Different key should not be revoked
        assert!(!registry.is_revoked(&test_key_hash_2()));
    }

    #[test]
    fn test_registry_has_revoked_keys() {
        let mut registry = RevocationRegistry::new();
        let identity = test_identity();

        assert!(!registry.has_revoked_keys(&identity));

        let record = RevocationRecord {
            identity_hash: identity.clone(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp(),
            block_height: 100,
        };
        registry.record_revocation(record).unwrap();

        assert!(registry.has_revoked_keys(&identity));
        assert!(!registry.has_revoked_keys(&test_identity_2()));
    }

    #[test]
    fn test_registry_get_revocations() {
        let mut registry = RevocationRegistry::new();
        let identity = test_identity();

        assert!(registry.get_revocations(&identity).is_none());

        let record = RevocationRecord {
            identity_hash: identity.clone(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::KeyExpired,
            revoked_at: test_timestamp(),
            block_height: 200,
        };
        registry.record_revocation(record).unwrap();

        let records = registry.get_revocations(&identity).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, RevocationReason::KeyExpired);
        assert_eq!(records[0].block_height, 200);
    }

    #[test]
    fn test_registry_multiple_revocations_per_identity() {
        let mut registry = RevocationRegistry::new();
        let identity = test_identity();

        let record1 = RevocationRecord {
            identity_hash: identity.clone(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::KeyExpired,
            revoked_at: test_timestamp(),
            block_height: 100,
        };
        let record2 = RevocationRecord {
            identity_hash: identity.clone(),
            revoked_key_hash: test_key_hash_2(),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp() + 1000,
            block_height: 110,
        };

        registry.record_revocation(record1).unwrap();
        registry.record_revocation(record2).unwrap();

        assert_eq!(registry.total_revocations(), 2);
        let records = registry.get_revocations(&identity).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_registry_duplicate_rejection() {
        let mut registry = RevocationRegistry::new();
        let key_hash = test_key_hash();

        let record1 = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: key_hash.clone(),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp(),
            block_height: 100,
        };
        let record2 = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: key_hash,
            reason: RevocationReason::KeyCompromise,
            revoked_at: test_timestamp() + 500,
            block_height: 105,
        };

        assert!(registry.record_revocation(record1).is_ok());
        let result = registry.record_revocation(record2);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already revoked"));

        // Only one revocation should be recorded
        assert_eq!(registry.total_revocations(), 1);
    }

    #[test]
    fn test_registry_bounds_enforcement() {
        let mut registry = RevocationRegistry::new();

        // Fill up to MAX_REVOCATIONS
        for i in 0..MAX_REVOCATIONS {
            let key_hash =
                Hash256::hash(format!("key-{}", i).as_bytes());
            let record = RevocationRecord {
                identity_hash: test_identity(),
                revoked_key_hash: key_hash,
                reason: RevocationReason::UserInitiated,
                revoked_at: test_timestamp(),
                block_height: i as u64,
            };
            registry.record_revocation(record).unwrap();
        }

        assert_eq!(registry.total_revocations(), MAX_REVOCATIONS);

        // One more should fail
        let overflow_record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: Hash256::hash(b"overflow-key"),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp(),
            block_height: MAX_REVOCATIONS as u64,
        };
        let result = registry.record_revocation(overflow_record);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("full"));
    }

    #[test]
    fn test_registry_process_request() {
        let mut registry = RevocationRegistry::new();
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        let record = registry.process_request(&req, 500).unwrap();
        assert_eq!(record.identity_hash, test_identity());
        assert_eq!(record.revoked_key_hash, test_key_hash());
        assert_eq!(record.reason, RevocationReason::KeyCompromise);
        assert_eq!(record.revoked_at, test_timestamp());
        assert_eq!(record.block_height, 500);

        assert!(registry.is_revoked(&test_key_hash()));
        assert_eq!(registry.total_revocations(), 1);
    }

    #[test]
    fn test_registry_process_request_duplicate_fails() {
        let mut registry = RevocationRegistry::new();
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        assert!(registry.process_request(&req, 500).is_ok());
        let result = registry.process_request(&req, 501);
        assert!(result.is_err());
    }

    // --- Admin revocation tests ---

    #[test]
    fn test_admin_revocation_flow() {
        let admin = test_identity_2();
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::AdminAction,
            test_timestamp(),
            test_signature(),
        )
        .unwrap()
        .with_revoker(admin.clone());

        // Admin should be the verifier
        assert_eq!(req.revoker.as_ref().unwrap(), &admin);

        // Verify uses admin identity
        let result = req.verify(|id, _payload, _sig| *id == admin);
        assert!(result.is_ok());

        // Process in registry
        let mut registry = RevocationRegistry::new();
        let record = registry.process_request(&req, 1000).unwrap();
        assert_eq!(record.reason, RevocationReason::AdminAction);
        assert!(registry.is_revoked(&test_key_hash()));
    }

    // --- Serialization tests ---

    #[test]
    fn test_revocation_record_serialization() {
        let record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::Superseded {
                new_identity: test_identity_2(),
            },
            revoked_at: test_timestamp(),
            block_height: 42,
        };

        let serialized = bincode::serialize(&record).unwrap();
        let deserialized: RevocationRecord = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.identity_hash, record.identity_hash);
        assert_eq!(deserialized.revoked_key_hash, record.revoked_key_hash);
        assert_eq!(deserialized.reason, record.reason);
        assert_eq!(deserialized.revoked_at, record.revoked_at);
        assert_eq!(deserialized.block_height, record.block_height);
    }

    #[test]
    fn test_revocation_request_serialization() {
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        let serialized = bincode::serialize(&req).unwrap();
        let deserialized: KeyRevocationRequest = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.identity_hash, req.identity_hash);
        assert_eq!(deserialized.revoked_key_hash, req.revoked_key_hash);
        assert_eq!(deserialized.reason, req.reason);
        assert_eq!(deserialized.timestamp, req.timestamp);
        assert_eq!(deserialized.signature, req.signature);
    }

    #[test]
    fn test_revocation_registry_serialization() {
        let mut registry = RevocationRegistry::new();
        let record = RevocationRecord {
            identity_hash: test_identity(),
            revoked_key_hash: test_key_hash(),
            reason: RevocationReason::UserInitiated,
            revoked_at: test_timestamp(),
            block_height: 100,
        };
        registry.record_revocation(record).unwrap();

        let serialized = bincode::serialize(&registry).unwrap();
        let deserialized: RevocationRegistry = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.total_revocations(), 1);
        assert!(deserialized.is_revoked(&test_key_hash()));
        assert!(deserialized.has_revoked_keys(&test_identity()));
    }

    // --- Comprehensive integration test ---

    #[test]
    fn test_full_revocation_lifecycle() {
        let mut registry = RevocationRegistry::new();

        // 1. Create request
        let req = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::KeyCompromise,
            test_timestamp(),
            test_signature(),
        )
        .unwrap();

        // 2. Validate timestamp
        assert!(req.validate_timestamp(test_timestamp() + 100).is_ok());

        // 3. Verify signature (mock)
        assert!(req.verify(|_id, _payload, _sig| true).is_ok());

        // 4. Process in registry
        let record = registry.process_request(&req, 500).unwrap();

        // 5. Verify state
        assert!(registry.is_revoked(&test_key_hash()));
        assert!(registry.has_revoked_keys(&test_identity()));
        assert_eq!(record.block_height, 500);

        // 6. Attempting second revocation of same key fails
        let req2 = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash(),
            RevocationReason::UserInitiated,
            test_timestamp() + 100,
            test_signature(),
        )
        .unwrap();
        assert!(registry.process_request(&req2, 501).is_err());

        // 7. Revoking a different key succeeds
        let req3 = KeyRevocationRequest::new(
            test_identity(),
            test_key_hash_2(),
            RevocationReason::Superseded {
                new_identity: test_identity_2(),
            },
            test_timestamp() + 200,
            test_signature(),
        )
        .unwrap();
        assert!(registry.process_request(&req3, 502).is_ok());
        assert_eq!(registry.total_revocations(), 2);

        let records = registry.get_revocations(&test_identity()).unwrap();
        assert_eq!(records.len(), 2);
    }
}
