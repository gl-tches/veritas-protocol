//! Cryptographic proofs for reputation interactions.
//!
//! This module provides the `InteractionProof` type which ensures that reputation
//! changes can only occur when both parties cryptographically attest to the interaction.
//!
//! ## Security Properties
//!
//! - **Authentication**: Both parties must sign the interaction
//! - **Replay Protection**: Each proof has a unique nonce that can only be used once
//! - **Self-Interaction Prevention**: Proofs where from == to are rejected
//! - **Timestamp Binding**: Proofs include a timestamp to prevent stale proofs
//!
//! ## Example
//!
//! ```ignore
//! use veritas_reputation::proof::{InteractionProof, InteractionType};
//!
//! // Create a proof for a message delivery interaction
//! let proof = InteractionProof::new(
//!     from_identity,
//!     to_identity,
//!     InteractionType::MessageDelivery,
//!     &from_private_key,
//!     Some(&to_private_key),
//! )?;
//!
//! // Verify the proof before accepting it
//! proof.verify(&from_pubkey, Some(&to_pubkey))?;
//! ```

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::error::{ReputationError, Result};
use crate::manager::IdentityHash;

/// Maximum allowed clock skew in seconds for timestamp validation.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300; // 5 minutes

/// Maximum age of a proof before it's considered stale (24 hours).
pub const MAX_PROOF_AGE_SECS: u64 = 86400;

/// Size of signature in bytes.
/// Using a reasonable size that works for both classical (Ed25519: 64 bytes)
/// and post-quantum signatures (ML-DSA-65: 3309 bytes, FIPS 204).
/// We use a max size and pad/truncate as needed.
pub const MAX_SIGNATURE_SIZE: usize = 4096;

/// Size of nonce in bytes.
pub const NONCE_SIZE: usize = 32;

/// Types of interactions that can generate reputation.
///
/// Each interaction type may have different base reputation gains
/// and verification requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InteractionType {
    /// Successfully relayed a message to another peer.
    MessageRelay,
    /// Stored a message for offline delivery.
    MessageStorage,
    /// Successfully delivered a message to the recipient.
    MessageDelivery,
    /// Participated in DHT operations (lookups, storage).
    DhtParticipation,
    /// Validated a block in the blockchain.
    BlockValidation,
}

impl InteractionType {
    /// Get the domain separator for this interaction type.
    ///
    /// Used in signature computation to prevent cross-type attacks.
    fn domain_separator(&self) -> &'static [u8] {
        match self {
            Self::MessageRelay => b"VERITAS-INTERACTION-MESSAGE-RELAY-v1",
            Self::MessageStorage => b"VERITAS-INTERACTION-MESSAGE-STORAGE-v1",
            Self::MessageDelivery => b"VERITAS-INTERACTION-MESSAGE-DELIVERY-v1",
            Self::DhtParticipation => b"VERITAS-INTERACTION-DHT-PARTICIPATION-v1",
            Self::BlockValidation => b"VERITAS-INTERACTION-BLOCK-VALIDATION-v1",
        }
    }

    /// Check if this interaction type requires a counter-signature from the recipient.
    ///
    /// All interaction types require both parties to sign, including block validation
    /// which requires a confirming validator's counter-signature (IDENT-D6).
    #[must_use]
    pub fn requires_counter_signature(&self) -> bool {
        match self {
            Self::MessageRelay => true,
            Self::MessageStorage => true,
            Self::MessageDelivery => true,
            Self::DhtParticipation => true,
            Self::BlockValidation => true, // CHANGED: Now requires confirming validator (IDENT-D6)
        }
    }

    /// Get the base reputation gain for this interaction type.
    #[must_use]
    pub fn base_gain(&self) -> u32 {
        match self {
            Self::MessageRelay => 3,
            Self::MessageStorage => 5,
            Self::MessageDelivery => 5,
            Self::DhtParticipation => 2,
            Self::BlockValidation => 7, // Reduced from 10: now requires confirming validator (IDENT-D6)
        }
    }
}

/// A cryptographic signature wrapper.
///
/// This wraps signature bytes with serialization support.
/// The actual signature algorithm depends on the identity's key type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The raw signature bytes.
    bytes: Vec<u8>,
}

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(ReputationError::InvalidSignature(
                "signature cannot be empty".into(),
            ));
        }
        if bytes.len() > MAX_SIGNATURE_SIZE {
            return Err(ReputationError::InvalidSignature(format!(
                "signature too large: {} > {}",
                bytes.len(),
                MAX_SIGNATURE_SIZE
            )));
        }
        Ok(Self { bytes })
    }

    /// Get the signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A cryptographic proof that an interaction occurred between two parties.
///
/// This proof must be presented when recording reputation changes to prevent
/// unauthorized reputation farming.
///
/// ## Structure
///
/// The proof contains:
/// - The hash of the interaction details (binding the proof to specific parties/type)
/// - The interaction type
/// - A timestamp when the interaction occurred
/// - A unique nonce for replay protection
/// - Signature from the initiating party
/// - Optional counter-signature from the receiving party
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteractionProof {
    /// Hash of the interaction details (from, to, type, timestamp, nonce).
    /// This binds all fields together cryptographically.
    interaction_hash: [u8; 32],

    /// The type of interaction this proof attests to.
    interaction_type: InteractionType,

    /// Unix timestamp when the interaction occurred.
    timestamp: u64,

    /// Unique nonce for replay protection.
    /// Must never be reused for the same identity pair.
    nonce: [u8; NONCE_SIZE],

    /// Identity hash of the initiating party.
    from_identity: IdentityHash,

    /// Identity hash of the receiving party.
    to_identity: IdentityHash,

    /// Signature from the initiating party (required).
    from_signature: Signature,

    /// Counter-signature from the receiving party (optional for some interaction types).
    to_signature: Option<Signature>,
}

impl InteractionProof {
    /// Create a new interaction proof.
    ///
    /// # Arguments
    ///
    /// * `from` - Identity hash of the initiating party
    /// * `to` - Identity hash of the receiving party
    /// * `interaction_type` - Type of interaction being proven
    /// * `timestamp` - Unix timestamp of the interaction
    /// * `nonce` - Unique nonce (should be randomly generated)
    /// * `from_signature` - Signature from the initiating party
    /// * `to_signature` - Optional counter-signature from the receiving party
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `from` and `to` are the same (self-interaction)
    /// - Counter-signature is required but not provided
    pub fn new(
        from: IdentityHash,
        to: IdentityHash,
        interaction_type: InteractionType,
        timestamp: u64,
        nonce: [u8; NONCE_SIZE],
        from_signature: Signature,
        to_signature: Option<Signature>,
    ) -> Result<Self> {
        // SECURITY: Prevent self-interaction
        if from == to {
            return Err(ReputationError::SelfInteractionNotAllowed);
        }

        // SECURITY: Require counter-signature if needed for this interaction type
        if interaction_type.requires_counter_signature() && to_signature.is_none() {
            return Err(ReputationError::MissingCounterSignature);
        }

        // Compute the interaction hash
        let interaction_hash =
            Self::compute_interaction_hash(&from, &to, &interaction_type, timestamp, &nonce);

        Ok(Self {
            interaction_hash,
            interaction_type,
            timestamp,
            nonce,
            from_identity: from,
            to_identity: to,
            from_signature,
            to_signature,
        })
    }

    /// Compute the hash of interaction details.
    ///
    /// This creates a unique, deterministic hash of all interaction parameters
    /// that both parties sign.
    fn compute_interaction_hash(
        from: &IdentityHash,
        to: &IdentityHash,
        interaction_type: &InteractionType,
        timestamp: u64,
        nonce: &[u8; NONCE_SIZE],
    ) -> [u8; 32] {
        let domain = interaction_type.domain_separator();
        let timestamp_bytes = timestamp.to_le_bytes();

        // Create deterministic hash of all fields
        Hash256::hash_many(&[domain, from, to, &timestamp_bytes, nonce]).to_bytes()
    }

    /// Get the signing payload for this proof.
    ///
    /// This is the data that both parties sign to create the proof.
    pub fn signing_payload(&self) -> [u8; 32] {
        self.interaction_hash
    }

    /// Verify the proof's signatures.
    ///
    /// # Arguments
    ///
    /// * `from_pubkey` - Public key of the initiating party
    /// * `to_pubkey` - Public key of the receiving party (if counter-signature present)
    /// * `verify_fn` - Function to verify a signature: (pubkey, message, signature) -> bool
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `from` signature is invalid
    /// - The `to` signature is required and invalid
    /// - Counter-signature is required but not provided
    pub fn verify<F>(&self, verify_fn: F) -> Result<()>
    where
        F: Fn(&IdentityHash, &[u8], &[u8]) -> bool,
    {
        let payload = self.signing_payload();

        // Verify the initiator's signature
        if !verify_fn(
            &self.from_identity,
            &payload,
            self.from_signature.as_bytes(),
        ) {
            return Err(ReputationError::InvalidSignature(
                "from_signature verification failed".into(),
            ));
        }

        // Verify counter-signature if present and required
        if self.interaction_type.requires_counter_signature() {
            match &self.to_signature {
                Some(sig) => {
                    if !verify_fn(&self.to_identity, &payload, sig.as_bytes()) {
                        return Err(ReputationError::InvalidSignature(
                            "to_signature verification failed".into(),
                        ));
                    }
                }
                None => {
                    return Err(ReputationError::MissingCounterSignature);
                }
            }
        }

        Ok(())
    }

    /// Validate the proof's timestamp.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The timestamp is too far in the future
    /// - The proof is too old
    pub fn validate_timestamp(&self, current_time: u64) -> Result<()> {
        // Reject future timestamps (with some clock skew allowance)
        if self.timestamp > current_time + MAX_CLOCK_SKEW_SECS {
            return Err(ReputationError::InvalidProof(
                "timestamp is in the future".into(),
            ));
        }

        // Reject stale proofs
        if current_time > self.timestamp + MAX_PROOF_AGE_SECS {
            return Err(ReputationError::InvalidProof("proof has expired".into()));
        }

        Ok(())
    }

    /// Get the nonce for replay protection.
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Get the interaction type.
    pub fn interaction_type(&self) -> InteractionType {
        self.interaction_type
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the initiating party's identity.
    pub fn from_identity(&self) -> &IdentityHash {
        &self.from_identity
    }

    /// Get the receiving party's identity.
    pub fn to_identity(&self) -> &IdentityHash {
        &self.to_identity
    }

    /// Get the interaction hash.
    pub fn interaction_hash(&self) -> &[u8; 32] {
        &self.interaction_hash
    }
}

/// Trait for looking up public keys by identity hash.
///
/// Implementations provide access to the public key registry
/// for signature verification.
pub trait PubkeyRegistry: Send + Sync {
    /// Look up a public key by identity hash.
    ///
    /// Returns the public key bytes if found, or an error if not found.
    fn get_pubkey(&self, identity: &IdentityHash) -> Result<Vec<u8>>;

    /// Verify a signature for an identity.
    ///
    /// This method looks up the identity's public key and verifies
    /// the signature using the appropriate algorithm.
    ///
    /// # Arguments
    ///
    /// * `identity` - The identity whose signature to verify
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    fn verify_signature(&self, identity: &IdentityHash, message: &[u8], signature: &[u8]) -> bool;
}

/// Generate a random nonce for interaction proofs.
///
/// Uses a cryptographically secure random number generator.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("getrandom failed");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(n: u8) -> IdentityHash {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn make_signature(data: &[u8]) -> Signature {
        // For testing, create a simple "signature" by hashing the data
        let hash = Hash256::hash(data);
        Signature::from_bytes(hash.to_bytes().to_vec()).unwrap()
    }

    /// A simple test implementation of PubkeyRegistry
    struct TestRegistry {
        // Maps identity hash to whether verification should succeed
        valid_identities: std::collections::HashSet<IdentityHash>,
    }

    impl TestRegistry {
        fn new() -> Self {
            Self {
                valid_identities: std::collections::HashSet::new(),
            }
        }

        fn add_valid(&mut self, identity: IdentityHash) {
            self.valid_identities.insert(identity);
        }
    }

    impl PubkeyRegistry for TestRegistry {
        fn get_pubkey(&self, identity: &IdentityHash) -> Result<Vec<u8>> {
            if self.valid_identities.contains(identity) {
                Ok(identity.to_vec())
            } else {
                Err(ReputationError::IdentityNotFound(hex::encode(identity)))
            }
        }

        fn verify_signature(
            &self,
            identity: &IdentityHash,
            _message: &[u8],
            _signature: &[u8],
        ) -> bool {
            // For testing, just check if the identity is registered
            self.valid_identities.contains(identity)
        }
    }

    #[test]
    fn test_interaction_type_domain_separators_unique() {
        let types = [
            InteractionType::MessageRelay,
            InteractionType::MessageStorage,
            InteractionType::MessageDelivery,
            InteractionType::DhtParticipation,
            InteractionType::BlockValidation,
        ];

        let separators: std::collections::HashSet<_> =
            types.iter().map(|t| t.domain_separator()).collect();

        // All domain separators should be unique
        assert_eq!(separators.len(), types.len());
    }

    #[test]
    fn test_interaction_type_counter_signature_requirements() {
        assert!(InteractionType::MessageRelay.requires_counter_signature());
        assert!(InteractionType::MessageStorage.requires_counter_signature());
        assert!(InteractionType::MessageDelivery.requires_counter_signature());
        assert!(InteractionType::DhtParticipation.requires_counter_signature());
        assert!(InteractionType::BlockValidation.requires_counter_signature()); // CHANGED: IDENT-D6
    }

    #[test]
    fn test_self_interaction_rejected() {
        let identity = make_identity(1);
        let nonce = generate_nonce();
        let timestamp = 1704067200; // 2024-01-01

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let result = InteractionProof::new(
            identity,
            identity, // Same as from!
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        );

        assert!(matches!(
            result,
            Err(ReputationError::SelfInteractionNotAllowed)
        ));
    }

    #[test]
    fn test_missing_counter_signature_rejected() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");

        // MessageDelivery requires counter-signature
        let result = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            None, // Missing counter-signature!
        );

        assert!(matches!(
            result,
            Err(ReputationError::MissingCounterSignature)
        ));
    }

    #[test]
    fn test_block_validation_requires_counter_signature() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");

        // BlockValidation NOW requires counter-signature (IDENT-D6 fix)
        let result = InteractionProof::new(
            from,
            to,
            InteractionType::BlockValidation,
            timestamp,
            nonce,
            from_sig,
            None, // Missing counter-signature - should fail now
        );

        assert!(matches!(
            result,
            Err(ReputationError::MissingCounterSignature)
        ));
    }

    #[test]
    fn test_block_validation_with_counter_signature_succeeds() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        // BlockValidation with counter-signature should succeed
        let result = InteractionProof::new(
            from,
            to,
            InteractionType::BlockValidation,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_proof_creation() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        assert_eq!(*proof.from_identity(), from);
        assert_eq!(*proof.to_identity(), to);
        assert_eq!(proof.interaction_type(), InteractionType::MessageDelivery);
        assert_eq!(proof.timestamp(), timestamp);
        assert_eq!(*proof.nonce(), nonce);
    }

    #[test]
    fn test_signature_verification() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        let mut registry = TestRegistry::new();
        registry.add_valid(from);
        registry.add_valid(to);

        // Verification should succeed when both identities are registered
        let result = proof.verify(|identity, message, signature| {
            registry.verify_signature(identity, message, signature)
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_verification_fails_for_unknown_identity() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        let registry = TestRegistry::new(); // Empty registry!

        // Verification should fail when identities are not registered
        let result = proof.verify(|identity, message, signature| {
            registry.verify_signature(identity, message, signature)
        });
        assert!(matches!(result, Err(ReputationError::InvalidSignature(_))));
    }

    #[test]
    fn test_timestamp_validation_future() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let current_time = 1704067200;
        let future_time = current_time + MAX_CLOCK_SKEW_SECS + 100; // Too far in future

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            future_time,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        let result = proof.validate_timestamp(current_time);
        assert!(matches!(result, Err(ReputationError::InvalidProof(_))));
    }

    #[test]
    fn test_timestamp_validation_expired() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let old_time = 1704067200;
        let current_time = old_time + MAX_PROOF_AGE_SECS + 100; // Proof expired

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            old_time,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        let result = proof.validate_timestamp(current_time);
        assert!(matches!(result, Err(ReputationError::InvalidProof(_))));
    }

    #[test]
    fn test_timestamp_validation_valid() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;
        let current_time = timestamp + 3600; // 1 hour later

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        let result = proof.validate_timestamp(current_time);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be unique (with overwhelming probability)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_interaction_hash_deterministic() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = [42u8; 32];
        let timestamp = 1704067200;

        let hash1 = InteractionProof::compute_interaction_hash(
            &from,
            &to,
            &InteractionType::MessageDelivery,
            timestamp,
            &nonce,
        );

        let hash2 = InteractionProof::compute_interaction_hash(
            &from,
            &to,
            &InteractionType::MessageDelivery,
            timestamp,
            &nonce,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_interaction_hash_differs_by_type() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = [42u8; 32];
        let timestamp = 1704067200;

        let hash1 = InteractionProof::compute_interaction_hash(
            &from,
            &to,
            &InteractionType::MessageDelivery,
            timestamp,
            &nonce,
        );

        let hash2 = InteractionProof::compute_interaction_hash(
            &from,
            &to,
            &InteractionType::MessageRelay, // Different type!
            timestamp,
            &nonce,
        );

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_signature_from_empty_bytes_rejected() {
        let result = Signature::from_bytes(vec![]);
        assert!(matches!(result, Err(ReputationError::InvalidSignature(_))));
    }

    #[test]
    fn test_signature_too_large_rejected() {
        let large_sig = vec![0u8; MAX_SIGNATURE_SIZE + 1];
        let result = Signature::from_bytes(large_sig);
        assert!(matches!(result, Err(ReputationError::InvalidSignature(_))));
    }

    #[test]
    fn test_base_gain_values() {
        assert_eq!(InteractionType::MessageRelay.base_gain(), 3);
        assert_eq!(InteractionType::MessageStorage.base_gain(), 5);
        assert_eq!(InteractionType::MessageDelivery.base_gain(), 5);
        assert_eq!(InteractionType::DhtParticipation.base_gain(), 2);
        assert_eq!(InteractionType::BlockValidation.base_gain(), 7); // Changed from 10: IDENT-D6
    }

    #[test]
    fn test_serialization_roundtrip() {
        let from = make_identity(1);
        let to = make_identity(2);
        let nonce = generate_nonce();
        let timestamp = 1704067200;

        let from_sig = make_signature(b"from");
        let to_sig = make_signature(b"to");

        let proof = InteractionProof::new(
            from,
            to,
            InteractionType::MessageDelivery,
            timestamp,
            nonce,
            from_sig,
            Some(to_sig),
        )
        .unwrap();

        // Serialize
        let serialized = bincode::serialize(&proof).unwrap();

        // Deserialize
        let deserialized: InteractionProof = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.from_identity(), proof.from_identity());
        assert_eq!(deserialized.to_identity(), proof.to_identity());
        assert_eq!(deserialized.interaction_type(), proof.interaction_type());
        assert_eq!(deserialized.timestamp(), proof.timestamp());
        assert_eq!(deserialized.nonce(), proof.nonce());
    }
}
