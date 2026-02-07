//! Validator Discovery and Trust Model.
//!
//! Implements the trusted validator list and 3-line trust fallback system
//! for the VERITAS protocol.
//!
//! ## Trust Model
//!
//! Users maintain a list of trusted validators with 3 lines of fallback:
//!
//! 1. **Line 1**: User's directly trusted validators
//! 2. **Line 2**: Trusted validators' trusted peers
//! 3. **Line 3**: Those peers' trusted peers
//!
//! This ensures that even if a user's primary validators go offline,
//! they can still submit transactions through the trust chain.
//!
//! ## Validator Registration
//!
//! Validators announce themselves via on-chain registration transactions.
//! The registration includes:
//! - ML-DSA-65 public key for block signing
//! - Staked reputation (minimum 700)
//! - Geographic region for diversity
//! - Network addresses for P2P connectivity
//!
//! ## Liveness Monitoring
//!
//! Validators send periodic heartbeats. If a trusted validator misses
//! too many heartbeats, the user is alerted to review their validator list.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use veritas_identity::IdentityHash;

use veritas_protocol::limits::{
    MAX_TRUSTED_VALIDATORS, VALIDATOR_HEARTBEAT_SECS, VALIDATOR_OFFLINE_THRESHOLD,
    VALIDATOR_TRUST_DEPTH,
};

/// Maximum number of peer validators per trusted validator.
const MAX_PEERS_PER_VALIDATOR: usize = 10;

/// Maximum total validators in the trust graph.
const MAX_TRUST_GRAPH_SIZE: usize = 500;

/// Maximum bootstrap validators.
const MAX_BOOTSTRAP_VALIDATORS: usize = 20;

// =============================================================================
// Validator Info
// =============================================================================

/// Information about a known validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// The validator's identity hash.
    pub identity: IdentityHash,
    /// Network addresses (multiaddr format).
    pub addresses: Vec<String>,
    /// Staked reputation amount.
    pub stake: u32,
    /// Geographic region.
    pub region: String,
    /// Unix timestamp of last heartbeat.
    pub last_heartbeat: u64,
    /// Whether this validator is currently considered online.
    pub online: bool,
    /// The trust level (1=direct, 2=peer-of-trusted, 3=peer-of-peer).
    pub trust_level: u8,
    /// Validators that this validator trusts (their peers).
    pub trusted_peers: Vec<IdentityHash>,
}

impl ValidatorInfo {
    /// Create a new validator info entry.
    pub fn new(
        identity: IdentityHash,
        addresses: Vec<String>,
        stake: u32,
        region: String,
        trust_level: u8,
    ) -> Self {
        Self {
            identity,
            addresses,
            stake,
            region,
            last_heartbeat: 0,
            online: false,
            trust_level,
            trusted_peers: Vec::new(),
        }
    }

    /// Update liveness status based on heartbeat timing.
    pub fn update_liveness(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last_heartbeat);
        let threshold = VALIDATOR_HEARTBEAT_SECS * VALIDATOR_OFFLINE_THRESHOLD;
        self.online = elapsed < threshold;
    }

    /// Record a heartbeat from this validator.
    pub fn record_heartbeat(&mut self, timestamp: u64) {
        self.last_heartbeat = timestamp;
        self.online = true;
    }
}

// =============================================================================
// Validator Liveness Alert
// =============================================================================

/// Alert types for validator liveness issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorAlert {
    /// A trusted validator has gone offline.
    ValidatorOffline {
        /// The offline validator.
        validator: IdentityHash,
        /// How long they've been offline (seconds).
        offline_duration: u64,
    },
    /// All directly trusted validators are offline.
    AllTrustedOffline,
    /// Recommendation to review the validator list.
    ReviewValidatorList {
        /// Number of offline validators.
        offline_count: usize,
        /// Total number of trusted validators.
        total_count: usize,
    },
}

// =============================================================================
// Trust Manager
// =============================================================================

/// Manages the trusted validator list and trust graph.
///
/// Implements the 3-line trust fallback model:
/// 1. User's directly trusted validators
/// 2. Those validators' trusted peers
/// 3. Those peers' trusted peers
///
/// ## Memory Safety
///
/// All collections are bounded:
/// - Direct trust list: MAX_TRUSTED_VALIDATORS
/// - Trust graph: MAX_TRUST_GRAPH_SIZE
/// - Bootstrap list: MAX_BOOTSTRAP_VALIDATORS
#[derive(Debug)]
pub struct TrustManager {
    /// Directly trusted validators (Line 1).
    directly_trusted: Vec<IdentityHash>,
    /// All known validators in the trust graph.
    known_validators: HashMap<IdentityHash, ValidatorInfo>,
    /// Bootstrap validators for initial discovery.
    bootstrap_validators: Vec<ValidatorInfo>,
    /// Validators we've been alerted about.
    alerted: HashSet<IdentityHash>,
}

impl TrustManager {
    /// Create a new trust manager.
    pub fn new() -> Self {
        Self {
            directly_trusted: Vec::new(),
            known_validators: HashMap::new(),
            bootstrap_validators: Vec::new(),
            alerted: HashSet::new(),
        }
    }

    /// Create a trust manager with bootstrap validators.
    pub fn with_bootstrap(bootstrap: Vec<ValidatorInfo>) -> Self {
        let mut manager = Self::new();
        for info in bootstrap.into_iter().take(MAX_BOOTSTRAP_VALIDATORS) {
            manager.bootstrap_validators.push(info);
        }
        manager
    }

    /// Add a directly trusted validator (Line 1).
    ///
    /// Returns an error if the trust list is full.
    pub fn add_trusted_validator(&mut self, info: ValidatorInfo) -> Result<(), TrustError> {
        if self.directly_trusted.len() >= MAX_TRUSTED_VALIDATORS {
            return Err(TrustError::TrustListFull);
        }

        if self.directly_trusted.contains(&info.identity) {
            return Err(TrustError::AlreadyTrusted);
        }

        let mut info = info;
        info.trust_level = 1;

        self.directly_trusted.push(info.identity.clone());
        self.known_validators.insert(info.identity.clone(), info);

        Ok(())
    }

    /// Remove a directly trusted validator.
    pub fn remove_trusted_validator(&mut self, identity: &IdentityHash) -> bool {
        if let Some(pos) = self.directly_trusted.iter().position(|id| id == identity) {
            self.directly_trusted.remove(pos);
            self.known_validators.remove(identity);
            true
        } else {
            false
        }
    }

    /// Get all directly trusted validators.
    pub fn directly_trusted(&self) -> &[IdentityHash] {
        &self.directly_trusted
    }

    /// Get the number of directly trusted validators.
    pub fn trusted_count(&self) -> usize {
        self.directly_trusted.len()
    }

    /// Get a validator's info.
    pub fn get_validator(&self, identity: &IdentityHash) -> Option<&ValidatorInfo> {
        self.known_validators.get(identity)
    }

    /// Register a validator's trusted peers (extends trust graph).
    ///
    /// When a trusted validator announces its own trusted peers,
    /// those peers become Line 2 in our trust graph.
    pub fn register_validator_peers(
        &mut self,
        validator: &IdentityHash,
        peers: Vec<ValidatorInfo>,
    ) {
        // Only accept peers from validators we directly trust
        let trust_level = match self.known_validators.get(validator) {
            Some(v) if v.trust_level <= 2 => v.trust_level + 1,
            _ => return,
        };

        if trust_level > VALIDATOR_TRUST_DEPTH as u8 {
            return;
        }

        // Record peer identities
        let peer_ids: Vec<IdentityHash> = peers
            .iter()
            .take(MAX_PEERS_PER_VALIDATOR)
            .map(|p| p.identity.clone())
            .collect();

        if let Some(v) = self.known_validators.get_mut(validator) {
            v.trusted_peers = peer_ids;
        }

        // Add peer validators to the trust graph
        for mut peer in peers.into_iter().take(MAX_PEERS_PER_VALIDATOR) {
            if self.known_validators.len() >= MAX_TRUST_GRAPH_SIZE {
                break;
            }

            if self.known_validators.contains_key(&peer.identity) {
                continue; // Don't overwrite existing entries
            }

            peer.trust_level = trust_level;
            self.known_validators.insert(peer.identity.clone(), peer);
        }
    }

    /// Get validators to submit transactions to, in trust priority order.
    ///
    /// Returns validators sorted by trust level (1 first, then 2, then 3),
    /// with online validators preferred within each level.
    pub fn get_submission_targets(&self) -> Vec<&ValidatorInfo> {
        let mut targets: Vec<&ValidatorInfo> = self.known_validators.values().collect();

        // Sort by: online status (online first), then trust level (lower first)
        targets.sort_by(|a, b| {
            match (a.online, b.online) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.trust_level.cmp(&b.trust_level),
            }
        });

        targets
    }

    /// Get online directly-trusted validators.
    pub fn online_trusted_validators(&self) -> Vec<&ValidatorInfo> {
        self.directly_trusted
            .iter()
            .filter_map(|id| self.known_validators.get(id))
            .filter(|v| v.online)
            .collect()
    }

    /// Record a heartbeat from a validator.
    pub fn record_heartbeat(&mut self, validator: &IdentityHash, timestamp: u64) {
        if let Some(info) = self.known_validators.get_mut(validator) {
            info.record_heartbeat(timestamp);
        }

        // Clear alert status if validator comes back online
        self.alerted.remove(validator);
    }

    /// Check liveness of all validators and generate alerts.
    ///
    /// Should be called periodically (e.g., every heartbeat interval).
    pub fn check_liveness(&mut self, now: u64) -> Vec<ValidatorAlert> {
        let mut alerts = Vec::new();

        // Update liveness for all known validators
        for info in self.known_validators.values_mut() {
            info.update_liveness(now);
        }

        // Check directly trusted validators
        let mut offline_count = 0;
        let total = self.directly_trusted.len();

        for id in &self.directly_trusted {
            if let Some(info) = self.known_validators.get(id) {
                if !info.online && !self.alerted.contains(id) {
                    let offline_duration = now.saturating_sub(info.last_heartbeat);
                    alerts.push(ValidatorAlert::ValidatorOffline {
                        validator: id.clone(),
                        offline_duration,
                    });
                    self.alerted.insert(id.clone());
                    offline_count += 1;
                } else if !info.online {
                    offline_count += 1;
                }
            }
        }

        // Check if all trusted validators are offline
        if total > 0 && offline_count == total {
            alerts.push(ValidatorAlert::AllTrustedOffline);
        } else if total > 0 && offline_count > total / 2 {
            alerts.push(ValidatorAlert::ReviewValidatorList {
                offline_count,
                total_count: total,
            });
        }

        alerts
    }

    /// Resolve validators through the trust chain using BFS.
    ///
    /// Starting from directly trusted validators, follows trust links
    /// up to `VALIDATOR_TRUST_DEPTH` levels deep.
    ///
    /// Returns all reachable validators in trust-level order.
    pub fn resolve_trust_chain(&self) -> Vec<&ValidatorInfo> {
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        let mut queue: VecDeque<(&IdentityHash, u8)> = VecDeque::new();

        // Start with directly trusted validators
        for id in &self.directly_trusted {
            if visited.insert(id.clone()) {
                queue.push_back((id, 1));
            }
        }

        while let Some((id, level)) = queue.pop_front() {
            if let Some(info) = self.known_validators.get(id) {
                result.push(info);

                // Follow trust links if within depth limit
                if level < VALIDATOR_TRUST_DEPTH as u8 {
                    for peer_id in &info.trusted_peers {
                        if visited.insert(peer_id.clone()) {
                            queue.push_back((peer_id, level + 1));
                        }
                    }
                }
            }
        }

        result
    }

    /// Get bootstrap validators for initial discovery.
    pub fn bootstrap_validators(&self) -> &[ValidatorInfo] {
        &self.bootstrap_validators
    }
}

impl Default for TrustManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Trust Errors
// =============================================================================

/// Errors related to the trust model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The trust list is full.
    #[error("Trust list full (max {MAX_TRUSTED_VALIDATORS} validators)")]
    TrustListFull,
    /// The validator is already trusted.
    #[error("Validator already in trust list")]
    AlreadyTrusted,
    /// The validator is not found.
    #[error("Validator not found")]
    NotFound,
}

// =============================================================================
// On-Chain Validator Registration
// =============================================================================

/// An on-chain validator registration transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// The validator's identity hash.
    pub identity: IdentityHash,
    /// ML-DSA-65 public key for block signing (1,952 bytes).
    pub signing_pubkey: Vec<u8>,
    /// Network addresses (multiaddr format).
    pub addresses: Vec<String>,
    /// Amount of reputation staked.
    pub stake: u32,
    /// Geographic region.
    pub region: String,
    /// Registration timestamp.
    pub timestamp: u64,
    /// ML-DSA-65 signature over the registration payload.
    pub signature: Vec<u8>,
}

impl ValidatorRegistration {
    /// Compute the signing payload for this registration.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"VERITAS-VALIDATOR-REGISTRATION-v1");
        payload.extend_from_slice(self.identity.as_bytes());
        payload.extend_from_slice(&self.signing_pubkey);
        payload.extend_from_slice(&(self.stake as u64).to_le_bytes());
        payload.extend_from_slice(self.region.as_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload
    }
}

/// A validator exit announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorExit {
    /// The validator leaving.
    pub identity: IdentityHash,
    /// Exit timestamp.
    pub timestamp: u64,
    /// ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

/// A validator heartbeat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorHeartbeat {
    /// The validator sending the heartbeat.
    pub identity: IdentityHash,
    /// Current block height the validator is at.
    pub current_height: u64,
    /// Heartbeat timestamp.
    pub timestamp: u64,
    /// List of this validator's trusted peers.
    pub trusted_peers: Vec<IdentityHash>,
    /// ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

impl ValidatorHeartbeat {
    /// Compute the signing payload.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"VERITAS-VALIDATOR-HEARTBEAT-v1");
        payload.extend_from_slice(self.identity.as_bytes());
        payload.extend_from_slice(&self.current_height.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        for peer in &self.trusted_peers {
            payload.extend_from_slice(peer.as_bytes());
        }
        payload
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(id: u8) -> IdentityHash {
        let bytes = [id; 32];
        IdentityHash::from_bytes(&bytes).unwrap()
    }

    fn make_validator_info(id: u8, region: &str) -> ValidatorInfo {
        ValidatorInfo::new(
            test_identity(id),
            vec![format!("/ip4/127.0.0.{}/tcp/9000", id)],
            800,
            region.to_string(),
            1,
        )
    }

    // ========================================================================
    // Trust Manager Tests
    // ========================================================================

    #[test]
    fn test_add_trusted_validator() {
        let mut manager = TrustManager::new();
        let info = make_validator_info(1, "us-east");

        assert!(manager.add_trusted_validator(info).is_ok());
        assert_eq!(manager.trusted_count(), 1);
    }

    #[test]
    fn test_add_duplicate_trusted_validator() {
        let mut manager = TrustManager::new();
        let info1 = make_validator_info(1, "us-east");
        let info2 = make_validator_info(1, "us-west"); // Same identity

        assert!(manager.add_trusted_validator(info1).is_ok());
        assert_eq!(
            manager.add_trusted_validator(info2),
            Err(TrustError::AlreadyTrusted)
        );
    }

    #[test]
    fn test_trust_list_capacity() {
        let mut manager = TrustManager::new();

        for i in 1..=(MAX_TRUSTED_VALIDATORS as u8) {
            let info = make_validator_info(i, "us-east");
            assert!(manager.add_trusted_validator(info).is_ok());
        }

        // Should be full
        let extra = make_validator_info(255, "us-east");
        assert_eq!(
            manager.add_trusted_validator(extra),
            Err(TrustError::TrustListFull)
        );
    }

    #[test]
    fn test_remove_trusted_validator() {
        let mut manager = TrustManager::new();
        let id = test_identity(1);
        let info = make_validator_info(1, "us-east");

        manager.add_trusted_validator(info).unwrap();
        assert!(manager.remove_trusted_validator(&id));
        assert_eq!(manager.trusted_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_validator() {
        let mut manager = TrustManager::new();
        assert!(!manager.remove_trusted_validator(&test_identity(99)));
    }

    // ========================================================================
    // Trust Chain Tests
    // ========================================================================

    #[test]
    fn test_trust_chain_resolution() {
        let mut manager = TrustManager::new();

        // Add directly trusted validator
        let mut v1 = make_validator_info(1, "us-east");
        v1.online = true;
        manager.add_trusted_validator(v1).unwrap();

        // Register v1's peers (Line 2)
        let v2 = make_validator_info(2, "eu-west");
        let v3 = make_validator_info(3, "ap-south");
        manager.register_validator_peers(&test_identity(1), vec![v2, v3]);

        let chain = manager.resolve_trust_chain();
        assert_eq!(chain.len(), 3); // v1 + v2 + v3
    }

    #[test]
    fn test_trust_chain_depth_limit() {
        let mut manager = TrustManager::new();

        // Line 1
        let v1 = make_validator_info(1, "us-east");
        manager.add_trusted_validator(v1).unwrap();

        // Line 2 (peers of v1)
        let mut v2 = make_validator_info(2, "eu-west");
        v2.trust_level = 2;
        manager.register_validator_peers(&test_identity(1), vec![v2]);

        // Line 3 (peers of v2)
        let v3 = make_validator_info(3, "ap-south");
        manager.register_validator_peers(&test_identity(2), vec![v3]);

        // Line 4 should NOT be added (exceeds VALIDATOR_TRUST_DEPTH)
        let v4 = make_validator_info(4, "sa-east");
        manager.register_validator_peers(&test_identity(3), vec![v4]);

        let chain = manager.resolve_trust_chain();
        // Should include v1, v2, v3 but NOT v4 (depth 4 exceeds limit of 3)
        assert!(chain.len() <= 3);
    }

    // ========================================================================
    // Liveness Tests
    // ========================================================================

    #[test]
    fn test_heartbeat_recording() {
        let mut manager = TrustManager::new();
        let info = make_validator_info(1, "us-east");
        manager.add_trusted_validator(info).unwrap();

        let id = test_identity(1);
        manager.record_heartbeat(&id, 1000);

        let v = manager.get_validator(&id).unwrap();
        assert_eq!(v.last_heartbeat, 1000);
        assert!(v.online);
    }

    #[test]
    fn test_liveness_check_offline_alert() {
        let mut manager = TrustManager::new();
        let mut info = make_validator_info(1, "us-east");
        info.last_heartbeat = 1000;
        info.online = true;
        manager.add_trusted_validator(info).unwrap();

        // Much later - validator should be considered offline
        let threshold = VALIDATOR_HEARTBEAT_SECS * VALIDATOR_OFFLINE_THRESHOLD;
        let alerts = manager.check_liveness(1000 + threshold + 1);

        assert!(alerts.iter().any(|a| matches!(
            a,
            ValidatorAlert::ValidatorOffline { .. }
        )));
    }

    #[test]
    fn test_all_trusted_offline_alert() {
        let mut manager = TrustManager::new();

        // Add two validators
        let mut v1 = make_validator_info(1, "us-east");
        v1.last_heartbeat = 100;
        v1.online = true;
        manager.add_trusted_validator(v1).unwrap();

        let mut v2 = make_validator_info(2, "eu-west");
        v2.last_heartbeat = 100;
        v2.online = true;
        manager.add_trusted_validator(v2).unwrap();

        // Both go offline
        let threshold = VALIDATOR_HEARTBEAT_SECS * VALIDATOR_OFFLINE_THRESHOLD;
        let alerts = manager.check_liveness(100 + threshold + 1);

        assert!(alerts.iter().any(|a| matches!(
            a,
            ValidatorAlert::AllTrustedOffline
        )));
    }

    // ========================================================================
    // Submission Target Tests
    // ========================================================================

    #[test]
    fn test_submission_targets_prioritize_online() {
        let mut manager = TrustManager::new();

        let mut v1 = make_validator_info(1, "us-east");
        v1.online = false;
        manager.add_trusted_validator(v1).unwrap();

        let mut v2 = make_validator_info(2, "eu-west");
        v2.online = true;
        manager.add_trusted_validator(v2).unwrap();

        let targets = manager.get_submission_targets();
        assert!(!targets.is_empty());
        // Online validators should come first
        assert!(targets[0].online);
    }

    #[test]
    fn test_submission_targets_prioritize_trust_level() {
        let mut manager = TrustManager::new();

        let mut v1 = make_validator_info(1, "us-east");
        v1.online = true;
        manager.add_trusted_validator(v1).unwrap();

        let v2 = make_validator_info(2, "eu-west");
        manager.register_validator_peers(&test_identity(1), vec![v2]);

        // Mark v2 as online
        manager.record_heartbeat(&test_identity(2), 1000);

        let targets = manager.get_submission_targets();
        assert!(targets.len() >= 2);
        // Trust level 1 should come before trust level 2
        assert!(targets[0].trust_level <= targets[1].trust_level);
    }

    // ========================================================================
    // Bootstrap Tests
    // ========================================================================

    #[test]
    fn test_bootstrap_validators() {
        let bootstrap = vec![
            make_validator_info(1, "us-east"),
            make_validator_info(2, "eu-west"),
        ];

        let manager = TrustManager::with_bootstrap(bootstrap);
        assert_eq!(manager.bootstrap_validators().len(), 2);
    }

    // ========================================================================
    // Signing Payload Tests
    // ========================================================================

    #[test]
    fn test_registration_signing_payload_deterministic() {
        let reg = ValidatorRegistration {
            identity: test_identity(1),
            signing_pubkey: vec![0u8; 1952],
            addresses: vec!["/ip4/127.0.0.1/tcp/9000".to_string()],
            stake: 800,
            region: "us-east".to_string(),
            timestamp: 1000,
            signature: vec![],
        };

        let p1 = reg.signing_payload();
        let p2 = reg.signing_payload();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_heartbeat_signing_payload_deterministic() {
        let hb = ValidatorHeartbeat {
            identity: test_identity(1),
            current_height: 100,
            timestamp: 1000,
            trusted_peers: vec![test_identity(2), test_identity(3)],
            signature: vec![],
        };

        let p1 = hb.signing_payload();
        let p2 = hb.signing_payload();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_heartbeat_includes_peer_ids() {
        let hb1 = ValidatorHeartbeat {
            identity: test_identity(1),
            current_height: 100,
            timestamp: 1000,
            trusted_peers: vec![test_identity(2)],
            signature: vec![],
        };

        let hb2 = ValidatorHeartbeat {
            identity: test_identity(1),
            current_height: 100,
            timestamp: 1000,
            trusted_peers: vec![test_identity(3)],
            signature: vec![],
        };

        // Different peers should produce different payloads
        assert_ne!(hb1.signing_payload(), hb2.signing_payload());
    }
}
