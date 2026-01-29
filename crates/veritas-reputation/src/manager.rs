//! Central reputation manager coordinating all operations.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::collusion::CollusionDetector;
use crate::decay::{apply_decay_for_time, DecayConfig, DecayState};
use crate::effects::{get_effects_for_score, get_tier, ReputationTier, TierEffects};
use crate::error::{ReputationError, Result};
use crate::proof::{InteractionProof, PubkeyRegistry, NONCE_SIZE};
use crate::rate_limiter::{RateLimitResult, ScoreRateLimiter};
use crate::report::{NegativeReport, ReportAggregator, ReportReason};
use crate::score::ReputationScore;

/// Identity hash type (32 bytes).
pub type IdentityHash = [u8; 32];

/// Maximum number of nonces to track for replay protection.
///
/// After this limit, older nonces are pruned. This prevents unbounded memory growth
/// while still providing protection against recent replay attacks.
pub const MAX_TRACKED_NONCES: usize = 100_000;

/// Central manager for all reputation operations.
///
/// # Security (VERITAS-2026-0010)
///
/// As of this version, all reputation-changing operations require cryptographic
/// proof of interaction. This prevents:
///
/// - **Reputation farming**: Can't claim interactions that didn't happen
/// - **Self-interaction**: Can't boost own reputation
/// - **Replay attacks**: Nonces ensure each proof can only be used once
pub struct ReputationManager {
    /// All identity scores.
    scores: HashMap<IdentityHash, ReputationScore>,
    /// Rate limiter per identity.
    rate_limiters: HashMap<IdentityHash, ScoreRateLimiter>,
    /// Report aggregator for negative reports.
    report_aggregator: ReportAggregator,
    /// Collusion detector.
    collusion_detector: CollusionDetector,
    /// Decay configuration.
    decay_config: DecayConfig,
    /// Decay state per identity.
    decay_states: HashMap<IdentityHash, DecayState>,

    // === VERITAS-2026-0010: Interaction proof authentication ===

    /// Used nonces for replay protection.
    ///
    /// Each interaction proof contains a unique nonce that can only be used once.
    /// This set tracks all used nonces to prevent replay attacks.
    used_nonces: HashSet<[u8; NONCE_SIZE]>,

    /// Public key registry for signature verification.
    ///
    /// This is optional to maintain backwards compatibility with tests.
    /// In production, this MUST be set.
    #[allow(dead_code)]
    pubkey_registry: Option<Arc<dyn PubkeyRegistry>>,
}

impl ReputationManager {
    /// Create a new reputation manager with default configuration.
    ///
    /// # Note
    ///
    /// This creates a manager without a pubkey registry. For production use,
    /// call `with_pubkey_registry()` to enable signature verification.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            rate_limiters: HashMap::new(),
            report_aggregator: ReportAggregator::new(),
            collusion_detector: CollusionDetector::new(),
            decay_config: DecayConfig::default(),
            decay_states: HashMap::new(),
            used_nonces: HashSet::new(),
            pubkey_registry: None,
        }
    }

    /// Create a new reputation manager with custom decay configuration.
    ///
    /// # Note
    ///
    /// This creates a manager without a pubkey registry. For production use,
    /// call `with_pubkey_registry()` to enable signature verification.
    #[must_use]
    pub fn with_decay_config(decay_config: DecayConfig) -> Self {
        Self {
            scores: HashMap::new(),
            rate_limiters: HashMap::new(),
            report_aggregator: ReportAggregator::new(),
            collusion_detector: CollusionDetector::new(),
            decay_config,
            decay_states: HashMap::new(),
            used_nonces: HashSet::new(),
            pubkey_registry: None,
        }
    }

    /// Create a new reputation manager with a public key registry.
    ///
    /// This is the recommended constructor for production use, as it enables
    /// full cryptographic verification of interaction proofs.
    #[must_use]
    pub fn with_pubkey_registry(pubkey_registry: Arc<dyn PubkeyRegistry>) -> Self {
        Self {
            scores: HashMap::new(),
            rate_limiters: HashMap::new(),
            report_aggregator: ReportAggregator::new(),
            collusion_detector: CollusionDetector::new(),
            decay_config: DecayConfig::default(),
            decay_states: HashMap::new(),
            used_nonces: HashSet::new(),
            pubkey_registry: Some(pubkey_registry),
        }
    }

    /// Set the public key registry.
    ///
    /// Call this to enable cryptographic signature verification.
    pub fn set_pubkey_registry(&mut self, registry: Arc<dyn PubkeyRegistry>) {
        self.pubkey_registry = Some(registry);
    }

    /// Get an identity's score, creating a new one if it doesn't exist.
    pub fn get_score(&mut self, identity: &IdentityHash) -> &ReputationScore {
        self.ensure_identity_exists(identity);
        self.scores.get(identity).expect("just ensured exists")
    }

    /// Get an identity's score mutably.
    pub fn get_score_mut(&mut self, identity: &IdentityHash) -> &mut ReputationScore {
        self.ensure_identity_exists(identity);
        self.scores.get_mut(identity).expect("just ensured exists")
    }

    /// Get an identity's current score value.
    #[must_use]
    pub fn get_score_value(&self, identity: &IdentityHash) -> u32 {
        self.scores
            .get(identity)
            .map(|s| s.current())
            .unwrap_or(crate::score::REPUTATION_START)
    }

    /// Ensure an identity exists in the system.
    fn ensure_identity_exists(&mut self, identity: &IdentityHash) {
        if !self.scores.contains_key(identity) {
            self.scores.insert(*identity, ReputationScore::new());
            self.rate_limiters
                .insert(*identity, ScoreRateLimiter::new());
            self.decay_states
                .insert(*identity, DecayState::new(self.decay_config.clone()));
        }
    }

    /// Record a positive interaction with cryptographic proof.
    ///
    /// # Security (VERITAS-2026-0010)
    ///
    /// This method requires a cryptographic proof that the interaction actually
    /// occurred between the two parties. The proof must:
    ///
    /// - Be signed by the initiating party
    /// - Be counter-signed by the receiving party (for most interaction types)
    /// - Have a unique nonce that hasn't been used before
    /// - Match the claimed `from` and `to` identities
    ///
    /// # Arguments
    ///
    /// * `from` - Identity sending the positive interaction
    /// * `to` - Identity receiving the positive interaction
    /// * `proof` - Cryptographic proof of the interaction
    ///
    /// # Returns
    ///
    /// The actual reputation points gained, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The proof identities don't match the claimed parties
    /// - The proof's nonce has already been used (replay attack)
    /// - The proof's signatures are invalid
    /// - The recipient is blacklisted or quarantined
    /// - Rate limits are exceeded
    pub fn record_positive_interaction(
        &mut self,
        from: IdentityHash,
        to: IdentityHash,
        proof: &InteractionProof,
    ) -> Result<u32> {
        // SECURITY: Verify proof identities match claimed parties
        if *proof.from_identity() != from {
            return Err(ReputationError::ProofIdentityMismatch {
                expected: hex::encode(from),
                actual: hex::encode(proof.from_identity()),
            });
        }
        if *proof.to_identity() != to {
            return Err(ReputationError::ProofIdentityMismatch {
                expected: hex::encode(to),
                actual: hex::encode(proof.to_identity()),
            });
        }

        // SECURITY: Check for replay attack (nonce reuse)
        let nonce = *proof.nonce();
        if self.used_nonces.contains(&nonce) {
            return Err(ReputationError::NonceAlreadyUsed);
        }

        // SECURITY: Verify signatures if pubkey registry is available
        if let Some(ref registry) = self.pubkey_registry {
            proof.verify(|identity, message, signature| {
                registry.verify_signature(identity, message, signature)
            })?;
        }

        // SECURITY: Validate timestamp
        let current_time = Utc::now().timestamp() as u64;
        proof.validate_timestamp(current_time)?;

        self.ensure_identity_exists(&from);
        self.ensure_identity_exists(&to);

        // Check if recipient is blacklisted
        let to_score = self.scores.get(&to).unwrap();
        if to_score.is_blacklisted() {
            return Err(ReputationError::Blacklisted);
        }
        if to_score.is_quarantined() {
            return Err(ReputationError::Quarantined);
        }

        // Get base gain from interaction type
        let base_gain = proof.interaction_type().base_gain();

        // Check rate limits for the recipient gaining reputation
        let rate_limiter = self.rate_limiters.get_mut(&to).unwrap();
        let rate_result = rate_limiter.can_gain_from_peer(&from, base_gain);

        let allowed_gain = match rate_result {
            RateLimitResult::Allowed(amount) => amount,
            RateLimitResult::TooSoon { wait_seconds } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Must wait {} seconds before interacting with this peer again",
                    wait_seconds
                )));
            }
            RateLimitResult::PeerLimitReached { current, max } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Daily limit from this peer reached ({}/{})",
                    current, max
                )));
            }
            RateLimitResult::TotalLimitReached { current, max } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Daily total limit reached ({}/{})",
                    current, max
                )));
            }
        };

        // SECURITY: Record the nonce as used BEFORE applying any changes
        // This prevents partial success attacks
        self.used_nonces.insert(nonce);

        // Prune old nonces if we've exceeded the limit
        if self.used_nonces.len() > MAX_TRACKED_NONCES {
            // In a real implementation, we'd use a time-based LRU cache
            // For now, just clear half when we hit the limit
            let to_remove: Vec<_> = self
                .used_nonces
                .iter()
                .take(MAX_TRACKED_NONCES / 2)
                .copied()
                .collect();
            for nonce in to_remove {
                self.used_nonces.remove(&nonce);
            }
        }

        // Record the interaction for collusion detection
        self.collusion_detector.record_interaction(from, to);

        // Get collusion penalty multiplier
        let collusion_multiplier = self.collusion_detector.get_suspicion_penalty(&to);

        // Apply the gain with collusion multiplier
        let score = self.scores.get_mut(&to).unwrap();
        let actual_gain = score.gain_with_multiplier(allowed_gain, collusion_multiplier);

        // Record the gain in rate limiter
        let rate_limiter = self.rate_limiters.get_mut(&to).unwrap();
        rate_limiter.record_gain(&from, actual_gain);

        Ok(actual_gain)
    }

    /// Record a positive interaction without proof (TEST ONLY).
    ///
    /// # Security Warning
    ///
    /// This method bypasses all cryptographic verification and should ONLY be
    /// used in tests. Using this in production allows reputation farming attacks.
    ///
    /// # Panics
    ///
    /// Panics if called outside of test configuration.
    #[cfg(test)]
    pub fn record_positive_interaction_unchecked(
        &mut self,
        from: IdentityHash,
        to: IdentityHash,
        base_gain: u32,
    ) -> Result<u32> {
        self.ensure_identity_exists(&from);
        self.ensure_identity_exists(&to);

        // Check if recipient is blacklisted
        let to_score = self.scores.get(&to).unwrap();
        if to_score.is_blacklisted() {
            return Err(ReputationError::Blacklisted);
        }
        if to_score.is_quarantined() {
            return Err(ReputationError::Quarantined);
        }

        // Check rate limits for the recipient gaining reputation
        let rate_limiter = self.rate_limiters.get_mut(&to).unwrap();
        let rate_result = rate_limiter.can_gain_from_peer(&from, base_gain);

        let allowed_gain = match rate_result {
            RateLimitResult::Allowed(amount) => amount,
            RateLimitResult::TooSoon { wait_seconds } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Must wait {} seconds before interacting with this peer again",
                    wait_seconds
                )));
            }
            RateLimitResult::PeerLimitReached { current, max } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Daily limit from this peer reached ({}/{})",
                    current, max
                )));
            }
            RateLimitResult::TotalLimitReached { current, max } => {
                return Err(ReputationError::RateLimitExceeded(format!(
                    "Daily total limit reached ({}/{})",
                    current, max
                )));
            }
        };

        // Record the interaction for collusion detection
        self.collusion_detector.record_interaction(from, to);

        // Get collusion penalty multiplier
        let collusion_multiplier = self.collusion_detector.get_suspicion_penalty(&to);

        // Apply the gain with collusion multiplier
        let score = self.scores.get_mut(&to).unwrap();
        let actual_gain = score.gain_with_multiplier(allowed_gain, collusion_multiplier);

        // Record the gain in rate limiter
        let rate_limiter = self.rate_limiters.get_mut(&to).unwrap();
        rate_limiter.record_gain(&from, actual_gain);

        Ok(actual_gain)
    }

    /// Check if a nonce has already been used.
    ///
    /// Returns `true` if the nonce is in the used set (potential replay attack).
    #[must_use]
    pub fn is_nonce_used(&self, nonce: &[u8; NONCE_SIZE]) -> bool {
        self.used_nonces.contains(nonce)
    }

    /// Get the number of tracked nonces.
    ///
    /// Useful for monitoring memory usage.
    #[must_use]
    pub fn nonce_count(&self) -> usize {
        self.used_nonces.len()
    }

    /// File a negative report against an identity.
    pub fn file_report(
        &mut self,
        reporter: IdentityHash,
        target: IdentityHash,
        reason: ReportReason,
        evidence_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        self.ensure_identity_exists(&reporter);
        self.ensure_identity_exists(&target);

        let reporter_score = self.scores.get(&reporter).unwrap();
        let reporter_reputation = reporter_score.current();

        // Create and add the report
        let report = NegativeReport::new(reporter, target, reporter_reputation, reason, evidence_hash)?;
        self.report_aggregator.add_report(report)?;

        Ok(())
    }

    /// Process pending reports and apply penalties.
    ///
    /// Returns a list of (target, penalty_applied) tuples.
    pub fn process_reports(&mut self) -> Vec<(IdentityHash, u32)> {
        let mut penalties = Vec::new();
        let targets = self.report_aggregator.get_targets_with_reports();

        for target in targets {
            if self.report_aggregator.should_penalize(&target) {
                if let Some((penalty, _reason)) = self.report_aggregator.get_penalty(&target) {
                    if let Some(score) = self.scores.get_mut(&target) {
                        score.lose(penalty);
                        penalties.push((target, penalty));
                    }
                    self.report_aggregator.clear_reports_for(&target);
                }
            }
        }

        penalties
    }

    /// Apply decay to all scores based on time elapsed.
    pub fn apply_decay_to_all(&mut self) {
        let now = Utc::now();

        let identities: Vec<_> = self.scores.keys().copied().collect();
        for identity in identities {
            if let Some(state) = self.decay_states.get(&identity) {
                if state.should_decay(now) {
                    let current = self.scores.get(&identity).unwrap().current();
                    let new_score = apply_decay_for_time(current, state, now);

                    if let Some(score) = self.scores.get_mut(&identity) {
                        score.set_score(new_score);
                    }
                    if let Some(state) = self.decay_states.get_mut(&identity) {
                        state.mark_decayed();
                    }
                }
            }
        }
    }

    /// Apply decay to a specific identity.
    pub fn apply_decay(&mut self, identity: &IdentityHash) {
        let now = Utc::now();

        if let Some(state) = self.decay_states.get(identity) {
            if state.should_decay(now) {
                let current = self.scores.get(identity).map(|s| s.current()).unwrap_or(500);
                let new_score = apply_decay_for_time(current, state, now);

                if let Some(score) = self.scores.get_mut(identity) {
                    score.set_score(new_score);
                }
                if let Some(state) = self.decay_states.get_mut(identity) {
                    state.mark_decayed();
                }
            }
        }
    }

    /// Run collusion detection analysis.
    pub fn analyze_collusion(&mut self) {
        self.collusion_detector.analyze_clusters();
    }

    /// Get an identity's reputation tier.
    #[must_use]
    pub fn get_tier(&self, identity: &IdentityHash) -> ReputationTier {
        let score = self.scores.get(identity).map(|s| s.current()).unwrap_or(500);
        get_tier(score)
    }

    /// Get an identity's tier effects.
    #[must_use]
    pub fn get_effects(&self, identity: &IdentityHash) -> TierEffects {
        let score = self.scores.get(identity).map(|s| s.current()).unwrap_or(500);
        get_effects_for_score(score)
    }

    /// Check if an identity can perform an action.
    pub fn can_interact(&self, identity: &IdentityHash) -> Result<()> {
        let score = self.scores.get(identity);

        match score {
            Some(s) if s.is_blacklisted() => Err(ReputationError::Blacklisted),
            Some(s) if s.is_quarantined() => Err(ReputationError::Quarantined),
            _ => Ok(()),
        }
    }

    /// Check if an identity can file reports.
    pub fn can_file_report(&self, identity: &IdentityHash) -> Result<()> {
        let score = self.scores.get(identity).map(|s| s.current()).unwrap_or(500);
        if score < crate::report::MIN_REPORTER_REPUTATION {
            return Err(ReputationError::InsufficientReputation {
                required: crate::report::MIN_REPORTER_REPUTATION,
                actual: score,
            });
        }
        Ok(())
    }

    /// Get the number of tracked identities.
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.scores.len()
    }

    /// Get all suspicious clusters.
    #[must_use]
    pub fn get_suspicious_clusters(&self) -> &[crate::collusion::SuspiciousCluster] {
        self.collusion_detector.get_suspicious_clusters()
    }

    /// Check if an identity is in a suspicious cluster.
    #[must_use]
    pub fn is_in_suspicious_cluster(&self, identity: &IdentityHash) -> bool {
        self.collusion_detector.is_in_suspicious_cluster(identity)
    }

    /// Get the report count for a target.
    #[must_use]
    pub fn get_report_count(&self, target: &IdentityHash) -> usize {
        self.report_aggregator.get_report_count(target)
    }

    /// Clean up old data (interactions, reports).
    pub fn cleanup(&mut self) {
        self.collusion_detector.cleanup_old_interactions();
        self.report_aggregator.cleanup_old_reports();

        for limiter in self.rate_limiters.values_mut() {
            limiter.cleanup_old_interactions();
        }
    }

    /// Get statistics about the reputation system.
    #[must_use]
    pub fn stats(&self) -> ReputationStats {
        let mut blacklisted = 0;
        let mut quarantined = 0;
        let mut deprioritized = 0;
        let mut normal = 0;
        let mut priority = 0;

        for score in self.scores.values() {
            match get_tier(score.current()) {
                ReputationTier::Blacklisted => blacklisted += 1,
                ReputationTier::Quarantined => quarantined += 1,
                ReputationTier::Deprioritized => deprioritized += 1,
                ReputationTier::Normal => normal += 1,
                ReputationTier::Priority => priority += 1,
            }
        }

        ReputationStats {
            total_identities: self.scores.len(),
            blacklisted,
            quarantined,
            deprioritized,
            normal,
            priority,
            suspicious_clusters: self.collusion_detector.get_suspicious_clusters().len(),
        }
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ReputationManager {
    fn clone(&self) -> Self {
        Self {
            scores: self.scores.clone(),
            rate_limiters: self.rate_limiters.clone(),
            report_aggregator: self.report_aggregator.clone(),
            collusion_detector: self.collusion_detector.clone(),
            decay_config: self.decay_config.clone(),
            decay_states: self.decay_states.clone(),
            used_nonces: self.used_nonces.clone(),
            pubkey_registry: self.pubkey_registry.clone(),
        }
    }
}

impl std::fmt::Debug for ReputationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReputationManager")
            .field("scores", &self.scores)
            .field("rate_limiters", &self.rate_limiters)
            .field("report_aggregator", &self.report_aggregator)
            .field("collusion_detector", &self.collusion_detector)
            .field("decay_config", &self.decay_config)
            .field("decay_states", &self.decay_states)
            .field("used_nonces_count", &self.used_nonces.len())
            .field(
                "pubkey_registry",
                &self.pubkey_registry.as_ref().map(|_| "[PubkeyRegistry]"),
            )
            .finish()
    }
}

/// Statistics about the reputation system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationStats {
    /// Total number of tracked identities.
    pub total_identities: usize,
    /// Number of blacklisted identities.
    pub blacklisted: usize,
    /// Number of quarantined identities.
    pub quarantined: usize,
    /// Number of deprioritized identities.
    pub deprioritized: usize,
    /// Number of normal identities.
    pub normal: usize,
    /// Number of priority identities.
    pub priority: usize,
    /// Number of suspicious clusters detected.
    pub suspicious_clusters: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(n: u8) -> IdentityHash {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_new_manager() {
        let manager = ReputationManager::new();
        assert_eq!(manager.identity_count(), 0);
    }

    #[test]
    fn test_get_score_creates_new() {
        let mut manager = ReputationManager::new();
        let id = make_identity(1);

        let score = manager.get_score(&id);
        assert_eq!(score.current(), 500);
        assert_eq!(manager.identity_count(), 1);
    }

    #[test]
    fn test_positive_interaction() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        let gained = manager
            .record_positive_interaction_unchecked(from, to, 10)
            .unwrap();
        assert_eq!(gained, 10);

        let score = manager.get_score(&to);
        assert_eq!(score.current(), 510);
    }

    #[test]
    fn test_rate_limiting() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        // First interaction succeeds
        manager
            .record_positive_interaction_unchecked(from, to, 10)
            .unwrap();

        // Immediate second interaction fails (too soon)
        let result = manager.record_positive_interaction_unchecked(from, to, 10);
        assert!(matches!(result, Err(ReputationError::RateLimitExceeded(_))));
    }

    #[test]
    fn test_file_report() {
        let mut manager = ReputationManager::new();
        let reporter = make_identity(1);
        let target = make_identity(2);

        // Set reporter reputation high enough
        manager.get_score_mut(&reporter).gain(100); // Now at 600

        let result = manager.file_report(reporter, target, ReportReason::Spam, None);
        assert!(result.is_ok());

        assert_eq!(manager.get_report_count(&target), 1);
    }

    #[test]
    fn test_file_report_requires_reputation() {
        let mut manager = ReputationManager::new();
        let reporter = make_identity(1);
        let target = make_identity(2);

        // Reporter has default 500, but we need to test with low rep
        manager.get_score_mut(&reporter).lose(200); // Now at 300

        let result = manager.file_report(reporter, target, ReportReason::Spam, None);
        assert!(matches!(
            result,
            Err(ReputationError::InsufficientReputation { .. })
        ));
    }

    #[test]
    fn test_process_reports() {
        let mut manager = ReputationManager::new();
        let target = make_identity(10);

        // File 3 reports from different reporters
        for i in 1..=3 {
            let reporter = make_identity(i);
            // Ensure reporter has enough reputation
            manager.ensure_identity_exists(&reporter);
            manager.get_score_mut(&reporter).gain(100);

            manager
                .file_report(reporter, target, ReportReason::Spam, None)
                .unwrap();
        }

        // Process reports - should apply penalty
        let penalties = manager.process_reports();
        assert!(!penalties.is_empty());

        // Target should have lost reputation
        let target_score = manager.get_score(&target);
        assert!(target_score.current() < 500);
    }

    #[test]
    fn test_get_tier() {
        let mut manager = ReputationManager::new();
        let id = make_identity(1);

        manager.ensure_identity_exists(&id);
        assert_eq!(manager.get_tier(&id), ReputationTier::Normal);

        manager.get_score_mut(&id).gain(400);
        assert_eq!(manager.get_tier(&id), ReputationTier::Priority);
    }

    #[test]
    fn test_can_interact_blacklisted() {
        let mut manager = ReputationManager::new();
        let id = make_identity(1);

        manager.ensure_identity_exists(&id);
        manager.get_score_mut(&id).lose(480); // Now at 20

        let result = manager.can_interact(&id);
        assert!(matches!(result, Err(ReputationError::Blacklisted)));
    }

    #[test]
    fn test_stats() {
        let mut manager = ReputationManager::new();

        // Create some identities at different tiers
        for i in 1..=5 {
            let id = make_identity(i);
            manager.ensure_identity_exists(&id);
        }

        let stats = manager.stats();
        assert_eq!(stats.total_identities, 5);
        assert_eq!(stats.normal, 5); // All start at normal (500)
    }

    #[test]
    fn test_collusion_tracking() {
        let mut manager = ReputationManager::new();

        // Create a tight cluster of identities
        let ids: Vec<_> = (1..=4).map(make_identity).collect();

        // Record many interactions (simulating collusion)
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    // Bypass rate limiting by using different "from" each time
                    for _ in 0..5 {
                        manager.collusion_detector.record_interaction(ids[i], ids[j]);
                    }
                }
            }
        }

        manager.analyze_collusion();
        // Analysis should run without error
        // Whether clusters are flagged depends on thresholds
    }

    // === VERITAS-2026-0010: Security tests for proof-based interactions ===

    use crate::proof::{generate_nonce, InteractionProof, InteractionType, Signature};

    fn make_test_proof(
        from: IdentityHash,
        to: IdentityHash,
        interaction_type: InteractionType,
    ) -> InteractionProof {
        let nonce = generate_nonce();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let from_sig = Signature::from_bytes(vec![1u8; 64]).unwrap();
        let to_sig = if interaction_type.requires_counter_signature() {
            Some(Signature::from_bytes(vec![2u8; 64]).unwrap())
        } else {
            None
        };

        InteractionProof::new(from, to, interaction_type, timestamp, nonce, from_sig, to_sig)
            .unwrap()
    }

    #[test]
    fn test_proof_based_interaction_success() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        let proof = make_test_proof(from, to, InteractionType::MessageDelivery);
        let gained = manager.record_positive_interaction(from, to, &proof).unwrap();

        // MessageDelivery has base_gain of 5
        assert_eq!(gained, 5);

        let score = manager.get_score(&to);
        assert_eq!(score.current(), 505);
    }

    #[test]
    fn test_proof_identity_mismatch_from() {
        let mut manager = ReputationManager::new();
        let real_from = make_identity(1);
        let fake_from = make_identity(3);
        let to = make_identity(2);

        // Proof was created with real_from, but we claim fake_from
        let proof = make_test_proof(real_from, to, InteractionType::MessageDelivery);
        let result = manager.record_positive_interaction(fake_from, to, &proof);

        assert!(matches!(
            result,
            Err(ReputationError::ProofIdentityMismatch { .. })
        ));
    }

    #[test]
    fn test_proof_identity_mismatch_to() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let real_to = make_identity(2);
        let fake_to = make_identity(3);

        // Proof was created with real_to, but we claim fake_to
        let proof = make_test_proof(from, real_to, InteractionType::MessageDelivery);
        let result = manager.record_positive_interaction(from, fake_to, &proof);

        assert!(matches!(
            result,
            Err(ReputationError::ProofIdentityMismatch { .. })
        ));
    }

    #[test]
    fn test_replay_attack_prevented() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        let proof = make_test_proof(from, to, InteractionType::BlockValidation);

        // First use succeeds
        manager
            .record_positive_interaction(from, to, &proof)
            .unwrap();

        // Second use of same proof fails (replay attack)
        let result = manager.record_positive_interaction(from, to, &proof);
        assert!(matches!(result, Err(ReputationError::NonceAlreadyUsed)));
    }

    #[test]
    fn test_nonce_tracking() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        let proof = make_test_proof(from, to, InteractionType::BlockValidation);
        let nonce = *proof.nonce();

        // Nonce not used yet
        assert!(!manager.is_nonce_used(&nonce));

        // Record interaction
        manager
            .record_positive_interaction(from, to, &proof)
            .unwrap();

        // Now nonce is marked as used
        assert!(manager.is_nonce_used(&nonce));
        assert_eq!(manager.nonce_count(), 1);
    }

    #[test]
    fn test_different_interaction_types_have_different_gains() {
        let mut manager = ReputationManager::new();

        // Test MessageRelay (base_gain = 3)
        let from1 = make_identity(1);
        let to1 = make_identity(2);
        let proof1 = make_test_proof(from1, to1, InteractionType::MessageRelay);
        let gained1 = manager
            .record_positive_interaction(from1, to1, &proof1)
            .unwrap();
        assert_eq!(gained1, 3);

        // Test BlockValidation (base_gain = 10)
        let from2 = make_identity(3);
        let to2 = make_identity(4);
        let proof2 = make_test_proof(from2, to2, InteractionType::BlockValidation);
        let gained2 = manager
            .record_positive_interaction(from2, to2, &proof2)
            .unwrap();
        assert_eq!(gained2, 10);

        // Test DhtParticipation (base_gain = 2)
        let from3 = make_identity(5);
        let to3 = make_identity(6);
        let proof3 = make_test_proof(from3, to3, InteractionType::DhtParticipation);
        let gained3 = manager
            .record_positive_interaction(from3, to3, &proof3)
            .unwrap();
        assert_eq!(gained3, 2);
    }

    #[test]
    fn test_blacklisted_identity_cannot_gain_reputation() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        // Blacklist the recipient
        manager.ensure_identity_exists(&to);
        manager.get_score_mut(&to).lose(480); // Now at 20

        let proof = make_test_proof(from, to, InteractionType::MessageDelivery);
        let result = manager.record_positive_interaction(from, to, &proof);

        assert!(matches!(result, Err(ReputationError::Blacklisted)));
    }

    #[test]
    fn test_multiple_proofs_with_different_nonces() {
        let mut manager = ReputationManager::new();
        let from = make_identity(1);
        let to = make_identity(2);

        // Create multiple proofs (different nonces)
        let proof1 = make_test_proof(from, to, InteractionType::BlockValidation);
        let proof2 = make_test_proof(from, to, InteractionType::BlockValidation);

        // Both should succeed (they have different nonces)
        manager
            .record_positive_interaction(from, to, &proof1)
            .unwrap();

        // Note: This will fail due to rate limiting (too soon), not nonce reuse
        let result = manager.record_positive_interaction(from, to, &proof2);
        assert!(matches!(result, Err(ReputationError::RateLimitExceeded(_))));

        // Verify both nonces are tracked
        assert!(manager.is_nonce_used(proof1.nonce()));
        // proof2's nonce should NOT be tracked because the interaction was rejected
        // before the nonce was recorded (rate limit check happens after nonce check
        // but before nonce recording)
    }
}
