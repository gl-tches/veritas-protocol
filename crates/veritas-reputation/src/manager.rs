//! Central reputation manager coordinating all operations.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::collusion::CollusionDetector;
use crate::decay::{apply_decay_for_time, DecayConfig, DecayState};
use crate::effects::{get_effects_for_score, get_tier, ReputationTier, TierEffects};
use crate::error::{ReputationError, Result};
use crate::rate_limiter::{RateLimitResult, ScoreRateLimiter};
use crate::report::{NegativeReport, ReportAggregator, ReportReason};
use crate::score::ReputationScore;

/// Identity hash type (32 bytes).
pub type IdentityHash = [u8; 32];

/// Central manager for all reputation operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

impl ReputationManager {
    /// Create a new reputation manager with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            rate_limiters: HashMap::new(),
            report_aggregator: ReportAggregator::new(),
            collusion_detector: CollusionDetector::new(),
            decay_config: DecayConfig::default(),
            decay_states: HashMap::new(),
        }
    }

    /// Create a new reputation manager with custom decay configuration.
    #[must_use]
    pub fn with_decay_config(decay_config: DecayConfig) -> Self {
        Self {
            scores: HashMap::new(),
            rate_limiters: HashMap::new(),
            report_aggregator: ReportAggregator::new(),
            collusion_detector: CollusionDetector::new(),
            decay_config,
            decay_states: HashMap::new(),
        }
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

    /// Record a positive interaction and potentially gain reputation.
    ///
    /// # Arguments
    /// * `from` - Identity sending the positive interaction
    /// * `to` - Identity receiving the positive interaction
    /// * `base_gain` - Base reputation points to gain
    ///
    /// # Returns
    /// The actual amount gained, or an error.
    pub fn record_positive_interaction(
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

        let gained = manager.record_positive_interaction(from, to, 10).unwrap();
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
        manager.record_positive_interaction(from, to, 10).unwrap();

        // Immediate second interaction fails (too soon)
        let result = manager.record_positive_interaction(from, to, 10);
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
}
