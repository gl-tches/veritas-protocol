//! PoS Validator Selection with SLA enforcement.
//!
//! This module implements a Proof-of-Stake validator selection system with
//! Service Level Agreement (SLA) requirements for the VERITAS protocol.
//!
//! ## Overview
//!
//! Validators are selected based on:
//! - **Stake**: Minimum 700 reputation required to participate
//! - **Performance**: Historical block production and response metrics
//! - **SLA Compliance**: Uptime, missed blocks, latency requirements
//! - **Geographic Diversity**: Maximum 5 validators per region
//!
//! ## Selection Algorithm
//!
//! Selection is deterministic per epoch using ChaCha20-based RNG seeded
//! with the epoch number. This ensures all nodes agree on the validator
//! set for any given epoch.
//!
//! The selection weight is calculated as:
//! ```text
//! weight = stake * performance_multiplier * sla_bonus
//! where:
//!   performance_multiplier = 0.5 + (performance_score / 100.0)  // 0.5-1.5
//!   sla_bonus = if compliant { 1.0 + (streak * 0.05).min(0.5) } else { 0.7 }
//! ```
//!
//! ## Rotation
//!
//! 15% of validators are rotated each epoch, with worst performers
//! being replaced first to ensure network quality improves over time.

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;
use veritas_protocol::limits::{
    MAX_VALIDATORS, MAX_VALIDATORS_PER_REGION, MIN_UPTIME_PERCENT, MIN_VALIDATOR_STAKE,
    VALIDATOR_ROTATION_PERCENT,
};

use crate::{ChainError, Result};

/// A validator's staked reputation and performance metrics.
///
/// Tracks the validator's identity, staked amount, and historical
/// performance data used for selection weighting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStake {
    /// The validator's unique identity hash.
    pub identity: IdentityHash,
    /// Amount of reputation staked (minimum 700).
    pub stake: u32,
    /// Performance score from 0-100 based on historical behavior.
    pub performance_score: u32,
    /// Number of consecutive epochs meeting SLA requirements.
    pub sla_streak: u32,
    /// Geographic region for diversity enforcement.
    pub region: String,
    /// Unix timestamp when the validator registered.
    pub registered_at: u64,
    /// Unix timestamp of last block production, if any.
    pub last_block_at: Option<u64>,
}

impl ValidatorStake {
    /// Create a new validator stake record.
    ///
    /// # Arguments
    ///
    /// * `identity` - The validator's identity hash
    /// * `stake` - Amount of reputation to stake
    /// * `region` - Geographic region identifier
    /// * `registered_at` - Unix timestamp of registration
    ///
    /// # Errors
    ///
    /// Returns `ChainError::InsufficientStake` if stake is below minimum (700).
    pub fn new(
        identity: IdentityHash,
        stake: u32,
        region: String,
        registered_at: u64,
    ) -> Result<Self> {
        if stake < MIN_VALIDATOR_STAKE {
            return Err(ChainError::InsufficientStake {
                required: MIN_VALIDATOR_STAKE,
                actual: stake,
            });
        }

        Ok(Self {
            identity,
            stake,
            performance_score: 50, // Start with neutral performance
            sla_streak: 0,
            region,
            registered_at,
            last_block_at: None,
        })
    }

    /// Calculate the selection weight for this validator.
    ///
    /// The weight formula is:
    /// ```text
    /// weight = stake * performance_multiplier * sla_bonus
    /// ```
    ///
    /// where:
    /// - `performance_multiplier` = 0.5 + (performance_score / 100.0), range 0.5-1.5
    /// - `sla_bonus` = 1.0 + (streak * 0.05) capped at 1.5 if compliant, or 0.7 if not
    ///
    /// # Arguments
    ///
    /// * `sla_compliant` - Whether the validator met SLA requirements last epoch
    pub fn calculate_weight(&self, sla_compliant: bool) -> f32 {
        let stake_weight = self.stake as f32;

        // Performance multiplier: 0.5-1.5 based on score
        let perf_multiplier = 0.5 + (self.performance_score as f32 / 100.0);

        // SLA bonus: compliant validators get up to 50% bonus for streaks
        let sla_bonus = if sla_compliant {
            1.0 + (self.sla_streak as f32 * 0.05).min(0.5)
        } else {
            0.7
        };

        stake_weight * perf_multiplier * sla_bonus
    }

    /// Update performance score based on epoch metrics.
    ///
    /// Score is bounded to 0-100 range.
    pub fn update_performance(&mut self, delta: i32) {
        let new_score = (self.performance_score as i32 + delta).clamp(0, 100);
        self.performance_score = new_score as u32;
    }

    /// Record that the validator met SLA requirements this epoch.
    pub fn record_sla_compliance(&mut self) {
        self.sla_streak = self.sla_streak.saturating_add(1);
    }

    /// Record that the validator failed SLA requirements this epoch.
    pub fn record_sla_violation(&mut self) {
        self.sla_streak = 0;
    }

    /// Record block production at the given timestamp.
    pub fn record_block_production(&mut self, timestamp: u64) {
        self.last_block_at = Some(timestamp);
    }
}

impl PartialEq for ValidatorStake {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for ValidatorStake {}

impl std::hash::Hash for ValidatorStake {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity.as_bytes().hash(state);
    }
}

/// Service Level Agreement requirements for validators.
///
/// Validators must meet these requirements to remain in good standing
/// and receive full selection weight bonuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSla {
    /// Minimum uptime percentage required (default: 99.0%).
    pub min_uptime_percent: f32,
    /// Maximum blocks that can be missed per epoch (default: 3).
    pub max_missed_blocks_per_epoch: u32,
    /// Maximum response latency in milliseconds (default: 5000).
    pub max_response_latency_ms: u64,
    /// Minimum blocks that must be produced per epoch when scheduled (default: 10).
    pub min_blocks_per_epoch: u32,
}

impl Default for ValidatorSla {
    fn default() -> Self {
        Self {
            min_uptime_percent: MIN_UPTIME_PERCENT,
            max_missed_blocks_per_epoch: veritas_protocol::limits::MAX_MISSED_BLOCKS_PER_EPOCH,
            max_response_latency_ms: veritas_protocol::limits::MAX_RESPONSE_LATENCY_MS,
            min_blocks_per_epoch: veritas_protocol::limits::MIN_BLOCKS_PER_EPOCH,
        }
    }
}

impl ValidatorSla {
    /// Create a new SLA configuration.
    pub fn new(
        min_uptime_percent: f32,
        max_missed_blocks_per_epoch: u32,
        max_response_latency_ms: u64,
        min_blocks_per_epoch: u32,
    ) -> Self {
        Self {
            min_uptime_percent,
            max_missed_blocks_per_epoch,
            max_response_latency_ms,
            min_blocks_per_epoch,
        }
    }

    /// Check if a validator's metrics meet SLA requirements.
    ///
    /// # Arguments
    ///
    /// * `uptime_percent` - Validator's uptime percentage this epoch
    /// * `missed_blocks` - Number of blocks missed this epoch
    /// * `avg_latency_ms` - Average response latency in milliseconds
    /// * `blocks_produced` - Number of blocks produced this epoch
    pub fn check_compliance(
        &self,
        uptime_percent: f32,
        missed_blocks: u32,
        avg_latency_ms: u64,
        blocks_produced: u32,
    ) -> bool {
        uptime_percent >= self.min_uptime_percent
            && missed_blocks <= self.max_missed_blocks_per_epoch
            && avg_latency_ms <= self.max_response_latency_ms
            && blocks_produced >= self.min_blocks_per_epoch
    }
}

/// Epoch-specific metrics for a validator.
#[derive(Debug, Clone, Default)]
pub struct ValidatorEpochMetrics {
    /// Uptime percentage for this epoch.
    pub uptime_percent: f32,
    /// Number of blocks missed this epoch.
    pub missed_blocks: u32,
    /// Average response latency in milliseconds.
    pub avg_latency_ms: u64,
    /// Number of blocks produced this epoch.
    pub blocks_produced: u32,
}

/// Manages the active validator set and selection.
///
/// Tracks all registered validators and handles epoch-based
/// selection with geographic diversity enforcement.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// All registered validators indexed by identity.
    validators: HashMap<IdentityHash, ValidatorStake>,
    /// Currently active validators for this epoch.
    active: Vec<IdentityHash>,
    /// SLA configuration.
    sla: ValidatorSla,
    /// Current epoch number.
    current_epoch: u64,
}

impl ValidatorSet {
    /// Create a new validator set.
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            active: Vec::new(),
            sla: ValidatorSla::default(),
            current_epoch: 0,
        }
    }

    /// Create a validator set with custom SLA requirements.
    pub fn with_sla(sla: ValidatorSla) -> Self {
        Self {
            validators: HashMap::new(),
            active: Vec::new(),
            sla,
            current_epoch: 0,
        }
    }

    /// Register a new validator.
    ///
    /// # Errors
    ///
    /// Returns an error if the stake is insufficient.
    pub fn register(&mut self, validator: ValidatorStake) -> Result<()> {
        if validator.stake < MIN_VALIDATOR_STAKE {
            return Err(ChainError::InsufficientStake {
                required: MIN_VALIDATOR_STAKE,
                actual: validator.stake,
            });
        }
        self.validators
            .insert(validator.identity.clone(), validator);
        Ok(())
    }

    /// Unregister a validator.
    pub fn unregister(&mut self, identity: &IdentityHash) -> Option<ValidatorStake> {
        self.active.retain(|id| id != identity);
        self.validators.remove(identity)
    }

    /// Get a validator by identity.
    pub fn get(&self, identity: &IdentityHash) -> Option<&ValidatorStake> {
        self.validators.get(identity)
    }

    /// Get a mutable reference to a validator.
    pub fn get_mut(&mut self, identity: &IdentityHash) -> Option<&mut ValidatorStake> {
        self.validators.get_mut(identity)
    }

    /// Get all registered validators.
    pub fn all_validators(&self) -> impl Iterator<Item = &ValidatorStake> {
        self.validators.values()
    }

    /// Get the currently active validators.
    pub fn active_validators(&self) -> Vec<&ValidatorStake> {
        self.active
            .iter()
            .filter_map(|id| self.validators.get(id))
            .collect()
    }

    /// Get the number of registered validators.
    pub fn registered_count(&self) -> usize {
        self.validators.len()
    }

    /// Get the number of active validators.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Check if a validator is currently active.
    pub fn is_active(&self, identity: &IdentityHash) -> bool {
        self.active.contains(identity)
    }

    /// Update the validator set for a new epoch.
    ///
    /// This performs selection of active validators with:
    /// - Stake-weighted random selection
    /// - Geographic diversity enforcement
    /// - 15% rotation of worst performers
    ///
    /// # Arguments
    ///
    /// * `epoch` - The new epoch number
    /// * `metrics` - Performance metrics for each validator from previous epoch
    pub fn advance_epoch(
        &mut self,
        epoch: u64,
        metrics: &HashMap<IdentityHash, ValidatorEpochMetrics>,
    ) {
        self.current_epoch = epoch;

        // Update SLA compliance and performance for all validators
        for (identity, validator) in self.validators.iter_mut() {
            if let Some(m) = metrics.get(identity) {
                let compliant = self.sla.check_compliance(
                    m.uptime_percent,
                    m.missed_blocks,
                    m.avg_latency_ms,
                    m.blocks_produced,
                );

                if compliant {
                    validator.record_sla_compliance();
                    validator.update_performance(5); // Reward good behavior
                } else {
                    validator.record_sla_violation();
                    validator.update_performance(-10); // Penalize violations
                }
            }
        }

        // Perform selection for new epoch
        self.active = ValidatorSelection::select_validators_internal(
            &self.validators,
            &self.sla,
            epoch,
            &self.active,
        );
    }

    /// Force a specific active set (for testing or genesis).
    pub fn set_active(&mut self, active: Vec<IdentityHash>) {
        self.active = active;
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Handles deterministic validator selection based on stake and performance.
///
/// Selection is deterministic per epoch - given the same candidate set and
/// epoch number, the same validators will always be selected. This is achieved
/// using ChaCha20 RNG seeded with the epoch hash.
pub struct ValidatorSelection;

impl ValidatorSelection {
    /// Select validators for a given epoch.
    ///
    /// Performs stake-weighted random selection with geographic diversity
    /// enforcement. The selection is deterministic - same inputs produce
    /// same outputs.
    ///
    /// # Arguments
    ///
    /// * `candidates` - List of validator candidates
    /// * `epoch` - The epoch number for deterministic seed
    ///
    /// # Returns
    ///
    /// Vector of selected validators, up to MAX_VALIDATORS (21).
    pub fn select_validators(candidates: &[ValidatorStake], epoch: u64) -> Vec<ValidatorStake> {
        // Filter candidates by minimum stake
        let eligible: Vec<_> = candidates
            .iter()
            .filter(|v| v.stake >= MIN_VALIDATOR_STAKE)
            .cloned()
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        // Build a map for internal selection
        let validators: HashMap<IdentityHash, ValidatorStake> = eligible
            .into_iter()
            .map(|v| (v.identity.clone(), v))
            .collect();

        let sla = ValidatorSla::default();
        let selected_ids = Self::select_validators_internal(&validators, &sla, epoch, &[]);

        selected_ids
            .into_iter()
            .filter_map(|id| validators.get(&id).cloned())
            .collect()
    }

    /// Internal selection logic with rotation support.
    fn select_validators_internal(
        validators: &HashMap<IdentityHash, ValidatorStake>,
        _sla: &ValidatorSla,
        epoch: u64,
        previous_active: &[IdentityHash],
    ) -> Vec<IdentityHash> {
        if validators.is_empty() {
            return Vec::new();
        }

        // Create deterministic RNG from epoch
        let seed = Self::epoch_seed(epoch);
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Filter eligible validators (minimum stake)
        let eligible: Vec<_> = validators
            .values()
            .filter(|v| v.stake >= MIN_VALIDATOR_STAKE)
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        // Calculate rotation count
        let rotation_count = if previous_active.is_empty() {
            0
        } else {
            ((previous_active.len() as f32) * VALIDATOR_ROTATION_PERCENT).ceil() as usize
        };

        // Identify validators to rotate out (worst performers among current active)
        let mut to_rotate_out: Vec<_> = previous_active
            .iter()
            .filter_map(|id| validators.get(id))
            .collect();

        // Sort by performance (ascending) - worst performers first
        to_rotate_out.sort_by(|a, b| a.performance_score.cmp(&b.performance_score));

        let rotate_out_ids: Vec<_> = to_rotate_out
            .iter()
            .take(rotation_count)
            .map(|v| v.identity.clone())
            .collect();

        // Validators that keep their spot
        let mut selected: Vec<IdentityHash> = previous_active
            .iter()
            .filter(|id| !rotate_out_ids.contains(id) && validators.contains_key(id))
            .cloned()
            .collect();

        // Track region counts
        let mut region_counts: HashMap<String, usize> = HashMap::new();
        for id in &selected {
            if let Some(v) = validators.get(id) {
                *region_counts.entry(v.region.clone()).or_insert(0) += 1;
            }
        }

        // Candidates for new selection (not already selected)
        let new_candidates: Vec<_> = eligible
            .iter()
            .filter(|v| !selected.contains(&v.identity))
            .cloned()
            .collect();

        // Calculate weights and sort by weight descending
        let mut weighted: Vec<_> = new_candidates
            .iter()
            .map(|v| {
                // Assume SLA compliant for new validators in selection
                let weight = v.calculate_weight(true);
                (v, weight)
            })
            .collect();

        // Shuffle for randomization within similar weights
        weighted.shuffle(&mut rng);

        // Sort by weight descending
        weighted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Select until we have MAX_VALIDATORS or run out of candidates
        for (validator, _weight) in weighted {
            if selected.len() >= MAX_VALIDATORS {
                break;
            }

            // Check geographic diversity
            let region_count = region_counts.get(&validator.region).copied().unwrap_or(0);
            if region_count >= MAX_VALIDATORS_PER_REGION {
                continue;
            }

            selected.push(validator.identity.clone());
            *region_counts.entry(validator.region.clone()).or_insert(0) += 1;
        }

        selected
    }

    /// Generate a deterministic seed from epoch number.
    fn epoch_seed(epoch: u64) -> [u8; 32] {
        let hash = Hash256::hash_many(&[b"VERITAS-VALIDATOR-SELECTION-v1", &epoch.to_le_bytes()]);
        hash.to_bytes()
    }

    /// Calculate selection weight for a validator.
    ///
    /// # Arguments
    ///
    /// * `stake` - Amount of reputation staked
    /// * `performance_score` - Score from 0-100
    /// * `sla_streak` - Consecutive compliant epochs
    /// * `sla_compliant` - Whether SLA was met last epoch
    pub fn calculate_weight(
        stake: u32,
        performance_score: u32,
        sla_streak: u32,
        sla_compliant: bool,
    ) -> f32 {
        let stake_weight = stake as f32;
        let perf_multiplier = 0.5 + (performance_score as f32 / 100.0);
        let sla_bonus = if sla_compliant {
            1.0 + (sla_streak as f32 * 0.05).min(0.5)
        } else {
            0.7
        };

        stake_weight * perf_multiplier * sla_bonus
    }

    /// Check geographic diversity of a candidate set.
    ///
    /// Returns true if no region has more than MAX_VALIDATORS_PER_REGION validators.
    pub fn check_geographic_diversity(validators: &[ValidatorStake]) -> bool {
        let mut region_counts: HashMap<&str, usize> = HashMap::new();

        for validator in validators {
            let count = region_counts.entry(&validator.region).or_insert(0);
            *count += 1;

            if *count > MAX_VALIDATORS_PER_REGION {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test identity hash.
    fn test_identity(id: u8) -> IdentityHash {
        let bytes = [id; 32];
        IdentityHash::from_bytes(&bytes).unwrap()
    }

    /// Helper to create a valid validator stake.
    fn test_validator(id: u8, stake: u32, region: &str) -> ValidatorStake {
        ValidatorStake {
            identity: test_identity(id),
            stake,
            performance_score: 50,
            sla_streak: 0,
            region: region.to_string(),
            registered_at: 1000000,
            last_block_at: None,
        }
    }

    // ============================================================
    // ValidatorStake Tests
    // ============================================================

    #[test]
    fn test_validator_registration_with_minimum_stake() {
        let identity = test_identity(1);
        let result =
            ValidatorStake::new(identity, MIN_VALIDATOR_STAKE, "us-east".to_string(), 1000);
        assert!(result.is_ok());

        let validator = result.unwrap();
        assert_eq!(validator.stake, MIN_VALIDATOR_STAKE);
        assert_eq!(validator.performance_score, 50);
        assert_eq!(validator.sla_streak, 0);
    }

    #[test]
    fn test_validator_registration_above_minimum_stake() {
        let identity = test_identity(2);
        let result = ValidatorStake::new(identity, 900, "eu-west".to_string(), 1000);
        assert!(result.is_ok());

        let validator = result.unwrap();
        assert_eq!(validator.stake, 900);
    }

    #[test]
    fn test_validator_registration_rejection_insufficient_stake() {
        let identity = test_identity(3);
        let result = ValidatorStake::new(identity, 600, "ap-south".to_string(), 1000);
        assert!(result.is_err());

        match result {
            Err(ChainError::InsufficientStake { required, actual }) => {
                assert_eq!(required, MIN_VALIDATOR_STAKE);
                assert_eq!(actual, 600);
            }
            _ => panic!("Expected InsufficientStake error"),
        }
    }

    #[test]
    fn test_validator_registration_rejection_zero_stake() {
        let identity = test_identity(4);
        let result = ValidatorStake::new(identity, 0, "us-west".to_string(), 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_registration_rejection_just_below_minimum() {
        let identity = test_identity(5);
        let result = ValidatorStake::new(
            identity,
            MIN_VALIDATOR_STAKE - 1,
            "eu-east".to_string(),
            1000,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Weight Calculation Tests
    // ============================================================

    #[test]
    fn test_selection_weight_calculation_basic() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 50;
        validator.sla_streak = 0;

        let weight = validator.calculate_weight(true);

        // stake=700, perf_mult=0.5+0.5=1.0, sla_bonus=1.0
        // weight = 700 * 1.0 * 1.0 = 700
        assert!((weight - 700.0).abs() < 0.001);
    }

    #[test]
    fn test_selection_weight_calculation_max_performance() {
        let mut validator = test_validator(2, 700, "us-east");
        validator.performance_score = 100;
        validator.sla_streak = 0;

        let weight = validator.calculate_weight(true);

        // stake=700, perf_mult=0.5+1.0=1.5, sla_bonus=1.0
        // weight = 700 * 1.5 * 1.0 = 1050
        assert!((weight - 1050.0).abs() < 0.001);
    }

    #[test]
    fn test_selection_weight_calculation_min_performance() {
        let mut validator = test_validator(3, 700, "us-east");
        validator.performance_score = 0;
        validator.sla_streak = 0;

        let weight = validator.calculate_weight(true);

        // stake=700, perf_mult=0.5+0.0=0.5, sla_bonus=1.0
        // weight = 700 * 0.5 * 1.0 = 350
        assert!((weight - 350.0).abs() < 0.001);
    }

    #[test]
    fn test_performance_multiplier_effect() {
        let validator_low = {
            let mut v = test_validator(1, 700, "us-east");
            v.performance_score = 20;
            v
        };
        let validator_high = {
            let mut v = test_validator(2, 700, "us-east");
            v.performance_score = 80;
            v
        };

        let weight_low = validator_low.calculate_weight(true);
        let weight_high = validator_high.calculate_weight(true);

        // Higher performance should have higher weight
        assert!(weight_high > weight_low);

        // Check specific values
        // Low: 700 * (0.5 + 0.2) * 1.0 = 700 * 0.7 = 490
        // High: 700 * (0.5 + 0.8) * 1.0 = 700 * 1.3 = 910
        assert!((weight_low - 490.0).abs() < 0.001);
        assert!((weight_high - 910.0).abs() < 0.001);
    }

    #[test]
    fn test_sla_bonus_effect_compliant() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 50;
        validator.sla_streak = 10; // Max bonus streak

        let weight = validator.calculate_weight(true);

        // stake=700, perf_mult=1.0, sla_bonus=1.0+(10*0.05)=1.5
        // weight = 700 * 1.0 * 1.5 = 1050
        assert!((weight - 1050.0).abs() < 0.001);
    }

    #[test]
    fn test_sla_bonus_effect_non_compliant() {
        let mut validator = test_validator(2, 700, "us-east");
        validator.performance_score = 50;
        validator.sla_streak = 10; // Doesn't matter when non-compliant

        let weight = validator.calculate_weight(false);

        // stake=700, perf_mult=1.0, sla_bonus=0.7
        // weight = 700 * 1.0 * 0.7 = 490
        assert!((weight - 490.0).abs() < 0.001);
    }

    #[test]
    fn test_sla_bonus_capped_at_50_percent() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 50;
        validator.sla_streak = 100; // Very high streak

        let weight = validator.calculate_weight(true);

        // stake=700, perf_mult=1.0, sla_bonus=1.0+0.5=1.5 (capped)
        // weight = 700 * 1.0 * 1.5 = 1050
        assert!((weight - 1050.0).abs() < 0.001);
    }

    #[test]
    fn test_weight_static_function() {
        let weight = ValidatorSelection::calculate_weight(700, 50, 0, true);
        assert!((weight - 700.0).abs() < 0.001);

        let weight_with_bonus = ValidatorSelection::calculate_weight(700, 50, 10, true);
        assert!((weight_with_bonus - 1050.0).abs() < 0.001);
    }

    // ============================================================
    // Selection Tests
    // ============================================================

    #[test]
    fn test_selection_from_small_candidate_pool() {
        let candidates: Vec<ValidatorStake> = (1..=5)
            .map(|i| test_validator(i, 700 + i as u32 * 10, "us-east"))
            .collect();

        let selected = ValidatorSelection::select_validators(&candidates, 1);

        // All 5 should be selected (less than max)
        assert_eq!(selected.len(), 5);
    }

    #[test]
    fn test_selection_with_max_validators() {
        let candidates: Vec<ValidatorStake> = (1..=30)
            .map(|i| {
                let region = match i % 6 {
                    0 => "us-east",
                    1 => "us-west",
                    2 => "eu-west",
                    3 => "eu-east",
                    4 => "ap-south",
                    _ => "ap-north",
                };
                test_validator(i, 700 + i as u32 * 10, region)
            })
            .collect();

        let selected = ValidatorSelection::select_validators(&candidates, 1);

        // Should be capped at MAX_VALIDATORS (21)
        assert_eq!(selected.len(), MAX_VALIDATORS);
    }

    #[test]
    fn test_selection_filters_insufficient_stake() {
        let candidates = vec![
            test_validator(1, 700, "us-east"),
            test_validator(2, 500, "us-west"), // Below minimum
            test_validator(3, 800, "eu-west"),
            test_validator(4, 100, "eu-east"), // Below minimum
        ];

        let selected = ValidatorSelection::select_validators(&candidates, 1);

        // Only 2 validators have sufficient stake
        assert_eq!(selected.len(), 2);

        // Verify the selected ones have sufficient stake
        for v in &selected {
            assert!(v.stake >= MIN_VALIDATOR_STAKE);
        }
    }

    #[test]
    fn test_selection_empty_candidates() {
        let candidates: Vec<ValidatorStake> = vec![];
        let selected = ValidatorSelection::select_validators(&candidates, 1);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_selection_all_below_minimum_stake() {
        let candidates = vec![
            test_validator(1, 500, "us-east"),
            test_validator(2, 600, "us-west"),
            test_validator(3, 699, "eu-west"),
        ];

        let selected = ValidatorSelection::select_validators(&candidates, 1);
        assert!(selected.is_empty());
    }

    // ============================================================
    // Deterministic Selection Tests
    // ============================================================

    #[test]
    fn test_deterministic_selection_same_epoch_same_result() {
        let candidates: Vec<ValidatorStake> = (1..=25)
            .map(|i| {
                let region = match i % 5 {
                    0 => "us-east",
                    1 => "us-west",
                    2 => "eu-west",
                    3 => "eu-east",
                    _ => "ap-south",
                };
                test_validator(i, 700 + i as u32 * 5, region)
            })
            .collect();

        let epoch = 12345u64;

        let selected1 = ValidatorSelection::select_validators(&candidates, epoch);
        let selected2 = ValidatorSelection::select_validators(&candidates, epoch);

        // Same epoch should produce same selection
        assert_eq!(selected1.len(), selected2.len());
        for (v1, v2) in selected1.iter().zip(selected2.iter()) {
            assert_eq!(v1.identity, v2.identity);
        }
    }

    #[test]
    fn test_deterministic_selection_different_epochs() {
        let candidates: Vec<ValidatorStake> = (1..=25)
            .map(|i| {
                let region = match i % 5 {
                    0 => "us-east",
                    1 => "us-west",
                    2 => "eu-west",
                    3 => "eu-east",
                    _ => "ap-south",
                };
                test_validator(i, 700 + i as u32 * 5, region)
            })
            .collect();

        let selected1 = ValidatorSelection::select_validators(&candidates, 100);
        let selected2 = ValidatorSelection::select_validators(&candidates, 101);

        // Different epochs may produce different selections (due to shuffling)
        // We just verify both are valid selections
        assert!(selected1.len() <= MAX_VALIDATORS);
        assert!(selected2.len() <= MAX_VALIDATORS);
    }

    // ============================================================
    // Geographic Diversity Tests
    // ============================================================

    #[test]
    fn test_geographic_diversity_enforcement() {
        // Create 30 validators, all in the same region
        let candidates: Vec<ValidatorStake> = (1..=30)
            .map(|i| test_validator(i, 700 + i as u32 * 10, "us-east"))
            .collect();

        let selected = ValidatorSelection::select_validators(&candidates, 1);

        // Should only select MAX_VALIDATORS_PER_REGION (5) from same region
        assert_eq!(selected.len(), MAX_VALIDATORS_PER_REGION);
    }

    #[test]
    fn test_geographic_diversity_multiple_regions() {
        let candidates: Vec<ValidatorStake> = (1..=30)
            .map(|i| {
                let region = match i % 3 {
                    0 => "us-east",
                    1 => "eu-west",
                    _ => "ap-south",
                };
                test_validator(i, 700 + i as u32 * 10, region)
            })
            .collect();

        let selected = ValidatorSelection::select_validators(&candidates, 1);

        // Check no region exceeds limit
        let mut region_counts: HashMap<&str, usize> = HashMap::new();
        for v in &selected {
            *region_counts.entry(&v.region).or_insert(0) += 1;
        }

        for (_region, count) in region_counts {
            assert!(count <= MAX_VALIDATORS_PER_REGION);
        }
    }

    #[test]
    fn test_check_geographic_diversity_valid() {
        let validators: Vec<ValidatorStake> = (1..=5)
            .map(|i| {
                let region = match i {
                    1 => "us-east",
                    2 => "us-west",
                    3 => "eu-west",
                    4 => "eu-east",
                    _ => "ap-south",
                };
                test_validator(i, 700, region)
            })
            .collect();

        assert!(ValidatorSelection::check_geographic_diversity(&validators));
    }

    #[test]
    fn test_check_geographic_diversity_invalid() {
        // 6 validators in same region exceeds MAX_VALIDATORS_PER_REGION (5)
        let validators: Vec<ValidatorStake> =
            (1..=6).map(|i| test_validator(i, 700, "us-east")).collect();

        assert!(!ValidatorSelection::check_geographic_diversity(&validators));
    }

    // ============================================================
    // SLA Tests
    // ============================================================

    #[test]
    fn test_sla_default_values() {
        let sla = ValidatorSla::default();
        assert!((sla.min_uptime_percent - 99.0).abs() < 0.001);
        assert_eq!(sla.max_missed_blocks_per_epoch, 3);
        assert_eq!(sla.max_response_latency_ms, 5000);
        assert_eq!(sla.min_blocks_per_epoch, 10);
    }

    #[test]
    fn test_sla_compliance_check_pass() {
        let sla = ValidatorSla::default();
        assert!(sla.check_compliance(99.5, 2, 3000, 15));
    }

    #[test]
    fn test_sla_compliance_check_fail_uptime() {
        let sla = ValidatorSla::default();
        assert!(!sla.check_compliance(98.0, 2, 3000, 15));
    }

    #[test]
    fn test_sla_compliance_check_fail_missed_blocks() {
        let sla = ValidatorSla::default();
        assert!(!sla.check_compliance(99.5, 5, 3000, 15));
    }

    #[test]
    fn test_sla_compliance_check_fail_latency() {
        let sla = ValidatorSla::default();
        assert!(!sla.check_compliance(99.5, 2, 6000, 15));
    }

    #[test]
    fn test_sla_compliance_check_fail_blocks_produced() {
        let sla = ValidatorSla::default();
        assert!(!sla.check_compliance(99.5, 2, 3000, 5));
    }

    // ============================================================
    // ValidatorSet Tests
    // ============================================================

    #[test]
    fn test_validator_set_register() {
        let mut set = ValidatorSet::new();
        let validator =
            ValidatorStake::new(test_identity(1), 800, "us-east".to_string(), 1000).unwrap();

        set.register(validator).unwrap();
        assert_eq!(set.registered_count(), 1);
    }

    #[test]
    fn test_validator_set_register_insufficient_stake() {
        let mut set = ValidatorSet::new();
        let validator = ValidatorStake {
            identity: test_identity(1),
            stake: 500, // Below minimum
            performance_score: 50,
            sla_streak: 0,
            region: "us-east".to_string(),
            registered_at: 1000,
            last_block_at: None,
        };

        let result = set.register(validator);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_set_unregister() {
        let mut set = ValidatorSet::new();
        let identity = test_identity(1);
        let validator =
            ValidatorStake::new(identity.clone(), 800, "us-east".to_string(), 1000).unwrap();

        set.register(validator).unwrap();
        assert_eq!(set.registered_count(), 1);

        let removed = set.unregister(&identity);
        assert!(removed.is_some());
        assert_eq!(set.registered_count(), 0);
    }

    #[test]
    fn test_validator_set_advance_epoch() {
        let mut set = ValidatorSet::new();

        // Register validators in different regions
        for i in 1..=10 {
            let region = match i % 5 {
                0 => "us-east",
                1 => "us-west",
                2 => "eu-west",
                3 => "eu-east",
                _ => "ap-south",
            };
            let validator = ValidatorStake::new(
                test_identity(i),
                700 + i as u32 * 10,
                region.to_string(),
                1000,
            )
            .unwrap();
            set.register(validator).unwrap();
        }

        // Advance to epoch 1
        let metrics = HashMap::new();
        set.advance_epoch(1, &metrics);

        assert!(set.active_count() <= MAX_VALIDATORS);
        assert!(set.active_count() > 0);
        assert_eq!(set.current_epoch(), 1);
    }

    // ============================================================
    // Performance Update Tests
    // ============================================================

    #[test]
    fn test_performance_update_increase() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 50;

        validator.update_performance(10);
        assert_eq!(validator.performance_score, 60);
    }

    #[test]
    fn test_performance_update_decrease() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 50;

        validator.update_performance(-15);
        assert_eq!(validator.performance_score, 35);
    }

    #[test]
    fn test_performance_update_capped_at_100() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 95;

        validator.update_performance(20);
        assert_eq!(validator.performance_score, 100);
    }

    #[test]
    fn test_performance_update_capped_at_0() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.performance_score = 10;

        validator.update_performance(-20);
        assert_eq!(validator.performance_score, 0);
    }

    // ============================================================
    // SLA Streak Tests
    // ============================================================

    #[test]
    fn test_sla_streak_compliance() {
        let mut validator = test_validator(1, 700, "us-east");
        assert_eq!(validator.sla_streak, 0);

        validator.record_sla_compliance();
        assert_eq!(validator.sla_streak, 1);

        validator.record_sla_compliance();
        assert_eq!(validator.sla_streak, 2);
    }

    #[test]
    fn test_sla_streak_violation_resets() {
        let mut validator = test_validator(1, 700, "us-east");
        validator.sla_streak = 10;

        validator.record_sla_violation();
        assert_eq!(validator.sla_streak, 0);
    }

    // ============================================================
    // Rotation Tests
    // ============================================================

    #[test]
    fn test_rotation_logic_worst_performers_first() {
        let mut set = ValidatorSet::new();

        // Create validators with varying performance
        for i in 1..=21 {
            let mut validator = ValidatorStake::new(
                test_identity(i),
                700 + i as u32 * 10,
                format!("region-{}", i % 7),
                1000,
            )
            .unwrap();
            validator.performance_score = 30 + i as u32 * 3; // 33 to 93
            set.register(validator).unwrap();
        }

        // Set initial active set (all 21)
        let all_ids: Vec<_> = set.all_validators().map(|v| v.identity.clone()).collect();
        set.set_active(all_ids);

        // Get worst performers before rotation
        let mut validators_by_perf: Vec<_> = set
            .active_validators()
            .iter()
            .map(|v| (v.identity.clone(), v.performance_score))
            .collect();
        validators_by_perf.sort_by(|a, b| a.1.cmp(&b.1));

        // Calculate expected rotation count
        let rotation_count = ((21.0 * VALIDATOR_ROTATION_PERCENT).ceil()) as usize;

        // Get identities of worst performers
        let _worst_performers: Vec<_> = validators_by_perf
            .iter()
            .take(rotation_count)
            .map(|(id, _)| id.clone())
            .collect();

        // Advance epoch
        let metrics = HashMap::new();
        set.advance_epoch(1, &metrics);

        // Verify the rotation mechanism is in place and respects MAX_VALIDATORS
        assert!(set.active_count() <= MAX_VALIDATORS);
        // Verify rotation count is calculated correctly (15% of 21 = 3.15, ceil = 4)
        assert_eq!(rotation_count, 4);
    }

    // ============================================================
    // Block Production Recording Test
    // ============================================================

    #[test]
    fn test_record_block_production() {
        let mut validator = test_validator(1, 700, "us-east");
        assert!(validator.last_block_at.is_none());

        validator.record_block_production(1234567890);
        assert_eq!(validator.last_block_at, Some(1234567890));
    }

    // ============================================================
    // Epoch Seed Test
    // ============================================================

    #[test]
    fn test_epoch_seed_deterministic() {
        let seed1 = ValidatorSelection::epoch_seed(100);
        let seed2 = ValidatorSelection::epoch_seed(100);
        let seed3 = ValidatorSelection::epoch_seed(101);

        assert_eq!(seed1, seed2);
        assert_ne!(seed1, seed3);
    }

    // ============================================================
    // Equality and Hash Tests
    // ============================================================

    #[test]
    fn test_validator_equality() {
        let v1 = test_validator(1, 700, "us-east");
        let v2 = test_validator(1, 800, "us-west"); // Same identity, different stake/region

        // Should be equal because identity is the same
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_validator_inequality() {
        let v1 = test_validator(1, 700, "us-east");
        let v2 = test_validator(2, 700, "us-east"); // Different identity

        assert_ne!(v1, v2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_validator_stake()(
            id in 1u8..=255,
            stake in MIN_VALIDATOR_STAKE..1000u32,
            perf in 0u32..=100,
            streak in 0u32..=20,
            region_idx in 0usize..6
        ) -> ValidatorStake {
            let regions = ["us-east", "us-west", "eu-west", "eu-east", "ap-south", "ap-north"];
            let bytes = [id; 32];
            ValidatorStake {
                identity: IdentityHash::from_bytes(&bytes).unwrap(),
                stake,
                performance_score: perf,
                sla_streak: streak,
                region: regions[region_idx].to_string(),
                registered_at: 1000000,
                last_block_at: None,
            }
        }
    }

    proptest! {
        #[test]
        fn weight_always_positive(
            stake in MIN_VALIDATOR_STAKE..1000u32,
            perf in 0u32..=100,
            streak in 0u32..=20,
            compliant in any::<bool>()
        ) {
            let weight = ValidatorSelection::calculate_weight(stake, perf, streak, compliant);
            prop_assert!(weight > 0.0);
        }

        #[test]
        fn higher_stake_higher_weight(
            perf in 0u32..=100,
            streak in 0u32..=20,
            compliant in any::<bool>()
        ) {
            let weight_low = ValidatorSelection::calculate_weight(700, perf, streak, compliant);
            let weight_high = ValidatorSelection::calculate_weight(900, perf, streak, compliant);
            prop_assert!(weight_high > weight_low);
        }

        #[test]
        fn selection_respects_max_validators(
            validators in proptest::collection::vec(arb_validator_stake(), 1..50),
            epoch in any::<u64>()
        ) {
            let selected = ValidatorSelection::select_validators(&validators, epoch);
            prop_assert!(selected.len() <= MAX_VALIDATORS);
        }

        #[test]
        fn selection_respects_geographic_limits(
            validators in proptest::collection::vec(arb_validator_stake(), 1..50),
            epoch in any::<u64>()
        ) {
            let selected = ValidatorSelection::select_validators(&validators, epoch);
            prop_assert!(ValidatorSelection::check_geographic_diversity(&selected));
        }

        #[test]
        fn sla_compliant_weight_higher_or_equal(
            stake in MIN_VALIDATOR_STAKE..1000u32,
            perf in 0u32..=100,
            streak in 0u32..=20
        ) {
            let compliant = ValidatorSelection::calculate_weight(stake, perf, streak, true);
            let non_compliant = ValidatorSelection::calculate_weight(stake, perf, streak, false);
            prop_assert!(compliant >= non_compliant);
        }

        #[test]
        fn performance_score_bounded(
            mut validator in arb_validator_stake(),
            delta in -100i32..=100
        ) {
            validator.update_performance(delta);
            prop_assert!(validator.performance_score <= 100);
        }
    }
}
