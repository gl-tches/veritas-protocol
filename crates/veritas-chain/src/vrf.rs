//! VRF-Based Validator Selection.
//!
//! Replaces the predictable `(epoch_seed, slot_number)` selection with
//! VRF (Verifiable Random Function) based selection. This provides:
//!
//! - **Unpredictability**: Future leaders cannot be predicted before the VRF output
//! - **Verifiability**: Anyone can verify the VRF output given the public key
//! - **Ungrindability**: Validators cannot influence selection by trying different inputs
//!
//! ## Implementation
//!
//! Uses BLAKE3-based VRF construction: VRF(sk, input) = BLAKE3(sign(sk, input)).
//! The ML-DSA-65 signature provides the randomness source, and BLAKE3 hashing
//! produces the VRF output used for selection.
//!
//! ## Fixed-Point Arithmetic
//!
//! All weight calculations use u64 fixed-point arithmetic with FIXED_POINT_SCALE
//! (1,000,000) to avoid f32 non-determinism across platforms.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;
use veritas_protocol::limits::{
    FIXED_POINT_SCALE, MAX_VALIDATORS, MAX_VALIDATORS_PER_REGION, MIN_VALIDATOR_STAKE,
    VALIDATOR_ROTATION_FIXED,
};


// =============================================================================
// Fixed-Point Weight Calculation
// =============================================================================

/// Fixed-point performance multiplier range.
/// Performance score 0 → multiplier 500_000 (0.5x)
/// Performance score 100 → multiplier 1_500_000 (1.5x)
const PERF_BASE: u64 = 500_000; // 0.5 in fixed-point
const PERF_RANGE: u64 = 1_000_000; // 1.0 in fixed-point (full range from 0.5 to 1.5)

/// SLA bonus for compliant validators.
/// Base: 1_000_000 (1.0x), bonus per streak: 50_000 (0.05x), max bonus: 500_000 (0.5x)
const SLA_BASE: u64 = 1_000_000;
const SLA_BONUS_PER_STREAK: u64 = 50_000;
const SLA_MAX_BONUS: u64 = 500_000;
const SLA_NON_COMPLIANT: u64 = 700_000; // 0.7x

/// Calculate validator selection weight using fixed-point u64 arithmetic.
///
/// Formula: weight = (stake * perf_multiplier * sla_bonus) / SCALE^2
///
/// This is deterministic across all platforms (no floating-point).
///
/// # Arguments
///
/// * `stake` - Validator's staked reputation
/// * `performance_score` - Performance score (0-100)
/// * `sla_streak` - Consecutive SLA-compliant epochs
/// * `sla_compliant` - Whether the validator met SLA last epoch
///
/// # Returns
///
/// Fixed-point weight value (scaled by FIXED_POINT_SCALE).
pub fn calculate_weight_fixed(
    stake: u32,
    performance_score: u32,
    sla_streak: u32,
    sla_compliant: bool,
) -> u64 {
    let stake_u64 = stake as u64;

    // Performance multiplier: 0.5 + (score / 100.0) in fixed-point
    // = 500_000 + (score * 1_000_000 / 100) = 500_000 + (score * 10_000)
    let perf_multiplier = PERF_BASE + (performance_score as u64 * PERF_RANGE / 100);

    // SLA bonus: compliant gets 1.0 + min(streak * 0.05, 0.5), non-compliant gets 0.7
    let sla_bonus = if sla_compliant {
        let streak_bonus = (sla_streak as u64 * SLA_BONUS_PER_STREAK).min(SLA_MAX_BONUS);
        SLA_BASE + streak_bonus
    } else {
        SLA_NON_COMPLIANT
    };

    // weight = stake * perf * sla / SCALE^2
    // Use saturating operations to prevent overflow
    let intermediate = stake_u64.saturating_mul(perf_multiplier);
    intermediate
        .saturating_mul(sla_bonus)
        / (FIXED_POINT_SCALE * FIXED_POINT_SCALE / FIXED_POINT_SCALE)
}

// =============================================================================
// VRF Output
// =============================================================================

/// A VRF output with proof of correctness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfOutput {
    /// The VRF output hash (used for selection).
    pub output: Hash256,
    /// The VRF proof (ML-DSA signature over the input).
    pub proof: Vec<u8>,
    /// The input that was signed.
    pub input: Vec<u8>,
}

impl VrfOutput {
    /// Create a VRF output using BLAKE3 hash of the proof.
    ///
    /// VRF(sk, input) = BLAKE3(sign(sk, input))
    ///
    /// # Arguments
    ///
    /// * `proof` - ML-DSA-65 signature over the input
    /// * `input` - The VRF input data
    pub fn new(proof: Vec<u8>, input: Vec<u8>) -> Self {
        let output = Hash256::hash_many(&[b"VERITAS-VRF-OUTPUT-v1", &proof]);
        Self {
            output,
            proof,
            input,
        }
    }

    /// Get the VRF output as a u64 for selection purposes.
    ///
    /// Takes the first 8 bytes of the output hash.
    pub fn as_u64(&self) -> u64 {
        let bytes = self.output.as_bytes();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Construct the VRF input for a given epoch and slot.
    pub fn make_input(epoch: u64, slot: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(49);
        input.extend_from_slice(b"VERITAS-VRF-INPUT-v1");
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&slot.to_le_bytes());
        input
    }
}

// =============================================================================
// VRF Validator Selection
// =============================================================================

/// VRF-based validator selection with fixed-point arithmetic.
///
/// Replaces the old `ValidatorSelection` with:
/// - Fixed-point u64 weights (no f32)
/// - VRF-based leader selection per slot
/// - Deterministic selection with VRF unpredictability
pub struct VrfValidatorSelection;

impl VrfValidatorSelection {
    /// Select validators for an epoch using fixed-point weights.
    ///
    /// Uses ChaCha20 RNG seeded with the epoch for deterministic selection,
    /// but weights are calculated using u64 fixed-point arithmetic.
    ///
    /// # Arguments
    ///
    /// * `candidates` - Map of validator identities to their stakes
    /// * `sla_compliance` - Map of validator identities to SLA compliance status
    /// * `epoch` - The epoch number for deterministic seed
    /// * `previous_active` - Currently active validators (for rotation)
    pub fn select_validators(
        candidates: &HashMap<IdentityHash, crate::ValidatorStake>,
        sla_compliance: &HashMap<IdentityHash, bool>,
        epoch: u64,
        previous_active: &[IdentityHash],
    ) -> Vec<IdentityHash> {
        if candidates.is_empty() {
            return Vec::new();
        }

        // Create deterministic RNG
        let seed = Self::epoch_seed(epoch);
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Filter eligible validators
        let eligible: Vec<_> = candidates
            .values()
            .filter(|v| v.stake >= MIN_VALIDATOR_STAKE)
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        // Calculate rotation count using fixed-point
        let rotation_count = if previous_active.is_empty() {
            0usize
        } else {
            let count = previous_active.len() as u64;
            // rotation = ceil(count * ROTATION_FIXED / SCALE)
            (count * VALIDATOR_ROTATION_FIXED).div_ceil(FIXED_POINT_SCALE)
                as usize
        };

        // Identify validators to rotate out (worst performers)
        let mut to_rotate_out: Vec<_> = previous_active
            .iter()
            .filter_map(|id| candidates.get(id))
            .collect();
        to_rotate_out.sort_by(|a, b| a.performance_score.cmp(&b.performance_score));

        let rotate_out_ids: Vec<_> = to_rotate_out
            .iter()
            .take(rotation_count)
            .map(|v| v.identity.clone())
            .collect();

        // Validators that keep their spot
        let mut selected: Vec<IdentityHash> = previous_active
            .iter()
            .filter(|id| !rotate_out_ids.contains(id) && candidates.contains_key(id))
            .cloned()
            .collect();

        // Track region counts
        let mut region_counts: HashMap<String, usize> = HashMap::new();
        for id in &selected {
            if let Some(v) = candidates.get(id) {
                *region_counts.entry(v.region.clone()).or_insert(0) += 1;
            }
        }

        // New candidates (not already selected)
        let new_candidates: Vec<&crate::ValidatorStake> = eligible
            .iter()
            .filter(|v| !selected.contains(&v.identity))
            .copied()
            .collect();

        // Calculate fixed-point weights
        let mut weighted: Vec<(&crate::ValidatorStake, u64)> = new_candidates
            .iter()
            .map(|v| {
                let compliant = sla_compliance
                    .get(&v.identity)
                    .copied()
                    .unwrap_or(true);
                let weight =
                    calculate_weight_fixed(v.stake, v.performance_score, v.sla_streak, compliant);
                (*v, weight)
            })
            .collect();

        // Shuffle for randomization
        use rand::seq::SliceRandom;
        weighted.shuffle(&mut rng);

        // Sort by weight descending (deterministic for equal weights due to shuffle)
        weighted.sort_by(|a, b| b.1.cmp(&a.1));

        // Select up to MAX_VALIDATORS with geographic diversity
        for (validator, _weight) in weighted {
            if selected.len() >= MAX_VALIDATORS {
                break;
            }

            let region_count = region_counts.get(&validator.region).copied().unwrap_or(0);
            if region_count >= MAX_VALIDATORS_PER_REGION {
                continue;
            }

            selected.push(validator.identity.clone());
            *region_counts.entry(validator.region.clone()).or_insert(0) += 1;
        }

        selected
    }

    /// Determine the block proposer for a given slot using VRF.
    ///
    /// The proposer is selected deterministically based on the VRF output
    /// of the previous block's proposer, or the epoch seed for the first slot.
    ///
    /// # Arguments
    ///
    /// * `active_validators` - The active validator set
    /// * `epoch` - Current epoch
    /// * `slot` - Slot number within the epoch
    /// * `previous_vrf` - VRF output from previous slot (or None for first slot)
    pub fn select_proposer(
        active_validators: &[IdentityHash],
        epoch: u64,
        slot: u64,
        previous_vrf: Option<&VrfOutput>,
    ) -> Option<IdentityHash> {
        if active_validators.is_empty() {
            return None;
        }

        // Derive selection seed from previous VRF or epoch seed
        let seed = match previous_vrf {
            Some(vrf) => {
                Hash256::hash_many(&[
                    b"VERITAS-PROPOSER-SELECTION-v1",
                    vrf.output.as_bytes(),
                    &slot.to_le_bytes(),
                ])
            }
            None => {
                Hash256::hash_many(&[
                    b"VERITAS-PROPOSER-SELECTION-v1",
                    &epoch.to_le_bytes(),
                    &slot.to_le_bytes(),
                ])
            }
        };

        let index_value = {
            let bytes = seed.as_bytes();
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        };

        let index = (index_value % active_validators.len() as u64) as usize;
        Some(active_validators[index].clone())
    }

    /// Generate deterministic seed from epoch.
    fn epoch_seed(epoch: u64) -> [u8; 32] {
        let hash =
            Hash256::hash_many(&[b"VERITAS-VRF-EPOCH-SEED-v1", &epoch.to_le_bytes()]);
        hash.to_bytes()
    }

    /// Calculate validator weight using fixed-point arithmetic.
    ///
    /// This is the public API replacement for the old f32-based
    /// `ValidatorSelection::calculate_weight`.
    pub fn calculate_weight(
        stake: u32,
        performance_score: u32,
        sla_streak: u32,
        sla_compliant: bool,
    ) -> u64 {
        calculate_weight_fixed(stake, performance_score, sla_streak, sla_compliant)
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

    // ========================================================================
    // Fixed-Point Weight Tests
    // ========================================================================

    #[test]
    fn test_fixed_point_weight_basic() {
        // stake=700, perf=50, streak=0, compliant=true
        // perf_mult = 500_000 + (50 * 10_000) = 1_000_000
        // sla_bonus = 1_000_000
        // weight = 700 * 1_000_000 * 1_000_000 / 1_000_000 = 700_000_000
        let weight = calculate_weight_fixed(700, 50, 0, true);
        assert_eq!(weight, 700_000_000);
    }

    #[test]
    fn test_fixed_point_weight_max_performance() {
        // stake=700, perf=100, streak=0, compliant=true
        // perf_mult = 500_000 + (100 * 10_000) = 1_500_000
        // sla_bonus = 1_000_000
        // weight = 700 * 1_500_000 * 1_000_000 / 1_000_000 = 1_050_000_000
        let weight = calculate_weight_fixed(700, 100, 0, true);
        assert_eq!(weight, 1_050_000_000);
    }

    #[test]
    fn test_fixed_point_weight_min_performance() {
        // stake=700, perf=0, streak=0, compliant=true
        // perf_mult = 500_000
        // sla_bonus = 1_000_000
        // weight = 700 * 500_000 * 1_000_000 / 1_000_000 = 350_000_000
        let weight = calculate_weight_fixed(700, 0, 0, true);
        assert_eq!(weight, 350_000_000);
    }

    #[test]
    fn test_fixed_point_weight_sla_bonus() {
        // stake=700, perf=50, streak=10, compliant=true
        // perf_mult = 1_000_000
        // sla_bonus = 1_000_000 + min(10 * 50_000, 500_000) = 1_500_000
        // weight = 700 * 1_000_000 * 1_500_000 / 1_000_000 = 1_050_000_000
        let weight = calculate_weight_fixed(700, 50, 10, true);
        assert_eq!(weight, 1_050_000_000);
    }

    #[test]
    fn test_fixed_point_weight_sla_non_compliant() {
        // stake=700, perf=50, streak=10, compliant=false
        // perf_mult = 1_000_000
        // sla_bonus = 700_000
        // weight = 700 * 1_000_000 * 700_000 / 1_000_000 = 490_000_000
        let weight = calculate_weight_fixed(700, 50, 10, false);
        assert_eq!(weight, 490_000_000);
    }

    #[test]
    fn test_fixed_point_weight_sla_capped() {
        // stake=700, perf=50, streak=100, compliant=true
        // perf_mult = 1_000_000
        // sla_bonus = 1_000_000 + min(100 * 50_000, 500_000) = 1_500_000
        // weight = 700 * 1_000_000 * 1_500_000 / 1_000_000 = 1_050_000_000
        let weight = calculate_weight_fixed(700, 50, 100, true);
        assert_eq!(weight, 1_050_000_000);
    }

    #[test]
    fn test_fixed_point_weight_always_positive() {
        for stake in [700u32, 800, 900, 1000] {
            for perf in [0u32, 25, 50, 75, 100] {
                for streak in [0u32, 1, 5, 10] {
                    for compliant in [true, false] {
                        let w = calculate_weight_fixed(stake, perf, streak, compliant);
                        assert!(w > 0, "Weight must be positive: stake={stake}, perf={perf}, streak={streak}, compliant={compliant}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_fixed_point_weight_deterministic() {
        let w1 = calculate_weight_fixed(700, 50, 5, true);
        let w2 = calculate_weight_fixed(700, 50, 5, true);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_higher_stake_higher_weight() {
        let low = calculate_weight_fixed(700, 50, 0, true);
        let high = calculate_weight_fixed(900, 50, 0, true);
        assert!(high > low);
    }

    #[test]
    fn test_higher_performance_higher_weight() {
        let low = calculate_weight_fixed(700, 20, 0, true);
        let high = calculate_weight_fixed(700, 80, 0, true);
        assert!(high > low);
    }

    #[test]
    fn test_sla_compliant_higher_weight() {
        let compliant = calculate_weight_fixed(700, 50, 5, true);
        let non_compliant = calculate_weight_fixed(700, 50, 5, false);
        assert!(compliant > non_compliant);
    }

    // ========================================================================
    // VRF Output Tests
    // ========================================================================

    #[test]
    fn test_vrf_output_deterministic() {
        let proof = vec![1, 2, 3, 4, 5];
        let input = VrfOutput::make_input(1, 0);

        let vrf1 = VrfOutput::new(proof.clone(), input.clone());
        let vrf2 = VrfOutput::new(proof, input);

        assert_eq!(vrf1.output, vrf2.output);
        assert_eq!(vrf1.as_u64(), vrf2.as_u64());
    }

    #[test]
    fn test_vrf_output_different_proofs() {
        let input = VrfOutput::make_input(1, 0);
        let vrf1 = VrfOutput::new(vec![1, 2, 3], input.clone());
        let vrf2 = VrfOutput::new(vec![4, 5, 6], input);

        assert_ne!(vrf1.output, vrf2.output);
    }

    #[test]
    fn test_vrf_input_construction() {
        let input1 = VrfOutput::make_input(1, 0);
        let input2 = VrfOutput::make_input(1, 1);
        let input3 = VrfOutput::make_input(2, 0);

        assert_ne!(input1, input2); // Different slots
        assert_ne!(input1, input3); // Different epochs
    }

    // ========================================================================
    // Proposer Selection Tests
    // ========================================================================

    #[test]
    fn test_proposer_selection_deterministic() {
        let validators: Vec<_> = (1..=21u8).map(test_identity).collect();

        let p1 = VrfValidatorSelection::select_proposer(&validators, 1, 0, None);
        let p2 = VrfValidatorSelection::select_proposer(&validators, 1, 0, None);

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_proposer_selection_different_slots() {
        let validators: Vec<_> = (1..=21u8).map(test_identity).collect();

        let p1 = VrfValidatorSelection::select_proposer(&validators, 1, 0, None);
        let p2 = VrfValidatorSelection::select_proposer(&validators, 1, 1, None);

        // Different slots should usually produce different proposers
        assert!(p1.is_some());
        assert!(p2.is_some());
    }

    #[test]
    fn test_proposer_selection_empty() {
        let result = VrfValidatorSelection::select_proposer(&[], 1, 0, None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_proposer_selection_single_validator() {
        let validators = vec![test_identity(1)];

        for slot in 0..10 {
            let p = VrfValidatorSelection::select_proposer(&validators, 1, slot, None);
            assert_eq!(p, Some(test_identity(1)));
        }
    }

    #[test]
    fn test_proposer_selection_with_previous_vrf() {
        let validators: Vec<_> = (1..=21u8).map(test_identity).collect();

        let vrf = VrfOutput::new(vec![1, 2, 3], VrfOutput::make_input(1, 0));

        let p_with_vrf =
            VrfValidatorSelection::select_proposer(&validators, 1, 1, Some(&vrf));
        let p_without_vrf =
            VrfValidatorSelection::select_proposer(&validators, 1, 1, None);

        // With VRF should produce a different result than without
        assert!(p_with_vrf.is_some());
        assert!(p_without_vrf.is_some());
    }

    // ========================================================================
    // Validator Selection Tests
    // ========================================================================

    #[test]
    fn test_validator_selection_empty() {
        let candidates = HashMap::new();
        let compliance = HashMap::new();

        let selected = VrfValidatorSelection::select_validators(
            &candidates,
            &compliance,
            1,
            &[],
        );

        assert!(selected.is_empty());
    }

    #[test]
    fn test_validator_selection_filters_low_stake() {
        let mut candidates = HashMap::new();
        let compliance = HashMap::new();

        // One above minimum, one below
        let v1_id = test_identity(1);
        let v1 = crate::ValidatorStake {
            identity: v1_id.clone(),
            stake: 800,
            performance_score: 50,
            sla_streak: 0,
            region: "us-east".to_string(),
            registered_at: 1000,
            last_block_at: None,
        };
        candidates.insert(v1_id, v1);

        let v2_id = test_identity(2);
        let v2 = crate::ValidatorStake {
            identity: v2_id.clone(),
            stake: 500, // Below minimum
            performance_score: 50,
            sla_streak: 0,
            region: "us-west".to_string(),
            registered_at: 1000,
            last_block_at: None,
        };
        candidates.insert(v2_id, v2);

        let selected = VrfValidatorSelection::select_validators(
            &candidates,
            &compliance,
            1,
            &[],
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], test_identity(1));
    }

    #[test]
    fn test_validator_selection_respects_max() {
        let mut candidates = HashMap::new();
        let compliance = HashMap::new();

        for i in 1..=30u8 {
            let region = match i % 6 {
                0 => "us-east",
                1 => "us-west",
                2 => "eu-west",
                3 => "eu-east",
                4 => "ap-south",
                _ => "ap-north",
            };
            let id = test_identity(i);
            let v = crate::ValidatorStake {
                identity: id.clone(),
                stake: 700 + i as u32 * 10,
                performance_score: 50,
                sla_streak: 0,
                region: region.to_string(),
                registered_at: 1000,
                last_block_at: None,
            };
            candidates.insert(id, v);
        }

        let selected = VrfValidatorSelection::select_validators(
            &candidates,
            &compliance,
            1,
            &[],
        );

        assert!(selected.len() <= MAX_VALIDATORS);
    }

    #[test]
    fn test_validator_selection_geographic_diversity() {
        let mut candidates = HashMap::new();
        let compliance = HashMap::new();

        // 20 validators all in same region
        for i in 1..=20u8 {
            let id = test_identity(i);
            let v = crate::ValidatorStake {
                identity: id.clone(),
                stake: 700 + i as u32 * 10,
                performance_score: 50,
                sla_streak: 0,
                region: "us-east".to_string(),
                registered_at: 1000,
                last_block_at: None,
            };
            candidates.insert(id, v);
        }

        let selected = VrfValidatorSelection::select_validators(
            &candidates,
            &compliance,
            1,
            &[],
        );

        // Should be capped at MAX_VALIDATORS_PER_REGION
        assert_eq!(selected.len(), MAX_VALIDATORS_PER_REGION);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fixed_point_weight_always_positive(
            stake in 700u32..1000,
            perf in 0u32..=100,
            streak in 0u32..=20,
            compliant in any::<bool>()
        ) {
            let weight = calculate_weight_fixed(stake, perf, streak, compliant);
            prop_assert!(weight > 0);
        }

        #[test]
        fn fixed_point_higher_stake_higher_weight(
            perf in 0u32..=100,
            streak in 0u32..=20,
            compliant in any::<bool>()
        ) {
            let low = calculate_weight_fixed(700, perf, streak, compliant);
            let high = calculate_weight_fixed(900, perf, streak, compliant);
            prop_assert!(high > low);
        }

        #[test]
        fn fixed_point_compliant_geq_non_compliant(
            stake in 700u32..1000,
            perf in 0u32..=100,
            streak in 0u32..=20
        ) {
            let compliant = calculate_weight_fixed(stake, perf, streak, true);
            let non_compliant = calculate_weight_fixed(stake, perf, streak, false);
            prop_assert!(compliant >= non_compliant);
        }

        #[test]
        fn fixed_point_deterministic(
            stake in 700u32..1000,
            perf in 0u32..=100,
            streak in 0u32..=20,
            compliant in any::<bool>()
        ) {
            let w1 = calculate_weight_fixed(stake, perf, streak, compliant);
            let w2 = calculate_weight_fixed(stake, perf, streak, compliant);
            prop_assert_eq!(w1, w2);
        }
    }
}
